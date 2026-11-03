"""Apply only the explicit frozen target manifest when the root explicitly passes --apply.

Default: read-only dry-run. Apply an explicit pilot of 3-5 targets, verify its receipt, then the remaining exact targets.
Every write has fresh tag-map CAS, durable intent, readback, and local undo preview.
No removal API, credential retrieval, resource creation/deletion or security toggle.
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent / 'control'))
import aws_context as aws
import verify_tags as readers
from botocore.exceptions import ClientError, BotoCoreError
PREVIEW_SHA256 = CONFIG.get('safety', {}).get('tag_preview_sha256')
TARGET_IDS_SHA256 = CONFIG.get('safety', {}).get('tag_target_ids_sha256')
EXPECTED_PRINCIPAL = CONFIG.get('safety', {}).get('tag_principal_arn')
PILOT = tuple(tuple(row) for row in CONFIG.get('safety', {}).get('tag_pilot', []))

def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load_preview(path):
    require(3 <= len(PILOT) <= 5 and len(set(PILOT)) == len(PILOT), 'Configure an explicit pilot of 3-5 distinct tag targets')
    if fingerprint(path) != PREVIEW_SHA256:
        raise ValueError('Frozen preview fingerprint mismatch')
    data = json.loads(path.read_text(encoding='utf-8-sig'))
    if (data.get('account'), data.get('region'), data.get('run_id')) != (aws.ACCOUNT, aws.REGION, aws.RUN):
        raise ValueError('Wrong preview scope')
    required = readers.tag_dict(aws.tags())
    if data.get('required_tags') != required:
        raise ValueError('Required tag contract mismatch')
    targets = data['resources']
    digest = hashlib.sha256(json.dumps(sorted(((r['service'], r['arn']) for r in targets)), separators=(',', ':')).encode()).hexdigest()
    if len(targets) != CONFIG.get('safety', {}).get('tag_target_count') or digest != TARGET_IDS_SHA256 or len({(r['service'], r['id']) for r in targets}) != CONFIG.get('safety', {}).get('tag_target_count'):
        raise ValueError('Exact target manifest mismatch')
    for target in targets:
        if target['arn'].split(':')[4] != aws.ACCOUNT:
            raise ValueError('Wrong target account')
        if target['service'] != 'iam' and target['arn'].split(':')[3] != aws.REGION:
            raise ValueError('Wrong target region')
        if target['service'] not in {'ec2', 'iam', 'logs', 'lambda', 'sqs', 'events'}:
            raise ValueError('Unapproved writer service')
        if not target['set_tags'] or any((k not in required or required[k] != v for k, v in target['set_tags'].items())):
            raise ValueError('Unapproved tag key/value')
        if any((k.startswith('aws:') or k == 'GuardDutyManaged' for k in target['set_tags'])):
            raise ValueError('Protected tag mutation refused')
    if not set(PILOT).issubset({(r['service'], r['id']) for r in targets}):
        raise ValueError('Pilot not bound to preview')
    return targets

def selected_targets(targets, phase):
    by_id = {(t['service'], t['id']): t for t in targets}
    if phase == 'pilot':
        return [by_id[k] for k in PILOT]
    if phase == 'remaining':
        return [t for t in targets if (t['service'], t['id']) not in PILOT]
    return targets

def read_tags(target, clients):
    service, identifier, arn = (target['service'], target['id'], target['arn'])
    if service == 'ec2':
        rows = readers.collect(clients, 'ec2', 'describe_tags', {'Filters': [{'Name': 'resource-id', 'Values': [identifier]}]}, 'Tags')
        return {r['Key']: r.get('Value', '') for r in rows}
    if service == 'iam':
        if target['kind'] == 'AWS::IAM::InstanceProfile':
            response = readers.request(clients, 'iam', 'get_instance_profile', {'InstanceProfileName': identifier})['InstanceProfile']
        else:
            response = readers.request(clients, 'iam', 'get_role', {'RoleName': identifier})['Role']
        return readers.tag_dict(response.get('Tags', []))
    if service == 'logs':
        return readers.request(clients, service, 'list_tags_for_resource', {'resourceArn': arn}).get('tags', {})
    if service == 'lambda':
        return readers.request(clients, service, 'list_tags', {'Resource': arn}).get('Tags', {})
    if service == 'sqs':
        return readers.request(clients, service, 'list_queue_tags', {'QueueUrl': identifier}).get('Tags', {})
    if service == 'events':
        return readers.tag_dict(readers.request(clients, service, 'list_tags_for_resource', {'ResourceARN': arn}).get('Tags', []))
    raise ValueError('No approved tag reader')

def write_request(target):
    service, identifier, arn = (target['service'], target['id'], target['arn'])
    updates = target['set_tags']
    tag_list = [{'Key': k, 'Value': v} for k, v in updates.items()]
    if service == 'ec2':
        return (service, 'create_tags', {'Resources': [identifier], 'Tags': tag_list})
    if service == 'iam':
        if target['kind'] == 'AWS::IAM::InstanceProfile':
            return (service, 'tag_instance_profile', {'InstanceProfileName': identifier, 'Tags': tag_list})
        return (service, 'tag_role', {'RoleName': identifier, 'Tags': tag_list})
    if service == 'logs':
        return (service, 'tag_resource', {'resourceArn': arn, 'tags': updates})
    if service == 'lambda':
        return (service, 'tag_resource', {'Resource': arn, 'Tags': updates})
    if service == 'sqs':
        return (service, 'tag_queue', {'QueueUrl': identifier, 'Tags': updates})
    if service == 'events':
        return (service, 'tag_resource', {'ResourceARN': arn, 'Tags': tag_list})
    raise ValueError('No approved tag writer')

def write_tags(target, clients, enabled):
    if enabled is not True:
        raise ValueError('AWS writes require explicit --apply')
    service, method, params = write_request(target)
    c = clients.get(service)
    if c is None:
        c = clients[service] = aws.client(service)
    allowed = {aws.REGION, 'aws-global'} if service == 'iam' else {aws.REGION}
    if c.meta.region_name not in allowed:
        raise ValueError('Wrong client region')
    result = getattr(c, method)(**params)
    meta = result.get('ResponseMetadata', {})
    return {'operation': method, 'request_id': meta.get('RequestId'), 'http_status': meta.get('HTTPStatusCode')}

def expected_after(target):
    return {**target['before_tags'], **target['set_tags']}

def cas_state(target, current):
    if current == expected_after(target):
        return 'already_applied'
    if current == target['before_tags']:
        return 'ready'
    return 'conflict'

def undo_preview(target):
    before = target['before_tags']
    return {'cas_required_current_tags': expected_after(target), 'restore_tag_values': {k: before[k] for k in target['set_tags'] if k in before}, 'remove_only_added_keys': [k for k in target['set_tags'] if k not in before], 'executed': False}

def save(path, receipt):
    if not path.resolve().is_relative_to(BASE):
        raise ValueError('Receipt must remain in verification directory')
    temp = path.with_name(path.name + '.tmp')
    temp.write_text(json.dumps(aws.clean(receipt), indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    temp.replace(path)

def validate_pilot(path, script_hash, targets, clients):
    receipt = json.loads(path.read_text(encoding='utf-8-sig'))
    if receipt.get('preview_sha256') != PREVIEW_SHA256 or receipt.get('script_sha256') != script_hash or receipt.get('phase') != 'pilot' or (receipt.get('apply') is not True) or (receipt.get('status') != 'complete'):
        raise ValueError('Completed pilot receipt does not match this script and preview')
    if {(r['service'], r['id']) for r in receipt.get('results', [])} != set(PILOT) or any((r.get('status') not in {'written_and_verified', 'already_applied'} for r in receipt['results'])):
        raise ValueError('Pilot did not verify all five bound targets')
    for target in selected_targets(targets, 'pilot'):
        if read_tags(target, clients) != expected_after(target):
            raise ValueError('Pilot target changed after verification')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--preview', type=Path, default=BASE / 'tags-required-diff.json')
    p.add_argument('--phase', choices=('pilot', 'remaining', 'all'), default='pilot')
    p.add_argument('--apply', action='store_true', help='Only the root execution process may invoke this flag')
    p.add_argument('--pilot-receipt', type=Path, default=BASE / 'tag-apply-pilot-receipt.json')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    if (aws.ACCOUNT, aws.REGION, aws.PROFILE) != (ACCOUNT, 'us-east-1', PROFILE):
        raise ValueError('AWS context is outside the authorized profile/account/region')
    if args.apply and args.phase == 'all':
        raise ValueError('Apply requires pilot then remaining; all is read-only')
    targets = load_preview(args.preview)
    selected = selected_targets(targets, args.phase)
    script_hash = fingerprint(Path(__file__))
    ident = aws.identity()
    if ident['Arn'] != EXPECTED_PRINCIPAL:
        raise ValueError('Wrong principal for this reviewed execution')
    clients = {}
    if args.apply and args.phase == 'remaining':
        validate_pilot(args.pilot_receipt, script_hash, targets, clients)
    path = args.output or BASE / ('tag-apply-' + args.phase + ('-receipt.json' if args.apply else '-dry-run.json'))
    if not path.resolve().is_relative_to(BASE):
        raise ValueError('Receipt must remain in verification directory')
    if path.exists():
        history = BASE / 'tag-apply-history'
        history.mkdir(exist_ok=True)
        old_name = aws.stamp().replace(':', '-').replace('+', '_') + '-' + path.name
        (history / old_name).write_bytes(path.read_bytes())
    receipt = {'schema_version': 1, 'started_at_utc': aws.stamp(), 'identity': ident, 'run_id': aws.RUN, 'preview_sha256': PREVIEW_SHA256, 'target_ids_sha256': TARGET_IDS_SHA256, 'script_sha256': script_hash, 'apply': args.apply, 'phase': args.phase, 'selected_count': len(selected), 'status': 'preflight', 'results': [], 'write_count': 0}
    save(path, receipt)
    try:
        for target in selected:
            current = read_tags(target, clients)
            state = cas_state(target, current)
            receipt['results'].append({'service': target['service'], 'id': target['id'], 'arn': target['arn'], 'before_tags': current, 'set_tags': target['set_tags'], 'precondition': state, 'status': 'planned', 'undo_preview': undo_preview(target)})
        if any((r['precondition'] == 'conflict' for r in receipt['results'])):
            receipt['status'] = 'precondition_failed'
            save(path, receipt)
            print(json.dumps({'status': receipt['status'], 'write_count': 0, 'receipt': str(path)}, indent=2))
            return 2
        if not args.apply:
            receipt['status'] = 'dry_run_complete'
            receipt['completed_at_utc'] = aws.stamp()
            save(path, receipt)
            print(json.dumps({'status': receipt['status'], 'targets': len(selected), 'write_count': 0, 'receipt': str(path)}, indent=2))
            return 0
        for target, row in zip(selected, receipt['results']):
            current = read_tags(target, clients)
            state = cas_state(target, current)
            row['cas_at_utc'] = aws.stamp()
            row['cas_tags'] = current
            if state == 'conflict':
                row['status'] = 'conflict_before_write'
                receipt['status'] = 'stopped'
                save(path, receipt)
                return 2
            if state == 'already_applied':
                row['status'] = 'already_applied'
                row['readback_tags'] = current
                save(path, receipt)
                continue
            row['status'] = 'write_requested'
            receipt['status'] = 'writing'
            save(path, receipt)
            row['write_response'] = write_tags(target, clients, args.apply)
            receipt['write_count'] += 1
            row['readback_attempts'] = []
            for attempt in range(3):
                after = read_tags(target, clients)
                row['readback_attempts'].append({'time_utc': aws.stamp(), 'tags': after})
                if after == expected_after(target):
                    break
                if attempt < 2:
                    time.sleep(1)
            row['readback_tags'] = after
            if after != expected_after(target):
                row['status'] = 'readback_mismatch'
                receipt['status'] = 'stopped'
                save(path, receipt)
                return 2
            row['status'] = 'written_and_verified'
            row['verified_at_utc'] = aws.stamp()
            save(path, receipt)
        receipt['status'] = 'complete'
        receipt['completed_at_utc'] = aws.stamp()
        save(path, receipt)
    except (ClientError, BotoCoreError, ValueError) as error:
        receipt['status'] = 'stopped_on_error'
        receipt['error_code'] = error.response['Error']['Code'] if isinstance(error, ClientError) else type(error).__name__
        pending = next((r for r in receipt['results'] if r['status'] == 'write_requested'), None)
        if pending:
            target = next((t for t in selected if t['service'] == pending['service'] and t['id'] == pending['id']))
            try:
                pending['reconciliation_tags'] = read_tags(target, clients)
                pending['effect_state'] = cas_state(target, pending['reconciliation_tags'])
            except (ClientError, BotoCoreError, ValueError):
                pending['effect_state'] = 'unknown; exact readback required before continuation'
        save(path, receipt)
        print(json.dumps({'status': receipt['status'], 'write_count': receipt['write_count'], 'error_code': receipt['error_code'], 'receipt': str(path)}, indent=2))
        return 2
    print(json.dumps({'status': receipt['status'], 'targets': len(selected), 'write_count': receipt['write_count'], 'receipt': str(path)}, indent=2))
    return 0
if __name__ == '__main__':
    sys.exit(main())
