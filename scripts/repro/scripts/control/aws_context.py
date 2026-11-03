"""Explicit local reproduction context. Import/help never authenticates or calls AWS.

Set PG_LAB_CONTEXT to the credential-free config.json before running a controller.
CloudFormation bindings are imported from saved, exact stack readbacks by the
local `bind` command. This file never resolves or accepts credential values.
"""
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTEXT_PATH = Path(os.environ.get('PG_LAB_CONTEXT', ROOT.parent / 'config.json')).resolve()
REGION = 'us-east-1'
SECRET_KEYS = {'password', 'secretstring', 'secretbinary', 'secretaccesskey', 'sessiontoken',
               'awsaccesskeyid', 'awssecretaccesskey', 'awssessiontoken', 'credentials', 'privatekey'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def no_secrets(value):
    if isinstance(value, dict):
        for key, item in value.items():
            require(re.sub('[^a-z0-9]', '', key.lower()) not in SECRET_KEYS, 'Credential value field refused')
            no_secrets(item)
    elif isinstance(value, list):
        for item in value:
            no_secrets(item)
    elif isinstance(value, str):
        require(not re.search(r'(?:AKIA|ASIA)[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|SCRAM-SHA-256\$', value), 'Credential value refused')


def read_context(path=CONTEXT_PATH):
    if not Path(path).is_file():
        return {}
    value = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    require(isinstance(value, dict), 'Context must be a JSON object')
    no_secrets(value)
    return value


def validate_context(value, *, now=None, require_future=True):
    require(isinstance(value, dict), 'Context must be a JSON object')
    no_secrets(value)
    require(value.get('region') == REGION, 'Only us-east-1 is authorized by this package')
    require(re.fullmatch(r'[0-9]{12}', str(value.get('expected_account_id', ''))) is not None, 'Set expected_account_id explicitly')
    require(isinstance(value.get('profile'), str) and re.fullmatch(r'[A-Za-z0-9_.@+-]{1,128}', value['profile']) is not None, 'Set the named local AWS profile explicitly')
    require(re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', str(value.get('prefix', ''))) is not None and 3 <= len(value['prefix']) <= 32, 'Set a unique resource prefix')
    for key in ('resource_run_id', 'run_id'):
        require(re.fullmatch(r'[A-Za-z0-9-]{3,64}', str(value.get(key, ''))) is not None, 'Set ' + key + ' explicitly')
    require(isinstance(value.get('owner'), str) and 1 <= len(value['owner']) <= 128, 'Set the Owner tag explicitly')
    require(value.get('environment', 'HML') == 'HML' and value.get('project', 'postgresql-migration-lab') == 'postgresql-migration-lab', 'HML laboratory ownership contract differs')
    require(value.get('database', 'migration_lab') == 'migration_lab', 'Only migration_lab is in scope')
    require(isinstance(value.get('expires_at'), str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value['expires_at']) is not None, 'Set expiry as UTC YYYY-MM-DDTHH:MM:SSZ')
    expiry = datetime.fromisoformat(value['expires_at'].replace('Z', '+00:00'))
    now = now or datetime.now(timezone.utc)
    if require_future:
        require(now < expiry <= now + timedelta(hours=72), 'Expiry must be future and no more than 72 hours away')
    require(0 < value.get('maximum_incremental_usd', 1000) <= 1000, 'The authorized ceiling cannot exceed USD1000')
    require(0 < value.get('operating_envelope_usd', 100) <= value.get('maximum_incremental_usd', 1000), 'Operating envelope exceeds the ceiling')
    bindings = value.get('bindings', {})
    require(isinstance(bindings, dict), 'bindings must be an object')
    runs = value.get('evidence_run_ids', [value['run_id']])
    require(isinstance(runs, list) and 1 <= len(runs) <= 2 and len(set(runs)) == len(runs) and all(re.fullmatch(r'[A-Za-z0-9-]{3,64}', str(x)) for x in runs), 'evidence_run_ids must contain one or two distinct explicit ledger IDs')
    for key, item in bindings.items():
        if not item or not isinstance(item, str) or not item.startswith('arn:'):
            continue
        parts = item.split(':', 5)
        require(len(parts) == 6 and parts[0:2] == ['arn', 'aws'] and parts[4] == value['expected_account_id'], 'Binding ARN account differs: ' + key)
        require(parts[3] == ('' if parts[2] == 'iam' else REGION), 'Binding ARN region differs: ' + key)
    for key, suffix in (('main_stack_arn', ''), ('migration_stack_arn', '-migration'), ('guardrail_stack_arn', '-guardrail')):
        item = bindings.get(key)
        if item:
            require(re.fullmatch(re.escape('arn:aws:cloudformation:' + REGION + ':' + value['expected_account_id'] + ':stack/' + value['prefix'] + suffix + '/') + r'[A-Za-z0-9-]+', item) is not None, 'Immutable stack/name binding differs: ' + key)
    for key in ('source_host', 'dms_private_ip'):
        if bindings.get(key):
            require(ipaddress.ip_address(bindings[key]).is_private, 'Database hosts must be private: ' + key)
    if bindings.get('rds_endpoint'):
        require(bindings['rds_endpoint'].endswith('.us-east-1.rds.amazonaws.com'), 'RDS DNS region differs')
    return value


def load_context(*, require_future=True):
    return validate_context(read_context(), require_future=require_future)


CONFIG = read_context()
ACCOUNT = CONFIG.get('expected_account_id') or ''
PROFILE = CONFIG.get('profile') or ''
STACK = CONFIG.get('prefix') or ''
RUN = CONFIG.get('resource_run_id') or ''
TEST_RUN = CONFIG.get('run_id') or ''
MAIN_STACK_ARN = CONFIG.get('bindings', {}).get('main_stack_arn') or ''
SESSION = None


def binding_value(name, *, required=True):
    value = CONFIG.get('bindings', {}).get(name)
    if required:
        require(bool(value), 'Bind the exact new resource before use: ' + name)
    return value


def client(service):
    global SESSION
    # A past deadline still permits readback and teardown; the operator must not
    # start a new test after expiry. No profile/account discovery fallback exists.
    load_context(require_future=False)
    if SESSION is None:
        import boto3
        SESSION = boto3.Session(profile_name=PROFILE, region_name=REGION)
    from botocore.config import Config
    return SESSION.client(service, region_name=REGION, config=Config(connect_timeout=10, read_timeout=30, retries={'max_attempts': 2, 'mode': 'standard'}))


def identity():
    load_context(require_future=False)
    result = client('sts').get_caller_identity()
    require(result['Account'] == ACCOUNT, 'Wrong AWS account')
    require(':root' not in result.get('Arn', ''), 'Root credentials are refused')
    return {'Account': result['Account'], 'Arn': result['Arn'], 'Region': REGION}


def stamp():
    return datetime.now(timezone.utc).isoformat()


def clean(value):
    no_secrets(value)
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items() if k != 'ResponseMetadata'}
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return '<binary not logged>'
    return value


def save(name, data):
    require(Path(name).name == name and re.fullmatch(r'[A-Za-z0-9_.-]+', name) is not None, 'Evidence path must be a simple filename')
    path = ROOT / 'evidence' / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(clean(data), ensure_ascii=False, indent=2, default=str) + '\n', encoding='utf-8')
    return str(path)


def tags():
    cfg = load_context(require_future=False)
    return [{'Key': k, 'Value': v} for k, v in {'Environment': 'HML', 'Project': 'postgresql-migration-lab', 'Owner': cfg['owner'], 'ManagedBy': cfg.get('managed_by', 'migration-lab-toolkit'), 'RunId': cfg['resource_run_id'], 'ExpiresAt': cfg['expires_at']}.items()]


def saved_stack(path, context, kind):
    value = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    no_secrets(value)
    value = value.get('result', value)
    stacks = value.get('Stacks')
    require(isinstance(stacks, list) and len(stacks) == 1, 'Use a complete describe-stacks readback containing exactly one stack')
    stack = stacks[0]
    suffix = {'main': '', 'migration': '-migration', 'guardrail': '-guardrail'}[kind]
    expected = 'arn:aws:cloudformation:' + REGION + ':' + context['expected_account_id'] + ':stack/' + context['prefix'] + suffix + '/'
    require(stack.get('StackId', '').startswith(expected), 'Saved stack identity differs')
    require(stack.get('StackStatus') in {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}, 'Saved stack is not successfully complete')
    observed = {row['Key']: row['Value'] for row in stack.get('Tags', [])}
    require(all(observed.get(k) == v for k, v in {'Environment': 'HML', 'Project': 'postgresql-migration-lab', 'RunId': context['resource_run_id']}.items()), 'Saved stack ownership differs')
    outputs = {row['OutputKey']: row['OutputValue'] for row in stack.get('Outputs', [])}
    require(len(outputs) == len(stack.get('Outputs', [])), 'Duplicate output key refused')
    return stack['StackId'], outputs


def bind_saved(context, kind, path):
    cfg = json.loads(json.dumps(context))
    arn, outputs = saved_stack(path, cfg, kind)
    bindings = cfg.setdefault('bindings', {})
    bindings[kind + '_stack_arn'] = arn
    mapping = {'VpcId': 'vpc_id', 'SourceInstanceId': 'source_instance_id', 'SourceRoleArn': 'source_role_arn', 'SourceRoleName': 'source_role_name', 'SourcePrivateIp': 'source_host', 'TargetEndpoint': 'rds_endpoint', 'ReplicationInstanceArn': 'replication_instance_arn', 'ReplicationInstanceIdentifier': 'replication_instance_identifier', 'SourceSecretArn': 'source_secret_arn', 'TargetSecretArn': 'target_secret_arn', 'ClientSecretArn': 'client_secret_arn', 'MasterSecretArn': 'master_secret_arn', 'SourceEndpointArn': 'source_endpoint_arn', 'TargetEndpointArn': 'target_endpoint_arn', 'ReplicationTaskArn': 'dms_task_arn', 'DeletionRoleArn': 'teardown_role_arn'}
    for output, key in mapping.items():
        if output in outputs:
            bindings[key] = outputs[output]
    if outputs.get('DmsPrivateIpAddresses'):
        ips = [x.strip() for x in outputs['DmsPrivateIpAddresses'].split(',') if x.strip()]
        require(len(ips) == 1, 'Single-AZ reproduction expects one DMS private IP')
        bindings['dms_private_ip'] = ips[0]
    if bindings.get('source_role_arn'):
        bindings['source_role_name'] = bindings['source_role_arn'].split('/', 1)[1]
    if kind == 'main':
        require(outputs.get('RunIdentifier') == cfg['resource_run_id'] and outputs.get('ExpiresAtUtc') == cfg['expires_at'], 'Main outputs ownership or TTL differs')
    bindings['certificate_identifier'] = cfg['prefix'] + '-rds-ca'
    if bindings.get('replication_instance_identifier'):
        bindings['log_group_name'] = 'dms-tasks-' + bindings['replication_instance_identifier']
    if bindings.get('dms_task_arn'):
        bindings['log_stream_name'] = 'dms-task-' + bindings['dms_task_arn'].rsplit(':', 1)[1]
    validate_context(cfg, require_future=False)
    return cfg


def runtime_config(context):
    validate_context(context, require_future=False)
    b = context.get('bindings', {})
    required = ('source_host', 'dms_private_ip', 'rds_endpoint', 'source_role_name', 'source_secret_arn', 'target_secret_arn', 'client_secret_arn', 'master_secret_arn')
    require(all(b.get(key) for key in required), 'Main-stack runtime bindings are incomplete')
    result = {key: b[key] for key in required}
    result.update(run_id=context['run_id'], resource_run_id=context['resource_run_id'], region=REGION, expected_account_id=context['expected_account_id'], database='migration_lab', rds_ca_path='/opt/pg-lab/certs/us-east-1-bundle.pem', state_dir='/opt/pg-lab/state')
    if b.get('dms_task_arn'):
        result['dms_task_arn'] = b['dms_task_arn']
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('validate', 'bind', 'runtime', 'policy'))
    parser.add_argument('--kind', choices=('main', 'migration', 'guardrail'))
    parser.add_argument('--readback', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        cfg = load_context(require_future=args.action == 'validate')
        if args.action == 'bind':
            require(args.kind and args.readback and args.output, 'bind requires --kind, --readback and --output')
            cfg = bind_saved(cfg, args.kind, args.readback)
        elif args.action == 'runtime':
            require(args.output, 'runtime requires --output')
            cfg = runtime_config(cfg)
        elif args.action == 'policy':
            require(args.output, 'policy requires --output')
            raw = (ROOT / 'guardrails' / 'teardown.bootstrap.policy.example.json').read_text(encoding='utf-8')
            raw = raw.replace('__ACCOUNT_ID__', cfg['expected_account_id']).replace('__PREFIX__', cfg['prefix']).replace('__RESOURCE_RUN_ID__', cfg['resource_run_id'])
            cfg = json.loads(raw)
            no_secrets(cfg)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        print(json.dumps({'success': True, 'aws_calls': 0, 'action': args.action, 'output': str(args.output) if args.output else None}))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({'success': False, 'aws_calls': 0, 'error': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
