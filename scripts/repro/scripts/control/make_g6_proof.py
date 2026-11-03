"""Fail-closed G6 attestation from preserved local JSON evidence; no AWS calls.

CLI: python make_g6_proof.py --inputs manifest.json --output evidence/proof.json
Manifest contains run_id, task_arn, marker_id and the eleven evidence basenames.
Success exits0; invalid/missing/stale evidence exits2 without writing a proof.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import math
from pathlib import Path
import re
import sys
EVIDENCE = Path(__file__).resolve().parents[1] / 'evidence'
FILES = ('marker_evidence', 'source_freeze_evidence', 'target_freeze_evidence', 'marker_observe_evidence', 'revalidation_request', 'native_readback', 'metrics_readback', 'logs_readback', 'divergence_comparison', 't04_revalidation_request', 'native_divergence_failure')
COUNTERS = ('ValidationPendingRecords', 'ValidationFailedRecords', 'ValidationSuspendedRecords')
METRICS = ('CDCIncomingChanges', 'CDCLatencySource', 'CDCLatencyTarget')

class InvalidProof(ValueError):
    pass

def need(condition, message):
    if not condition:
        raise InvalidProof(message)

def stamp(value):
    need(isinstance(value, str), 'timestamp missing or not a string')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise InvalidProof('invalid evidence timestamp') from None
    need(result.tzinfo is not None, 'timestamp must have a timezone')
    return result.astimezone(timezone.utc)

def utc(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

def number(value, label):
    need(type(value) in (int, float) and math.isfinite(value), label + ' must be a finite number')
    return value

def counter(data, key):
    need(type(data.get(key)) is int and data[key] >= 0, 'missing/invalid native counter: ' + key)
    return data[key]

def envelope(data, run, command):
    if 'envelope' in data:
        need(data.get('returncode') == 0 and data.get('execution_state') == 'completed', 'harness process did not complete successfully')
        data = data['envelope']
    need(data.get('success') is True and data.get('run_id') == run, 'harness failed or run_id differs')
    need(data.get('evidence_kind') == 'observed' and data.get('command') == command, 'wrong harness evidence kind/command')
    identity = data.get('aws_identity', {})
    need(identity.get('account') == ACCOUNT and identity.get('region') == 'us-east-1', 'harness account/region differs')
    stamp(data.get('finished_at_utc'))
    return data

def inspect(data, task):
    need(data.get('action') == 'inspect', 'expected DMS inspect evidence')
    result = data['result']
    need(result['task'].get('ReplicationTaskArn') == task and result['task'].get('Status') == 'running', 'native task binding/state differs')
    tables = result['tables']
    need(tables.get('ReplicationTaskArn') == task, 'native table task binding differs')
    rows = tables.get('TableStatistics')
    need(isinstance(rows, list) and len(rows) == 1, 'native selection must contain exactly one table')
    row = rows[0]
    need(row.get('SchemaName') == 'lab' and row.get('TableName') == 'orders_lab', 'native table differs')
    for key in COUNTERS:
        counter(row, key)
    stamp(row.get('LastUpdateTime'))
    return row

def request_time(data, task):
    need(data.get('action') == 'revalidate' and data.get('result', {}).get('ReplicationTaskArn') == task, 'revalidation task/action differs')
    return stamp(data.get('time'))

def freeze(data, side):
    report, probe = (data['role_report'], data['negative_probe'])
    need(report.get('side') == side, 'freeze side differs')
    writer = 'lab_writer_' + side
    need(report.get('writer_sessions') == [], 'writer sessions missing or remain')
    need(report.get('memberships') == [], 'writer/reader membership path remains')
    owners = report.get('owners', {})
    need('table_owner' in owners and 'schema_owner' in owners and (writer not in owners.values()), 'writer ownership path missing or remains')
    roles = [r for r in report.get('roles', []) if r.get('rolname') == writer]
    need(len(roles) == 1, 'writer role not uniquely evidenced')
    need(all((roles[0].get(k) is False for k in ('rolsuper', 'rolcreaterole', 'rolcreatedb', 'rolreplication', 'rolbypassrls'))), 'writer administrative role remains or is unknown')
    privileges = report.get('writer_privileges', {})
    need(all((privileges.get(k) is False for k in ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'))), 'writer privileges missing or remain')
    columns = report.get('column_writes')
    need(isinstance(columns, list) and {x.get('attname') for x in columns} == {'id', 'customer_label', 'status', 'amount', 'revision', 'note'}, 'column write coverage incomplete')
    need(all((x.get('can_insert') is False and x.get('can_update') is False for x in columns)), 'column writer privileges remain or are unknown')
    need(probe.get('passed') is True and probe.get('sqlstate') == '42501' and (probe.get('attempt_succeeded') is False) and (probe.get('rollback_confirmed') is True), 'negative probe did not prove 42501 and rollback')
    need(probe.get('identity', {}).get('side') == side and probe['identity'].get('username') == writer, 'negative probe identity differs')

def validate(inputs, evidence_dir=EVIDENCE, now=None):
    now = now or datetime.now(timezone.utc)
    root = Path(evidence_dir).resolve()
    run, task, marker = (inputs['run_id'], inputs['task_arn'], inputs['marker_id'])
    need(isinstance(run, str) and run == TEST_RUN and re.fullmatch('[A-Za-z0-9-]{3,64}', run), 'unexpected run_id')
    need(isinstance(task, str) and re.fullmatch(f'arn:aws:dms:us-east-1:{ACCOUNT}:task:[A-Z0-9]+', task), 'task account/region/ARN differs')
    need(type(marker) is int and marker in (901, 902), 'marker_id must be901 or902')
    docs, hashes, names = ({}, {}, {})
    for key in FILES:
        name = inputs[key]
        need(isinstance(name, str) and Path(name).name == name and ('/' not in name) and ('\\' not in name) and name.endswith('.json'), 'evidence inputs must be JSON basenames')
        need(run[-3:] in name, 'evidence filename lacks its run suffix: ' + key)
        path = (root / name).resolve()
        need(path.parent == root, 'evidence path escaped its directory')
        raw = path.read_bytes()
        docs[key] = json.loads(raw.decode('utf-8-sig'))
        hashes[key], names[key] = (hashlib.sha256(raw).hexdigest(), name)
    need(len(set(names.values())) == len(FILES), 'evidence files must be distinct')
    envs = {}
    for key, command in (('marker_evidence', 'marker-' + str(marker)), ('source_freeze_evidence', 'freeze-source'), ('target_freeze_evidence', 'freeze-target'), ('marker_observe_evidence', 'observe'), ('divergence_comparison', 'compare')):
        envs[key] = envelope(docs[key], run, command)
    md = envs['marker_evidence']['data']
    need(md.get('test') == 'T05-marker-' + str(marker) and md.get('side') == 'source' and (md.get('before') == []), 'marker commit receipt differs')
    after = md.get('after')
    need(isinstance(after, list) and len(after) == 1 and (after[0].get('id') == marker), 'marker row differs')
    commit = stamp(md.get('commit_ack_utc'))
    frozen_times = []
    for side in ('source', 'target'):
        entry = envs[side + '_freeze_evidence']
        freeze(entry['data'], side)
        at = stamp(entry['finished_at_utc'])
        need(at >= commit, 'freeze must follow marker commit')
        frozen_times.append(at)
    observation = envs['marker_observe_evidence']['data']
    need(observation.get('test') == md['test'] and observation.get('row_id') == marker and (observation.get('target_rows') == after), 'marker observation differs')
    need(stamp(observation.get('commit_ack_utc')) == commit, 'observed marker commit differs')
    observed = stamp(observation.get('first_observation_utc'))
    need(observed >= commit, 'marker observation predates commit')
    boundary = max(*frozen_times, observed)
    req = request_time(docs['revalidation_request'], task)
    need(req >= boundary, 'final revalidation predates freeze/marker observation')
    native = inspect(docs['native_readback'], task)
    need(native.get('ValidationState') == 'Validated' and all((native[k] == 0 for k in COUNTERS)), 'native validation is not clean')
    need(native.get('TableState', '').lower() == 'table completed' and counter(native, 'FullLoadErrorRows') == 0, 'full load incomplete or has errors')
    need(stamp(native['LastUpdateTime']) >= req and stamp(docs['native_readback']['time']) >= req, 'native validation predates request')
    comparison = envs['divergence_comparison']['data']
    need(comparison.get('counts_equal') is True and comparison.get('totals_equal') is True and (comparison.get('content_equal') is False), 'T04 did not prove equal totals/counts with differing content')
    left, right = (comparison['source'], comparison['target'])
    need(type(left.get('row_count')) is int and left['row_count'] == right.get('row_count') and (Decimal(left['amount_total']) == Decimal(right['amount_total'])), 'T04 observed counts/totals differ')
    changes = comparison.get('differences', [])
    need(len(changes) == 1 and changes[0].get('id') == 106 and (changes[0].get('column') == 'note') and (changes[0].get('kind') == 'column') and (changes[0].get('source') != changes[0].get('target')), 'T04 expected only id106 note divergence')
    t04_req = request_time(docs['t04_revalidation_request'], task)
    failed = inspect(docs['native_divergence_failure'], task)
    need(counter(failed, 'ValidationFailedRecords') > 0, 'T04 native failed-record count did not increase')
    need(stamp(failed['LastUpdateTime']) > max(t04_req, stamp(envs['divergence_comparison']['finished_at_utc'])), 'T04 native failure is not newer than request and comparison')
    need(stamp(failed['LastUpdateTime']) < commit, 'T04 failure must precede final marker')
    metrics_doc = docs['metrics_readback']
    need(metrics_doc.get('action') == 'metrics', 'expected DMS metrics evidence')
    metrics = metrics_doc['result']
    dims = metrics.get('dimensions')
    expected_dims = [{'Name': 'ReplicationInstanceIdentifier', 'Value': binding_value('replication_instance_identifier')}, {'Name': 'ReplicationTaskIdentifier', 'Value': task.rsplit(':', 1)[1]}]
    need(isinstance(dims, list) and len(dims) == 2 and (sorted(dims, key=lambda d: d['Name']) == sorted(expected_dims, key=lambda d: d['Name'])), 'metric dimensions differ')
    maps = {}
    for metric in METRICS:
        points = metrics['metrics'][metric]['Datapoints']
        maps[metric] = {}
        for point in points:
            at = stamp(point['Timestamp'])
            need(at not in maps[metric], 'duplicate metric timestamp')
            value = number(point.get('Maximum'), 'metric Maximum')
            need(value >= 0, 'negative metric Maximum')
            maps[metric][at] = value
    shared = sorted(set.intersection(*(set(m) for m in maps.values())))
    selected = [at for at in shared if at >= boundary]
    need(len(selected) >= 2, 'need two shared metric timestamps after freezes/marker observation')
    selected = selected[-2:]
    need(all((-5 <= (now - at).total_seconds() <= 240 for at in selected)), 'a selected shared metric is stale or future')
    need(-5 <= (now - stamp(metrics_doc['time'])).total_seconds() <= 240, 'metrics readback is stale or future')
    need(all((maps['CDCIncomingChanges'][at] == 0 for at in selected)), 'incoming changes are not zero')
    for metric in METRICS[1:]:
        values = [maps[metric][at] for at in selected]
        need(max(values) <= 5 and abs(values[1] - values[0]) <= 1, 'latencies violate lab bound or stability')
    logs = docs['logs_readback']
    need(logs.get('task_arn') == task and logs.get('group') == binding_value('log_group_name') and (logs.get('stream') == 'dms-task-' + task.rsplit(':', 1)[1]), 'log task/group/stream binding differs')
    need(type(logs.get('start_time_ms')) is int and logs['start_time_ms'] <= int(min(frozen_times).timestamp() * 1000), 'log window starts after freeze')
    need(logs.get('pagination_complete') is True, 'log pagination completeness is missing or false')
    need(type(logs.get('end_time_ms')) is int and logs['end_time_ms'] >= int(max(selected[-1], boundary).timestamp() * 1000), 'log window does not cover final metric/marker/freeze boundary')
    need(logs['end_time_ms'] <= int(stamp(logs.get('time')).timestamp() * 1000), 'log readback predates its fixed window end')
    need(-5 <= (now - stamp(logs.get('time'))).total_seconds() <= 240 and stamp(logs['time']) >= boundary, 'log readback stale or before freeze')
    need(logs.get('error_candidates') == [] and isinstance(logs.get('events'), list) and (len(logs['events']) > 0), 'logs missing/empty or blocking candidates remain')
    need(not any((re.search('\\[E\\]|\\[F\\]|\\][EF]\\s*:|\\bERROR\\b|\\bFATAL\\b', event.get('message', ''), re.I) for event in logs['events'])), 'log events contain blocking error candidates')
    return {'checked_at_utc': utc(now), 'run_id': run, 'task_arn': task, 'marker_id': marker, 'incoming_changes_zero': all((maps['CDCIncomingChanges'][at] == 0 for at in selected)), 'latencies_stable': all((max((maps[m][at] for at in selected)) <= 5 and abs(maps[m][selected[1]] - maps[m][selected[0]]) <= 1 for m in METRICS[1:])), 'logs_checked': bool(logs['events']), 'no_blocking_errors': not logs['error_candidates'] and all((native[k] == 0 for k in COUNTERS)), 'metrics_fresh_samples': len(selected), 'evidence_ids': list(names.values()), 'final_revalidation_requested_at_utc': utc(req), 'native_revalidation_evidence_id': names['native_readback'], 'divergence_native_failed': failed['ValidationFailedRecords'] > 0, 'divergence_detected_evidence_id': names['divergence_comparison'], 'divergence_native_failure_evidence_id': names['native_divergence_failure'], 'evidence_sha256': {names[k]: hashes[k] for k in FILES}, 'marker_commit_ack_utc': utc(commit), 'marker_first_observed_utc': utc(observed), 'freeze_finished_utc': [utc(t) for t in frozen_times], 'native_last_update_utc': utc(stamp(native['LastUpdateTime'])), 'log_window': {'start_time_ms': logs['start_time_ms'], 'end_time_ms': logs['end_time_ms'], 'pagination_complete': logs['pagination_complete'], 'readback_at_utc': logs['time']}, 'selected_metric_points': [{'timestamp_utc': utc(at), **{m: {'Maximum': maps[m][at]} for m in METRICS}} for at in selected], 'lab_criteria': {'latest_sample_max_age_seconds': 240, 'latency_maximum_seconds': 5, 'latency_maximum_change_seconds': 1, 'shared_distinct_samples': 2}}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        inputs = json.loads(Path(args.inputs).read_text(encoding='utf-8-sig'))
        output = Path(args.output).resolve()
        need(output.parent == EVIDENCE.resolve() and output.suffix == '.json', 'output must be a JSON file directly inside evidence/')
        need(output.name not in [inputs.get(k) for k in FILES], 'output must not overwrite an input evidence file')
        proof = validate(inputs)
        temporary = output.with_name(output.name + '.tmp')
        temporary.write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
        temporary.replace(output)
        print(json.dumps({'proof': output.name, 'run_id': proof['run_id'], 'marker_id': proof['marker_id'], 'metrics_fresh_samples': proof['metrics_fresh_samples']}))
        return 0
    except (InvalidProof, KeyError, ValueError, TypeError, OSError, AttributeError, ArithmeticError) as exc:
        detail = str(exc) if isinstance(exc, InvalidProof) else 'missing, malformed or unreadable evidence (' + type(exc).__name__ + ')'
        print(json.dumps({'g6_approved': False, 'error': detail}), file=sys.stderr)
        return 2
if __name__ == '__main__':
    sys.exit(main())
