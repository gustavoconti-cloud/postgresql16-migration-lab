"""Explicit, state-gated actions for the one CloudFormation-bound DMS task."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse, json
from datetime import timedelta
from aws_context import *

def binding():
    require(bool(MAIN_STACK_ARN), 'Bind main_stack_arn before AWS use')
    identity()
    cf = client('cloudformation')
    main = cf.describe_stacks(StackName=MAIN_STACK_ARN)['Stacks'][0]
    migration_arn = binding_value('migration_stack_arn')
    assert migration_arn.startswith(f'arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/' + STACK + '-migration/')
    migration = cf.describe_stacks(StackName=migration_arn)['Stacks'][0]
    expected = {'Environment': 'HML', 'Project': 'postgresql-migration-lab', 'RunId': RUN}
    for obj in (main, migration):
        actual = {t['Key']: t['Value'] for t in obj['Tags']}
        assert all((actual.get(k) == v for k, v in expected.items())), 'Stack ownership mismatch'
    outputs = {o['OutputKey']: o['OutputValue'] for o in main['Outputs'] + migration['Outputs']}
    arn = outputs['ReplicationTaskArn']
    dms = client('dms')
    tasks = dms.describe_replication_tasks(Filters=[{'Name': 'replication-task-arn', 'Values': [arn]}])['ReplicationTasks']
    assert len(tasks) == 1
    task = tasks[0]
    for key in ('ReplicationInstanceArn', 'SourceEndpointArn', 'TargetEndpointArn'):
        assert task[key] == outputs[key], 'DMS dependency mismatch'
    actual = {t['Key']: t['Value'] for t in dms.list_tags_for_resource(ResourceArn=arn)['TagList']}
    assert all((actual.get(k) == v for k, v in expected.items())), 'Task ownership mismatch'
    return (dms, outputs, task)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['inspect', 'test-connections', 'start', 'resume', 'reload', 'recover-initial-load', 'stop', 'revalidate', 'metrics'])
    p.add_argument('--label', required=True)
    p.add_argument('--recovery-proof')
    a = p.parse_args()
    dms, o, t = binding()
    if a.action in ('test-connections', 'start', 'resume', 'reload', 'recover-initial-load', 'revalidate'):
        load_context()
    arn = t['ReplicationTaskArn']
    before = {'time': stamp(), 'task': t}
    save(a.label + '-before.json', before)
    if a.action == 'inspect':
        result = {'task': t, 'tables': dms.describe_table_statistics(ReplicationTaskArn=arn), 'connections': dms.describe_connections(Filters=[{'Name': 'replication-instance-arn', 'Values': [o['ReplicationInstanceArn']]}])}
    elif a.action == 'test-connections':
        result = [dms.test_connection(ReplicationInstanceArn=o['ReplicationInstanceArn'], EndpointArn=o[k]) for k in ('SourceEndpointArn', 'TargetEndpointArn')]
    elif a.action in ('start', 'resume', 'reload'):
        assert t['Status'] == ('ready' if a.action == 'start' else 'stopped'), 'Unexpected task start state'
        result = dms.start_replication_task(ReplicationTaskArn=arn, StartReplicationTaskType={'start': 'start-replication', 'resume': 'resume-processing', 'reload': 'reload-target'}[a.action])
    elif a.action == 'recover-initial-load':
        assert t['Status'] == 'failed' and t.get('ReplicationTaskStartDate'), 'Recovery requires a previously started, failed task'
        proof_path = Path(a.recovery_proof).resolve()
        assert proof_path.parent == (ROOT / 'evidence').resolve(), 'Recovery proof must be a preserved local execution receipt'
        record = json.loads(proof_path.read_text(encoding='utf-8'))
        proof = record['envelope']
        data = proof['data']
        assert record['returncode'] == 0 and proof['success'] is True and (proof['command'] == 'inspect') and (proof['run_id'] == TEST_RUN)
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(proof['finished_at_utc'].replace('Z', '+00:00'))).total_seconds()
        assert 0 <= age <= 600 and proof['aws_identity']['account'] == ACCOUNT, 'Stale or wrong-account recovery proof'
        assert data['dms_task']['ReplicationTaskArn'] == arn and data['dms_task']['Status'] == 'failed'
        assert not data['ledger']['completed'] and (not data['ledger'].get('pending_dml')) and (not data['ledger'].get('target_exclusive_commit'))
        comparison = data['comparison']
        assert comparison['catalog_equal'] and comparison['target']['row_count'] == 0
        assert comparison['source']['ids'] == list(range(101, 109)) and comparison['source']['sha256'] == 'aefab5afdbaf55e622c821550e4f449e9d3f4c631a7f737f1bee0ccb63930c34'
        assert all((data['roles']['target']['writer_privileges'][p] is False for p in ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')))
        tables = dms.describe_table_statistics(ReplicationTaskArn=arn)['TableStatistics']
        assert len(tables) == 1 and tables[0]['SchemaName'] == 'lab' and (tables[0]['TableName'] == 'orders_lab') and (tables[0]['FullLoadRows'] == 0)
        save(a.label + '-recovery-proof-binding.json', {'time': stamp(), 'proof_file': str(proof_path), 'proof_sha256': hashlib.sha256(proof_path.read_bytes()).hexdigest(), 'tables': tables, 'restart_mode': 'reload-target'})
        result = dms.start_replication_task(ReplicationTaskArn=arn, StartReplicationTaskType='reload-target')
    elif a.action == 'stop':
        assert t['Status'] == 'running', 'Task must be running before stop'
        result = dms.stop_replication_task(ReplicationTaskArn=arn)
    elif a.action == 'revalidate':
        assert t['Status'] == 'running', 'Revalidation requires running task'
        result = dms.reload_tables(ReplicationTaskArn=arn, TablesToReload=[{'SchemaName': 'lab', 'TableName': 'orders_lab'}], ReloadOption='validate-only')
    else:
        cw = client('cloudwatch')
        now = datetime.now(timezone.utc)
        instance = dms.describe_replication_instances(Filters=[{'Name': 'replication-instance-arn', 'Values': [o['ReplicationInstanceArn']]}])['ReplicationInstances'][0]
        dimensions = [{'Name': 'ReplicationInstanceIdentifier', 'Value': instance['ReplicationInstanceIdentifier']}, {'Name': 'ReplicationTaskIdentifier', 'Value': arn.rsplit(':', 1)[1]}]
        result = {'time': stamp(), 'dimensions': dimensions, 'metrics': {}}
        for name in ('CDCIncomingChanges', 'CDCLatencySource', 'CDCLatencyTarget'):
            metric = cw.get_metric_statistics(Namespace='AWS/DMS', MetricName=name, Dimensions=dimensions, StartTime=now - timedelta(minutes=20), EndTime=now, Period=60, Statistics=['Maximum', 'Average'])
            metric['Datapoints'] = sorted(metric['Datapoints'], key=lambda x: x['Timestamp'])
            result['metrics'][name] = metric
    save(a.label + '-result.json', {'time': stamp(), 'action': a.action, 'result': result})
    print(json.dumps(clean(result), ensure_ascii=False))
if __name__ == '__main__':
    main()
