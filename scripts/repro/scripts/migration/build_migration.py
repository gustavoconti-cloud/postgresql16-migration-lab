"""Build the separate three-resource DMS migration stack. No AWS calls.

Input: optional AWS describe-stacks Outputs JSON plus the imported RDS CA ARN.
Output: deterministic template/settings/mappings; bound parameters when supplied.
All files are UTF-8 and atomically replaced. Exit2 for invalid or mismatched input.
No credential value is read, accepted, printed, or written.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
ACCOUNT = ACCOUNT
REGION = 'us-east-1'
HERE = Path(__file__).resolve().parent

def ref(key):
    return {'Ref': key}

def sub(value):
    return {'Fn::Sub': value}

def tags():
    return [{'Key': 'Environment', 'Value': 'HML'}, {'Key': 'Project', 'Value': 'postgresql-migration-lab'}, {'Key': 'Owner', 'Value': CONFIG.get('owner', '')}, {'Key': 'ManagedBy', 'Value': CONFIG.get('managed_by', 'migration-lab-toolkit')}, {'Key': 'RunId', 'Value': ref('RunId')}, {'Key': 'ExpiresAt', 'Value': ref('ExpiresAt')}]
TABLE_MAPPINGS = {'rules': [{'rule-type': 'selection', 'rule-id': '1', 'rule-name': 'OrdersLabExact', 'object-locator': {'schema-name': 'lab', 'table-name': 'orders_lab', 'table-type': 'table'}, 'rule-action': 'explicit'}]}
TASK_SETTINGS = {'TargetMetadata': {'TargetSchema': '', 'SupportLobs': False, 'BatchApplyEnabled': False}, 'FullLoadSettings': {'TargetTablePrepMode': 'DO_NOTHING', 'CreatePkAfterFullLoad': False, 'StopTaskCachedChangesApplied': False, 'StopTaskCachedChangesNotApplied': False, 'MaxFullLoadSubTasks': 1, 'TransactionConsistencyTimeout': 600, 'CommitRate': 1000}, 'ValidationSettings': {'EnableValidation': True, 'ValidationMode': 'ROW_LEVEL', 'ValidationOnly': False, 'ThreadCount': 1, 'HandleCollationDiff': True, 'FailureMaxCount': 100, 'TableFailureMaxCount': 100, 'RecordFailureDelayInMinutes': 1, 'RecordSuspendDelayInMinutes': 1, 'ValidationQueryCdcDelaySeconds': 0, 'SkipLobColumns': False}, 'ErrorBehavior': {'DataErrorPolicy': 'STOP_TASK', 'DataTruncationErrorPolicy': 'STOP_TASK', 'DataErrorEscalationPolicy': 'STOP_TASK', 'DataErrorEscalationCount': 0, 'TableErrorPolicy': 'STOP_TASK', 'TableErrorEscalationPolicy': 'STOP_TASK', 'TableErrorEscalationCount': 0, 'ApplyErrorDeletePolicy': 'STOP_TASK', 'ApplyErrorInsertPolicy': 'STOP_TASK', 'ApplyErrorUpdatePolicy': 'STOP_TASK', 'ApplyErrorEscalationPolicy': 'STOP_TASK', 'ApplyErrorEscalationCount': 0, 'EventErrorPolicy': 'STOP_TASK', 'RecoverableErrorCount': 0, 'FailOnNoTablesCaptured': True, 'FullLoadIgnoreConflicts': False}, 'Logging': {'EnableLogging': True, 'DeleteTaskLogs': False, 'LogComponents': [{'Id': component, 'Severity': 'LOGGER_SEVERITY_DEFAULT'} for component in ('SOURCE_UNLOAD', 'SOURCE_CAPTURE', 'TARGET_LOAD', 'TARGET_APPLY', 'TASK_MANAGER', 'TABLES_MANAGER', 'SORTER', 'VALIDATOR_EXT')]}}
PATTERNS = {'Prefix': '[a-z][a-z0-9]*(?:-[a-z0-9]+)*', 'RunId': '[A-Za-z0-9-]{3,64}', 'ExpiresAt': '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', 'ReplicationInstanceArn': f'arn:aws:dms:{REGION}:{ACCOUNT}:rep:[A-Za-z0-9-]+', 'SourceSecretArn': f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:[A-Za-z0-9/_+=.@-]+', 'TargetSecretArn': f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:[A-Za-z0-9/_+=.@-]+', 'DmsSecretAccessRoleArn': f'arn:aws:iam::{ACCOUNT}:role/[A-Za-z0-9_+=,.@/-]+', 'SecretsManagerEndpointOverride': f'vpce-[a-z0-9.-]+\\.secretsmanager\\.{REGION}\\.vpce\\.amazonaws\\.com', 'TargetCertificateArn': f'arn:aws:dms:{REGION}:{ACCOUNT}:cert:[A-Za-z0-9-]+'}

def create_template():
    parameters = {key: {'Type': 'String', 'AllowedPattern': value} for key, value in PATTERNS.items()}
    parameters['Prefix'].update(Default=STACK, MinLength=3, MaxLength=32)
    parameters['RunId'].update(Default=RUN)
    parameters['ExpiresAt']['Description'] = "Match the main stack's UTC expiry; this stack cannot outlive its guardrail"
    for key in ('SourceSecretArn', 'TargetSecretArn'):
        parameters[key]['Description'] = 'Exact main-stack credential ARN only; never provide SecretString or a password'
    parameters['TargetCertificateArn']['Description'] = 'Exact ARN of the imported official RDS CA certificate; owned outside this stack'
    resources = {}
    for logical, kind, secret_key, tls in (('SourceEndpoint', 'source', 'SourceSecretArn', 'require'), ('TargetEndpoint', 'target', 'TargetSecretArn', 'verify-full')):
        settings = {'SecretsManagerAccessRoleArn': ref('DmsSecretAccessRoleArn'), 'SecretsManagerSecretId': ref(secret_key)}
        if kind == 'source':
            settings.update(PluginName='test-decoding', CaptureDdls=False, HeartbeatEnable=False)
        props = {'EndpointIdentifier': sub('${Prefix}-' + kind), 'EndpointType': kind, 'EngineName': 'postgres', 'DatabaseName': 'migration_lab', 'SslMode': tls, 'PostgreSqlSettings': settings, 'ExtraConnectionAttributes': sub('secretsManagerEndpointOverride=${SecretsManagerEndpointOverride}'), 'Tags': tags()}
        if kind == 'target':
            props['CertificateArn'] = ref('TargetCertificateArn')
        resources[logical] = {'Type': 'AWS::DMS::Endpoint', 'DeletionPolicy': 'Delete', 'UpdateReplacePolicy': 'Delete', 'Properties': props}
    resources['ReplicationTask'] = {'Type': 'AWS::DMS::ReplicationTask', 'DeletionPolicy': 'Delete', 'UpdateReplacePolicy': 'Delete', 'Properties': {'ReplicationTaskIdentifier': sub('${Prefix}-task'), 'ReplicationInstanceArn': ref('ReplicationInstanceArn'), 'SourceEndpointArn': ref('SourceEndpoint'), 'TargetEndpointArn': ref('TargetEndpoint'), 'MigrationType': 'full-load-and-cdc', 'TableMappings': json.dumps(TABLE_MAPPINGS, separators=(',', ':')), 'ReplicationTaskSettings': json.dumps(TASK_SETTINGS, separators=(',', ':')), 'Tags': tags()}}
    return {'AWSTemplateFormatVersion': '2010-09-09', 'Description': 'Disposable private PostgreSQL migration endpoints and full-load+CDC task; exact synthetic table only; task creation does not start replication.', 'Metadata': {'ExecutionContract': {'AccountId': ACCOUNT, 'Region': REGION, 'ExpectedStackName': f'{STACK}-migration', 'RequiredMainStack': STACK, 'Database': 'migration_lab', 'ExactTable': 'lab.orders_lab', 'NativeSecretsManager': True, 'AutomaticStart': False, 'CutoverRequiresCurrentValidationAndIndependentComparison': True, 'CertificateOwnership': 'External exclusive lab certificate; delete separately after endpoints are removed', 'LogOwnership': 'DMS creates CloudWatch group/stream; export and delete separately', 'Cleanup': 'Stop task, delete this migration stack, remove exclusive certificate/logs, delete main stack'}}, 'Parameters': parameters, 'Resources': resources, 'Outputs': {'SourceEndpointArn': {'Value': ref('SourceEndpoint'), 'Description': 'Exact private PostgreSQL source endpoint ARN'}, 'TargetEndpointArn': {'Value': ref('TargetEndpoint'), 'Description': 'Exact private PostgreSQL target endpoint ARN with TLS verification'}, 'ReplicationTaskArn': {'Value': ref('ReplicationTask'), 'Description': 'Task ARN; inspect ready state and TestConnection before manually starting'}, 'ReplicationTaskIdentifier': {'Value': sub('${Prefix}-task'), 'Description': "Task's human-readable identifier"}, 'RunIdentifier': {'Value': ref('RunId'), 'Description': 'Same execution lineage as main stack'}, 'ExpiresAtUtc': {'Value': ref('ExpiresAt'), 'Description': 'Same deadline as main stack'}}}

def write_json(name, payload):
    destination = HERE / name
    temporary = HERE / (name + '.tmp')
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + '\n', encoding='utf-8', newline='\n')
    os.replace(temporary, destination)
    return {'path': str(destination), 'bytes': destination.stat().st_size, 'sha256': hashlib.sha256(destination.read_bytes()).hexdigest().upper()}

def normalize_outputs(payload):
    if 'Stacks' in payload:
        stacks = payload['Stacks']
        if not isinstance(stacks, list) or len(stacks) != 1:
            raise ValueError('main-outputs must contain exactly one stack')
        stack = stacks[0]
        stack_arn = stack.get('StackId', '')
        if not stack_arn.startswith(f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/'):
            raise ValueError('main stack identity differs from the bound account/region/name')
        if stack.get('StackStatus') not in ('CREATE_COMPLETE', 'UPDATE_COMPLETE'):
            raise ValueError('main stack is not in a successfully completed state')
        payload = stack.get('Outputs', [])
    elif isinstance(payload, dict) and 'Outputs' in payload:
        payload = payload['Outputs']
    if isinstance(payload, list):
        entries = {}
        for row in payload:
            key, value = (row['OutputKey'], row['OutputValue'])
            if key in entries:
                raise ValueError('duplicate main-stack output key')
            entries[key] = value
        return entries
    if isinstance(payload, dict):
        return payload
    raise ValueError('invalid main stack output structure')

def bind_inputs(args):
    if not args.main_outputs and (not args.certificate_arn):
        return None
    if not args.main_outputs or not args.certificate_arn:
        raise ValueError('both --main-outputs and --certificate-arn are required for bound deployment inputs')
    path = Path(args.main_outputs)
    outputs = normalize_outputs(json.loads(path.read_text(encoding='utf-8-sig')))
    data = {key: outputs[key] for key in ('ReplicationInstanceArn', 'SourceSecretArn', 'TargetSecretArn', 'DmsSecretAccessRoleArn', 'SecretsManagerEndpointOverride')}
    require(outputs['RunIdentifier'] == RUN and outputs['ExpiresAtUtc'] == CONFIG['expires_at'], 'Saved outputs RunId/expiry differ from context')
    data.update(Prefix=args.prefix, RunId=outputs['RunIdentifier'], ExpiresAt=outputs['ExpiresAtUtc'], TargetCertificateArn=args.certificate_arn)
    for key, value in data.items():
        if not isinstance(value, str) or not re.fullmatch(PATTERNS[key], value):
            raise ValueError(f'invalid bound input: {key}')
    if not 3 <= len(data['Prefix']) <= 32:
        raise ValueError('invalid prefix length')
    expiry = datetime.strptime(data['ExpiresAt'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        raise ValueError('bound lab expiry has passed')
    if data['SourceSecretArn'] == data['TargetSecretArn']:
        raise ValueError('source and target credential ARNs must differ')
    return {'account_id': ACCOUNT, 'region': REGION, 'stack_name': args.prefix + '-migration', 'main_outputs_sha256': hashlib.sha256(path.read_bytes()).hexdigest().upper(), 'parameters': data}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--main-outputs', help='Saved describe-stacks result, Outputs array, or output map; contains no secret values')
    parser.add_argument('--certificate-arn', help='Exact imported DMS RDS CA ARN')
    parser.add_argument('--prefix', default=STACK)
    args = parser.parse_args()
    load_context()
    require(args.prefix == STACK, 'Prefix differs from explicit context')
    try:
        bindings = bind_inputs(args)
        written = [write_json('migration.template.json', create_template()), write_json('task-settings.json', TASK_SETTINGS), write_json('table-mappings.json', TABLE_MAPPINGS)]
        if bindings:
            written.append(write_json('migration.bindings.json', bindings))
            written.append(write_json('migration.parameters.json', [{'ParameterKey': key, 'ParameterValue': value} for key, value in bindings['parameters'].items()]))
        print(json.dumps({'aws_calls': 0, 'bound_inputs_created': bool(bindings), 'files': written}, indent=2))
    except (KeyError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'message': str(exc), 'aws_calls': 0}), file=sys.stderr)
        return 2
    return 0
if __name__ == '__main__':
    sys.exit(main())
