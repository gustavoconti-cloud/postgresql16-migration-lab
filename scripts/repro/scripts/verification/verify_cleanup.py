"""Bounded read-only inventory. Never deletes resources or reads secret values.

Run cfn-baseline while provision is in progress, full-baseline before teardown,
and final with that full baseline after teardown. Root owns every AWS mutation.
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent / 'control'))
import aws_context as aws
from botocore.exceptions import BotoCoreError, ClientError
MAIN_ARN = MAIN_STACK_ARN
STACK_NAMES = (aws.STACK, aws.STACK + '-migration', aws.STACK + '-guardrail')
PROJECT = 'postgresql-migration-lab'
TAG_FILTER = [{'Name': 'tag:RunId', 'Values': [aws.RUN]}]
ALLOWED = {'cloudformation': {'describe_stacks', 'list_stack_resources'}, 'ec2': {'describe_instances', 'describe_volumes', 'describe_snapshots', 'describe_nat_gateways', 'describe_addresses', 'describe_vpc_endpoints', 'describe_network_interfaces', 'describe_vpcs', 'describe_subnets', 'describe_security_groups', 'describe_route_tables', 'describe_internet_gateways'}, 'rds': {'describe_db_instances', 'describe_db_snapshots', 'describe_db_instance_automated_backups', 'describe_db_subnet_groups', 'describe_db_parameter_groups'}, 'dms': {'describe_replication_instances', 'describe_replication_tasks', 'describe_endpoints', 'describe_certificates', 'describe_replication_subnet_groups'}, 'secretsmanager': {'describe_secret', 'list_secrets'}, 'iam': {'get_role', 'get_instance_profile'}, 'logs': {'describe_log_groups'}, 'lambda': {'get_function_configuration'}, 'events': {'list_rules'}, 'cloudwatch': {'describe_alarms'}, 'sqs': {'get_queue_attributes'}}

@dataclass
class Query:
    label: str
    service: str
    operation: str
    params: dict
    key: str
    fields: tuple[str, ...]
    ids: tuple[str, ...] = ()
    id_field: str = ''
    paginate: bool = True
    kind: str = 'resource'

def project(row: dict, fields: tuple[str, ...]) -> dict:
    return {k: row[k] for k in fields if k in row}

def extract(response: dict, key: str) -> list[dict]:
    if key == '_whole':
        return [response]
    if key == 'Reservations.Instances':
        return [i for r in response.get('Reservations', []) for i in r.get('Instances', [])]
    value = response.get(key, [])
    return value if isinstance(value, list) else [value]

def perform(query: Query, clients: dict) -> list[dict]:
    if query.operation not in ALLOWED.get(query.service, set()):
        raise ValueError('Non-read operation refused')
    c = clients.get(query.service)
    if c is None:
        c = clients[query.service] = aws.client(query.service)
    allowed_regions = {aws.REGION, 'aws-global'} if query.service == 'iam' else {aws.REGION}
    if c.meta.region_name not in allowed_regions:
        raise ValueError('Wrong client region')
    if query.paginate and c.can_paginate(query.operation):
        pages = c.get_paginator(query.operation).paginate(**query.params)
    else:
        pages = [getattr(c, query.operation)(**query.params)]
    rows = [r for p in pages for r in extract(p, query.key)]
    if query.ids:
        rows = [r for r in rows if r.get(query.id_field) in query.ids]
    return [project(r, query.fields) for r in rows]

def absent_error(error: ClientError, query: Query) -> bool:
    code = error.response.get('Error', {}).get('Code', '')
    message = error.response.get('Error', {}).get('Message', '')
    known = {'ResourceNotFoundException', 'ResourceNotFoundFault', 'DBInstanceNotFound', 'DBInstanceNotFoundFault', 'DBInstanceAutomatedBackupNotFound', 'DBInstanceAutomatedBackupNotFoundFault', 'DBSubnetGroupNotFoundFault', 'DBParameterGroupNotFound', 'DBParameterGroupNotFoundFault', 'NoSuchEntity', 'NoSuchEntityException', 'InvalidInstanceID.NotFound', 'InvalidVolume.NotFound', 'InvalidSnapshot.NotFound', 'InvalidAllocationID.NotFound', 'InvalidAddress.NotFound', 'InvalidVpcID.NotFound', 'InvalidNatGatewayID.NotFound', 'InvalidVpcEndpointId.NotFound', 'AWS.SimpleQueueService.NonExistentQueue', 'QueueDoesNotExist'}
    if code in known:
        return True
    return query.service == 'cloudformation' and code == 'ValidationError' and ('does not exist' in message)

def live(row: dict, query: Query) -> bool:
    if query.kind == 'stack':
        return row.get('StackStatus') != 'DELETE_COMPLETE'
    if query.service == 'ec2' and query.operation == 'describe_instances':
        return row.get('State', {}).get('Name') != 'terminated'
    if query.service == 'ec2' and query.operation == 'describe_nat_gateways':
        return row.get('State') != 'deleted'
    if query.service == 'ec2' and query.operation == 'describe_vpc_endpoints':
        return row.get('State') != 'deleted'
    return True

def cfn_plan(manifest: dict) -> list[Query]:
    exact = {s.get('name'): s.get('arn') for s in manifest.get('stacks', [])}
    exact[aws.STACK] = MAIN_ARN
    plan = []
    for name in STACK_NAMES:
        identifier = exact.get(name) or name
        plan.append(Query('stack:' + name, 'cloudformation', 'describe_stacks', {'StackName': identifier}, 'Stacks', ('StackId', 'StackName', 'CreationTime', 'LastUpdatedTime', 'DeletionTime', 'StackStatus', 'Tags', 'Outputs'), kind='stack'))
        plan.append(Query('stack-resources:' + name, 'cloudformation', 'list_stack_resources', {'StackName': identifier}, 'StackResourceSummaries', ('LogicalResourceId', 'PhysicalResourceId', 'ResourceType', 'ResourceStatus', 'LastUpdatedTimestamp'), kind='metadata'))
    return plan

def merge_manifest(old: dict, cfn_results: list[dict]) -> dict:
    merged = {s['name']: dict(s) for s in old.get('stacks', [])}
    for name in STACK_NAMES:
        current = merged.setdefault(name, {'name': name, 'resources': []})
        desc = next((r for r in cfn_results if r['label'] == 'stack:' + name))
        rs = next((r for r in cfn_results if r['label'] == 'stack-resources:' + name))
        if desc['rows']:
            d = desc['rows'][0]
            current.update({'arn': d['StackId'], 'creation_time': d['CreationTime'], 'status': d['StackStatus'], 'outputs': d.get('Outputs', []), 'tags': d.get('Tags', [])})
        resources = {r['LogicalResourceId']: r for r in current.get('resources', [])}
        resources.update({r['LogicalResourceId']: r for r in rs['rows']})
        current['resources'] = list(resources.values())
    return {'account': aws.ACCOUNT, 'region': aws.REGION, 'run_id': aws.RUN, 'stacks': list(merged.values()), 'extra': old.get('extra', {}), 'discovered': old.get('discovered', {})}

def resource_plan(manifest: dict) -> list[Query]:
    resources = [r for s in manifest['stacks'] for r in s.get('resources', []) if r.get('PhysicalResourceId')]
    extra = manifest.get('extra', {})
    discovered = manifest.get('discovered', {})

    def ids(kind):
        return sorted(set((r['PhysicalResourceId'] for r in resources if r['ResourceType'] == kind)))
    outputs = {o['OutputKey']: o['OutputValue'] for s in manifest['stacks'] for o in s.get('outputs', [])}
    plan = []

    def q(label, svc, op, params, key, fields, select=(), id_field=''):
        plan.append(Query(label, svc, op, params, key, tuple(fields.split()), tuple(select), id_field))
    q('EC2 by run tag', 'ec2', 'describe_instances', {'Filters': TAG_FILTER}, 'Reservations.Instances', 'InstanceId InstanceType State LaunchTime VpcId BlockDeviceMappings Tags')
    for identifier in ids('AWS::EC2::Instance'):
        q('EC2 exact:' + identifier, 'ec2', 'describe_instances', {'InstanceIds': [identifier]}, 'Reservations.Instances', 'InstanceId InstanceType State LaunchTime VpcId BlockDeviceMappings Tags')
    q('EBS volumes by run tag', 'ec2', 'describe_volumes', {'Filters': TAG_FILTER}, 'Volumes', 'VolumeId State Size VolumeType CreateTime Attachments Tags')
    for identifier in discovered.get('ebs_volume_ids', []):
        q('EBS volume exact:' + identifier, 'ec2', 'describe_volumes', {'VolumeIds': [identifier]}, 'Volumes', 'VolumeId State Size VolumeType CreateTime Attachments Tags')
    q('EBS snapshots owned by run', 'ec2', 'describe_snapshots', {'OwnerIds': [aws.ACCOUNT], 'Filters': TAG_FILTER}, 'Snapshots', 'SnapshotId VolumeId State StartTime VolumeSize Tags')
    for identifier in discovered.get('ebs_snapshot_ids', []):
        q('EBS snapshot exact:' + identifier, 'ec2', 'describe_snapshots', {'OwnerIds': [aws.ACCOUNT], 'SnapshotIds': [identifier]}, 'Snapshots', 'SnapshotId VolumeId State StartTime VolumeSize Tags')
    q('Elastic IP by run tag', 'ec2', 'describe_addresses', {'Filters': TAG_FILTER}, 'Addresses', 'AllocationId PublicIp AssociationId NetworkInterfaceId Tags')
    for ip in ids('AWS::EC2::EIP'):
        q('Elastic IP exact:' + ip, 'ec2', 'describe_addresses', {'Filters': [{'Name': 'public-ip', 'Values': [ip]}]}, 'Addresses', 'AllocationId PublicIp AssociationId NetworkInterfaceId Tags')
    for identifier in discovered.get('allocation_ids', []):
        q('Elastic IP allocation exact:' + identifier, 'ec2', 'describe_addresses', {'AllocationIds': [identifier]}, 'Addresses', 'AllocationId PublicIp AssociationId NetworkInterfaceId Tags')
    for vpc in ids('AWS::EC2::VPC'):
        filt = [{'Name': 'vpc-id', 'Values': [vpc]}]
        for label, op, key, fields in (('NAT gateway', 'describe_nat_gateways', 'NatGateways', 'NatGatewayId State CreateTime DeleteTime VpcId NatGatewayAddresses Tags'), ('Interface endpoint', 'describe_vpc_endpoints', 'VpcEndpoints', 'VpcEndpointId State VpcEndpointType ServiceName VpcId RequesterManaged SubnetIds NetworkInterfaceIds Groups CreationTimestamp Tags'), ('Network interface', 'describe_network_interfaces', 'NetworkInterfaces', 'NetworkInterfaceId Status InterfaceType VpcId Description TagSet'), ('VPC', 'describe_vpcs', 'Vpcs', 'VpcId State CidrBlock Tags'), ('Subnet', 'describe_subnets', 'Subnets', 'SubnetId State VpcId Tags'), ('Security group', 'describe_security_groups', 'SecurityGroups', 'GroupId GroupName VpcId Tags'), ('Route table', 'describe_route_tables', 'RouteTables', 'RouteTableId VpcId Tags')):
            param = 'Filter' if op == 'describe_nat_gateways' else 'Filters'
            q(label + ' exact VPC:' + vpc, 'ec2', op, {param: filt}, key, fields)
        q('Internet gateway attachment:' + vpc, 'ec2', 'describe_internet_gateways', {'Filters': [{'Name': 'attachment.vpc-id', 'Values': [vpc]}]}, 'InternetGateways', 'InternetGatewayId Attachments Tags')
    for identifier in ids('AWS::RDS::DBInstance'):
        q('RDS instance:' + identifier, 'rds', 'describe_db_instances', {'DBInstanceIdentifier': identifier}, 'DBInstances', 'DBInstanceIdentifier DBInstanceArn DbiResourceId DBInstanceStatus DBInstanceClass InstanceCreateTime AllocatedStorage StorageType PubliclyAccessible MasterUserSecret')
        q('RDS snapshots:' + identifier, 'rds', 'describe_db_snapshots', {'DBInstanceIdentifier': identifier, 'IncludeShared': False, 'IncludePublic': False}, 'DBSnapshots', 'DBSnapshotIdentifier DBSnapshotArn DBInstanceIdentifier SnapshotType Status SnapshotCreateTime AllocatedStorage')
        q('RDS retained automated backups:' + identifier, 'rds', 'describe_db_instance_automated_backups', {'DBInstanceIdentifier': identifier}, 'DBInstanceAutomatedBackups', 'DBInstanceAutomatedBackupsArn DBInstanceIdentifier DbiResourceId Status AllocatedStorage')
    for identifier in discovered.get('rds_dbi_resource_ids', []):
        q('RDS retained backup by immutable DB resource ID:' + identifier, 'rds', 'describe_db_instance_automated_backups', {'DbiResourceId': identifier}, 'DBInstanceAutomatedBackups', 'DBInstanceAutomatedBackupsArn DBInstanceIdentifier DbiResourceId Status AllocatedStorage')
    for identifier in ids('AWS::RDS::DBSubnetGroup'):
        q('RDS subnet group:' + identifier, 'rds', 'describe_db_subnet_groups', {'DBSubnetGroupName': identifier}, 'DBSubnetGroups', 'DBSubnetGroupName DBSubnetGroupArn SubnetGroupStatus VpcId')
    for identifier in ids('AWS::RDS::DBParameterGroup'):
        q('RDS parameter group:' + identifier, 'rds', 'describe_db_parameter_groups', {'DBParameterGroupName': identifier}, 'DBParameterGroups', 'DBParameterGroupName DBParameterGroupArn DBParameterGroupFamily')
    for identifier in ids('AWS::DMS::ReplicationInstance'):
        q('DMS instance:' + identifier, 'dms', 'describe_replication_instances', {'Filters': [{'Name': 'replication-instance-arn', 'Values': [identifier]}]}, 'ReplicationInstances', 'ReplicationInstanceArn ReplicationInstanceIdentifier ReplicationInstanceStatus ReplicationInstanceClass EngineVersion AllocatedStorage InstanceCreateTime PubliclyAccessible')
        q('DMS tasks attached to exact instance', 'dms', 'describe_replication_tasks', {'Filters': [{'Name': 'replication-instance-arn', 'Values': [identifier]}], 'WithoutSettings': True}, 'ReplicationTasks', 'ReplicationTaskArn ReplicationTaskIdentifier ReplicationInstanceArn SourceEndpointArn TargetEndpointArn Status ReplicationTaskCreationDate')
    for kind, op, key, filt, fields in (('AWS::DMS::Endpoint', 'describe_endpoints', 'Endpoints', 'endpoint-arn', 'EndpointArn EndpointIdentifier EndpointType EngineName Status SslMode CertificateArn'), ('AWS::DMS::ReplicationTask', 'describe_replication_tasks', 'ReplicationTasks', 'replication-task-arn', 'ReplicationTaskArn ReplicationTaskIdentifier ReplicationInstanceArn SourceEndpointArn TargetEndpointArn Status'), ('AWS::DMS::ReplicationSubnetGroup', 'describe_replication_subnet_groups', 'ReplicationSubnetGroups', 'replication-subnet-group-id', 'ReplicationSubnetGroupIdentifier ReplicationSubnetGroupDescription VpcId SubnetGroupStatus')):
        for identifier in ids(kind):
            params = {'Filters': [{'Name': filt, 'Values': [identifier]}]}
            if op == 'describe_replication_tasks':
                params['WithoutSettings'] = True
            q('DMS exact:' + identifier, 'dms', op, params, key, fields)
    cert_ids = [aws.STACK + '-rds-ca'] + extra.get('certificate_identifiers', [])
    q('DMS exclusive certificate', 'dms', 'describe_certificates', {}, 'Certificates', 'CertificateIdentifier CertificateArn CertificateCreationDate ValidToDate', cert_ids, 'CertificateIdentifier')
    secret_ids = ids('AWS::SecretsManager::Secret') + extra.get('secret_arns', [])
    if outputs.get('MasterSecretArn'):
        secret_ids.append(outputs['MasterSecretArn'])
    for identifier in sorted(set(secret_ids)):
        q('Secret metadata:' + identifier, 'secretsmanager', 'describe_secret', {'SecretId': identifier}, '_whole', 'ARN Name CreatedDate DeletedDate OwningService Tags')
    q('Secrets tagged to run including pending deletion', 'secretsmanager', 'list_secrets', {'IncludePlannedDeletion': True, 'Filters': [{'Key': 'tag-key', 'Values': ['RunId']}, {'Key': 'tag-value', 'Values': [aws.RUN]}]}, 'SecretList', 'ARN Name CreatedDate DeletedDate OwningService Tags')
    for identifier in ids('AWS::IAM::Role'):
        q('IAM role:' + identifier, 'iam', 'get_role', {'RoleName': identifier}, 'Role', 'RoleName RoleId Arn CreateDate Tags')
    for identifier in ids('AWS::IAM::InstanceProfile'):
        q('IAM instance profile:' + identifier, 'iam', 'get_instance_profile', {'InstanceProfileName': identifier}, 'InstanceProfile', 'InstanceProfileName InstanceProfileId Arn CreateDate Roles Tags')
    for identifier in ids('AWS::Lambda::Function'):
        q('Guard Lambda:' + identifier, 'lambda', 'get_function_configuration', {'FunctionName': identifier}, '_whole', 'FunctionName FunctionArn Runtime LastModified State')
    for identifier in ids('AWS::SQS::Queue'):
        q('Guard failure queue:' + identifier, 'sqs', 'get_queue_attributes', {'QueueUrl': identifier, 'AttributeNames': ['QueueArn', 'CreatedTimestamp', 'ApproximateNumberOfMessages', 'ApproximateNumberOfMessagesNotVisible']}, 'Attributes', 'QueueArn CreatedTimestamp ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible')
    for prefix in (aws.STACK, 'dms-tasks-' + aws.STACK, '/aws/lambda/' + aws.STACK):
        q('CloudWatch logs prefix:' + prefix, 'logs', 'describe_log_groups', {'logGroupNamePrefix': prefix}, 'logGroups', 'logGroupName arn creationTime retentionInDays storedBytes')
    for name in extra.get('log_group_names', []):
        q('CloudWatch log group exact:' + name, 'logs', 'describe_log_groups', {'logGroupNamePrefix': name}, 'logGroups', 'logGroupName arn creationTime retentionInDays storedBytes', [name], 'logGroupName')
    q('Guard EventBridge rules', 'events', 'list_rules', {'NamePrefix': aws.STACK}, 'Rules', 'Name Arn State ScheduleExpression')
    q('CloudWatch alarms by lab prefix', 'cloudwatch', 'describe_alarms', {'AlarmNamePrefix': aws.STACK}, 'MetricAlarms', 'AlarmName AlarmArn StateValue')
    return plan

def preserve_discovered(manifest: dict, results: list[dict]) -> None:
    discovered = {k: set(v) for k, v in manifest.get('discovered', {}).items()}
    for result in results:
        for row in result['rows']:
            for field, name in (('VolumeId', 'ebs_volume_ids'), ('SnapshotId', 'ebs_snapshot_ids'), ('AllocationId', 'allocation_ids'), ('DbiResourceId', 'rds_dbi_resource_ids')):
                if row.get(field):
                    discovered.setdefault(name, set()).add(row[field])
            for mapping in row.get('BlockDeviceMappings', []):
                if mapping.get('Ebs', {}).get('VolumeId'):
                    discovered.setdefault('ebs_volume_ids', set()).add(mapping['Ebs']['VolumeId'])
            tags = {t.get('Key'): t.get('Value') for t in row.get('Tags', [])}
            if tags.get('GuardDutyManaged') == 'true' and row.get('VpcEndpointId'):
                discovered.setdefault('guardduty_endpoint_ids', set()).add(row['VpcEndpointId'])
                for group in row.get('Groups', []):
                    discovered.setdefault('guardduty_security_group_ids', set()).add(group['GroupId'])
    manifest['discovered'] = {k: sorted(v) for k, v in discovered.items()}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('cfn-baseline', 'full-baseline', 'final'), required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--extra-manifest', type=Path, help='Optional exact secret ARNs/certificate identifiers/log-group names, no values')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    before = json.loads(args.baseline.read_text(encoding='utf-8-sig')) if args.baseline else {}
    old = before.get('manifest', before)
    if old and (old.get('account') != aws.ACCOUNT or old.get('region') != aws.REGION or old.get('run_id') != aws.RUN):
        raise ValueError('Baseline scope mismatch')
    if args.mode == 'final' and before.get('mode') != 'full-baseline':
        raise ValueError('Final verification requires a full-baseline inventory')
    if args.extra_manifest:
        extra = json.loads(args.extra_manifest.read_text(encoding='utf-8-sig'))
        allowed_extra = {'certificate_identifiers', 'secret_arns', 'log_group_names'}
        if not set(extra).issubset(allowed_extra):
            raise ValueError('Unexpected extra-manifest fields')
        if any((not isinstance(v, list) or len(v) > 20 or any((not isinstance(i, str) for i in v)) for v in extra.values())):
            raise ValueError('Extra identifiers must be bounded string lists')
        if any((not arn.startswith('arn:aws:secretsmanager:' + aws.REGION + ':' + aws.ACCOUNT + ':secret:') for arn in extra.get('secret_arns', []))):
            raise ValueError('Secret ARN scope mismatch')
        old['extra'] = extra
    ident = aws.identity()
    clients: dict[str, Any] = {}
    results = []
    plan = cfn_plan(old)
    for phase in ('cfn', 'services'):
        if phase == 'services':
            manifest = merge_manifest(old, results)
            if args.mode == 'cfn-baseline':
                break
            plan = resource_plan(manifest)
        for query in plan:
            r = {'label': query.label, 'service': query.service, 'operation': query.operation, 'observed_at_utc': aws.stamp(), 'rows': [], 'live_count': 0}
            try:
                r['rows'] = perform(query, clients)
                if query.kind == 'stack':
                    for row in r['rows']:
                        tags = {t['Key']: t['Value'] for t in row.get('Tags', [])}
                        if tags.get('RunId') != aws.RUN or tags.get('Project') != PROJECT or tags.get('Environment') != 'HML':
                            raise ValueError('CloudFormation ownership mismatch: ' + query.label)
                r['live_count'] = sum((live(row, query) for row in r['rows'])) if query.kind != 'metadata' else 0
                r['status'] = 'present' if r['rows'] else 'absent'
            except ClientError as error:
                r['status'] = 'absent' if absent_error(error, query) else 'error'
                r['error_code'] = error.response.get('Error', {}).get('Code', 'unknown')
            except BotoCoreError as error:
                r['status'] = 'error'
                r['error_code'] = type(error).__name__
            except ValueError as error:
                r['status'] = 'error'
                r['rows'] = []
                r['error_code'] = 'scope_or_ownership_mismatch'
            results.append(r)
    preserve_discovered(manifest, results)
    errors = [r['label'] for r in results if r['status'] == 'error']
    residuals = [{'label': r['label'], 'count': r['live_count']} for r in results if r['live_count']]
    complete_states = {'CREATE_COMPLETE', 'UPDATE_COMPLETE'}
    baseline_incomplete = args.mode == 'final' and (len(old.get('stacks', [])) != len(STACK_NAMES) or any((s.get('status') not in complete_states or not s.get('resources') for s in old.get('stacks', []))))
    clean = args.mode == 'final' and (not errors) and (not residuals) and (not baseline_incomplete)
    report = {'schema_version': 1, 'mode': args.mode, 'identity': ident, 'observed_at_utc': aws.stamp(), 'manifest': manifest, 'checks': results, 'cleanup_verified': clean, 'coverage_errors': errors, 'residuals': residuals, 'baseline_incomplete': baseline_incomplete, 'limitations': ['Service-specific reads in us-east-1 plus exact owned global IAM names; unrelated resources excluded.', 'Tag discovery supplements exact CloudFormation IDs; the full baseline and explicit extra manifest must include resources created outside CloudFormation.', 'No Cost Explorer calls, no invoice claim, no secret-value access, no AWS writes.', 'Terminated EC2 and deleted NAT/VPCE tombstones are reported as retired; pending secret deletion remains a residual.']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(aws.clean(report), ensure_ascii=False, indent=2, default=str) + '\n', encoding='utf-8')
    print(json.dumps({'mode': args.mode, 'output': str(args.output), 'checks': len(results), 'coverage_errors': len(errors), 'residual_checks': len(residuals), 'cleanup_verified': clean}, indent=2))
    return 0 if args.mode != 'final' and (not errors) else 0 if clean else 2
if __name__ == '__main__':
    sys.exit(main())
