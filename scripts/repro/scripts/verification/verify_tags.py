"""Read-only tag audit for exact lab resources and automatic VPC dependencies."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse
import json
import sys
from pathlib import Path
BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent / 'control'))
import aws_context as aws
from botocore.exceptions import ClientError, BotoCoreError
READ = {'ec2': {'describe_vpcs', 'describe_subnets', 'describe_route_tables', 'describe_security_groups', 'describe_network_interfaces', 'describe_network_acls', 'describe_security_group_rules', 'describe_volumes', 'describe_vpc_endpoints', 'describe_tags'}, 'cloudformation': {'describe_stacks'}, 'iam': {'get_role', 'get_instance_profile', 'list_attached_role_policies'}, 'rds': {'list_tags_for_resource', 'describe_db_instances'}, 'dms': {'list_tags_for_resource', 'describe_replication_instances'}, 'secretsmanager': {'describe_secret'}, 'lambda': {'list_tags'}, 'events': {'list_tags_for_resource'}, 'logs': {'list_tags_for_resource'}, 'sqs': {'list_queue_tags'}, 'kms': {'describe_key'}}
EC2_KIND = {'AWS::EC2::VPC': 'vpc', 'AWS::EC2::Subnet': 'subnet', 'AWS::EC2::RouteTable': 'route-table', 'AWS::EC2::SecurityGroup': 'security-group', 'AWS::EC2::SecurityGroupIngress': 'security-group-rule', 'AWS::EC2::SecurityGroupEgress': 'security-group-rule', 'AWS::EC2::InternetGateway': 'internet-gateway', 'AWS::EC2::NatGateway': 'natgateway', 'AWS::EC2::VPCEndpoint': 'vpc-endpoint', 'AWS::EC2::Instance': 'instance'}
UNTAGGABLE = {'AWS::EC2::VPCGatewayAttachment': 'Attachment is an association; Internet Gateway and VPC are audited.', 'AWS::EC2::Route': 'Route entry has no independent tagging API; owning route table is audited.', 'AWS::EC2::SubnetRouteTableAssociation': 'Association has no independent tagging API; subnet and route table are audited.', 'AWS::IAM::Policy': 'Inline IAM policy has no tagging API; owning IAM role is audited.', 'AWS::Lambda::Permission': 'Resource-policy statement has no independent tagging API; Lambda is audited.'}

def tag_dict(tags):
    if isinstance(tags, dict):
        return tags
    return {x['Key']: x.get('Value', '') for x in tags}

def missing_tags(current, required):
    return {k: {'before': current.get(k), 'after': v, 'kind': 'missing' if k not in current else 'mismatch'} for k, v in required.items() if current.get(k) != v}

def request(clients, service, method, params):
    if method not in READ.get(service, set()):
        raise ValueError('Non-read operation refused')
    c = clients.get(service)
    if c is None:
        c = clients[service] = aws.client(service)
    allowed = {aws.REGION, 'aws-global'} if service == 'iam' else {aws.REGION}
    if c.meta.region_name not in allowed:
        raise ValueError('Wrong client region')
    return getattr(c, method)(**params)

def collect(clients, service, method, params, key):
    if method not in READ.get(service, set()):
        raise ValueError('Non-read operation refused')
    c = clients.get(service)
    if c is None:
        c = clients[service] = aws.client(service)
    if c.can_paginate(method):
        return [r for page in c.get_paginator(method).paginate(**params) for r in page.get(key, [])]
    return request(clients, service, method, params).get(key, [])

def target_for_cfn(resource):
    kind, identifier = (resource['ResourceType'], resource['PhysicalResourceId'])
    prefix = 'arn:aws:'
    region_account = aws.REGION + ':' + aws.ACCOUNT + ':'
    if kind == 'AWS::SQS::Queue':
        expected = 'https://sqs.' + aws.REGION + '.amazonaws.com/' + aws.ACCOUNT + '/'
        if not identifier.startswith(expected):
            raise ValueError('Queue URL account/region mismatch')
        return ('sqs', 'list_queue_tags', {'QueueUrl': identifier}, None, 'Tags', prefix + 'sqs:' + region_account + identifier.rsplit('/', 1)[1])
    spec = {'AWS::IAM::Role': ('iam', 'get_role', {'RoleName': identifier}, 'Role', 'Tags', 'arn:aws:iam::' + aws.ACCOUNT + ':role/' + identifier), 'AWS::IAM::InstanceProfile': ('iam', 'get_instance_profile', {'InstanceProfileName': identifier}, 'InstanceProfile', 'Tags', 'arn:aws:iam::' + aws.ACCOUNT + ':instance-profile/' + identifier), 'AWS::RDS::DBInstance': ('rds', 'list_tags_for_resource', {'ResourceName': prefix + 'rds:' + region_account + 'db:' + identifier}, None, 'TagList', prefix + 'rds:' + region_account + 'db:' + identifier), 'AWS::RDS::DBSubnetGroup': ('rds', 'list_tags_for_resource', {'ResourceName': prefix + 'rds:' + region_account + 'subgrp:' + identifier}, None, 'TagList', prefix + 'rds:' + region_account + 'subgrp:' + identifier), 'AWS::RDS::DBParameterGroup': ('rds', 'list_tags_for_resource', {'ResourceName': prefix + 'rds:' + region_account + 'pg:' + identifier}, None, 'TagList', prefix + 'rds:' + region_account + 'pg:' + identifier), 'AWS::DMS::ReplicationSubnetGroup': ('dms', 'list_tags_for_resource', {'ResourceArn': prefix + 'dms:' + region_account + 'subgrp:' + identifier}, None, 'TagList', prefix + 'dms:' + region_account + 'subgrp:' + identifier), 'AWS::Lambda::Function': ('lambda', 'list_tags', {'Resource': prefix + 'lambda:' + region_account + 'function:' + identifier}, None, 'Tags', prefix + 'lambda:' + region_account + 'function:' + identifier), 'AWS::Events::Rule': ('events', 'list_tags_for_resource', {'ResourceARN': prefix + 'events:' + region_account + 'rule/' + identifier}, None, 'Tags', prefix + 'events:' + region_account + 'rule/' + identifier), 'AWS::Logs::LogGroup': ('logs', 'list_tags_for_resource', {'resourceArn': prefix + 'logs:' + region_account + 'log-group:' + identifier}, None, 'tags', prefix + 'logs:' + region_account + 'log-group:' + identifier)}
    if kind == 'AWS::SecretsManager::Secret':
        return ('secretsmanager', 'describe_secret', {'SecretId': identifier}, None, 'Tags', identifier)
    if kind in {'AWS::DMS::ReplicationInstance', 'AWS::DMS::Endpoint', 'AWS::DMS::ReplicationTask'}:
        return ('dms', 'list_tags_for_resource', {'ResourceArn': identifier}, None, 'TagList', identifier)
    return spec.get(kind)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    baseline = json.loads(args.baseline.read_text(encoding='utf-8-sig'))
    m = baseline['manifest']
    if (m.get('account'), m.get('region'), m.get('run_id')) != (aws.ACCOUNT, aws.REGION, aws.RUN):
        raise ValueError('Wrong baseline scope')
    ident = aws.identity()
    required = tag_dict(aws.tags())
    clients = {}
    errors = []
    excluded = []
    targets = {}
    ec2 = {}
    kms_ids = set()
    resources = [r for stack in m['stacks'] for r in stack['resources'] if r.get('PhysicalResourceId')]

    def add(service, kind, identifier, spec, source):
        arn = spec[-1]
        if arn.startswith('arn:') and arn.split(':')[4] != aws.ACCOUNT:
            raise ValueError('Target ARN account mismatch')
        targets[service, arn] = {'service': service, 'kind': kind, 'id': identifier, 'arn': arn, 'source': source, 'spec': spec}
    for stack in m['stacks']:
        arn = stack['arn']
        add('cloudformation', 'stack', stack['name'], ('cloudformation', 'describe_stacks', {'StackName': arn}, 'Stacks', 'Tags', arn), 'CloudFormation')
    for r in resources:
        kind, identifier = (r['ResourceType'], r['PhysicalResourceId'])
        if kind in EC2_KIND:
            ec2[identifier] = {'kind': EC2_KIND[kind], 'source': 'CloudFormation'}
        elif kind == 'AWS::EC2::EIP':
            for allocation in m['discovered'].get('allocation_ids', []):
                ec2[allocation] = {'kind': 'elastic-ip', 'source': 'CloudFormation EIP / live allocation binding'}
        elif kind in UNTAGGABLE:
            excluded.append({'id': identifier, 'kind': kind, 'reason': UNTAGGABLE[kind]})
        else:
            spec = target_for_cfn(r)
            if spec:
                add(spec[0], kind, identifier, spec, 'CloudFormation')
            else:
                errors.append({'stage': 'coverage', 'id': identifier, 'code': 'unsupported_resource_type:' + kind})
    vpcs = [r['PhysicalResourceId'] for r in resources if r['ResourceType'] == 'AWS::EC2::VPC']
    group_ids = []
    discovery = []
    for vpc in vpcs:
        filt = {'Filters': [{'Name': 'vpc-id', 'Values': [vpc]}]}
        for op, key, field, kind in (('describe_vpcs', 'Vpcs', 'VpcId', 'vpc'), ('describe_subnets', 'Subnets', 'SubnetId', 'subnet'), ('describe_route_tables', 'RouteTables', 'RouteTableId', 'route-table'), ('describe_security_groups', 'SecurityGroups', 'GroupId', 'security-group'), ('describe_network_interfaces', 'NetworkInterfaces', 'NetworkInterfaceId', 'network-interface'), ('describe_network_acls', 'NetworkAcls', 'NetworkAclId', 'network-acl'), ('describe_vpc_endpoints', 'VpcEndpoints', 'VpcEndpointId', 'vpc-endpoint')):
            discovery.append((op, filt, key, field, kind))
    instance_ids = [r['PhysicalResourceId'] for r in resources if r['ResourceType'] == 'AWS::EC2::Instance']
    if instance_ids:
        discovery.append(('describe_volumes', {'Filters': [{'Name': 'attachment.instance-id', 'Values': instance_ids}]}, 'Volumes', 'VolumeId', 'volume'))
    for op, params, key, field, kind in discovery:
        try:
            for row in collect(clients, 'ec2', op, params, key):
                ec2[row[field]] = {'kind': kind, 'source': 'Automatic/exclusive VPC discovery'}
                if field == 'GroupId':
                    group_ids.append(row[field])
                if row.get('KmsKeyId'):
                    kms_ids.add(row['KmsKeyId'])
                if row.get('DhcpOptionsId'):
                    excluded.append({'id': row['DhcpOptionsId'], 'kind': 'EC2 DHCP option set', 'reason': 'Referenced account default; not created by the lab CloudFormation, shared configuration preserved.'})
        except (ClientError, BotoCoreError) as e:
            errors.append({'stage': 'discovery', 'operation': op, 'code': e.response['Error']['Code'] if isinstance(e, ClientError) else type(e).__name__})
    if group_ids:
        try:
            for row in collect(clients, 'ec2', 'describe_security_group_rules', {'Filters': [{'Name': 'group-id', 'Values': sorted(set(group_ids))}]}, 'SecurityGroupRules'):
                ec2[row['SecurityGroupRuleId']] = {'kind': 'security-group-rule', 'source': 'All rules of exclusive VPC groups, including defaults'}
        except (ClientError, BotoCoreError) as e:
            errors.append({'stage': 'discovery', 'operation': 'describe_security_group_rules', 'code': e.response['Error']['Code'] if isinstance(e, ClientError) else type(e).__name__})
    for check in baseline['checks']:
        for row in check['rows']:
            if row.get('VpcEndpointId'):
                ec2[row['VpcEndpointId']] = {'kind': 'vpc-endpoint', 'source': 'Observed exclusive VPC endpoint, including GuardDuty'}
            if row.get('ARN') and check['service'] == 'secretsmanager':
                arn = row['ARN']
                add('secretsmanager', 'secret including RDS-managed master', arn, ('secretsmanager', 'describe_secret', {'SecretId': arn}, None, 'Tags', arn), 'Live secret metadata')
            if row.get('CertificateArn') and check['operation'] == 'describe_certificates':
                arn = row['CertificateArn']
                add('dms', 'certificate', arn, ('dms', 'list_tags_for_resource', {'ResourceArn': arn}, None, 'TagList', arn), 'External DMS certificate')
            if row.get('logGroupName'):
                name = row['logGroupName']
                arn = 'arn:aws:logs:' + aws.REGION + ':' + aws.ACCOUNT + ':log-group:' + name
                add('logs', 'log group including DMS automatic', name, ('logs', 'list_tags_for_resource', {'resourceArn': arn}, None, 'tags', arn), 'Observed exact log group')
    for volume in m['discovered'].get('ebs_volume_ids', []):
        ec2[volume] = {'kind': 'volume', 'source': 'Immutable full-baseline volume binding'}
    records = []
    try:
        raw_tags = collect(clients, 'ec2', 'describe_tags', {'Filters': [{'Name': 'resource-id', 'Values': sorted(ec2)}]}, 'Tags')
        by_id = {identifier: {} for identifier in ec2}
        for tag in raw_tags:
            by_id[tag['ResourceId']][tag['Key']] = tag.get('Value', '')
        for identifier, meta in sorted(ec2.items()):
            arn = 'arn:aws:ec2:' + aws.REGION + ':' + aws.ACCOUNT + ':' + meta['kind'] + '/' + identifier
            current = by_id[identifier]
            records.append({'service': 'ec2', 'id': identifier, 'kind': meta['kind'], 'arn': arn, 'source': meta['source'], 'current_tags': current, 'required_diff': missing_tags(current, required), 'status': 'read'})
    except (ClientError, BotoCoreError) as e:
        errors.append({'stage': 'tags', 'service': 'ec2', 'code': e.response['Error']['Code'] if isinstance(e, ClientError) else type(e).__name__})
    for target in targets.values():
        service, op, params, root, key, arn = target.pop('spec')
        try:
            raw = request(clients, service, op, params)
            obj = raw.get(root, {}) if root else raw
            if isinstance(obj, list):
                obj = obj[0]
            current = tag_dict(obj.get(key, []))
            target.update({'current_tags': current, 'required_diff': missing_tags(current, required), 'status': 'read'})
            records.append(target)
        except (ClientError, BotoCoreError) as e:
            errors.append({'stage': 'tags', 'id': target['id'], 'service': service, 'code': e.response['Error']['Code'] if isinstance(e, ClientError) else type(e).__name__})
    for r in resources:
        if r['ResourceType'] != 'AWS::IAM::Role':
            continue
        try:
            for policy in collect(clients, 'iam', 'list_attached_role_policies', {'RoleName': r['PhysicalResourceId']}, 'AttachedPolicies'):
                if policy['PolicyArn'].split(':')[4] == 'aws':
                    excluded.append({'id': policy['PolicyArn'], 'kind': 'AWS-managed IAM policy', 'reason': 'AWS-owned shared policy attached to a lab role; the role is audited, the shared policy is preserved.'})
        except (ClientError, BotoCoreError) as e:
            errors.append({'stage': 'exclusions', 'id': r['PhysicalResourceId'], 'code': e.response['Error']['Code'] if isinstance(e, ClientError) else type(e).__name__})
    for check in baseline['checks']:
        for row in check['rows']:
            key = row.get('MasterUserSecret', {}).get('KmsKeyId')
            if key:
                kms_ids.add(key)
    for r in resources:
        op, params = ('describe_db_instances', {'DBInstanceIdentifier': r['PhysicalResourceId']}) if r['ResourceType'] == 'AWS::RDS::DBInstance' else ('describe_replication_instances', {'Filters': [{'Name': 'replication-instance-arn', 'Values': [r['PhysicalResourceId']]}]}) if r['ResourceType'] == 'AWS::DMS::ReplicationInstance' else (None, None)
        if not op:
            continue
        service = 'rds' if op == 'describe_db_instances' else 'dms'
        key = 'DBInstances' if service == 'rds' else 'ReplicationInstances'
        try:
            for row in collect(clients, service, op, params, key):
                if row.get('KmsKeyId'):
                    kms_ids.add(row['KmsKeyId'])
        except (ClientError, BotoCoreError) as e:
            errors.append({'stage': 'KMS reference', 'id': r['PhysicalResourceId'], 'code': e.response['Error']['Code'] if isinstance(e, ClientError) else type(e).__name__})
    for key in sorted(kms_ids):
        try:
            metadata = request(clients, 'kms', 'describe_key', {'KeyId': key})['KeyMetadata']
            excluded.append({'id': metadata['Arn'], 'kind': 'KMS key', 'key_manager': metadata['KeyManager'], 'reason': 'AWS-managed shared regional encryption key; not created by the laboratory.' if metadata['KeyManager'] == 'AWS' else 'Referenced preexisting customer key; no KMS resource created by lab CloudFormation; ownership requires separate review.'})
        except (ClientError, BotoCoreError) as e:
            errors.append({'stage': 'KMS metadata', 'id': key, 'code': e.response['Error']['Code'] if isinstance(e, ClientError) else type(e).__name__})
    excluded = list({(e['kind'], e['id']): e for e in excluded}.values())
    report = {'schema_version': 1, 'time_utc': aws.stamp(), 'identity': ident, 'run_id': aws.RUN, 'required_tags': required, 'population': 'Every taggable CloudFormation-owned lab resource plus exclusive VPC defaults, ENIs, SG rules, EBS, automatic GuardDuty dependencies, DMS logs and RDS-managed master secret.', 'records': records, 'exclusions': excluded, 'coverage_errors': errors, 'taggable_resources_audited': len(records), 'resources_missing_or_mismatching_required_tags': sum((bool(r['required_diff']) for r in records)), 'tags_verified': not errors and all((not r['required_diff'] for r in records)), 'write_performed': False, 'preservation': 'Only required keys are diffed. Existing GuardDutyManaged, aws:* and every unrelated tag must remain intact. No security exclusions or account-wide changes are proposed.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(aws.clean(report), indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('time_utc', 'taggable_resources_audited', 'resources_missing_or_mismatching_required_tags', 'coverage_errors', 'tags_verified', 'write_performed')}, indent=2))
    return 0 if not errors else 2
if __name__ == '__main__':
    sys.exit(main())
