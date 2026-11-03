"""Replace bootstrap deletion ARN patterns with exact CFN resource inventory.

This is a local deterministic transformation with no AWS calls. Input files are
AWS DescribeStackResources/ListStackResources responses for the authorized
principal and (optionally) migration stack. Pass the principal DescribeStacks
response for outputs such as the EIP allocation ID. Unknown types/identifiers
fail closed. Exit 0 writes a policy; exit 2 reports invalid input.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse
import hashlib
import json
import pathlib
import re
import sys
ACCOUNT = ACCOUNT
REGION = 'us-east-1'
MAIN = STACK
MIGRATION = MAIN + '-migration'
EC2_TYPES = {'AWS::EC2::VPC': ('vpc', 'vpc-'), 'AWS::EC2::InternetGateway': ('internet-gateway', 'igw-'), 'AWS::EC2::Subnet': ('subnet', 'subnet-'), 'AWS::EC2::RouteTable': ('route-table', 'rtb-'), 'AWS::EC2::NatGateway': ('natgateway', 'nat-'), 'AWS::EC2::SecurityGroup': ('security-group', 'sg-'), 'AWS::EC2::VPCEndpoint': ('vpc-endpoint', 'vpce-'), 'AWS::EC2::Instance': ('instance', 'i-')}
NESTED = {'AWS::EC2::VPCGatewayAttachment', 'AWS::EC2::Route', 'AWS::EC2::SubnetRouteTableAssociation', 'AWS::EC2::SecurityGroupIngress', 'AWS::EC2::SecurityGroupEgress', 'AWS::IAM::Policy'}

def load(path):
    return json.loads(pathlib.Path(path).read_text(encoding='utf-8-sig'))

def resources(document, expected_stack_name):
    prefix = 'arn:aws:cloudformation:' + REGION + ':' + ACCOUNT + ':stack/' + expected_stack_name + '/'
    if document.get('StackId') and (not document['StackId'].startswith(prefix)):
        raise ValueError('Inventory top-level StackId identifies a different stack')
    if document.get('NextToken'):
        raise ValueError('Inventory is paginated; aggregate every page before tightening')
    records = document.get('StackResources', document.get('StackResourceSummaries', document.get('resources')))
    if not isinstance(records, list):
        raise ValueError('Inventory must contain StackResources or StackResourceSummaries')
    for item in records:
        if item.get('StackId'):
            if not item['StackId'].startswith(prefix):
                raise ValueError('Inventory contains a different stack')
        if item.get('ResourceStatus') == 'DELETE_COMPLETE':
            continue
        if not item.get('PhysicalResourceId'):
            raise ValueError('Incomplete physical resource ID for ' + item.get('LogicalResourceId', 'unknown'))
        yield item

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--principal-inventory', required=True)
    parser.add_argument('--principal-stack-description', required=True)
    parser.add_argument('--migration-inventory')
    parser.add_argument('--principal-template', default=str(pathlib.Path(__file__).resolve().parents[1] / 'infra' / 'postgres-migration-lab.template.json'))
    parser.add_argument('--bootstrap-policy', default=str(pathlib.Path(__file__).with_name('teardown.bootstrap.policy.json')))
    parser.add_argument('--output', required=True)
    parser.add_argument('--allow-partial', action='store_true', help='Keep reviewed tag/prefix fallbacks only for not-yet-created resources')
    parser.add_argument('--eip-allocation-id', default='')
    args = parser.parse_args()
    load_context()
    try:
        description = load(args.principal_stack_description)
        stack = description.get('Stacks', [description.get('stack', description)])[0]
        stack_prefix = 'arn:aws:cloudformation:' + REGION + ':' + ACCOUNT + ':stack/' + MAIN + '/'
        if not stack.get('StackId', '').startswith(stack_prefix):
            raise ValueError('Principal description must identify the authorized immutable stack')
        if not args.allow_partial and stack.get('StackStatus') not in {'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE'}:
            raise ValueError('Tightening requires a complete stable principal stack')
        tags = {tag['Key']: tag['Value'] for tag in stack.get('Tags', [])}
        if any((tags.get(key) != value for key, value in {'Environment': 'HML', 'Project': 'postgresql-migration-lab', 'RunId': RUN}.items())):
            raise ValueError('Principal description ownership tags do not match')
        outputs = {entry['OutputKey']: entry['OutputValue'] for entry in stack.get('Outputs', [])}
        records = list(resources(load(args.principal_inventory), MAIN))
        expected_logical_ids = set(load(args.principal_template)['Resources'])
        observed_logical_ids = {item['LogicalResourceId'] for item in records}
        if observed_logical_ids - expected_logical_ids or (not args.allow_partial and observed_logical_ids != expected_logical_ids):
            raise ValueError('Inventory does not exactly cover the principal template logical IDs')
        if args.migration_inventory:
            records.extend(resources(load(args.migration_inventory), MIGRATION))
        exact = {'ec2': set(), 'dms': set(), 'rds': set(), 'secret': set(), 'role': set(), 'profile': set()}
        ec2_prefix = 'arn:aws:ec2:' + REGION + ':' + ACCOUNT + ':'
        for item in records:
            kind = item['ResourceType']
            physical = item['PhysicalResourceId']
            if kind in NESTED:
                continue
            if kind in EC2_TYPES:
                resource_type, id_prefix = EC2_TYPES[kind]
                if not re.fullmatch(re.escape(id_prefix) + '[a-f0-9]+', physical):
                    raise ValueError('Invalid EC2 ID for ' + item['LogicalResourceId'])
                exact['ec2'].add(ec2_prefix + resource_type + '/' + physical)
            elif kind == 'AWS::EC2::EIP':
                allocation = args.eip_allocation_id or outputs.get('NatElasticIpAllocationId', physical)
                if not re.fullmatch('eipalloc-[a-f0-9]+', allocation):
                    raise ValueError('EIP allocation ID is required in principal stack outputs')
                exact['ec2'].add(ec2_prefix + 'elastic-ip/' + allocation)
            elif kind.startswith('AWS::DMS::'):
                if kind == 'AWS::DMS::ReplicationSubnetGroup' and (not physical.startswith('arn:')):
                    physical = 'arn:aws:dms:' + REGION + ':' + ACCOUNT + ':subgrp:' + physical
                if not physical.startswith('arn:aws:dms:' + REGION + ':' + ACCOUNT + ':'):
                    raise ValueError('DMS resource is outside account/region')
                exact['dms'].add(physical)
            elif kind.startswith('AWS::RDS::'):
                resource_type = {'AWS::RDS::DBInstance': 'db', 'AWS::RDS::DBParameterGroup': 'pg', 'AWS::RDS::DBSubnetGroup': 'subgrp'}.get(kind)
                if not resource_type or not physical.lower().startswith(MAIN):
                    raise ValueError('Unexpected RDS resource')
                exact['rds'].add('arn:aws:rds:' + REGION + ':' + ACCOUNT + ':' + resource_type + ':' + physical)
            elif kind == 'AWS::SecretsManager::Secret':
                if item['LogicalResourceId'] not in {'SourceCredential', 'TargetCredential', 'ClientCredential'} or not physical.startswith('arn:aws:secretsmanager:' + REGION + ':' + ACCOUNT + ':secret:'):
                    raise ValueError('Secret ARN is outside the authorized CFN logical resources/account/region')
                exact['secret'].add(physical)
            elif kind in {'AWS::IAM::Role', 'AWS::IAM::InstanceProfile'}:
                if not (physical.startswith(MAIN + '-') or (kind == 'AWS::IAM::Role' and physical in {'dms-vpc-role', 'dms-cloudwatch-logs-role'})):
                    raise ValueError('IAM resource is outside the authorized names')
                category = 'role' if kind.endswith('::Role') else 'profile'
                resource_type = 'role' if category == 'role' else 'instance-profile'
                exact[category].add('arn:aws:iam::' + ACCOUNT + ':' + resource_type + '/' + physical)
            else:
                raise ValueError('Unsupported inventory resource type: ' + kind)
        if any((not values for category, values in exact.items() if category != 'dms')):
            raise ValueError('Principal inventory is incomplete; do not tighten before creation stabilizes')
        policy = load(args.bootstrap_policy)
        categories = {'DeleteOnlyTaggedLabEc2Resources': 'ec2', 'DeleteOnlyTaggedLabDmsResources': 'dms', 'ReadOnlyLabDmsTags': 'dms', 'DeleteNamedLabDatabaseResources': 'rds', 'DeleteGeneratedLabSecretsWithoutReadingValues': 'secret', 'DeleteOnlyLabOwnedRoles': 'role', 'DeleteOnlyGeneratedLabInstanceProfile': 'profile'}
        for statement in policy['Statement']:
            if statement['Sid'] in categories:
                statement['Resource'] = sorted(exact[categories[statement['Sid']]])
                if args.allow_partial and statement['Sid'] == 'DeleteOnlyLabOwnedRoles' and ('DmsSecretAccessRole' not in observed_logical_ids):
                    statement['Resource'].append('arn:aws:iam::' + ACCOUNT + ':role/' + MAIN + '-DmsSecretAccessRole-*')
            if statement['Sid'] == 'DeleteOnlyTaggedLabEc2Resources':
                statement['Action'] = [action for action in statement['Action'] if action != 'ec2:DeleteVolume']
        if args.allow_partial and 'TargetCredential' not in observed_logical_ids:
            policy['Statement'].append({'Sid': 'PendingTaggedTargetCredentialOnly', 'Effect': 'Allow', 'Action': ['secretsmanager:DescribeSecret', 'secretsmanager:DeleteSecret'], 'Resource': 'arn:aws:secretsmanager:' + REGION + ':' + ACCOUNT + ':secret:TargetCredential-*', 'Condition': {'StringEquals': {'aws:ResourceTag/RunId': RUN, 'aws:ResourceTag/Project': 'postgresql-migration-lab', 'aws:ResourceTag/Environment': 'HML'}}})
        if not args.migration_inventory:
            policy['Statement'].append({'Sid': 'PendingTaggedMigrationResources', 'Effect': 'Allow', 'Action': ['dms:DeleteReplicationTask', 'dms:DeleteEndpoint', 'dms:DeleteConnection', 'dms:ListTagsForResource'], 'Resource': ['arn:aws:dms:' + REGION + ':' + ACCOUNT + ':task:*', 'arn:aws:dms:' + REGION + ':' + ACCOUNT + ':endpoint:*', *sorted(exact['dms'])], 'Condition': {'StringEquals': {'aws:ResourceTag/RunId': RUN, 'aws:ResourceTag/Project': 'postgresql-migration-lab', 'aws:ResourceTag/Environment': 'HML'}}})
        target = pathlib.Path(args.output)
        payload = (json.dumps(policy, indent=2) + '\n').encode('utf-8')
        target.write_bytes(payload)
        print(json.dumps({'aws_writes': 0, 'principal_stack_arn': stack['StackId'], 'partial': args.allow_partial, 'pending_logical_ids': sorted(expected_logical_ids - observed_logical_ids), 'migration_exact_inventory': bool(args.migration_inventory), 'resource_counts': {key: len(value) for key, value in exact.items()}, 'output': str(target), 'sha256': hashlib.sha256(payload).hexdigest()}, indent=2))
        return 0
    except (ValueError, KeyError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
if __name__ == '__main__':
    sys.exit(main())
