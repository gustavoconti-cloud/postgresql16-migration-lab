"""Build a bound guardrail template locally; performs no AWS calls or writes.

Input: immutable target stack ARN, TTL, run ID and reviewed deletion IAM policy.
Output: UTF-8 CloudFormation JSON and a local binding receipt.
Idempotent: writes deterministically for the same inputs. Exit 0 success; 2 invalid
input. Deployment/readback remain the root operator's responsibility.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
ACCOUNT = ACCOUNT
REGION = 'us-east-1'
PROJECT = 'postgresql-migration-lab'

def ref(name):
    return {'Ref': name}

def sub(value):
    return {'Fn::Sub': value}

def att(name, attribute='Arn'):
    return {'Fn::GetAtt': [name, attribute]}

def build(args):
    load_context()
    require(args.run_id == RUN and args.expires_at == CONFIG['expires_at'], 'Guard resource RunId/expiry differ from context')
    require(args.target_stack_arn == binding_value('main_stack_arn'), 'Guard target differs from the immutable context binding')
    if not re.fullmatch(f'arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/{STACK}/[a-zA-Z0-9-]+', args.target_stack_arn):
        raise ValueError('Target must be the immutable ARN of the authorized stack')
    if not re.fullmatch('[a-zA-Z0-9-]{1,80}', args.run_id):
        raise ValueError('Run ID must be a short alphanumeric and hyphen identifier')
    expiry = dt.datetime.fromisoformat(args.expires_at.replace('Z', '+00:00'))
    if expiry.tzinfo is None or expiry.utcoffset() != dt.timedelta(0):
        raise ValueError('Expiry must include UTC timezone')
    now = dt.datetime.now(dt.timezone.utc)
    if not now < expiry <= now + dt.timedelta(hours=72):
        raise ValueError('Expiry must be future and at most 72 hours from this build')
    migration_name = f'{STACK}-migration'
    migration_prefix = 'arn:aws:cloudformation:' + REGION + ':' + ACCOUNT + ':stack/' + migration_name + '/'
    if args.migration_stack_arn and (not args.migration_stack_arn.startswith(migration_prefix)):
        raise ValueError('Dependent stack ARN must match the exact migration stack name')
    if args.certificate_arn and (not args.certificate_arn.startswith('arn:aws:dms:' + REGION + ':' + ACCOUNT + ':cert:')):
        raise ValueError('Certificate ARN must be in the authorized account and region')
    if args.replication_task_arn and (not args.replication_task_arn.startswith('arn:aws:dms:' + REGION + ':' + ACCOUNT + ':task:')):
        raise ValueError('Task ARN must be in the authorized account and region')
    policy = json.loads(pathlib.Path(args.deletion_policy_file).read_text(encoding='utf-8-sig'))
    if policy.get('Version') != '2012-10-17' or not policy.get('Statement'):
        raise ValueError('Deletion policy must be a nonempty IAM policy document')
    for statement in policy['Statement']:
        if statement.get('Effect') != 'Allow':
            raise ValueError('Teardown policy accepts reviewed Allow statements only')
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        if any((action == '*' or action.endswith(':*') for action in actions)):
            raise ValueError('Service-wide or administrator wildcard actions are forbidden')
    tags = [{'Key': 'Environment', 'Value': 'HML'}, {'Key': 'Project', 'Value': PROJECT}, {'Key': 'Owner', 'Value': CONFIG.get('owner', '')}, {'Key': 'ManagedBy', 'Value': CONFIG.get('managed_by', 'migration-lab-toolkit')}, {'Key': args.run_tag_key, 'Value': args.run_id}, {'Key': 'ExpiresAt', 'Value': expiry.isoformat()}]
    resources = {}
    resources['DeletionRole'] = {'Type': 'AWS::IAM::Role', 'Properties': {'RoleName': sub('${AWS::StackName}-teardown'), 'Tags': tags, 'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'cloudformation.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}, 'Policies': [{'PolicyName': 'DeleteBoundLabResources', 'PolicyDocument': policy}]}}
    lambda_statements = [{'Effect': 'Allow', 'Action': ['cloudformation:DescribeStacks', 'cloudformation:DescribeStackResource', 'cloudformation:DeleteStack'], 'Resource': [args.target_stack_arn, args.migration_stack_arn or migration_prefix + '*']}, {'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': att('DeletionRole'), 'Condition': {'StringEquals': {'iam:PassedToService': 'cloudformation.amazonaws.com'}}}, {'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'], 'Resource': sub('arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/${AWS::StackName}-ttl:*')}, {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': att('FailureQueue')}, {'Effect': 'Allow', 'Action': ['dms:DescribeReplicationTasks', 'dms:DescribeCertificates'], 'Resource': '*', 'Condition': {'StringEquals': {'aws:RequestedRegion': REGION}}}, {'Effect': 'Allow', 'Action': 'dms:ListTagsForResource', 'Resource': [args.replication_task_arn or 'arn:aws:dms:' + REGION + ':' + ACCOUNT + ':task:*', args.certificate_arn or 'arn:aws:dms:' + REGION + ':' + ACCOUNT + ':cert:*']}, {'Effect': 'Allow', 'Action': 'dms:StopReplicationTask', 'Resource': args.replication_task_arn or 'arn:aws:dms:' + REGION + ':' + ACCOUNT + ':task:*', 'Condition': {'StringEquals': {'aws:ResourceTag/' + args.run_tag_key: args.run_id, 'aws:ResourceTag/Project': PROJECT, 'aws:ResourceTag/Environment': 'HML'}}}, {'Effect': 'Allow', 'Action': 'dms:DeleteCertificate', 'Resource': args.certificate_arn or 'arn:aws:dms:' + REGION + ':' + ACCOUNT + ':cert:*', 'Condition': {'StringEquals': {'aws:ResourceTag/' + args.run_tag_key: args.run_id, 'aws:ResourceTag/Project': PROJECT, 'aws:ResourceTag/Environment': 'HML'}}}]
    budget_name = ''
    if args.enable_budget:
        budget_name = f'{STACK}-guardrail-cost'
        lambda_statements.append({'Effect': 'Allow', 'Action': 'budgets:ViewBudget', 'Resource': 'arn:aws:budgets::' + ACCOUNT + ':budget/' + budget_name})
        resources['LabBudget'] = {'Type': 'AWS::Budgets::Budget', 'Properties': {'Budget': {'BudgetName': budget_name, 'BudgetType': 'COST', 'TimeUnit': 'CUSTOM', 'BudgetLimit': {'Amount': 100, 'Unit': 'USD'}, 'TimePeriod': {'Start': args.budget_start, 'End': args.budget_end}, 'CostFilters': {'TagKeyValue': ['user:' + args.run_tag_key + '$' + args.run_id]}, 'CostTypes': {'IncludeCredit': False, 'IncludeRefund': False, 'IncludeTax': True, 'IncludeSupport': True}}, 'ResourceTags': tags}}
    resources['FailureQueue'] = {'Type': 'AWS::SQS::Queue', 'DeletionPolicy': 'Delete', 'UpdateReplacePolicy': 'Delete', 'Properties': {'QueueName': sub('${AWS::StackName}-failures'), 'SqsManagedSseEnabled': True, 'MessageRetentionPeriod': 1209600, 'Tags': tags}}
    resources['GuardRole'] = {'Type': 'AWS::IAM::Role', 'Properties': {'RoleName': sub('${AWS::StackName}-execution'), 'Tags': tags, 'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}, 'Policies': [{'PolicyName': 'OneStackTTLGuard', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': lambda_statements}}]}}
    resources['GuardLogs'] = {'Type': 'AWS::Logs::LogGroup', 'DeletionPolicy': 'Delete', 'UpdateReplacePolicy': 'Delete', 'Properties': {'LogGroupName': sub('/aws/lambda/${AWS::StackName}-ttl'), 'RetentionInDays': 7, 'Tags': tags}}
    resources['GuardFunction'] = {'Type': 'AWS::Lambda::Function', 'DependsOn': ['GuardLogs'], 'Properties': {'FunctionName': sub('${AWS::StackName}-ttl'), 'Runtime': 'python3.12', 'Handler': 'index.handler', 'Role': att('GuardRole'), 'Timeout': 60, 'MemorySize': 128, 'DeadLetterConfig': {'TargetArn': att('FailureQueue')}, 'Tags': tags, 'Environment': {'Variables': {'EXPECTED_STACK_NAME': STACK, 'TARGET_STACK_ARN': args.target_stack_arn, 'TARGET_RUN_ID': args.run_id, 'EXPECTED_ACCOUNT_ID': ACCOUNT, 'EXPECTED_PROJECT': PROJECT, 'RUN_TAG_KEY': args.run_tag_key, 'DELETION_ROLE_ARN': att('DeletionRole'), 'EXPIRES_AT_UTC': expiry.isoformat(), 'COST_CUTOFF_USD': str(CONFIG.get('operating_envelope_usd', 100)), 'BUDGET_NAME': budget_name, 'MIGRATION_STACK_NAME': migration_name, 'MIGRATION_STACK_ARN': args.migration_stack_arn, 'CERTIFICATE_IDENTIFIER': f'{STACK}-rds-ca', 'CERTIFICATE_ARN': args.certificate_arn, 'REPLICATION_TASK_ARN': args.replication_task_arn}}, 'Code': {'ZipFile': pathlib.Path(__file__).with_name('ttl_handler.py').read_text(encoding='utf-8')}}}
    resources['TTLRule'] = {'Type': 'AWS::Events::Rule', 'Properties': {'Name': sub('${AWS::StackName}-ttl'), 'Description': 'Independent five-minute expiry check for a bound temporary laboratory', 'ScheduleExpression': 'rate(5 minutes)', 'State': 'ENABLED', 'Tags': tags, 'Targets': [{'Id': 'LabTTLGuard', 'Arn': att('GuardFunction'), 'Input': '{"operation":"evaluate"}', 'RetryPolicy': {'MaximumRetryAttempts': 2, 'MaximumEventAgeInSeconds': 600}}]}}
    resources['InvokePermission'] = {'Type': 'AWS::Lambda::Permission', 'Properties': {'Action': 'lambda:InvokeFunction', 'FunctionName': ref('GuardFunction'), 'Principal': 'events.amazonaws.com', 'SourceArn': att('TTLRule'), 'SourceAccount': ACCOUNT}}
    template = {'AWSTemplateFormatVersion': '2010-09-09', 'Description': 'Independent TTL and optional delayed-billing guard for one authorized HML PostgreSQL laboratory.', 'Resources': resources, 'Outputs': {'TargetStackArn': {'Value': args.target_stack_arn, 'Description': 'Immutable laboratory stack ID'}, 'GuardFunctionName': {'Value': ref('GuardFunction'), 'Description': 'Invoke operation=probe before tests'}, 'DeletionRoleArn': {'Value': att('DeletionRole'), 'Description': 'Least-privilege teardown service role'}, 'FailureQueueUrl': {'Value': ref('FailureQueue'), 'Description': 'Inspect if guard invocations fail'}, 'ExpiresAtUtc': {'Value': expiry.isoformat(), 'Description': 'UTC expiry checked every five minutes'}}}
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(template, indent=2, ensure_ascii=False) + '\n'
    output.write_bytes(serialized.encode('utf-8'))
    receipt = {'class': 'draft', 'aws_writes': 0, 'profile': PROFILE, 'account': ACCOUNT, 'region': REGION, 'target_stack_arn': args.target_stack_arn, 'run_id': args.run_id, 'expires_at_utc': expiry.isoformat(), 'migration_stack_name': migration_name, 'migration_stack_arn': args.migration_stack_arn or 'pending_immutable_arn_binding', 'certificate_identifier': f'{STACK}-rds-ca', 'certificate_arn': args.certificate_arn or 'pending_immutable_arn_binding', 'replication_task_arn': args.replication_task_arn or 'pending_immutable_arn_binding', 'budget_enabled': bool(budget_name), 'budget_lag_warning': 'Billing data are delayed; the budget cannot guarantee an absolute spending cap.', 'template_sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'policy_sha256': hashlib.sha256(pathlib.Path(args.deletion_policy_file).read_bytes()).hexdigest(), 'policy_canonical_sha256': hashlib.sha256(json.dumps(policy, sort_keys=True).encode('utf-8')).hexdigest(), 'pending_gates': ['independent_policy_review', 'cfn_lint', 'validate_template', 'deployment_readback', 'probe', 'iam_simulation_and_actual_cleanup']}
    output.with_suffix('.binding.json').write_bytes((json.dumps(receipt, indent=2) + '\n').encode('utf-8'))
    return receipt

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-stack-arn', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--run-tag-key', default='RunId')
    parser.add_argument('--expires-at', required=True)
    parser.add_argument('--deletion-policy-file', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--migration-stack-arn', default='')
    parser.add_argument('--certificate-arn', default='')
    parser.add_argument('--replication-task-arn', default='')
    parser.add_argument('--enable-budget', action='store_true')
    parser.add_argument('--budget-start', default='')
    parser.add_argument('--budget-end', default='')
    args = parser.parse_args()
    load_context()
    if args.enable_budget and (not args.budget_start or not args.budget_end):
        parser.error('An enabled budget requires its exact start and end epoch timestamps')
    try:
        receipt = build(args)
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2))
    return 0
if __name__ == '__main__':
    sys.exit(main())
