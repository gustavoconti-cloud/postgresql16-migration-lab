"""Bounded SSM execution on the exact lab source instance; no credential payloads."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse, json
from pathlib import Path
from aws_context import *

def source_instance():
    require(bool(MAIN_STACK_ARN), 'Bind main_stack_arn before AWS use')
    identity()
    resource = client('cloudformation').describe_stack_resource(StackName=MAIN_STACK_ARN, LogicalResourceId='SourceInstance')['StackResourceDetail']
    instance_id = resource['PhysicalResourceId']
    obj = client('ec2').describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
    observed = {x['Key']: x['Value'] for x in obj.get('Tags', [])}
    for k, v in {'Environment': 'HML', 'Project': 'postgresql-migration-lab', 'RunId': RUN}.items():
        assert observed.get(k) == v, 'Instance ownership mismatch'
    assert obj['State']['Name'] == 'running', 'Instance is not running'
    return instance_id

def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['submit', 'read'])
    p.add_argument('value')
    p.add_argument('--label', default='command')
    a = p.parse_args()
    ssm = client('ssm')
    instance_id = source_instance()
    if a.action == 'submit':
        load_context()
        managed = ssm.describe_instance_information(Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}])['InstanceInformationList']
        assert len(managed) == 1 and managed[0]['PingStatus'] == 'Online', 'Wait for SSM Online before submission'
        command = Path(a.value).read_text(encoding='utf-8')
        assert len(command.encode()) < 50000, 'Split command into bounded stages'
        request = {'InstanceIds': [instance_id], 'DocumentName': 'AWS-RunShellScript', 'TimeoutSeconds': 120, 'Comment': 'PostgreSQL isolated laboratory: ' + a.label, 'Parameters': {'commands': [command], 'executionTimeout': ['900']}}
        save(a.label + '-request.json', {'time': stamp(), 'request': request})
        result = ssm.send_command(**request)
        command_id = result['Command']['CommandId']
        save(a.label + '-submitted.json', {'time': stamp(), 'instance_id': instance_id, 'command_id': command_id})
        print(json.dumps({'command_id': command_id, 'instance_id': instance_id}))
    else:
        result = ssm.get_command_invocation(CommandId=a.value, InstanceId=instance_id)
        save(a.label + '-readback.json', {'time': stamp(), 'result': result})
        print(json.dumps(clean(result), ensure_ascii=False))
if __name__ == '__main__':
    main()
