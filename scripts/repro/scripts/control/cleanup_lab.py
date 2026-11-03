"""Explicit final cleanup for this one PostgreSQL laboratory; default is read-only.

The existing TTL Lambda remains the offline guard. This helper is necessary
because final teardown must pause after DMS cleanup and before deleting the main
stack to remove its exact unmanaged GuardDuty endpoint/security group. CFN stays
the lifecycle owner of managed resources, including secrets, roles and SQS.

Usage: cleanup_lab.py --step probe
       cleanup_lab.py --step stop-task [--execute --evidence-receipt FILE]
Repeat pending steps after inspecting their readback; there is no all/auto mode.
Exit 0: observed requested state or read-only plan; 3: asynchronous pending;
2: blocked, mismatch, API error or unknown write effect. No internal sleep loops.

For --execute, an evidence receipt must state account/region/run_id/verified_at_utc, gates
G6/T07/T08/repeat=true, and captures slot/disk/state/no_active_tests,
source_frozen_after_target_release/target_exclusive_commit/diffs/negative_block/
replay_ledger=true. cutover_markers must contain at least two distinct markers.
files [{kind, path, sha256}] must include final-inspect, target-commit, diffs,
negative-block and replay-ledger. JSON/JSONL bytes are parsed as UTF-8 as well as
hashed locally. Those assertions must come from root's completed evidence review;
the helper does not independently prove SQL semantics or require a final report.

Every write has before -> plan -> fresh revalidation -> write -> readback journal.
Freshness checks are not atomic CAS: these AWS APIs do not offer If-Match. Unknown
effects stop the step; re-read the same step before any dependent work. No force
stack delete, ENI detach/delete, GuardDuty setting, KMS or DHCP write is exposed.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid
ROOT = Path(__file__).resolve().parents[1]
from botocore.exceptions import BotoCoreError, ClientError
ACCOUNT = ACCOUNT
REGION = 'us-east-1'
RUN = RUN
PREFIX = STACK
MAIN = binding_value('main_stack_arn', required=False) or ''
MIGRATION = binding_value('migration_stack_arn', required=False) or ''
GUARD = binding_value('guardrail_stack_arn', required=False) or ''
VPC = binding_value('vpc_id', required=False) or ''
SOURCE = binding_value('source_instance_id', required=False) or ''
REPLICATION = binding_value('replication_instance_arn', required=False) or ''
TASK = binding_value('dms_task_arn', required=False) or ''
CERT = binding_value('certificate_arn', required=False) or ''
GD_ENDPOINT = binding_value('guardduty_endpoint_id', required=False) or ''
GD_GROUP = binding_value('guardduty_security_group_id', required=False) or ''
GD_ENIS = set(CONFIG.get('bindings', {}).get('guardduty_network_interface_ids', []))
GD_SUBNETS = set(CONFIG.get('bindings', {}).get('guardduty_subnet_ids', []))
DMS_LOG = binding_value('log_group_name', required=False) or ''
TEARDOWN_ROLE = binding_value('teardown_role_arn', required=False) or ''
TAGS = {'Environment': 'HML', 'Project': 'postgresql-migration-lab', 'RunId': RUN}
STEPS = ('probe', 'stop-task', 'delete-migration', 'delete-certificate', 'terminate-source', 'delete-gd-endpoint', 'delete-gd-sg', 'delete-main', 'delete-dms-logs', 'delete-guard')

class Blocked(Exception):
    pass

def require(condition, message):
    if not condition:
        raise Blocked(message)

def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)

def tag_map(values):
    return values if isinstance(values, dict) else {v['Key']: v['Value'] for v in values}

def owned(values):
    tags = tag_map(values)
    require(all((tags.get(k) == v for k, v in TAGS.items())), 'Ownership tags do not match this laboratory')

def error_code(error):
    return error.response.get('Error', {}).get('Code', 'Unknown')

class Cleanup:

    def __init__(self, baseline_path, journal_path, client_factory):
        self.factory = client_factory
        self.clients = {}
        self.evidence_verified_at = None
        self.journal_path = Path(journal_path)
        require(self.journal_path.resolve().is_relative_to(ROOT / 'evidence') and self.journal_path.suffix == '.jsonl' and self.journal_path.name.startswith('cleanup'), 'Journal must be a cleanup JSONL inside the lab evidence directory')
        self.baseline_path = Path(baseline_path)
        baseline_bytes = self.baseline_path.read_bytes()
        self.baseline_sha = hashlib.sha256(baseline_bytes).hexdigest()
        self.baseline = json.loads(baseline_bytes)
        manifest = self.baseline['manifest']
        require((manifest['account'], manifest['region'], manifest['run_id']) == (ACCOUNT, REGION, RUN), 'Wrong baseline scope')
        require(not self.baseline.get('coverage_errors') and (not self.baseline.get('baseline_incomplete')), 'Incomplete baseline cannot authorize teardown')
        self.stacks = {s['arn']: s for s in manifest['stacks']}
        require(set(self.stacks) == {MAIN, MIGRATION, GUARD}, 'Baseline stack IDs differ from the authorized immutable IDs')
        for item in self.stacks.values():
            owned(item['tags'])
        self.expected = {arn: {(r['LogicalResourceId'], r['ResourceType'], r['PhysicalResourceId']) for r in self.stacks[arn]['resources']} for arn in self.stacks}
        resources = {r['LogicalResourceId']: r['PhysicalResourceId'] for r in self.stacks[MAIN]['resources']}
        require(resources.get('Vpc') == VPC and resources.get('SourceInstance') == SOURCE and (resources.get('ReplicationInstance') == REPLICATION), 'Baseline principal bindings differ')
        child = {r['LogicalResourceId']: r['PhysicalResourceId'] for r in self.stacks[MIGRATION]['resources']}
        require(child.get('ReplicationTask') == TASK and len(child) == 3, 'Unexpected migration inventory')
        discovered = manifest.get('discovered', {})
        require(discovered.get('guardduty_endpoint_ids', []) == ([GD_ENDPOINT] if GD_ENDPOINT else []) and discovered.get('guardduty_security_group_ids', []) == ([GD_GROUP] if GD_GROUP else []), 'GuardDuty auxiliary baseline binding differs')
        self.volumes = set(discovered['ebs_volume_ids'])
        self.baseline_enis = set()
        for check in self.baseline.get('checks', []):
            if check.get('operation') == 'describe_network_interfaces':
                for row in check.get('rows', []):
                    if row.get('VpcId') == VPC:
                        self.baseline_enis.add(row['NetworkInterfaceId'])
        require(GD_ENIS <= self.baseline_enis, 'Baseline lacks the exact GuardDuty ENIs')

    def client(self, service):
        if service not in self.clients:
            candidate = self.factory(service)
            require(candidate.meta.region_name == REGION or (service == 'iam' and candidate.meta.region_name == 'aws-global'), 'Client endpoint region differs from Virginia')
            self.clients[service] = candidate
        return self.clients[service]

    def journal(self, event, **values):
        record = {'at_utc': stamp(), 'event': event, 'account': ACCOUNT, 'region': REGION, 'run_id': RUN, 'baseline_sha256': self.baseline_sha, **values}
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open('ab') as stream:
            stream.write((canonical(record) + '\n').encode('utf-8'))
            stream.flush()
            os.fsync(stream.fileno())

    def unresolved(self):
        affected = set()
        if self.journal_path.exists():
            for line in self.journal_path.read_bytes().decode('utf-8-sig').splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get('event') in {'write_attempt_started', 'write_accepted', 'unknown_effect_or_rejected', 'readback_unknown'}:
                    affected.add(record['step'])
                elif record.get('event') in {'readback', 'observed_same_step'}:
                    affected.discard(record['step'])
                elif record.get('event') == 'probe_observed':
                    affected.clear()
        return affected

    def rows(self, service, operation, result_key, parameters, absent=()):
        client = self.client(service)
        try:
            if client.can_paginate(operation):
                pages = client.get_paginator(operation).paginate(**parameters)
            else:
                pages = [getattr(client, operation)(**parameters)]
            return [row for page in pages for row in page.get(result_key, [])]
        except ClientError as error:
            if error_code(error) in absent:
                return []
            raise

    def stack(self, arn, inventory=False):
        try:
            rows = self.client('cloudformation').describe_stacks(StackName=arn)['Stacks']
        except ClientError as error:
            if error_code(error) == 'ValidationError' and 'does not exist' in error.response['Error'].get('Message', ''):
                return None
            raise
        item = rows[0]
        require(item['StackId'] == arn, 'CloudFormation returned another immutable stack ID')
        owned(item.get('Tags', []))
        require(not item.get('EnableTerminationProtection'), 'Termination protection cannot be bypassed')
        result = {'arn': arn, 'status': item['StackStatus'], 'tags': tag_map(item.get('Tags', []))}
        if inventory and item['StackStatus'] not in {'DELETE_COMPLETE', 'DELETE_IN_PROGRESS'}:
            records = self.rows('cloudformation', 'list_stack_resources', 'StackResourceSummaries', {'StackName': arn})
            observed = {(r['LogicalResourceId'], r['ResourceType'], r['PhysicalResourceId']) for r in records}
            require(observed == self.expected[arn], 'Stack physical inventory changed; refresh and review its exact binding')
            result['inventory_sha256'] = hashlib.sha256(canonical(sorted(observed)).encode()).hexdigest()
        return result

    def deleted(self, arn):
        state = self.stack(arn)
        return state is None or state['status'] == 'DELETE_COMPLETE'

    def task(self):
        records = self.rows('dms', 'describe_replication_tasks', 'ReplicationTasks', {'Filters': [{'Name': 'replication-task-arn', 'Values': [TASK]}], 'WithoutSettings': True}, ('ResourceNotFoundFault',))
        if not records:
            return None
        item = records[0]
        require(item['ReplicationTaskArn'] == TASK and item['ReplicationInstanceArn'] == REPLICATION, 'Task/replication binding differs')
        owned(self.client('dms').list_tags_for_resource(ResourceArn=TASK).get('TagList', []))
        return {'arn': TASK, 'status': item['Status'], 'replication_arn': REPLICATION}

    def certificate(self):
        records = self.rows('dms', 'describe_certificates', 'Certificates', {'Filters': [{'Name': 'certificate-arn', 'Values': [CERT]}]}, ('ResourceNotFoundFault',))
        if not records:
            return None
        item = records[0]
        require(item['CertificateArn'] == CERT and item['CertificateIdentifier'] == PREFIX + '-rds-ca', 'Certificate binding differs')
        owned(self.client('dms').list_tags_for_resource(ResourceArn=CERT).get('TagList', []))
        return {'arn': CERT, 'identifier': item['CertificateIdentifier']}

    def source(self):
        records = self.rows('ec2', 'describe_instances', 'Reservations', {'InstanceIds': [SOURCE]}, ('InvalidInstanceID.NotFound',))
        instances = [i for r in records for i in r.get('Instances', [])]
        if not instances:
            return {'id': SOURCE, 'state': 'absent'}
        require(len(instances) == 1, 'Unexpected source instance count')
        item = instances[0]
        require(item.get('InstanceId') == SOURCE, 'Source instance ID differs')
        owned(item.get('Tags', []))
        state = item['State']['Name']
        vpc = item.get('VpcId')
        if state == 'terminated':
            require(vpc is None or vpc == VPC, 'Terminated source VPC binding differs')
            code = item['State'].get('Code')
            if 'Code' in item['State']:
                require(type(code) is int and 0 <= code <= 65535 and (code & 255 == 48), 'Terminated source state code differs')
            expected_tags = tag_map(self.stacks[MAIN]['tags'])
            observed_tags = tag_map(item.get('Tags', []))
            require(all((k in expected_tags and observed_tags.get(k) == expected_tags[k] for k in ('Environment', 'Project', 'RunId', 'Owner', 'ManagedBy', 'ExpiresAt'))), 'Terminated source ownership tags differ')
            require(observed_tags.get('aws:cloudformation:stack-id') == MAIN and observed_tags.get('aws:cloudformation:logical-id') == 'SourceInstance', 'Terminated source CloudFormation binding differs')
        else:
            require(vpc == VPC, 'Source instance/VPC binding differs')
        attached = {m['Ebs']['VolumeId'] for m in item.get('BlockDeviceMappings', []) if 'Ebs' in m}
        require(attached <= self.volumes, 'Unexpected source disk; preserve it and reconcile the baseline')
        require(all((m.get('Ebs', {}).get('DeleteOnTermination', True) for m in item.get('BlockDeviceMappings', []))), 'Source disk retention differs from the disposable lab contract')
        return {'id': SOURCE, 'vpc': vpc, 'state': state, 'volumes': sorted(attached)}

    def gd_endpoint(self):
        if not GD_ENDPOINT:
            return None
        records = self.rows('ec2', 'describe_vpc_endpoints', 'VpcEndpoints', {'VpcEndpointIds': [GD_ENDPOINT]}, ('InvalidVpcEndpointId.NotFound',))
        if not records or records[0]['State'] == 'deleted':
            return None
        item = records[0]
        require(item['VpcEndpointId'] == GD_ENDPOINT and item['VpcId'] == VPC, 'GuardDuty endpoint/VPC differs')
        require(item['ServiceName'] == 'com.amazonaws.us-east-1.guardduty-data' and item.get('RequesterManaged') is False, 'Unexpected endpoint ownership or service')
        require(tag_map(item.get('Tags', [])).get('GuardDutyManaged') == 'true', 'GuardDuty ownership marker missing')
        subnets = set(item.get('SubnetIds', []))
        groups = {g['GroupId'] for g in item.get('Groups', [])}
        enis = set(item.get('NetworkInterfaceIds', []))
        if item['State'] == 'deleting':
            require(subnets <= GD_SUBNETS and groups <= {GD_GROUP} and (enis <= GD_ENIS), 'Deleting GuardDuty endpoint has unexpected dependencies')
        else:
            require(subnets == GD_SUBNETS and groups == {GD_GROUP} and (enis == GD_ENIS), 'GuardDuty subnet/group/ENI binding differs')
        return {'id': GD_ENDPOINT, 'vpc': VPC, 'state': item['State'], 'enis': sorted(item.get('NetworkInterfaceIds', []))}

    def gd_enis(self):
        live = []
        for eni in sorted(GD_ENIS):
            records = self.rows('ec2', 'describe_network_interfaces', 'NetworkInterfaces', {'NetworkInterfaceIds': [eni]}, ('InvalidNetworkInterfaceID.NotFound',))
            for item in records:
                require(item['NetworkInterfaceId'] == eni and item['VpcId'] == VPC and ({g['GroupId'] for g in item.get('Groups', [])} == {GD_GROUP}), 'GuardDuty ENI binding differs')
                live.append({'id': eni, 'status': item['Status'], 'vpc': VPC})
        return live

    def gd_group(self):
        if not GD_GROUP:
            return None
        records = self.rows('ec2', 'describe_security_groups', 'SecurityGroups', {'GroupIds': [GD_GROUP]}, ('InvalidGroup.NotFound',))
        if not records:
            return None
        item = records[0]
        require(item['GroupId'] == GD_GROUP and item['VpcId'] == VPC and (item['GroupName'] == 'GuardDutyManagedSecurityGroup-' + VPC), 'GuardDuty security group binding differs')
        require(tag_map(item.get('Tags', [])).get('GuardDutyManaged') == 'true', 'GuardDuty group ownership marker missing')
        return {'id': GD_GROUP, 'vpc': VPC, 'name': item['GroupName']}

    def log(self):
        groups = self.rows('logs', 'describe_log_groups', 'logGroups', {'logGroupNamePrefix': DMS_LOG})
        matches = [g for g in groups if g['logGroupName'] == DMS_LOG]
        if not matches:
            return None
        group = matches[0]
        arn = group.get('logGroupArn') or group.get('arn', '').removesuffix(':*')
        require(arn == f'arn:aws:logs:us-east-1:{ACCOUNT}:log-group:' + DMS_LOG, 'DMS log group ARN differs')
        owned(self.client('logs').list_tags_for_resource(resourceArn=arn).get('tags', {}))
        return {'name': DMS_LOG, 'arn': arn}

    def no_active_source_work(self):
        records = self.rows('ssm', 'list_command_invocations', 'CommandInvocations', {'InstanceId': SOURCE, 'Details': False})
        active = [{'id': i['CommandId'], 'status': i['Status']} for i in records if i['Status'] in {'Pending', 'InProgress', 'Delayed', 'Cancelling'}]
        require(not active, 'Active SSM commands remain on source: ' + canonical(active))
        if self.evidence_verified_at is not None:
            for item in records:
                requested = item.get('RequestedDateTime')
                require(isinstance(requested, dt.datetime), 'SSM invocation freshness is unknown')
                require(requested <= self.evidence_verified_at, 'A newer SSM command exists after evidence review; capture and reverify the final source state')
        value = self.client('ec2').describe_instance_attribute(InstanceId=SOURCE, Attribute='disableApiTermination')
        require(not value.get('DisableApiTermination', {}).get('Value'), 'Instance termination protection cannot be bypassed')

    def no_foreign_vpc_workloads(self):
        reservations = self.rows('ec2', 'describe_instances', 'Reservations', {'Filters': [{'Name': 'vpc-id', 'Values': [VPC]}]})
        live = [i['InstanceId'] for r in reservations for i in r.get('Instances', []) if i['State']['Name'] != 'terminated']
        require(not live, 'A live EC2 workload remains in the lab VPC: ' + canonical(live))
        enis = self.rows('ec2', 'describe_network_interfaces', 'NetworkInterfaces', {'Filters': [{'Name': 'vpc-id', 'Values': [VPC]}]})
        require({i['NetworkInterfaceId'] for i in enis} <= self.baseline_enis, 'Unexpected VPC ENIs; stop and bind their owner before deletion')

    def dms_removed(self):
        require(self.deleted(MIGRATION), 'Migration stack is not deleted')
        require(self.task() is None and self.certificate() is None, 'DMS task/certificate remain')

    def gd_removed(self):
        require(self.gd_endpoint() is None and (not self.gd_enis()) and (self.gd_group() is None), 'GuardDuty endpoint/ENIs/group remain')

    def prepare(self, step):
        if step == 'probe':
            return ({'stacks': {arn: self.stack(arn) for arn in (MAIN, MIGRATION, GUARD)}, 'task': self.task(), 'certificate': self.certificate(), 'source': self.source(), 'gd_endpoint': self.gd_endpoint(), 'gd_enis': self.gd_enis(), 'gd_group': self.gd_group(), 'dms_log': self.log()}, None, False)
        if step == 'stop-task':
            item = self.task()
            if item is None or item['status'] in {'stopped', 'ready', 'failed'}:
                return (item, None, True)
            if item['status'] == 'stopping':
                return (item, None, False)
            require(item['status'] == 'running', 'Task state is not safely stoppable')
            return (item, ('dms', 'stop_replication_task', {'ReplicationTaskArn': TASK}), False)
        if step == 'delete-migration':
            item = self.task()
            require(item is None or item['status'] in {'stopped', 'ready', 'failed'}, 'Task must be inactive before migration deletion')
            return self.stack_plan(MIGRATION)
        if step == 'delete-certificate':
            require(self.deleted(MIGRATION) and self.task() is None, 'Migration/task must be absent before certificate deletion')
            item = self.certificate()
            return (item, None if item is None else ('dms', 'delete_certificate', {'CertificateArn': CERT}), item is None)
        if step == 'terminate-source':
            self.dms_removed()
            item = self.source()
            if item['state'] in {'absent', 'terminated'}:
                return (item, None, True)
            if item['state'] == 'shutting-down':
                return (item, None, False)
            require(item['state'] in {'running', 'stopped'}, 'Unexpected source state')
            self.no_active_source_work()
            return (item, ('ec2', 'terminate_instances', {'InstanceIds': [SOURCE]}), False)
        if step in {'delete-gd-endpoint', 'delete-gd-sg', 'delete-main'}:
            self.dms_removed()
            require(self.source()['state'] in {'absent', 'terminated'}, 'Source must be fully terminated')
            self.no_foreign_vpc_workloads()
            if step == 'delete-gd-endpoint':
                item = self.gd_endpoint()
                if item is None:
                    return (item, None, not self.gd_enis())
                if item['state'] == 'deleting':
                    return (item, None, False)
                require(item['state'] == 'available', 'Unexpected GuardDuty endpoint state')
                return (item, ('ec2', 'delete_vpc_endpoints', {'VpcEndpointIds': [GD_ENDPOINT]}), False)
            require(self.gd_endpoint() is None and (not self.gd_enis()), 'Endpoint and its ENIs must be absent')
            if step == 'delete-gd-sg':
                if not GD_GROUP:
                    return (None, None, True)
                item = self.gd_group()
                attached = self.rows('ec2', 'describe_network_interfaces', 'NetworkInterfaces', {'Filters': [{'Name': 'group-id', 'Values': [GD_GROUP]}]})
                require(not attached, 'GuardDuty group is still attached; no detach fallback is allowed')
                return (item, None if item is None else ('ec2', 'delete_security_group', {'GroupId': GD_GROUP}), item is None)
            require(self.gd_group() is None, 'GuardDuty security group remains')
            return self.stack_plan(MAIN)
        if step in {'delete-dms-logs', 'delete-guard'}:
            require(self.deleted(MAIN), 'Main stack must be fully deleted')
            self.dms_removed()
            self.gd_removed()
            if step == 'delete-dms-logs':
                item = self.log()
                return (item, None if item is None else ('logs', 'delete_log_group', {'logGroupName': DMS_LOG}), item is None)
            require(self.log() is None, 'Preserve/export and remove DMS logs before guard stack deletion')
            return self.stack_plan(GUARD)
        raise Blocked('Unsupported cleanup step')

    def stack_plan(self, arn):
        item = self.stack(arn, inventory=True)
        if item is None or item['status'] == 'DELETE_COMPLETE':
            return (item, None, True)
        if item['status'] == 'DELETE_IN_PROGRESS':
            return (item, None, False)
        require(item['status'] in {'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE', 'DELETE_FAILED'}, 'Stack state is not a reviewed deletion checkpoint')
        parameters = {'StackName': arn, 'ClientRequestToken': 'lab-cleanup-' + uuid.uuid4().hex}
        if arn != GUARD:
            role = self.client('iam').get_role(RoleName=PREFIX + '-guardrail-teardown')['Role']
            require(role['Arn'] == TEARDOWN_ROLE, 'Teardown service role ARN differs')
            owned(role.get('Tags', []))
            parameters['RoleARN'] = TEARDOWN_ROLE
        return (item, ('cloudformation', 'delete_stack', parameters), False)

    def run(self, step, execute):
        require(not execute or not self.unresolved(), 'An earlier write has unknown effect; run a read-only probe or the affected step before any new write')
        before, plan, done = self.prepare(step)
        self.journal('before_and_plan', step=step, before=before, plan=plan, execute=execute)
        if step == 'probe' or plan is None or (not execute):
            self.journal('probe_observed' if step == 'probe' else 'observed_same_step', step=step, observed=before)
            return ({'step': step, 'state': 'observed_complete' if done else 'probe' if step == 'probe' else 'would_write' if plan else 'pending', 'before': before, 'plan': plan, 'aws_write': False}, 3 if plan is None and (not done) and (step != 'probe') else 0)
        fresh, fresh_plan, fresh_done = self.prepare(step)
        stable_plan = lambda p: None if p is None else (p[0], p[1], {k: v for k, v in p[2].items() if k != 'ClientRequestToken'})
        require(canonical(fresh) == canonical(before) and stable_plan(fresh_plan) == stable_plan(plan) and (not fresh_done), 'State changed during freshness check; re-plan this exact step')
        self.journal('freshness_revalidated', step=step, before=fresh, plan=plan)
        service, operation, parameters = plan
        self.journal('write_attempt_started', step=step, operation=operation, parameters=parameters)
        try:
            response = getattr(self.client(service), operation)(**parameters)
            if operation == 'delete_vpc_endpoints':
                require(not response.get('Unsuccessful'), 'DeleteVpcEndpoints reported unsuccessful items')
            self.journal('write_accepted', step=step, operation=operation, parameters=parameters, request_id=response.get('ResponseMetadata', {}).get('RequestId'))
        except Exception as error:
            self.journal('unknown_effect_or_rejected', step=step, operation=operation, parameters=parameters, error_type=type(error).__name__, error_code=error_code(error) if isinstance(error, ClientError) else None)
            raise
        try:
            after, _, completed = self.prepare(step)
        except Exception as error:
            self.journal('readback_unknown', step=step, operation=operation, error_type=type(error).__name__, error_code=error_code(error) if isinstance(error, ClientError) else None)
            raise
        self.journal('readback', step=step, after=after, completed=completed)
        return ({'step': step, 'state': 'readback_complete' if completed else 'pending', 'before': before, 'after': after, 'aws_write': True, 'request_id': response.get('ResponseMetadata', {}).get('RequestId')}, 0 if completed else 3)

def verify_evidence_receipt(path):
    require(path is not None, '--execute requires a completed, preserved evidence receipt')
    receipt = json.loads(Path(path).read_bytes().decode('utf-8-sig'))
    require((receipt.get('account'), receipt.get('region'), receipt.get('run_id')) == (ACCOUNT, REGION, RUN), 'Evidence receipt scope differs')
    reviewed = dt.datetime.fromisoformat(receipt.get('verified_at_utc', '').replace('Z', '+00:00'))
    require(reviewed.tzinfo is not None and reviewed.utcoffset() == dt.timedelta(0) and (dt.timedelta(seconds=-60) <= dt.datetime.now(dt.timezone.utc) - reviewed <= dt.timedelta(hours=24)), 'Evidence review must be recent and explicitly UTC')
    require(all((receipt.get('gates', {}).get(k) is True for k in ('G6', 'T07', 'T08', 'repeat'))), 'Final test gates are not all confirmed')
    require(all((receipt.get('captures', {}).get(k) is True for k in ('slot', 'disk', 'state', 'no_active_tests', 'source_frozen_after_target_release', 'target_exclusive_commit', 'diffs', 'negative_block', 'replay_ledger'))), 'Final source/cutover capture is incomplete')
    markers = receipt.get('cutover_markers', [])
    require(isinstance(markers, list) and len(markers) >= 2 and all((isinstance(m, (str, int)) and (not isinstance(m, bool)) and str(m).strip() for m in markers)) and (len({str(m).strip() for m in markers}) == len(markers)), 'Two distinct scalar cutover markers are required')
    files = receipt.get('files', [])
    require(bool(files), 'Evidence receipt must bind preserved files')
    require({'final-inspect', 'target-commit', 'diffs', 'negative-block', 'replay-ledger'} <= {f.get('kind') for f in files}, 'Evidence file roles are incomplete')
    from aws_context import CONTEXT_PATH
    evidence_root_value = CONFIG.get('preserved_evidence_root')
    require(isinstance(evidence_root_value, str) and bool(evidence_root_value.strip()), 'Set preserved_evidence_root explicitly before cleanup')
    evidence_root = Path(evidence_root_value)
    if not evidence_root.is_absolute():
        evidence_root = CONTEXT_PATH.parent / evidence_root
    evidence_root = evidence_root.resolve(strict=True)
    require(evidence_root.is_dir(), 'Preserved evidence root is not a directory')
    for item in files:
        file_path = Path(item['path'])
        if not file_path.is_absolute():
            file_path = evidence_root / file_path
        file_path = file_path.resolve(strict=True)
        require(file_path.is_relative_to(evidence_root) and file_path.is_file() and (file_path.stat().st_size > 0), 'Evidence file is outside the explicit evidence root or empty')
        payload = file_path.read_bytes()
        require(hashlib.sha256(payload).hexdigest() == item['sha256'], 'Preserved evidence hash mismatch')
        if file_path.suffix.lower() == '.json':
            json.loads(payload.decode('utf-8-sig'))
        elif file_path.suffix.lower() == '.jsonl':
            for line in payload.decode('utf-8-sig').splitlines():
                if line.strip():
                    json.loads(line)
    return reviewed

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--step', choices=STEPS, default='probe')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--baseline', default=str(ROOT / 'verification' / 'before-teardown-v2-sqs.json'))
    parser.add_argument('--journal', default=str(ROOT / 'evidence' / 'cleanup-journal.jsonl'))
    parser.add_argument('--evidence-receipt')
    args = parser.parse_args()
    try:
        require(all((MAIN, MIGRATION, GUARD, VPC, SOURCE, REPLICATION, TASK, CERT, DMS_LOG, TEARDOWN_ROLE)), 'Exact cleanup bindings are incomplete')
        require(not args.execute or args.step != 'probe', 'Probe is always read-only')
        reviewed = verify_evidence_receipt(args.evidence_receipt) if args.execute else None
        from aws_context import client, identity
        actor = identity()
        require(actor['Account'] == ACCOUNT and actor['Region'] == REGION, 'Wrong live account or region')
        cleanup = Cleanup(args.baseline, args.journal, client)
        cleanup.evidence_verified_at = reviewed
        result, code = cleanup.run(args.step, args.execute)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return code
    except (Blocked, ClientError, BotoCoreError, OSError, ValueError, KeyError) as error:
        print(json.dumps({'state': 'blocked_or_unknown', 'step': args.step, 'error_type': type(error).__name__, 'error_code': error_code(error) if isinstance(error, ClientError) else None, 'detail': str(error) if isinstance(error, (Blocked, OSError, ValueError, KeyError)) else 'AWS failure; inspect journal and re-read the same step before proceeding'}, ensure_ascii=False), file=sys.stderr)
        return 2
if __name__ == '__main__':
    sys.exit(main())
