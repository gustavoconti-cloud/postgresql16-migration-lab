"""Build the disposable PostgreSQL migration lab CloudFormation template.

No AWS calls. Deterministic UTF-8 output, atomic replacement, exit 0 on success.
Generated credentials remain exclusively in Secrets Manager.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import json
import os
from pathlib import Path
HERE = Path(__file__).resolve().parent

def ref(name):
    return {'Ref': name}

def sub(value):
    return {'Fn::Sub': value}

def att(resource, field):
    return {'Fn::GetAtt': [resource, field]}

def tags(name=None):
    result = [{'Key': 'Environment', 'Value': 'HML'}, {'Key': 'Project', 'Value': 'postgresql-migration-lab'}, {'Key': 'Owner', 'Value': CONFIG.get('owner', '')}, {'Key': 'ManagedBy', 'Value': CONFIG.get('managed_by', 'migration-lab-toolkit')}, {'Key': 'RunId', 'Value': ref('RunId')}, {'Key': 'ExpiresAt', 'Value': ref('ExpiresAt')}]
    if name:
        result.append({'Key': 'Name', 'Value': sub('${Prefix}-' + name)})
    return result
resources = {}

def resource(name, kind, properties, *, depends=None, disposable=False):
    entry = {'Type': kind, 'Properties': properties}
    if depends:
        entry['DependsOn'] = depends
    if disposable:
        entry['DeletionPolicy'] = 'Delete'
        entry['UpdateReplacePolicy'] = 'Delete'
    resources[name] = entry
resource('Vpc', 'AWS::EC2::VPC', {'CidrBlock': '10.87.0.0/16', 'EnableDnsSupport': True, 'EnableDnsHostnames': True, 'InstanceTenancy': 'default', 'Tags': tags('vpc')})
resource('InternetGateway', 'AWS::EC2::InternetGateway', {'Tags': tags('igw')})
resource('GatewayAttachment', 'AWS::EC2::VPCGatewayAttachment', {'VpcId': ref('Vpc'), 'InternetGatewayId': ref('InternetGateway')})
for name, cidr, az, public in (('PublicSubnetA', '10.87.0.0/24', 'AvailabilityZoneA', True), ('PrivateSubnetA', '10.87.10.0/24', 'AvailabilityZoneA', False), ('PrivateSubnetB', '10.87.20.0/24', 'AvailabilityZoneB', False)):
    resource(name, 'AWS::EC2::Subnet', {'VpcId': ref('Vpc'), 'CidrBlock': cidr, 'AvailabilityZone': ref(az), 'MapPublicIpOnLaunch': False, 'Tags': tags(name.lower())})
resource('PublicRouteTable', 'AWS::EC2::RouteTable', {'VpcId': ref('Vpc'), 'Tags': tags('public-rt')})
resource('PublicDefaultRoute', 'AWS::EC2::Route', {'RouteTableId': ref('PublicRouteTable'), 'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': ref('InternetGateway')}, depends='GatewayAttachment')
resource('PublicRouteAssociation', 'AWS::EC2::SubnetRouteTableAssociation', {'RouteTableId': ref('PublicRouteTable'), 'SubnetId': ref('PublicSubnetA')})
resource('NatElasticIp', 'AWS::EC2::EIP', {'Domain': 'vpc', 'Tags': tags('nat-eip')}, depends='GatewayAttachment')
resource('NatGateway', 'AWS::EC2::NatGateway', {'AllocationId': att('NatElasticIp', 'AllocationId'), 'SubnetId': ref('PublicSubnetA'), 'ConnectivityType': 'public', 'Tags': tags('nat')}, depends=['PublicDefaultRoute', 'PublicRouteAssociation'])
resource('PrivateRouteTable', 'AWS::EC2::RouteTable', {'VpcId': ref('Vpc'), 'Tags': tags('private-rt')})
resource('PrivateDefaultRoute', 'AWS::EC2::Route', {'RouteTableId': ref('PrivateRouteTable'), 'DestinationCidrBlock': '0.0.0.0/0', 'NatGatewayId': ref('NatGateway')})
for suffix in ('A', 'B'):
    resource('PrivateRouteAssociation' + suffix, 'AWS::EC2::SubnetRouteTableAssociation', {'RouteTableId': ref('PrivateRouteTable'), 'SubnetId': ref('PrivateSubnet' + suffix)})
for name, purpose in (('SourceSecurityGroup', 'Private PostgreSQL source; no inbound administration'), ('DmsSecurityGroup', 'Private DMS; database connections and regional HTTPS'), ('TargetSecurityGroup', 'Private RDS; DMS and source workstation only'), ('SecretsEndpointSecurityGroup', 'Secrets Manager HTTPS from laboratory source and DMS only')):
    egress = [{'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'CidrIp': '0.0.0.0/0', 'Description': 'Regional AWS HTTPS and official package repositories'}]
    if name in ('TargetSecurityGroup', 'SecretsEndpointSecurityGroup'):
        egress = [{'IpProtocol': '-1', 'CidrIp': '10.87.0.0/16', 'Description': 'VPC-only egress; stateful replies do not require outbound rules'}]
    resource(name, 'AWS::EC2::SecurityGroup', {'VpcId': ref('Vpc'), 'GroupDescription': purpose, 'SecurityGroupEgress': egress, 'Tags': tags(name.lower())})
for name, group, source_group, port in (('SourcePostgresIngress', 'SourceSecurityGroup', 'DmsSecurityGroup', 5432), ('TargetDmsIngress', 'TargetSecurityGroup', 'DmsSecurityGroup', 5432), ('TargetWorkstationIngress', 'TargetSecurityGroup', 'SourceSecurityGroup', 5432), ('SecretsSourceIngress', 'SecretsEndpointSecurityGroup', 'SourceSecurityGroup', 443), ('SecretsDmsIngress', 'SecretsEndpointSecurityGroup', 'DmsSecurityGroup', 443)):
    resource(name, 'AWS::EC2::SecurityGroupIngress', {'GroupId': ref(group), 'IpProtocol': 'tcp', 'FromPort': port, 'ToPort': port, 'SourceSecurityGroupId': ref(source_group), 'Description': 'Exclusive migration lab path'})
for name, group, destination in (('DmsSourceEgress', 'DmsSecurityGroup', 'SourceSecurityGroup'), ('DmsTargetEgress', 'DmsSecurityGroup', 'TargetSecurityGroup'), ('SourceTargetEgress', 'SourceSecurityGroup', 'TargetSecurityGroup')):
    resource(name, 'AWS::EC2::SecurityGroupEgress', {'GroupId': ref(group), 'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'DestinationSecurityGroupId': ref(destination), 'Description': 'Exclusive migration lab PostgreSQL'})
resource('SecretsManagerEndpoint', 'AWS::EC2::VPCEndpoint', {'VpcId': ref('Vpc'), 'VpcEndpointType': 'Interface', 'ServiceName': sub('com.amazonaws.${AWS::Region}.secretsmanager'), 'PrivateDnsEnabled': True, 'SubnetIds': [ref('PrivateSubnetA')], 'SecurityGroupIds': [ref('SecretsEndpointSecurityGroup')], 'Tags': tags('secrets-endpoint')})
service_trust = lambda service: {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': service}, 'Action': 'sts:AssumeRole'}]}
resource('SourceRole', 'AWS::IAM::Role', {'Description': 'Disposable lab source SSM instance role; no administrative AWS policy', 'AssumeRolePolicyDocument': service_trust('ec2.amazonaws.com'), 'ManagedPolicyArns': [sub('arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore')], 'Policies': [{'PolicyName': 'ReadLabDmsStatus', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['dms:DescribeReplicationTasks', 'dms:DescribeTableStatistics'], 'Resource': '*', 'Condition': {'StringEquals': {'aws:RequestedRegion': ref('AWS::Region')}}}]}}], 'Tags': tags('source-role')})
resource('SourceInstanceProfile', 'AWS::IAM::InstanceProfile', {'Roles': [ref('SourceRole')]})
if '--help' in sys.argv or '-h' in sys.argv:
    print('Local template builder. Set PG_LAB_CONTEXT to config.json; then run without arguments. AWS calls: 0. Shared DMS role creation is explicitly configured.')
    raise SystemExit(0)
load_context()
bootstrap = "#!/bin/bash\nset -Eeuo pipefail\numask 027\nexec > >(tee -a /var/log/postgresql-migration-bootstrap.log) 2>&1\nexport DEBIAN_FRONTEND=noninteractive\ninstall -d -m 0750 /var/lib/postgresql-migration-lab\nif [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then\n  sed -i -E 's|http://[a-z0-9.-]*ec2.archive.ubuntu.com/ubuntu/?|https://archive.ubuntu.com/ubuntu/|g; s|http://archive.ubuntu.com/ubuntu/?|https://archive.ubuntu.com/ubuntu/|g; s|http://security.ubuntu.com/ubuntu/?|https://security.ubuntu.com/ubuntu/|g' /etc/apt/sources.list.d/ubuntu.sources\nfi\ntimeout 600 apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=4 -o Acquire::https::Timeout=30 -o APT::Update::Error-Mode=any update\ntimeout 900 apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=4 -o Acquire::https::Timeout=30 install -y --no-install-recommends postgresql-16 postgresql-client-16 postgresql-contrib python3-boto3 python3-psycopg2 python3-venv ca-certificates curl jq\ntest -f /usr/lib/postgresql/16/lib/test_decoding.so\nif systemctl list-unit-files snap.amazon-ssm-agent.amazon-ssm-agent.service --no-legend | grep -q amazon-ssm-agent; then\n  systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service\nelse\n  systemctl enable --now amazon-ssm-agent.service\nfi\nsystemctl enable --now postgresql\ncurl --fail --silent --show-error --retry 3 --max-time 90 https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem -o /var/lib/postgresql-migration-lab/us-east-1-bundle.pem\nchmod 0644 /var/lib/postgresql-migration-lab/us-east-1-bundle.pem\n/usr/bin/python3 - <<'PY'\nimport json, platform, subprocess\nfrom datetime import datetime, timezone\nfrom pathlib import Path\npayload = {\n    'ready_at_utc': datetime.now(timezone.utc).isoformat(),\n    'kernel': platform.release(),\n    'psql': subprocess.check_output(['psql', '--version'], text=True).strip(),\n    'python': platform.python_version(),\n    'test_decoding_present': Path('/usr/lib/postgresql/16/lib/test_decoding.so').is_file(),\n}\nPath('/var/lib/postgresql-migration-lab/bootstrap.ready.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')\nprint(json.dumps(payload))\nPY\n"
resource('SourceInstance', 'AWS::EC2::Instance', {'ImageId': ref('UbuntuImageParameter'), 'InstanceType': 't3.small', 'IamInstanceProfile': ref('SourceInstanceProfile'), 'NetworkInterfaces': [{'DeviceIndex': '0', 'AssociatePublicIpAddress': False, 'SubnetId': ref('PrivateSubnetA'), 'GroupSet': [ref('SourceSecurityGroup')], 'DeleteOnTermination': True}], 'MetadataOptions': {'HttpTokens': 'required', 'HttpEndpoint': 'enabled', 'HttpPutResponseHopLimit': 1}, 'CreditSpecification': {'CPUCredits': 'standard'}, 'BlockDeviceMappings': [{'DeviceName': '/dev/sda1', 'Ebs': {'VolumeSize': 20, 'VolumeType': 'gp3', 'Encrypted': True, 'DeleteOnTermination': True}}], 'PropagateTagsToVolumeOnCreation': True, 'DisableApiTermination': False, 'Monitoring': False, 'UserData': {'Fn::Base64': bootstrap}, 'Tags': tags('source')}, depends=['PrivateDefaultRoute', 'PrivateRouteAssociationA', 'SourceTargetEgress'], disposable=True)
resource('DbSubnetGroup', 'AWS::RDS::DBSubnetGroup', {'DBSubnetGroupDescription': 'Dedicated migration lab private subnets in two AZs', 'SubnetIds': [ref('PrivateSubnetA'), ref('PrivateSubnetB')], 'Tags': tags('db-subnets')})
resource('DbParameterGroup', 'AWS::RDS::DBParameterGroup', {'Description': 'Dedicated PostgreSQL16 target TLS enforcement; logical replication is not enabled', 'Family': 'postgres16', 'Parameters': {'rds.force_ssl': '1', 'password_encryption': 'scram-sha-256'}, 'Tags': tags('db-params')})
resource('TargetDatabase', 'AWS::RDS::DBInstance', {'DBInstanceIdentifier': sub('${Prefix}-target'), 'Engine': 'postgres', 'EngineVersion': '16.15', 'DBInstanceClass': 'db.t4g.small', 'AllocatedStorage': '20', 'StorageType': 'gp3', 'StorageEncrypted': True, 'DBName': 'migration_lab', 'MasterUsername': 'lab_admin', 'ManageMasterUserPassword': True, 'AvailabilityZone': ref('AvailabilityZoneA'), 'DBSubnetGroupName': ref('DbSubnetGroup'), 'DBParameterGroupName': ref('DbParameterGroup'), 'VPCSecurityGroups': [ref('TargetSecurityGroup')], 'Port': '5432', 'MultiAZ': False, 'PubliclyAccessible': False, 'NetworkType': 'IPV4', 'BackupRetentionPeriod': 0, 'DeleteAutomatedBackups': True, 'DeletionProtection': False, 'CopyTagsToSnapshot': True, 'AutoMinorVersionUpgrade': False, 'AllowMajorVersionUpgrade': False, 'MonitoringInterval': 0, 'EnablePerformanceInsights': False, 'EnableIAMDatabaseAuthentication': False, 'Tags': tags('target')}, depends=['TargetDmsIngress', 'TargetWorkstationIngress'], disposable=True)
for name, role_name, policy in (('DmsVpcRole', 'dms-vpc-role', 'AmazonDMSVPCManagementRole'), ('DmsCloudWatchRole', 'dms-cloudwatch-logs-role', 'AmazonDMSCloudWatchLogsRole')):
    resource(name, 'AWS::IAM::Role', {'RoleName': role_name, 'Description': 'Created exclusively for the disposable migration lab; confirm absent before deployment', 'AssumeRolePolicyDocument': service_trust('dms.amazonaws.com'), 'ManagedPolicyArns': [sub('arn:${AWS::Partition}:iam::aws:policy/service-role/' + policy)], 'Tags': tags(role_name)})
resource('DmsSubnetGroup', 'AWS::DMS::ReplicationSubnetGroup', {'ReplicationSubnetGroupDescription': 'Dedicated migration lab private subnets in two AZs', 'SubnetIds': [ref('PrivateSubnetA'), ref('PrivateSubnetB')], 'Tags': tags('dms-subnets')}, depends='DmsVpcRole')
resource('ReplicationInstance', 'AWS::DMS::ReplicationInstance', {'ReplicationInstanceIdentifier': sub('${Prefix}-dms'), 'ReplicationInstanceClass': 'dms.t3.medium', 'EngineVersion': '3.6.1', 'AllocatedStorage': 50, 'AvailabilityZone': ref('AvailabilityZoneA'), 'ReplicationSubnetGroupIdentifier': ref('DmsSubnetGroup'), 'VpcSecurityGroupIds': [ref('DmsSecurityGroup')], 'MultiAZ': False, 'PubliclyAccessible': False, 'NetworkType': 'IPV4', 'AutoMinorVersionUpgrade': False, 'AllowMajorVersionUpgrade': False, 'Tags': tags('dms')}, depends=['DmsVpcRole', 'DmsCloudWatchRole', 'PrivateDefaultRoute', 'PrivateRouteAssociationA', 'DmsSourceEgress', 'DmsTargetEgress', 'SecretsManagerEndpoint'], disposable=True)
for name, username, host, suffix in (('SourceCredential', 'dms_source', '${SourceInstance.PrivateIp}', 'dms-source'), ('TargetCredential', 'dms_target', '${TargetDatabase.Endpoint.Address}', 'dms-target')):
    resource(name, 'AWS::SecretsManager::Secret', {'Description': 'Exclusive synthetic migration lab credential; never export SecretString', 'GenerateSecretString': {'SecretStringTemplate': sub(json.dumps({'host': host, 'port': 5432, 'dbname': 'migration_lab', 'username': username}, separators=(',', ':'))), 'GenerateStringKey': 'password', 'PasswordLength': 32, 'ExcludePunctuation': True, 'IncludeSpace': False, 'RequireEachIncludedType': True}, 'Tags': tags(suffix)}, disposable=True)
resource('ClientCredential', 'AWS::SecretsManager::Secret', {'Description': 'Shared password only for separate restricted lab writer/reader database logins; never an administrator password', 'GenerateSecretString': {'SecretStringTemplate': json.dumps({'dbname': 'migration_lab', 'purpose': 'lab-writers-and-readers'}, separators=(',', ':')), 'GenerateStringKey': 'password', 'PasswordLength': 32, 'ExcludePunctuation': True, 'IncludeSpace': False, 'RequireEachIncludedType': True}, 'Tags': tags('clients')}, disposable=True)
resource('SourceSecretPolicy', 'AWS::IAM::Policy', {'PolicyName': 'ReadOnlyExclusiveLabSecrets', 'Roles': [ref('SourceRole')], 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'Resource': [ref('SourceCredential'), ref('TargetCredential'), ref('ClientCredential'), att('TargetDatabase', 'MasterUserSecret.SecretArn')], 'Condition': {'StringEquals': {'aws:RequestedRegion': ref('AWS::Region')}}}]}})
resource('DmsSecretAccessRole', 'AWS::IAM::Role', {'Description': 'DMS endpoint access to the two exclusive synthetic credentials only', 'AssumeRolePolicyDocument': service_trust(sub('dms.${AWS::Region}.amazonaws.com')), 'Policies': [{'PolicyName': 'ReadOnlyLabEndpointSecrets', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'Resource': [ref('SourceCredential'), ref('TargetCredential')]}]}}], 'Tags': tags('dms-secret-role')})
outputs = {}

def output(name, value, description):
    outputs[name] = {'Value': value, 'Description': description}
for name, logical, description in (('VpcId', 'Vpc', 'Dedicated lab VPC identifier'), ('PrivateSubnetAId', 'PrivateSubnetA', 'Workload subnet in primary AZ'), ('PrivateSubnetBId', 'PrivateSubnetB', 'Secondary private subnet for subnet groups'), ('PublicSubnetAId', 'PublicSubnetA', 'Public subnet containing only temporary NAT'), ('NatGatewayId', 'NatGateway', 'Temporary NAT to delete at teardown'), ('SourceInstanceId', 'SourceInstance', 'Private EC2 source and workstation via SSM'), ('TargetDbIdentifier', 'TargetDatabase', 'Private disposable RDS target identifier'), ('ReplicationInstanceArn', 'ReplicationInstance', 'Private provisioned DMS replication instance ARN'), ('SourceSecurityGroupId', 'SourceSecurityGroup', 'Only DMS may enter source PostgreSQL TCP5432'), ('TargetSecurityGroupId', 'TargetSecurityGroup', 'DMS and source may enter target PostgreSQL TCP5432'), ('DmsSecurityGroupId', 'DmsSecurityGroup', 'DMS connections to exclusive lab databases'), ('SecretsManagerEndpointId', 'SecretsManagerEndpoint', 'Private Secrets Manager interface endpoint'), ('SourceSecretArn', 'SourceCredential', 'Credential ARN only; do not export its value'), ('TargetSecretArn', 'TargetCredential', 'Credential ARN only; do not export its value'), ('ClientSecretArn', 'ClientCredential', 'Restricted lab writer/reader credential ARN only')):
    output(name, ref(logical), description)
output('SourcePrivateIp', att('SourceInstance', 'PrivateIp'), 'Private source host; configure HBA with real DMS address separately')
output('TargetEndpoint', att('TargetDatabase', 'Endpoint.Address'), 'Use DNS and TLS verify-full for the RDS target')
output('MasterSecretArn', att('TargetDatabase', 'MasterUserSecret.SecretArn'), 'RDS managed administrator credential ARN only')
output('DmsPrivateIpAddresses', att('ReplicationInstance', 'ReplicationInstancePrivateIpAddresses'), 'DMS private IPs; use real addresses for source HBA')
output('DmsSecretAccessRoleArn', att('DmsSecretAccessRole', 'Arn'), 'Regional DMS service role reads the source and target credential only')
output('SecretsManagerEndpointOverride', {'Fn::Select': [1, {'Fn::Split': [':', {'Fn::Select': [0, att('SecretsManagerEndpoint', 'DnsEntries')]}]}]}, 'Interface endpoint regional DNS hostname; use in DMS secretsManagerEndpointOverride')
output('NatElasticIpAllocationId', att('NatElasticIp', 'AllocationId'), 'Allocation must be released by CloudFormation during teardown')
output('ExpiresAtUtc', ref('ExpiresAt'), 'Tags are metadata only; operational guardrail must enforce this deadline')
output('RunIdentifier', ref('RunId'), 'Execution lineage identifier')
output('SourceRoleArn', att('SourceRole', 'Arn'), 'Exact EC2 runtime role ARN')
output('SourceRoleName', ref('SourceRole'), 'Exact EC2 runtime role name')
output('ReplicationInstanceIdentifier', sub('${Prefix}-dms'), 'Real replication instance identifier')
template = {'AWSTemplateFormatVersion': '2010-09-09', 'Description': 'Disposable PostgreSQL16 EC2 to private RDS16 migration lab via provisioned AWS DMS, POC/HML Virginia only. Synthetic data; explicit operator authorization required before creation or deletion.', 'Metadata': {'ExecutionContract': {'ExpectedAccountId': ACCOUNT, 'ExpectedRegion': 'us-east-1', 'Profile': PROFILE, 'MaximumHours': 72, 'MaximumIncrementalUsd': 1000, 'OperatingEnvelopeUsd': 100, 'Writer': 'authorized-operator', 'ExternalDmsResources': 'Endpoints, certificates and task are created later and must be removed before deleting stack', 'SharedRolePrerequisite': 'dms-vpc-role and dms-cloudwatch-logs-role must both be absent immediately before this stack creates them', 'Secrets': 'No SecretString retrieval in evidence or context; runtime references only'}}, 'Parameters': {'Prefix': {'Type': 'String', 'Default': STACK, 'AllowedPattern': '[a-z][a-z0-9]*(?:-[a-z0-9]+)*', 'MinLength': 3, 'MaxLength': 32, 'Description': 'Exclusive lab resource prefix; no trailing hyphen or consecutive hyphens'}, 'RunId': {'Type': 'String', 'Default': RUN, 'AllowedPattern': '[a-zA-Z0-9-]{3,64}', 'Description': 'Execution ID applied to all taggable resources'}, 'ExpiresAt': {'Type': 'String', 'AllowedPattern': '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', 'Description': 'Absolute UTC deadline; set no later than72h after creation; independent guardrail required'}, 'AvailabilityZoneA': {'Type': 'AWS::EC2::AvailabilityZone::Name', 'Default': 'us-east-1a', 'Description': 'Primary Virginia AZ; preflight verify all chosen classes'}, 'AvailabilityZoneB': {'Type': 'AWS::EC2::AvailabilityZone::Name', 'Default': 'us-east-1b', 'Description': 'Different Virginia AZ for subnet-group coverage only'}, 'UbuntuImageParameter': {'Type': 'AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>', 'Default': '/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id', 'Description': 'Official Canonical Ubuntu24.04 LTS amd64 AMI; preflight verify owner099720109477 and record resolved AMI'}}, 'Rules': {'DistinctAvailabilityZones': {'Assertions': [{'Assert': {'Fn::Not': [{'Fn::Equals': [ref('AvailabilityZoneA'), ref('AvailabilityZoneB')]}]}, 'AssertDescription': 'The two private subnets must use distinct Availability Zones'}]}}, 'Resources': resources, 'Outputs': outputs}
template['Parameters']['AvailabilityZoneA']['Default'] = CONFIG.get('provisioning', {}).get('availability_zone_a', 'us-east-1a')
template['Parameters']['AvailabilityZoneB']['Default'] = CONFIG.get('provisioning', {}).get('availability_zone_b', 'us-east-1b')
template['Parameters']['UbuntuImageParameter']['Default'] = CONFIG.get('provisioning', {}).get('ubuntu_image_parameter', template['Parameters']['UbuntuImageParameter']['Default'])
template['Parameters']['ExpiresAt']['Default'] = CONFIG['expires_at']
for logical, key in (('DmsVpcRole', 'create_dms_vpc_role'), ('DmsCloudWatchRole', 'create_dms_logs_role')):
    if CONFIG.get('provisioning', {}).get(key, True) is False:
        del resources[logical]
        for entry in resources.values():
            dependencies = entry.get('DependsOn', [])
            dependencies = [dependencies] if isinstance(dependencies, str) else dependencies
            dependencies = [item for item in dependencies if item != logical]
            if dependencies:
                entry['DependsOn'] = dependencies
            else:
                entry.pop('DependsOn', None)
text = json.dumps(template, indent=1, ensure_ascii=False) + '\n'
target = HERE / 'postgres-migration-lab.template.json'
temporary = HERE / 'postgres-migration-lab.template.json.tmp'
temporary.write_text(text, encoding='utf-8', newline='\n')
os.replace(temporary, target)
(HERE / 'bootstrap-source.sh').write_text(bootstrap, encoding='utf-8', newline='\n')
print(json.dumps({'path': str(target), 'resources': len(resources), 'outputs': len(outputs), 'bytes': len(text.encode('utf-8'))}))
