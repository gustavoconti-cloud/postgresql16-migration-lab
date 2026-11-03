"""Offline-only reproduction QA. Every test uses synthetic identifiers.

No credentials are read, AWS is never contacted, and socket connections are
blocked in child Python programs. Generated snapshots remain under qa/.
"""
import ast
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import gzip
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

REPRO = Path(__file__).resolve().parents[1]
SCRIPTS = REPRO / 'scripts'
QA = REPRO / 'qa'
SPEC = importlib.util.spec_from_file_location('reproduction_context', SCRIPTS / 'control/aws_context.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


def fixture(account='111122223333', prefix='fixture-lab'):
    cfg = json.loads((REPRO / 'config.example.json').read_text(encoding='utf-8'))
    cfg.update(profile='fixture-profile', expected_account_id=account, prefix=prefix,
               resource_run_id='fixture-resource-run', run_id='fixture-r01',
               evidence_run_ids=['fixture-r01', 'fixture-r02'], owner='fixture-owner',
               expires_at=(datetime.now(timezone.utc) + timedelta(hours=48)).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
    cfg['bindings'].update(main_stack_arn=f'arn:aws:cloudformation:us-east-1:{account}:stack/{prefix}/00000000-0000-0000-0000-000000000001',
       replication_instance_identifier=prefix + '-dms', log_group_name='dms-tasks-' + prefix + '-dms')
    return cfg


def run_offline(script, arguments, config, cwd=None, timeout=55):
    environment = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
    environment.update(PG_LAB_CONTEXT=str(config), AWS_EC2_METADATA_DISABLED='true',
                       PYTHONDONTWRITEBYTECODE='1', AWS_DEFAULT_REGION='us-east-1')
    # Build/runtime imports can construct SDK clients; every attempted network
    # connection is forbidden even if a test misses a mock.
    guard = "import socket,runpy,sys;defn='def blocked(*a,**k): raise RuntimeError(\"OFFLINE_QA_NETWORK_REFUSED\")';exec(defn);socket.create_connection=blocked;socket.socket.connect=blocked;sys.argv=[sys.argv[1],*sys.argv[2:]];runpy.run_path(sys.argv[0],run_name='__main__')"
    return subprocess.run([sys.executable, '-B', '-c', guard, str(script), *arguments],
                          cwd=cwd or script.parent, env=environment, text=True,
                          capture_output=True, timeout=timeout)


def cleanup_fixture():
    cfg = fixture()
    stacks = []
    checks = []
    for index, (suffix, key) in enumerate((('', 'main_stack_arn'), ('-migration', 'migration_stack_arn'),
                                          ('-guardrail', 'guardrail_stack_arn')), 1):
        name = cfg['prefix'] + suffix
        arn = f"arn:aws:cloudformation:us-east-1:{cfg['expected_account_id']}:stack/{name}/00000000-0000-0000-0000-00000000000{index}"
        cfg['bindings'][key] = arn
        stacks.append({'name': name, 'arn': arn, 'status': 'CREATE_COMPLETE',
                       'tags': [{'Key': k, 'Value': v} for k, v in
                                {'Environment': 'HML', 'Project': cfg['project'], 'RunId': cfg['resource_run_id']}.items()],
                       'resources': [{'LogicalResourceId': 'FixtureResource', 'PhysicalResourceId': name + '-fixture',
                                      'ResourceType': 'AWS::IAM::Role'}]})
        checks.extend({'label': kind + name, 'status': 'absent', 'live_count': 0}
                      for kind in ('stack:', 'stack-resources:'))
    receipt = {'mode': 'final', 'cleanup_verified': True, 'coverage_errors': [], 'residuals': [],
               'baseline_incomplete': False, 'identity': {'Account': cfg['expected_account_id'], 'Region': cfg['region']},
               'manifest': {'account': cfg['expected_account_id'], 'region': cfg['region'],
                            'run_id': cfg['resource_run_id'], 'stacks': stacks}, 'checks': checks}
    return cfg, receipt


class ContextTests(unittest.TestCase):
    def test_example_refuses_execution(self):
        with self.assertRaises(ValueError):
            C.validate_context(json.loads((REPRO / 'config.example.json').read_text()))

    def test_two_accounts_prefixes_and_separate_ledger(self):
        for account, prefix in [('111122223333', 'fixture-lab'), ('444455556666', 'other-fixture')]:
            cfg = fixture(account, prefix)
            cfg['run_id'] = 'fixture-r02'
            self.assertEqual(C.validate_context(cfg)['resource_run_id'], 'fixture-resource-run')
            self.assertEqual(cfg['run_id'], 'fixture-r02')

    def test_invalid_region_foreign_arn_expired_and_excess_budget_refused(self):
        for key, value in [('region', 'us-west-2'), ('expires_at', '2000-01-01T00:00:00Z'), ('maximum_incremental_usd', 1001)]:
            cfg = fixture(); cfg[key] = value
            with self.assertRaises(ValueError):
                C.validate_context(cfg)
        cfg = fixture(); cfg['bindings']['main_stack_arn'] = cfg['bindings']['main_stack_arn'].replace('111122223333', '444455556666')
        with self.assertRaises(ValueError):
            C.validate_context(cfg)

    def test_secret_field_and_value_refused(self):
        for key in ('password', 'SecretString', 'AWS_SECRET_ACCESS_KEY'):
            cfg = fixture(); cfg[key] = 'synthetic-sentinel'
            with self.assertRaises(ValueError):
                C.validate_context(cfg)

    def test_identity_checks_real_response_and_refuses_root(self):
        with patch.object(C, 'load_context', return_value=fixture()), patch.object(C, 'ACCOUNT', '111122223333'):
            for arn, account in [('arn:aws:iam::111122223333:root', '111122223333'), ('arn:aws:iam::444455556666:user/fixture', '444455556666')]:
                fake = type('Fake', (), {'get_caller_identity': lambda self: {'Account': account, 'Arn': arn}})()
                with patch.object(C, 'client', return_value=fake), self.assertRaises(ValueError):
                    C.identity()

    def test_saved_stack_binding_refuses_wrong_tags_and_preserves_scope(self):
        cfg = fixture()
        saved = {'Stacks': [{'StackId': cfg['bindings']['main_stack_arn'], 'StackStatus': 'CREATE_COMPLETE',
            'Tags': [{'Key': k, 'Value': v} for k, v in {'Environment': 'HML', 'Project': 'postgresql-migration-lab', 'RunId': cfg['resource_run_id']}.items()],
            'Outputs': [{'OutputKey': k, 'OutputValue': v} for k, v in {'RunIdentifier': cfg['resource_run_id'], 'ExpiresAtUtc': cfg['expires_at'], 'SourceRoleArn': 'arn:aws:iam::111122223333:role/fixture-source', 'ReplicationInstanceIdentifier': 'fixture-lab-dms'}.items()]}]}
        path = QA / 'fixture-stack.json'; path.write_text(json.dumps(saved), encoding='utf-8')
        result = C.bind_saved(cfg, 'main', path)
        self.assertEqual(result['bindings']['source_role_name'], 'fixture-source')
        self.assertEqual(result['resource_run_id'], cfg['resource_run_id'])
        saved['Stacks'][0]['Tags'][2]['Value'] = 'foreign-run'
        path.write_text(json.dumps(saved), encoding='utf-8')
        with self.assertRaises(ValueError):
            C.bind_saved(cfg, 'main', path)


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = QA / 'fixture-context.json'
        cls.config.write_text(json.dumps(fixture(), indent=2), encoding='utf-8')

    def test_python_sources_compile_without_import(self):
        for source in SCRIPTS.rglob('*.py'):
            compile(source.read_text(encoding='utf-8'), source.name, 'exec')

    def test_helpers_import_offline(self):
        for relative in ['control/aws_context.py', 'control/dms_runtime.py', 'control/ssm_runtime.py', 'control/make_g6_proof.py', 'control/collect_dms_logs.py', 'control/cleanup_lab.py', 'verification/verify_cleanup.py', 'verification/verify_tags.py', 'verification/apply_required_tags.py', 'verification/estimate_runtime_cost.py']:
            source = SCRIPTS / relative
            code = "import socket,importlib.util,sys;exec('def blocked(*a,**k): raise RuntimeError(\"OFFLINE_QA_NETWORK_REFUSED\")');socket.socket.connect=blocked;sys.path.insert(0,sys.argv[2]);s=importlib.util.spec_from_file_location('offline_module',sys.argv[1]);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)"
            env = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
            env.update(PG_LAB_CONTEXT=str(self.config), AWS_EC2_METADATA_DISABLED='true', PYTHONDONTWRITEBYTECODE='1')
            result = subprocess.run([sys.executable, '-B', '-c', code, str(source), str(source.parent)], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, relative + ': ' + result.stderr)

    def test_controller_help_does_not_call_aws(self):
        for relative in ['control/aws_context.py', 'control/stage_actions.py', 'control/run_stage.py', 'control/ssm_runtime.py', 'control/read_stage.py', 'control/dms_runtime.py', 'control/run_with_secrets.py', 'control/make_g6_proof.py', 'control/collect_dms_logs.py', 'control/export_evidence.py', 'control/cleanup_lab.py', 'migration/build_migration.py', 'guardrails/build_guardrail.py', 'guardrails/tighten_policy.py', 'verification/verify_cleanup.py', 'verification/verify_tags.py', 'verification/apply_required_tags.py', 'verification/estimate_runtime_cost.py', 'infra/build_template.py']:
            result = run_offline(SCRIPTS / relative, ['--help'], self.config)
            self.assertEqual(result.returncode, 0, relative + ': ' + result.stderr)

    def test_runtime_install_is_draft_only_and_bounded(self):
        result = run_offline(SCRIPTS / 'control/stage_actions.py', ['fixture-install', '--install-runtime'], self.config)
        self.assertEqual(result.returncode, 0, result.stderr)
        path = SCRIPTS / 'control/fixture-install.sh'
        text = path.read_text(encoding='utf-8')
        self.assertLess(len(text.encode('utf-8')), 50000)
        encoded = re.search(r"base64\.b64decode\('([^']+)'\)", text).group(1)
        contents = json.loads(gzip.decompress(base64.b64decode(encoded)))
        self.assertIn('/opt/pg-lab/harness/asm-exec', contents)
        for name, source in contents.items():
            self.assertTrue(name.startswith('/opt/pg-lab/harness/'))
        self.assertNotIn('GetSecretValue', text)

    def test_g6_stage_preserves_bytes_and_rejects_foreign_run(self):
        cfg = fixture()
        cfg['bindings'].update(source_host='10.1.1.10', dms_private_ip='10.1.2.20',
            rds_endpoint='fixture.abcdefgh.us-east-1.rds.amazonaws.com', source_role_name='fixture-source',
            dms_task_arn='arn:aws:dms:us-east-1:111122223333:task:FIXTURETASK')
        for key in ('source_secret_arn', 'target_secret_arn', 'client_secret_arn', 'master_secret_arn'):
            cfg['bindings'][key] = 'arn:aws:secretsmanager:us-east-1:111122223333:secret:fixture-' + key
        self.config.write_text(json.dumps(cfg), encoding='utf-8')
        runtime = QA / 'fixture-runtime.json'
        runtime.write_text(json.dumps(C.runtime_config(cfg)), encoding='utf-8')
        proof = QA / 'fixture-r01-g6a-proof.json'
        original = (json.dumps({'run_id': cfg['run_id'], 'task_arn': cfg['bindings']['dms_task_arn']},
                               indent=2) + '\n').encode('utf-8')
        proof.write_bytes(original)
        actions = json.dumps([['record-g6', '--proof', '/opt/pg-lab/evidence/' + proof.name]])
        args = ['fixture-r01-proof', actions, '--config', str(runtime), '--proof', str(proof)]
        result = run_offline(SCRIPTS / 'control/stage_actions.py', args, self.config)
        self.assertEqual(result.returncode, 0, result.stderr)
        stage = (SCRIPTS / 'control/fixture-r01-proof.sh').read_text(encoding='utf-8')
        encoded = re.search(r"base64\.b64decode\('([^']+)'\)", stage).group(1)
        data = json.loads(base64.b64decode(encoded))
        self.assertEqual(data['proof']['name'], proof.name)
        self.assertEqual(base64.b64decode(data['proof']['base64']), original)
        self.assertNotIn(str(QA), stage)
        proof.write_text(json.dumps({'run_id': 'foreign-run', 'task_arn': cfg['bindings']['dms_task_arn']}), encoding='utf-8')
        result = run_offline(SCRIPTS / 'control/stage_actions.py', args, self.config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('G6 proof differs', result.stderr)
        self.config.write_text(json.dumps(fixture()), encoding='utf-8')

    def test_export_remote_source_is_self_contained(self):
        source = (SCRIPTS / 'control/export_evidence.py').read_text(encoding='utf-8')
        namespace = {'__name__': 'offline_remote_fixture', '__file__': '<stdin>'}
        with patch.dict(os.environ, {'PG_LAB_RUN_IDS': '["fixture-r01","fixture-r02"]'}):
            exec(compile(source, '<stdin>', 'exec'), namespace)
        self.assertEqual(namespace['STATE_PATHS'], ('state/fixture-r01.json', 'state/fixture-r02.json'))

    def test_cleanup_preserved_root_and_path_escape_are_checked(self):
        sys.path.insert(0, str(SCRIPTS / 'control'))
        spec = importlib.util.spec_from_file_location('cleanup_fixture', SCRIPTS / 'control/cleanup_lab.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        root = QA / 'fixture-preserved'; root.mkdir(exist_ok=True)
        payload = b'{"fixture":true}\n'; (root / 'proof.json').write_bytes(payload)
        receipt = json.loads((REPRO / 'cleanup-evidence-receipt.example.json').read_text())
        receipt.update(account='111122223333', run_id='fixture-resource-run',
                       verified_at_utc=datetime.now(timezone.utc).isoformat())
        receipt['gates'] = dict.fromkeys(receipt['gates'], True)
        receipt['captures'] = dict.fromkeys(receipt['captures'], True)
        for row in receipt['files']:
            row.update(path='proof.json', sha256=hashlib.sha256(payload).hexdigest())
        path = QA / 'fixture-cleanup-receipt.json'
        path.write_text(json.dumps(receipt), encoding='utf-8')
        with patch.object(module, 'ACCOUNT', '111122223333'), patch.object(module, 'RUN', 'fixture-resource-run'):
            with patch.object(module, 'CONFIG', {'preserved_evidence_root': str(root)}):
                self.assertIsNotNone(module.verify_evidence_receipt(path))
                (QA / 'fixture-outside-evidence-root.json').write_bytes(payload)
                receipt['files'][0]['path'] = '../fixture-outside-evidence-root.json'
                path.write_text(json.dumps(receipt), encoding='utf-8')
                with self.assertRaisesRegex(module.Blocked, 'outside the explicit evidence root'):
                    module.verify_evidence_receipt(path)
            with patch.object(module, 'CONFIG', {}), self.assertRaisesRegex(module.Blocked, 'preserved_evidence_root explicitly'):
                module.verify_evidence_receipt(path)

    def test_source_terminated_tombstone_requires_exact_binding_and_live_vpc(self):
        sys.path.insert(0, str(SCRIPTS / 'control'))
        spec = importlib.util.spec_from_file_location('cleanup_tombstone_fixture', SCRIPTS / 'control/cleanup_lab.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        cfg = fixture(); main = cfg['bindings']['main_stack_arn']
        source, vpc = 'i-00000000000000001', 'vpc-00000000000000002'
        ownership = {'Environment': 'HML', 'Project': cfg['project'], 'RunId': cfg['resource_run_id'],
                     'Owner': cfg['owner'], 'ManagedBy': cfg.get('managed_by', 'migration-lab-toolkit'), 'ExpiresAt': cfg['expires_at']}
        frozen = [{'Key': k, 'Value': v} for k, v in ownership.items()]
        record = {'InstanceId': source, 'State': {'Name': 'terminated', 'Code': 48}, 'VpcId': None,
                  'Tags': frozen + [{'Key': 'aws:cloudformation:stack-id', 'Value': main},
                                    {'Key': 'aws:cloudformation:logical-id', 'Value': 'SourceInstance'}],
                  'BlockDeviceMappings': []}

        def helper(value):
            result = object.__new__(module.Cleanup)
            result.stacks = {main: {'tags': frozen}}
            result.volumes = {'vol-00000000000000003'}
            result.rows = lambda *a, **k: [{'Instances': [copy.deepcopy(value)]}]
            result.dms_removed = lambda: None
            return result

        with patch.multiple(module, SOURCE=source, VPC=vpc, MAIN=main,
                            TAGS={k: ownership[k] for k in ('Environment', 'Project', 'RunId')}):
            for variant in ('null', 'omitted', 'high_byte', 'code_omitted', 'present_correct'):
                value = copy.deepcopy(record)
                if variant == 'omitted': value.pop('VpcId')
                elif variant == 'high_byte': value['State']['Code'] = 304
                elif variant == 'code_omitted': value['State'].pop('Code')
                elif variant == 'present_correct': value['VpcId'] = vpc
                observed, plan, done = helper(value).prepare('terminate-source')
                self.assertTrue(done); self.assertIsNone(plan)
                self.assertEqual(observed['state'], 'terminated')
                self.assertEqual(observed['vpc'], vpc if variant == 'present_correct' else None)
            changes = [('InstanceId', 'i-foreign'), ('VpcId', 'vpc-foreign'), ('VpcId', '')]
            changes += [('tag:' + key, 'foreign') for key in (*ownership, 'aws:cloudformation:stack-id', 'aws:cloudformation:logical-id')]
            changes += [('missing:' + key, None) for key in (*ownership, 'aws:cloudformation:stack-id', 'aws:cloudformation:logical-id')]
            changes += [('code', value) for value in (16, True, -1, 65536, None)]
            for field, value in changes:
                bad = copy.deepcopy(record)
                if field.startswith('tag:'):
                    next(t for t in bad['Tags'] if t['Key'] == field[4:])['Value'] = value
                elif field.startswith('missing:'):
                    bad['Tags'] = [t for t in bad['Tags'] if t['Key'] != field[8:]]
                elif field == 'code': bad['State']['Code'] = value
                else: bad[field] = value
                with self.subTest(field=field), self.assertRaises(module.Blocked): helper(bad).source()
            for state in ('running', 'stopped', 'pending', 'shutting-down'):
                for mode in ('null', 'omitted', 'wrong'):
                    bad = copy.deepcopy(record); bad['State'] = {'Name': state}
                    if mode == 'omitted': bad.pop('VpcId')
                    elif mode == 'wrong': bad['VpcId'] = 'vpc-foreign'
                    with self.subTest(state=state, mode=mode), self.assertRaises(module.Blocked): helper(bad).source()
            live = copy.deepcopy(record); live['State'] = {'Name': 'running', 'Code': 16}; live['VpcId'] = vpc
            self.assertEqual(helper(live).source()['vpc'], vpc)

    def test_cost_cleanup_gate_refuses_coercion_wrong_scope_and_incomplete_baseline(self):
        sys.path.insert(0, str(SCRIPTS / 'control'))
        spec = importlib.util.spec_from_file_location('cost_fixture', SCRIPTS / 'verification/estimate_runtime_cost.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        cfg, receipt = cleanup_fixture()
        self.assertIs(module.validate_cleanup_receipt(receipt, cfg), True)
        changes = [
            ('string_false', lambda r: r.update(cleanup_verified='false')),
            ('string_true', lambda r: r.update(cleanup_verified='true')),
            ('numeric_true', lambda r: r.update(cleanup_verified=1)),
            ('boolean_false', lambda r: r.update(cleanup_verified=False)),
            ('baseline_mode', lambda r: r.update(mode='full-baseline')),
            ('wrong_account', lambda r: r['manifest'].update(account='444455556666')),
            ('wrong_region', lambda r: r['manifest'].update(region='us-west-2')),
            ('execution_ledger_not_resource_run', lambda r: r['manifest'].update(run_id=cfg['run_id'])),
            ('wrong_identity_account', lambda r: r['identity'].update(Account='444455556666')),
            ('wrong_identity_region', lambda r: r['identity'].update(Region='us-west-2')),
            ('coverage_error', lambda r: r.update(coverage_errors=['permission'])),
            ('coverage_string', lambda r: r.update(coverage_errors='[]')),
            ('residual', lambda r: r.update(residuals=[{'count': 1}])),
            ('residual_string', lambda r: r.update(residuals='[]')),
            ('baseline_string', lambda r: r.update(baseline_incomplete='false')),
            ('baseline_incomplete', lambda r: r.update(baseline_incomplete=True)),
            ('missing_stack', lambda r: r['manifest']['stacks'].pop()),
            ('missing_resources', lambda r: r['manifest']['stacks'][0].update(resources=[])),
            ('foreign_stack_arn', lambda r: r['manifest']['stacks'][0].update(arn=r['manifest']['stacks'][1]['arn'])),
            ('wrong_resource_owner', lambda r: r['manifest']['stacks'][0]['tags'][0].update(Value='PRD')),
            ('missing_checks', lambda r: r.update(checks=[])),
            ('readback_error', lambda r: r['checks'][0].update(status='error')),
            ('live_resource', lambda r: r['checks'][0].update(live_count=1)),
            ('false_count_type', lambda r: r['checks'][0].update(live_count=False))]
        for label, mutate in changes:
            bad = copy.deepcopy(receipt); mutate(bad)
            with self.subTest(label=label), self.assertRaises(ValueError):
                module.validate_cleanup_receipt(bad, cfg)
        bad_context = copy.deepcopy(cfg); bad_context['region'] = 'us-west-2'
        with self.assertRaises(ValueError):
            module.validate_cleanup_receipt(receipt, bad_context)

    def test_cost_cli_writes_only_for_valid_context_and_final_cleanup_receipt(self):
        cfg, receipt = cleanup_fixture()
        cfg['maximum_incremental_usd'] = 500; cfg['operating_envelope_usd'] = 50
        self.config.write_text(json.dumps(cfg), encoding='utf-8')
        path = QA / 'fixture-cost-cleanup.json'; path.write_text(json.dumps(receipt), encoding='utf-8')
        output = QA / 'fixture-cost.json'
        args = ['--start-utc', '2026-10-15T00:00:00Z', '--end-utc', '2026-10-15T01:00:00Z',
                '--cleanup-inventory', str(path), '--output', str(output)]
        result = run_offline(SCRIPTS / 'verification/estimate_runtime_cost.py', args, self.config)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(output.read_text())
        self.assertIs(value['lab_deleted_verified'], True)
        self.assertIs(value['ongoing_cost_possible'], False)
        self.assertEqual(value['authorized_incremental_ceiling_usd'], '500.00')
        self.assertEqual(value['operating_envelope_usd'], '50.00')
        for invalid in ('string_false', 'foreign_scope'):
            bad = copy.deepcopy(receipt)
            if invalid == 'string_false': bad['cleanup_verified'] = 'false'
            else: bad['manifest']['account'] = '444455556666'
            path.write_text(json.dumps(bad), encoding='utf-8')
            output.unlink(missing_ok=True)
            result = run_offline(SCRIPTS / 'verification/estimate_runtime_cost.py', args, self.config)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
        self.config.write_text(json.dumps({}), encoding='utf-8')
        result = run_offline(SCRIPTS / 'verification/estimate_runtime_cost.py', args, self.config)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        self.config.write_text(json.dumps(fixture()), encoding='utf-8')

    def test_core_templates_are_deterministic_with_two_contexts(self):
        for account, prefix in [('111122223333', 'fixture-lab'), ('444455556666', 'other-fixture')]:
            cfg = fixture(account, prefix)
            cfg['managed_by'] = 'fixture-toolkit-' + account[-4:]
            self.config.write_text(json.dumps(cfg), encoding='utf-8')
            result = run_offline(SCRIPTS / 'infra/build_template.py', [], self.config)
            self.assertEqual(result.returncode, 0, result.stderr)
            template = SCRIPTS / 'infra/postgres-migration-lab.template.json'
            first = template.read_bytes()
            result = run_offline(SCRIPTS / 'infra/build_template.py', [], self.config)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(first, template.read_bytes())
            value = json.loads(first)
            self.assertEqual(value['Parameters']['Prefix']['Default'], prefix)
            self.assertEqual(value['Metadata']['ExecutionContract']['ExpectedAccountId'], account)
            self.assertEqual({t['Value'] for r in value['Resources'].values() for t in r.get('Properties', {}).get('Tags', []) if t.get('Key') == 'ManagedBy'}, {cfg['managed_by']})
            self.assertIn('SourceRoleArn', value['Outputs'])
            self.assertFalse(value['Resources']['TargetDatabase']['Properties']['PubliclyAccessible'])
            cfg['provisioning']['create_dms_vpc_role'] = False; cfg['provisioning']['create_dms_logs_role'] = False
            self.config.write_text(json.dumps(cfg), encoding='utf-8')
            result = run_offline(SCRIPTS / 'infra/build_template.py', [], self.config)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(template.read_bytes())
            self.assertNotIn('DmsVpcRole', value['Resources'])
            self.assertNotIn('DmsCloudWatchRole', value['Resources'])
            self.assertNotIn('DmsVpcRole', value['Resources']['DmsSubnetGroup'].get('DependsOn', []))
            result = run_offline(SCRIPTS / 'migration/build_migration.py', [], self.config)
            self.assertEqual(result.returncode, 0, result.stderr)
            migration = json.loads((SCRIPTS / 'migration/migration.template.json').read_text())
            self.assertEqual(migration['Parameters']['Prefix']['Default'], prefix)
            self.assertEqual({t['Value'] for r in json.loads((SCRIPTS / 'migration/migration.template.json').read_text())['Resources'].values() for t in r.get('Properties', {}).get('Tags', []) if t.get('Key') == 'ManagedBy'}, {cfg['managed_by']})
            mapping = json.loads((SCRIPTS / 'migration/table-mappings.json').read_text())
            self.assertEqual(mapping['rules'][0]['rule-action'], 'explicit')
        self.config.write_text(json.dumps(fixture()), encoding='utf-8')

    def test_guardrail_build_and_cfn_lint_are_offline(self):
        cfg = fixture()
        self.config.write_text(json.dumps(cfg), encoding='utf-8')
        policy = QA / 'fixture-bootstrap-policy.json'
        result = run_offline(SCRIPTS / 'control/aws_context.py', ['policy', '--output', str(policy)], self.config)
        self.assertEqual(result.returncode, 0, result.stderr)
        guardrail = QA / 'fixture-guardrail.template.json'
        result = run_offline(SCRIPTS / 'guardrails/build_guardrail.py', ['--target-stack-arn', cfg['bindings']['main_stack_arn'], '--run-id', cfg['resource_run_id'], '--expires-at', cfg['expires_at'], '--deletion-policy-file', str(policy), '--output', str(guardrail)], self.config)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(guardrail.read_text())
        self.assertEqual(value['Resources']['GuardFunction']['Properties']['Environment']['Variables']['EXPECTED_STACK_NAME'], cfg['prefix'])
        self.assertEqual({t['Value'] for r in value['Resources'].values() for t in r.get('Properties', {}).get('Tags', []) if t.get('Key') == 'ManagedBy'}, {cfg['managed_by']})
        environment = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
        environment.update(AWS_EC2_METADATA_DISABLED='true', PYTHONDONTWRITEBYTECODE='1')
        code = "import socket;exec('def blocked(*a,**k): raise RuntimeError(\"OFFLINE_QA_NETWORK_REFUSED\")');socket.socket.connect=blocked;from cfnlint.runner import main;main()"
        for path in [SCRIPTS / 'infra/postgres-migration-lab.template.json', SCRIPTS / 'migration/migration.template.json', guardrail]:
            result = subprocess.run([sys.executable, '-B', '-c', code, '-t', str(path), '-r', 'us-east-1'], env=environment, capture_output=True, text=True, timeout=55)
            self.assertEqual(result.returncode, 0, path.name + ': ' + result.stdout + result.stderr)

    def test_existing_semantic_suites(self):
        for relative in ['control/test_collect_dms_logs.py', 'control/g6-proof-tests/test_make_g6_proof.py', 'control/test_export_evidence.py', 'guardrails/test_guardrail.py', 'verification/test_verification.py', 'resolver/offline_checks.py']:
            result = run_offline(SCRIPTS / relative, [], self.config)
            self.assertEqual(result.returncode, 0, relative + ': ' + result.stderr + result.stdout)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    receipt = {'state': 'passed' if result.wasSuccessful() else 'failed', 'tests_run': result.testsRun,
               'failures': len(result.failures), 'errors': len(result.errors), 'aws_calls': 0,
               'network_policy': 'socket connections blocked in child programs',
               'validation': 'offline copies and synthetic contexts only; no new AWS-account deployment claimed'}
    (QA / 'offline-qa-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    raise SystemExit(0 if result.wasSuccessful() else 1)
