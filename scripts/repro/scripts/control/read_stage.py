"""Read SSM receipt and decode only secret-free harness evidence locally."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse, base64, gzip, json
from aws_context import *
from ssm_runtime import source_instance
p = argparse.ArgumentParser()
p.add_argument('label')
p.add_argument('command_id')
p.add_argument('--compact', action='store_true')
a = p.parse_args()
r = client('ssm').get_command_invocation(CommandId=a.command_id, InstanceId=source_instance())
save(a.label + '-ssm.json', {'time': stamp(), 'result': r})
print(json.dumps({'status': r['Status'], 'response_code': r['ResponseCode'], 'stderr': r['StandardErrorContent'][:1000]}))
valid = r['Status'] == 'Success' and r['ResponseCode'] == 0
found = False
for line in r['StandardOutputContent'].splitlines():
    if line.startswith('LAB_EVIDENCE_MANIFEST='):
        manifest = json.loads(line.split('=', 1)[1])
        save(a.label + '-transport-pending.json', manifest)
        print(json.dumps({'evidence_transport_pending': manifest}))
        raise SystemExit(2)
    if line.startswith('LAB_EVIDENCE_GZIP_BASE64='):
        records = json.loads(gzip.decompress(base64.b64decode(line.split('=', 1)[1])))
        found = bool(records)
        for index, record in enumerate(records):
            try:
                record['envelope'] = json.loads(record['stdout'])
            except json.JSONDecodeError:
                pass
            save(a.label + '-' + str(index) + '-' + record['action'][0] + '.json', record)
            valid = valid and record['returncode'] == 0 and (record.get('envelope', {}).get('success') is True)
            envelope = record.get('envelope', {})
            if a.compact:
                data = envelope.get('data', {})
                report = {k: envelope[k] for k in ('success', 'command', 'run_id', 'failure_class', 'exception_type', 'sqlstate', 'message', 'error', 'started_at_utc', 'finished_at_utc') if k in envelope}
                report['data_keys'] = list(data) if isinstance(data, dict) else []
                report['evidence_file'] = a.label + '-' + str(index) + '-' + record['action'][0] + '.json'
            else:
                report = envelope
            print(json.dumps({'action': record['action'], 'returncode': record['returncode'], 'envelope': report, 'stderr': record['stderr']}, ensure_ascii=True))
raise SystemExit(0 if valid and found else 2)
