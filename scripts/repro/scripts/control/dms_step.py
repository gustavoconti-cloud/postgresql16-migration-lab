"""Run the state-gated DMS action and display compact results; full evidence stays in dms_runtime."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import subprocess, sys, json
from pathlib import Path
root = Path(__file__).resolve().parent
r = subprocess.run([sys.executable, '-B', str(root / 'dms_runtime.py'), *sys.argv[1:]], capture_output=True, text=True)
if r.returncode:
    print(r.stderr)
    print(r.stdout)
    raise SystemExit(r.returncode)
v = json.loads(r.stdout)
if isinstance(v, dict) and 'task' in v:
    t = v['task']
    print(json.dumps({'task': {k: t.get(k) for k in ('Status', 'LastFailureMessage', 'StopReason', 'RecoveryCheckpoint')}, 'tables': v['tables'].get('TableStatistics', []), 'connections': v['connections'].get('Connections', [])}, ensure_ascii=True))
elif isinstance(v, dict) and 'metrics' in v:
    print(json.dumps({'time': v['time'], 'metrics': {k: x.get('Datapoints', [])[-5:] for k, x in v['metrics'].items()}}, ensure_ascii=True))
elif isinstance(v, dict) and 'ReplicationTask' in v:
    t = v['ReplicationTask']
    print(json.dumps({k: t.get(k) for k in ('ReplicationTaskArn', 'Status', 'LastFailureMessage', 'StopReason')}))
else:
    print(json.dumps(v, ensure_ascii=True))
