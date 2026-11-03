"""Draft a credential-free, bounded remote harness stage; no AWS writes."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse, base64, json, re, shlex
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('label')
p.add_argument('actions_json', nargs='?', default='[]')
p.add_argument('--config', default=str(ROOT / 'control/runtime-config.json'))
p.add_argument('--install-runtime', action='store_true')
p.add_argument('--proof', type=Path, help='Exact local G6 proof to stage at /opt/pg-lab/evidence/<basename>')
a = p.parse_args()
assert re.fullmatch('[a-zA-Z0-9-]{1,64}', a.label)
if a.install_runtime:
    load_context()
    require(a.actions_json == '[]', 'Install is a separate stage without database actions')
    import gzip
    files = {
        '/opt/pg-lab/harness/lab_harness.py': ROOT / 'harness/lab_harness.py',
        '/opt/pg-lab/harness/run_with_secrets.py': ROOT / 'control/run_with_secrets.py',
        '/opt/pg-lab/harness/asm-exec': ROOT / 'resolver/asm-exec-compat',
        '/opt/pg-lab/harness/bootstrap_source.sh': ROOT / 'harness/bootstrap_source.sh'
    }
    content = {name: path.read_text(encoding='utf-8') for name, path in files.items()}
    encoded = base64.b64encode(gzip.compress(json.dumps(content).encode('utf-8'), mtime=0)).decode('ascii')
    script = "set -eu\n/usr/bin/python3 - <<'PG_LAB_INSTALL'\nimport base64,gzip,hashlib,json,os,subprocess\nfrom pathlib import Path\nfiles=json.loads(gzip.decompress(base64.b64decode(" + repr(encoded) + ")))\nfor name,value in files.items():\n p=Path(name);p.parent.mkdir(parents=True,exist_ok=True);os.chmod(p.parent,0o700);p.write_bytes(value.encode('utf-8'));os.chmod(p,0o700)\nsubprocess.run(['/bin/bash','/opt/pg-lab/harness/bootstrap_source.sh'],check=True,timeout=850)\nprint(json.dumps({'installed_sha256':{name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in files}}))\nPG_LAB_INSTALL\n"
    require(len(script.encode('utf-8')) < 50000, 'Installer exceeds the bounded SSM payload; refuse to submit')
    out = ROOT / 'control' / (a.label + '.sh')
    out.write_text(script, encoding='utf-8', newline='\n')
    print(str(out))
    raise SystemExit(0)
actions = json.loads(a.actions_json)
allowed = {'diagnose-target-control-schema', 'diagnose-target-default-privileges', 'diagnose-target-setup', 'prepare-source', 'prepare-target', 'configure-hba', 'inspect', 'compare', 't01', 't02', 't03', 'diverge-target', 'correct-divergence', 'marker-901', 'marker-902', 'freeze-source', 'freeze-target', 'record-g6', 'prewrite-return', 'open-target', 'postwrite-insert', 'postwrite-update', 'postwrite-delete', 'observe', 'reset-for-replay', 'open-source-for-replay'}
assert 1 <= len(actions) <= 8 and all((isinstance(x, list) and x and (x[0] in allowed) and all((isinstance(v, str) for v in x)) for x in actions))
cfg = json.loads(Path(a.config).read_text())
from aws_context import no_secrets
no_secrets(cfg)
require(cfg.get('expected_account_id') == ACCOUNT and cfg.get('resource_run_id') == RUN and cfg.get('run_id') == TEST_RUN, 'Runtime config differs from local explicit context')
proof = None
if a.proof:
    proof_bytes = a.proof.read_bytes()
    proof_data = json.loads(proof_bytes)
    no_secrets(proof_data)
    require(proof_data.get('run_id') == TEST_RUN and proof_data.get('task_arn') == binding_value('dms_task_arn'), 'G6 proof differs from current run/task')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+', a.proof.name) is not None, 'Proof requires a simple basename')
    require(any(x[0] == 'record-g6' and x[-1] == '/opt/pg-lab/evidence/' + a.proof.name for x in actions), 'Proof may only accompany its exact record-g6 action')
    proof = {'name': a.proof.name, 'base64': base64.b64encode(proof_bytes).decode('ascii')}
assert cfg['region'] == 'us-east-1'
payload = base64.b64encode(json.dumps({'config': cfg, 'actions': actions, 'label': a.label, 'proof': proof}).encode()).decode()
script = "set -eu\n/usr/bin/python3 - <<'PY'\nimport base64,gzip,json,os,subprocess,hashlib,math\nfrom pathlib import Path\ndata=json.loads(base64.b64decode('PAYLOAD'))\nif data.get('proof'):\n proof_path=Path('/opt/pg-lab/evidence')/data['proof']['name'];proof_path.parent.mkdir(parents=True,exist_ok=True);os.chmod(proof_path.parent,0o700);proof_path.write_bytes(base64.b64decode(data['proof']['base64']));os.chmod(proof_path,0o600)\nconfig=Path('/opt/pg-lab/config.json');config.write_text(json.dumps(data['config']),encoding='utf-8');os.chmod(config,0o600)\nfolder=Path('/opt/pg-lab/evidence')/data['label'];folder.mkdir(parents=True,exist_ok=True);os.chmod(folder,0o700)\naction_path=folder/'actions.json';action_path.write_text(json.dumps(data['actions']),encoding='utf-8')\nresult=subprocess.run(['/usr/bin/python3','-B','/opt/pg-lab/harness/run_with_secrets.py',str(config),'--batch',str(action_path)],capture_output=True,text=True,timeout=800)\nexit_code=result.returncode\ntry:receipts=json.loads(result.stdout)\nexcept json.JSONDecodeError:receipts=[{'action':['resolver-batch'],'returncode':exit_code,'stdout':result.stdout,'stderr':result.stderr}]\nfor index,record in enumerate(receipts):\n (folder/(str(index)+'-'+record['action'][0]+'.json')).write_text(json.dumps(record),encoding='utf-8')\nencoded=base64.b64encode(gzip.compress(json.dumps(receipts).encode(),mtime=0)).decode()\nexport_path=folder/'encoded-evidence.txt';export_path.write_text(encoded,encoding='ascii')\nif len(encoded)<=22000:\n print('LAB_EVIDENCE_GZIP_BASE64='+encoded)\nelse:\n print('LAB_EVIDENCE_MANIFEST='+json.dumps({'path':str(export_path),'length':len(encoded),'sha256':hashlib.sha256(encoded.encode()).hexdigest(),'chunk_size':20000,'chunks':math.ceil(len(encoded)/20000),'transport_state':'requires_chunk_readback'}))\nraise SystemExit(exit_code)\nPY\n".replace('PAYLOAD', payload)
out = ROOT / 'control' / (a.label + '.sh')
out.write_bytes(script.encode())
print(str(out))
