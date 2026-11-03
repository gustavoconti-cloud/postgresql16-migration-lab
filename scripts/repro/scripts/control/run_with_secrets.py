#!/usr/bin/env python3
"""Resolve approved dynamic references into child-only environment. Never log values."""
import importlib.machinery,importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
base=Path(__file__).resolve().parent
if '--help' in sys.argv or '-h' in sys.argv:
    print('run_with_secrets.py CONFIG HARNESS_ARGS...; Linux EC2 only; approved in-memory resolver')
    raise SystemExit(0)
if len(sys.argv)<3: raise SystemExit('usage: run_with_secrets.py CONFIG HARNESS_ARGS...')
cfg=json.loads(Path(sys.argv[1]).read_text())
started=time.monotonic()
def resolution_timeout(_signum,_frame):
    print('Credential resolution time budget exhausted.',file=sys.stderr)
    raise SystemExit(124)
signal.signal(signal.SIGALRM,resolution_timeout)
signal.alarm(300)
assert cfg['region']=='us-east-1'
for key in ('AWS_PROFILE','AWS_DEFAULT_PROFILE','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_SECURITY_TOKEN','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_ROLE_ARN','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI','AWS_CONTAINER_CREDENTIALS_FULL_URI'):
    os.environ.pop(key,None)
os.environ['AWS_REGION']='us-east-1'
os.environ['AWS_DEFAULT_REGION']='us-east-1'
os.environ['AWS_SHARED_CREDENTIALS_FILE']='/dev/null'
os.environ['AWS_CONFIG_FILE']='/dev/null'
import boto3
identity=boto3.client('sts',region_name='us-east-1').get_caller_identity()
assert identity['Account']==cfg['expected_account_id'], 'Runtime account mismatch'
assert identity['Arn'].startswith('arn:aws:sts::'+cfg['expected_account_id']+':assumed-role/'+cfg['source_role_name']+'/'), 'Runtime role mismatch'
loader=importlib.machinery.SourceFileLoader('asm_exec_runtime',str(base/'asm-exec'))
spec=importlib.util.spec_from_loader(loader.name,loader)
module=importlib.util.module_from_spec(spec);loader.exec_module(module)
env=os.environ.copy()
for name,key,field in [('LAB_SOURCE_DMS_PASSWORD','source_secret_arn','password'),('LAB_TARGET_DMS_PASSWORD','target_secret_arn','password'),('LAB_CLIENT_PASSWORD','client_secret_arn','password'),('LAB_RDS_MASTER_PASSWORD','master_secret_arn','password'),('LAB_RDS_MASTER_USERNAME','master_secret_arn','username')]:
    arn=cfg[key]
    assert arn.startswith('arn:aws:secretsmanager:us-east-1:'+cfg['expected_account_id']+':secret:')
    ref='{{resolve:secretsmanager:'+arn+':SecretString:'+field+':AWSCURRENT}}'
    env[name]=module.resolve_string(ref)
signal.alarm(0)
if sys.argv[2]=='--batch':
    assert len(sys.argv)==4
    actions=json.loads(Path(sys.argv[3]).read_text())
    assert isinstance(actions,list) and 1<=len(actions)<=8
    records=[];code=0
    receipt_path=Path(sys.argv[3]).with_name('runtime-receipts.json')
    for args in actions:
        assert isinstance(args,list) and args and all(isinstance(x,str) for x in args)
        remaining=int(700-(time.monotonic()-started))
        if remaining<5:
            records.append({'action':args,'returncode':124,'execution_state':'not_started_time_budget_exhausted','stdout':'','stderr':'Batch time budget exhausted before this action.'})
            code=124
        else:
            try:
                result=subprocess.run([sys.executable,'-B',str(base/'lab_harness.py'),'--config',sys.argv[1],*args],env=env,capture_output=True,text=True,timeout=min(120,remaining))
                records.append({'action':args,'returncode':result.returncode,'execution_state':'completed','stdout':result.stdout,'stderr':result.stderr})
                code=result.returncode
            except subprocess.TimeoutExpired:
                records.append({'action':args,'returncode':124,'execution_state':'unknown_after_timeout','stdout':'','stderr':'Inspect the database ledger before retrying; commit state is unknown.'})
                code=124
        temporary=receipt_path.with_suffix('.tmp');temporary.write_text(json.dumps(records,ensure_ascii=False),encoding='utf-8');os.chmod(temporary,0o600);os.replace(temporary,receipt_path)
        if code:break
    print(json.dumps(records,ensure_ascii=False))
    raise SystemExit(code)
else:
    result=subprocess.run([sys.executable,'-B',str(base/'lab_harness.py'),'--config',sys.argv[1],*sys.argv[2:]],env=env)
    raise SystemExit(result.returncode)
