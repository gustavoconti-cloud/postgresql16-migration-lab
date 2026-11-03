"""Draft and submit a bounded harness batch; root operator only."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import json, subprocess, sys
from pathlib import Path
root = Path(__file__).resolve().parent
if '--help' in sys.argv or '-h' in sys.argv:
    print('run_stage.py LABEL ACTIONS_JSON; prepares and submits an SSM stage; AWS write')
    raise SystemExit(0)
if len(sys.argv) != 3:
    raise SystemExit('usage: run_stage.py LABEL ACTIONS_JSON')
label, actions = sys.argv[1:]
subprocess.run([sys.executable, '-B', str(root / 'stage_actions.py'), label, actions], check=True, capture_output=True, text=True)
raise SystemExit(subprocess.run([sys.executable, '-B', str(root / 'ssm_runtime.py'), 'submit', str(root / (label + '.sh')), '--label', label]).returncode)
