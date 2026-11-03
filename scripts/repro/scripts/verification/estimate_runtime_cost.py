"""Deterministic local upper runtime envelope, not invoiced AWS expenditure."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
from aws_context import CONFIG, ACCOUNT, PROFILE, STACK, RUN, TEST_RUN, MAIN_STACK_ARN, binding_value, load_context, require
import argparse
import json
import sys
from datetime import datetime, timezone
from decimal import Decimal as D, ROUND_CEILING, ROUND_HALF_UP
from pathlib import Path
BASE = Path(__file__).resolve().parent


def validate_cleanup_receipt(receipt: dict, context: dict) -> bool:
    """Accept only a complete final readback for these exact owned resources."""
    from aws_context import validate_context
    validate_context(context, require_future=False)
    require(isinstance(receipt, dict) and receipt.get('mode') == 'final', 'Cleanup receipt must be final')
    require(receipt.get('cleanup_verified') is True, 'Cleanup must be verified with boolean true')
    require(receipt.get('coverage_errors') == [] and type(receipt.get('coverage_errors')) is list,
            'Cleanup coverage errors must be an explicit empty list')
    require(receipt.get('residuals') == [] and type(receipt.get('residuals')) is list,
            'Cleanup residuals must be an explicit empty list')
    require(receipt.get('baseline_incomplete') is False, 'Cleanup requires an explicitly complete baseline')
    manifest = receipt.get('manifest')
    require(isinstance(manifest, dict), 'Cleanup manifest missing')
    expected_scope = (context['expected_account_id'], context['region'], context['resource_run_id'])
    require((manifest.get('account'), manifest.get('region'), manifest.get('run_id')) == expected_scope,
            'Cleanup manifest scope differs from account/region/resource_run_id')
    identity = receipt.get('identity')
    require(isinstance(identity, dict) and (identity.get('Account'), identity.get('Region')) == expected_scope[:2],
            'Cleanup identity account/region differs')
    stack_bindings = {context['prefix'] + suffix: context.get('bindings', {}).get(key)
                      for suffix, key in (('', 'main_stack_arn'), ('-migration', 'migration_stack_arn'),
                                          ('-guardrail', 'guardrail_stack_arn'))}
    require(all(stack_bindings.values()), 'Bind all three immutable stack ARNs before using cleanup evidence')
    stacks = manifest.get('stacks')
    require(isinstance(stacks, list) and len(stacks) == 3 and all(isinstance(s, dict) for s in stacks),
            'Cleanup baseline must preserve all three stacks')
    require({s.get('name') for s in stacks} == set(stack_bindings), 'Cleanup baseline stack set differs')
    ownership = {'Environment': 'HML', 'Project': context['project'], 'RunId': context['resource_run_id']}
    for stack in stacks:
        require(stack.get('arn') == stack_bindings[stack['name']], 'Cleanup immutable stack ARN differs')
        require(stack.get('status') in {'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'DELETE_COMPLETE'},
                'Cleanup baseline stack was not complete or retired')
        tags = stack.get('tags')
        require(isinstance(tags, list) and all(isinstance(t, dict) for t in tags), 'Cleanup baseline ownership missing')
        observed = {t.get('Key'): t.get('Value') for t in tags}
        require(all(observed.get(k) == v for k, v in ownership.items()), 'Cleanup baseline ownership differs')
        resources = stack.get('resources')
        require(isinstance(resources, list) and bool(resources) and all(isinstance(r, dict) for r in resources),
                'Cleanup baseline resource inventory missing')
        require(all(all(isinstance(r.get(k), str) and r[k] for k in
                        ('LogicalResourceId', 'PhysicalResourceId', 'ResourceType')) for r in resources)
                and len({r['LogicalResourceId'] for r in resources}) == len(resources),
                'Cleanup baseline resource inventory incomplete')
    checks = receipt.get('checks')
    require(isinstance(checks, list) and bool(checks) and all(isinstance(c, dict) for c in checks),
            'Cleanup readback checks missing')
    required_labels = {kind + name for name in stack_bindings for kind in ('stack:', 'stack-resources:')}
    require(required_labels <= {c.get('label') for c in checks}, 'Cleanup stack readback coverage incomplete')
    require(all(c.get('status') in {'present', 'absent'} and type(c.get('live_count')) is int
                and c['live_count'] == 0 for c in checks), 'Cleanup readback contains unknown state or live resources')
    return True

def when(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('UTC offset required')
    return result.astimezone(timezone.utc)

def usd(value: D) -> str:
    return str(value.quantize(D('0.01'), rounding=ROUND_HALF_UP))

def calculate(start: datetime, end: datetime, rates: dict[str, str], nat_gb: D, vpce_gb: D) -> dict:
    if nat_gb < 0 or vpce_gb < 0:
        raise ValueError('Data volumes cannot be negative')
    seconds = D(str((end - start).total_seconds()))
    if seconds <= 0 or seconds > D(3600 * 168):
        raise ValueError('Runtime must be positive and at most 168h; investigate scope if exceeded')
    hours = seconds / D('3600')
    billed_hours = hours.to_integral_value(rounding=ROUND_CEILING)
    month = D('730')
    r = {k: D(v) for k, v in rates.items()}
    rows = {'EC2 t3.small standard CPU credits': billed_hours * r['ec2_t3_small_per_hour'], 'EBS gp3 20 GiB': billed_hours * D('20') * r['ebs_gp3_per_gb_month'] / month, 'RDS db.t4g.small Single-AZ': billed_hours * r['rds_t4g_small_per_hour'], 'RDS gp3 20 GiB': billed_hours * D('20') * r['rds_gp3_per_gb_month'] / month, 'DMS dms.t3.medium Single-AZ incl 50 GiB gp2': billed_hours * r['dms_t3_medium_single_az_per_hour'], 'One zonal NAT gateway': billed_hours * r['nat_gateway_per_hour'], 'One public IPv4 address': billed_hours * r['public_ipv4_per_hour'], 'One interface endpoint in one AZ': billed_hours * D('0.01'), 'Four Secrets Manager secrets allowance': billed_hours * D('4') * D('0.40') / month, 'NAT data supplied by operator': nat_gb * r['nat_gateway_processed_per_gb'], 'Interface endpoint data supplied by operator': vpce_gb * D('0.01')}
    base = sum(rows.values(), D('0'))
    cpu_allowance = billed_hours * D('4') * D('0.075')
    auxiliary = D('20')
    envelope = base + cpu_allowance + auxiliary
    return {'start_utc': start.isoformat(), 'end_utc': end.isoformat(), 'elapsed_hours': str(hours), 'rounded_component_hours': str(billed_hours), 'component_usd': {k: usd(v) for k, v in rows.items()}, 'base_runtime_usd': usd(base), 'cpu_surplus_upper_allowance_usd': usd(cpu_allowance), 'auxiliary_reserve_usd': usd(auxiliary), 'conservative_runtime_envelope_usd': usd(envelope), 'authorized_incremental_ceiling_usd': '1000.00', 'operating_envelope_usd': '100.00', 'within_authorized_ceiling': envelope <= D('1000'), 'within_operating_envelope': envelope <= D('100'), 'scope': 'One complete laboratory. Existing account charges, taxes, support and invoice reconciliation excluded.', 'assumptions': ['Common runtime bounds encompass provisioning through verified deletion of all cost-bearing laboratory resources.', 'Whole hours for all components, including services that may charge more precisely; 730h/month is an explicit estimate convention.', 'NAT/interface data volumes are supplied separately. Zero means not supplied, not observed zero traffic; auxiliary reserve covers low-volume unmeasured traffic/API/logs/TTL execution.', 'Secrets Manager: four secret-hour prorations at USD0.40/month are a conservative allowance, not an assertion that a managed RDS secret is separately billed.', 'CPU allowance charges all DMS/RDS vCPU hours at USD0.075 despite baseline credits; it is a bound, not measured surplus.', 'No credits, Free Tier or commitments applied; no Cost Explorer call and no invoice claim.']}

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--start-utc', required=True)
    p.add_argument('--end-utc', required=True)
    p.add_argument('--cleanup-inventory', type=Path)
    p.add_argument('--nat-gb', type=D, default=D('0'))
    p.add_argument('--vpce-gb', type=D, default=D('0'))
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    context = load_context(require_future=False)
    rates_path = BASE.parents[1] / 'rates' / 'cost-scenarios.json'
    rates = json.loads(rates_path.read_text(encoding='utf-8'))['rates']
    result = calculate(when(args.start_utc), when(args.end_utc), rates, args.nat_gb, args.vpce_gb)
    result.update({'schema_version': 1, 'region': 'us-east-1', 'account': ACCOUNT, 'run_id': RUN, 'currency': 'USD', 'billing_status': 'estimated; invoice unverified', 'lab_deleted_verified': False, 'rate_source': str(rates_path), 'interface_endpoint_price_source': 'https://aws.amazon.com/privatelink/pricing/'})
    ceiling = D(str(context['maximum_incremental_usd']))
    operating = D(str(context['operating_envelope_usd']))
    envelope = D(result['conservative_runtime_envelope_usd'])
    result.update(authorized_incremental_ceiling_usd=usd(ceiling), operating_envelope_usd=usd(operating),
                  within_authorized_ceiling=envelope <= ceiling, within_operating_envelope=envelope <= operating)
    if args.cleanup_inventory:
        receipt = json.loads(args.cleanup_inventory.read_text(encoding='utf-8-sig'))
        result['lab_deleted_verified'] = validate_cleanup_receipt(receipt, context)
        result['cleanup_evidence'] = str(args.cleanup_inventory)
        result['ongoing_cost_possible'] = not result['lab_deleted_verified']
    else:
        result['ongoing_cost_possible'] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('elapsed_hours', 'rounded_component_hours', 'base_runtime_usd', 'conservative_runtime_envelope_usd', 'lab_deleted_verified', 'billing_status')}, indent=2))
    return 0
if __name__ == '__main__':
    sys.exit(main())
