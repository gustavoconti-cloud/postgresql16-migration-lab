"""Expiry guard for one immutable CloudFormation stack ID.

Deploy only through the independent guardrail stack. Configuration lives in
environment variables; incoming events cannot change the deletion target.
"""

import datetime as dt
import json
import os
import re
from decimal import Decimal

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


CLIENT_CONFIG = Config(
    connect_timeout=5,
    read_timeout=15,
    retries={"mode": "standard", "total_max_attempts": 3},
)
SESSION = boto3.Session(region_name="us-east-1")
CFN = SESSION.client("cloudformation", config=CLIENT_CONFIG)
BUDGETS = SESSION.client("budgets", config=CLIENT_CONFIG)
DMS = SESSION.client("dms", config=CLIENT_CONFIG)


def _result(**values):
    print(json.dumps(values, sort_keys=True, default=str))
    return values


def _describe_stack(target):
    try:
        return CFN.describe_stacks(StackName=target)["Stacks"][0]
    except ClientError as error:
        if error.response["Error"]["Code"] == "ValidationError" and "does not exist" in error.response["Error"]["Message"]:
            return None
        raise


def _check_tags(tags, expected):
    actual = {tag["Key"]: tag["Value"] for tag in tags}
    if any(actual.get(key) != value for key, value in expected.items()):
        raise ValueError("Resource tags do not match the authorized laboratory")


def _optional_dms_pages(operation, **parameters):
    """The two filtered describe APIs report no matches as ResourceNotFoundFault.

    Catch only the real SDK absence class, and only around the describe call.
    Permission/authentication errors and failures in tag reads or mutations must
    propagate; they are not evidence of resource absence.
    """
    if operation not in {"describe_replication_tasks", "describe_certificates"}:
        raise ValueError("Unsupported optional DMS describe operation")
    try:
        return list(DMS.get_paginator(operation).paginate(**parameters))
    except DMS.exceptions.ResourceNotFoundFault:
        return []


def _dependencies(stack, expected, role, token, mutate):
    """One bounded cleanup tick; never waits for asynchronous AWS operations."""
    account = os.environ["EXPECTED_ACCOUNT_ID"]
    dms_prefix = "arn:aws:dms:us-east-1:" + account + ":"
    outputs = {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}
    replication = outputs.get("ReplicationInstanceArn")
    migration_name = os.environ.get("MIGRATION_STACK_NAME", "")
    migration_arn = os.environ.get("MIGRATION_STACK_ARN", "")
    if not migration_name:
        return {"ready": True, "state": "no_dependencies_configured"}
    if not replication:
        try:
            resource = CFN.describe_stack_resource(StackName=stack["StackId"], LogicalResourceId="ReplicationInstance")["StackResourceDetail"]
            if resource.get("ResourceStatus") != "DELETE_COMPLETE":
                replication = resource.get("PhysicalResourceId")
        except ClientError as error:
            if error.response["Error"]["Code"] != "ValidationError" or "does not exist" not in error.response["Error"]["Message"]:
                raise
    if not replication:
        # A partially created or rolled-back principal may have no DMS instance.
        # Principal deletion is safe only if the dependent stack is also absent.
        migration = _describe_stack(migration_arn or migration_name)
        if migration is not None and migration["StackStatus"] != "DELETE_COMPLETE":
            raise ValueError("Migration exists while the principal stack has no replication ARN")
        return {"ready": True, "state": "no_replication_resource_no_migration"}
    if not replication or not replication.startswith(dms_prefix + "rep:"):
        raise ValueError("Principal stack did not provide a valid bound replication-instance ARN")
    task_states = []
    for page in _optional_dms_pages("describe_replication_tasks",
        Filters=[{"Name": "replication-instance-arn", "Values": [replication]}], WithoutSettings=True,
    ):
        for task in page.get("ReplicationTasks", []):
            arn = task["ReplicationTaskArn"]
            if task.get("ReplicationInstanceArn") != replication or not arn.startswith(dms_prefix + "task:"):
                raise ValueError("DMS task is outside the bound replication instance")
            configured_task_arn = os.environ.get("REPLICATION_TASK_ARN", "")
            if configured_task_arn and arn != configured_task_arn:
                raise ValueError("Task immutable ARN does not match")
            _check_tags(DMS.list_tags_for_resource(ResourceArn=arn).get("TagList", []), expected)
            status = task["Status"]
            task_states.append({"arn": arn, "status": status})
            if mutate and status == "running":
                DMS.stop_replication_task(ReplicationTaskArn=arn)
    if any(task["status"] not in {"stopped", "ready", "failed"} for task in task_states):
        return {"ready": False, "state": "tasks_stopping", "tasks": task_states, "replication_arn": replication}

    migration = _describe_stack(migration_arn or migration_name)
    if migration is not None and migration["StackStatus"] != "DELETE_COMPLETE":
        actual_arn = migration["StackId"]
        prefix = "arn:aws:cloudformation:us-east-1:" + account + ":stack/" + migration_name + "/"
        if (migration_arn and migration_arn != actual_arn) or not actual_arn.startswith(prefix):
            raise ValueError("Unexpected dependent migration stack ID")
        _check_tags(migration.get("Tags", []), expected)
        if migration.get("EnableTerminationProtection"):
            raise ValueError("Migration stack termination protection cannot be bypassed")
        if not mutate:
            return {"ready": False, "state": "migration_present", "migration_stack_arn": actual_arn, "tasks": task_states}
        if migration["StackStatus"] != "DELETE_IN_PROGRESS":
            CFN.delete_stack(StackName=actual_arn, RoleARN=role, ClientRequestToken=token + "-migration")
        return {"ready": False, "state": "migration_deleting", "migration_stack_arn": actual_arn}
    if task_states:
        raise ValueError("Tasks remain on the bound instance after the migration stack disappeared")

    certificate_id = os.environ["CERTIFICATE_IDENTIFIER"]
    certificates = []
    for page in _optional_dms_pages("describe_certificates", Filters=[{"Name": "certificate-id", "Values": [certificate_id]}]):
        certificates.extend(page.get("Certificates", []))
    if len(certificates) > 1:
        raise ValueError("Certificate identifier is not unique")
    if certificates:
        certificate = certificates[0]
        arn = certificate["CertificateArn"]
        if certificate.get("CertificateIdentifier") != certificate_id or not arn.startswith(dms_prefix + "cert:"):
            raise ValueError("Certificate is outside the authorized laboratory")
        configured_arn = os.environ.get("CERTIFICATE_ARN", "")
        if configured_arn and arn != configured_arn:
            raise ValueError("Certificate immutable ARN does not match")
        _check_tags(DMS.list_tags_for_resource(ResourceArn=arn).get("TagList", []), expected)
        if mutate:
            DMS.delete_certificate(CertificateArn=arn)
        return {"ready": False, "state": "certificate_delete_requested" if mutate else "certificate_present", "certificate_arn": arn}
    return {"ready": True, "state": "dependencies_absent", "replication_arn": replication}


def handler(event, context):
    target = os.environ["TARGET_STACK_ARN"]
    run_id = os.environ["TARGET_RUN_ID"]
    account = os.environ["EXPECTED_ACCOUNT_ID"]
    role = os.environ["DELETION_ROLE_ARN"]
    expiry = dt.datetime.fromisoformat(os.environ["EXPIRES_AT_UTC"].replace("Z", "+00:00"))
    current = dt.datetime.now(dt.timezone.utc)
    prefix = "arn:aws:cloudformation:us-east-1:" + account + ":stack/" + os.environ["EXPECTED_STACK_NAME"] + "/"
    if re.fullmatch(r"[0-9]{12}", account) is None or not target.startswith(prefix):
        raise ValueError("Unexpected account, region or stack ARN")
    if expiry.tzinfo is None or expiry.utcoffset() != dt.timedelta(0):
        raise ValueError("Expiry must be UTC")

    stack = _describe_stack(target)
    if stack is None:
        return _result(state="target_absent", target=target, run_id=run_id)
    if stack["StackId"] != target:
        raise ValueError("CloudFormation returned a different immutable stack ID")
    tags = {tag["Key"]: tag["Value"] for tag in stack.get("Tags", [])}
    expected = {
        "Environment": "HML",
        "Project": os.environ["EXPECTED_PROJECT"],
        os.environ["RUN_TAG_KEY"]: run_id,
    }
    if any(tags.get(key) != value for key, value in expected.items()):
        raise ValueError("Target stack tags do not match the authorized laboratory")
    creation = stack["CreationTime"]
    if isinstance(creation, str):
        creation = dt.datetime.fromisoformat(creation.replace("Z", "+00:00"))
    if not creation < expiry <= creation + dt.timedelta(hours=72):
        raise ValueError("Expiry must fall within 72 hours of principal stack creation")
    tagged_expiry = dt.datetime.fromisoformat(tags.get("ExpiresAt", "").replace("Z", "+00:00"))
    if tagged_expiry != expiry:
        raise ValueError("Configured expiry does not match principal stack tag")
    status = stack["StackStatus"]
    if status in {"DELETE_IN_PROGRESS", "DELETE_COMPLETE"}:
        return _result(state=status.lower(), target=target, run_id=run_id)
    if stack.get("EnableTerminationProtection"):
        raise ValueError("Target has termination protection; guard cannot bypass it")

    actual = None
    cost_state = "disabled"
    budget_name = os.environ.get("BUDGET_NAME", "")
    if budget_name:
        try:
            budget = BUDGETS.describe_budget(AccountId=account, BudgetName=budget_name)["Budget"]
            amount = budget.get("CalculatedSpend", {}).get("ActualSpend", {})
            if amount.get("Unit") == "USD" and "Amount" in amount:
                actual = Decimal(amount["Amount"])
                cost_state = "available_delayed_billing_data"
            else:
                cost_state = "data_not_available"
        except ClientError as error:
            # Billing failures must never prevent the independent TTL check.
            cost_state = "unavailable_" + error.response["Error"]["Code"]
    cutoff = Decimal(os.environ["COST_CUTOFF_USD"])
    reason = "ttl_expired" if current >= expiry else None
    if actual is not None and actual >= cutoff:
        reason = "recorded_cost_cutoff"
    if event.get("operation") == "cleanup":
        if event.get("confirm_target_arn") != target or event.get("confirm_run_id") != run_id:
            raise ValueError("Manual cleanup requires matching immutable ARN and run ID")
        reason = "authorized_manual_cleanup"

    probe = event.get("operation") == "probe"
    window = int(current.timestamp()) // 300
    token = "lab-guard-" + run_id + "-" + str(window)
    if reason is None or probe:
        dependencies = _dependencies(stack, expected, role, token, False) if probe else {"state": "not_requested"}
        return _result(
            state="probe" if probe else "watching", target=target, run_id=run_id,
            expires_at=expiry.isoformat(), now=current.isoformat(),
            would_delete=bool(reason), reason=reason, stack_status=status,
            cost_state=cost_state, actual_usd=None if actual is None else str(actual),
            cost_cutoff_usd=str(cutoff),
            dependencies=dependencies,
        )

    dependencies = _dependencies(stack, expected, role, token, True)
    if not dependencies["ready"]:
        return _result(state="cleanup_pending", target=target, run_id=run_id, reason=reason, dependencies=dependencies)

    # A stable token within each five-minute window handles transport retries;
    # later windows may retry a DELETE_FAILED stack after a transient failure.
    # No force deletion or retained resources are permitted.
    response = CFN.delete_stack(
        StackName=target,
        RoleARN=role,
        ClientRequestToken=token,
    )
    return _result(
        state="delete_requested", target=target, run_id=run_id, reason=reason,
        request_id=response["ResponseMetadata"]["RequestId"],
        cost_state=cost_state, actual_usd=None if actual is None else str(actual),
    )
