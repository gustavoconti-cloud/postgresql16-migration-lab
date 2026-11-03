"""Meaningful scope/expiry tests with no AWS network calls."""

import datetime as dt
import importlib
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from botocore.exceptions import ClientError
from botocore.stub import Stubber

os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
guard = importlib.import_module("ttl_handler")

ARN = "arn:aws:cloudformation:us-east-1:111122223333:stack/fixture-lab/00000000-0000-0000-0000-000000000000"
ENV = {
    "EXPECTED_STACK_NAME": "fixture-lab", "TARGET_STACK_ARN": ARN, "TARGET_RUN_ID": "fixture-lab", "EXPECTED_ACCOUNT_ID": "111122223333",
    "DELETION_ROLE_ARN": "arn:aws:iam::111122223333:role/fixture-lab-guardrail-teardown",
    "EXPIRES_AT_UTC": "2026-10-18T23:45:00Z", "EXPECTED_PROJECT": "postgresql-migration-lab",
    "RUN_TAG_KEY": "RunId", "COST_CUTOFF_USD": "100", "BUDGET_NAME": "",
}


class FakeDateTime(dt.datetime):
    current = dt.datetime(2026, 10, 15, 23, 45, tzinfo=dt.timezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls.current


class FakeCFN:
    def __init__(self):
        self.deletes = []
        self.stack = {"StackId": ARN, "StackStatus": "CREATE_COMPLETE", "CreationTime": dt.datetime(2026, 10, 15, 23, 45, tzinfo=dt.timezone.utc), "Tags": [
            {"Key": "Environment", "Value": "HML"}, {"Key": "Project", "Value": "postgresql-migration-lab"},
            {"Key": "RunId", "Value": "fixture-lab"},
            {"Key": "ExpiresAt", "Value": "2026-10-18T23:45:00Z"},
        ]}

    def describe_stacks(self, **kwargs):
        if kwargs != {"StackName": ARN}:
            raise AssertionError("Lookup must use exact immutable ARN")
        return {"Stacks": [self.stack]}

    def delete_stack(self, **kwargs):
        self.deletes.append(kwargs)
        return {"ResponseMetadata": {"RequestId": "test-request"}}


class FakeBudget:
    def describe_budget(self, **kwargs):
        return {"Budget": {"CalculatedSpend": {"ActualSpend": {"Amount": "100.01", "Unit": "USD"}}}}


RI = "arn:aws:dms:us-east-1:111122223333:rep:bound-instance"
TASK = "arn:aws:dms:us-east-1:111122223333:task:bound-task"
CERT = "arn:aws:dms:us-east-1:111122223333:cert:bound-certificate"
MIGRATION = "arn:aws:cloudformation:us-east-1:111122223333:stack/fixture-lab-migration/00000000-0000-0000-0000-000000000001"


class FakeDMS:
    class MissingCertificate(Exception):
        pass

    def __init__(self):
        self.exceptions = SimpleNamespace(ResourceNotFoundFault=self.MissingCertificate)
        self.tasks = []
        self.certificates = []
        self.stops = []
        self.deletes = []
        self.tags = [
            {"Key": "Environment", "Value": "HML"}, {"Key": "Project", "Value": "postgresql-migration-lab"},
            {"Key": "RunId", "Value": "fixture-lab"},
        ]

    def get_paginator(self, operation):
        def paginate(**kwargs):
            if operation == "describe_replication_tasks":
                if kwargs["Filters"] != [{"Name": "replication-instance-arn", "Values": [RI]}]:
                    raise AssertionError("Tasks must be filtered by exact bound RI ARN")
                return [{"ReplicationTasks": self.tasks}]
            if kwargs["Filters"] != [{"Name": "certificate-id", "Values": ["fixture-lab-rds-ca"]}]:
                raise AssertionError("Certificate lookup must use the exact approved identifier")
            return [{"Certificates": self.certificates}]
        return SimpleNamespace(paginate=paginate)

    def list_tags_for_resource(self, **kwargs):
        return {"TagList": self.tags}

    def stop_replication_task(self, **kwargs):
        self.stops.append(kwargs)

    def delete_certificate(self, **kwargs):
        self.deletes.append(kwargs)


class FakeDependencyCFN(FakeCFN):
    def __init__(self):
        super().__init__()
        self.stack["Outputs"] = [{"OutputKey": "ReplicationInstanceArn", "OutputValue": RI}]
        self.migration = None
        self.replication_detail = {"PhysicalResourceId": RI, "ResourceStatus": "CREATE_COMPLETE"}

    def describe_stacks(self, **kwargs):
        if kwargs["StackName"] == ARN:
            return {"Stacks": [self.stack]}
        if kwargs["StackName"] not in {MIGRATION, "fixture-lab-migration"}:
            raise AssertionError("Unexpected CloudFormation lookup")
        if self.migration is None:
            raise ClientError({"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks")
        return {"Stacks": [self.migration]}

    def describe_stack_resource(self, **kwargs):
        if kwargs != {"StackName": ARN, "LogicalResourceId": "ReplicationInstance"}:
            raise AssertionError("Unexpected resource lookup")
        return {"StackResourceDetail": self.replication_detail}


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.cfn = FakeCFN()
        FakeDateTime.current = dt.datetime(2026, 10, 15, 23, 45, tzinfo=dt.timezone.utc)
        self.patchers = [patch.dict(os.environ, ENV), patch.object(guard, "CFN", self.cfn), patch.object(guard.dt, "datetime", FakeDateTime)]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_before_expiry_does_not_delete(self):
        result = guard.handler({"operation": "evaluate"}, None)
        self.assertEqual(result["state"], "watching")
        self.assertEqual(self.cfn.deletes, [])

    def test_at_expiry_deletes_only_bound_arn_with_exact_role(self):
        FakeDateTime.current = dt.datetime(2026, 10, 18, 23, 45, tzinfo=dt.timezone.utc)
        result = guard.handler({"operation": "evaluate", "target": "other-stack"}, None)
        self.assertEqual(result["reason"], "ttl_expired")
        self.assertEqual(self.cfn.deletes[0]["StackName"], ARN)
        self.assertEqual(self.cfn.deletes[0]["RoleARN"], ENV["DELETION_ROLE_ARN"])
        self.assertNotIn("RetainResources", self.cfn.deletes[0])
        self.assertNotIn("DeletionMode", self.cfn.deletes[0])

    def test_probe_never_mutates_even_after_expiry(self):
        FakeDateTime.current = dt.datetime(2026, 10, 19, 0, 0, tzinfo=dt.timezone.utc)
        result = guard.handler({"operation": "probe"}, None)
        self.assertTrue(result["would_delete"])
        self.assertEqual(self.cfn.deletes, [])

    def test_tag_mismatch_blocks_delete(self):
        self.cfn.stack["Tags"][0]["Value"] = "PRD"
        with self.assertRaisesRegex(ValueError, "tags do not match"):
            guard.handler({"operation": "cleanup", "confirm_target_arn": ARN, "confirm_run_id": ENV["TARGET_RUN_ID"]}, None)
        self.assertEqual(self.cfn.deletes, [])

    def test_stack_id_mismatch_blocks_delete(self):
        self.cfn.stack["StackId"] = ARN + "-replacement"
        with self.assertRaisesRegex(ValueError, "different immutable"):
            guard.handler({"operation": "evaluate"}, None)
        self.assertEqual(self.cfn.deletes, [])

    def test_manual_cleanup_requires_both_confirmations(self):
        with self.assertRaisesRegex(ValueError, "Manual cleanup requires"):
            guard.handler({"operation": "cleanup", "confirm_target_arn": ARN}, None)
        self.assertEqual(self.cfn.deletes, [])
        result = guard.handler({"operation": "cleanup", "confirm_target_arn": ARN, "confirm_run_id": ENV["TARGET_RUN_ID"]}, None)
        self.assertEqual(result["reason"], "authorized_manual_cleanup")

    def test_recorded_cost_cutoff_deletes_before_ttl(self):
        with patch.dict(os.environ, {"BUDGET_NAME": "test-budget"}), patch.object(guard, "BUDGETS", FakeBudget()):
            result = guard.handler({"operation": "evaluate"}, None)
        self.assertEqual(result["reason"], "recorded_cost_cutoff")
        self.assertEqual(len(self.cfn.deletes), 1)

    def test_already_deleting_is_idempotent(self):
        self.cfn.stack["StackStatus"] = "DELETE_IN_PROGRESS"
        result = guard.handler({"operation": "evaluate"}, None)
        self.assertEqual(result["state"], "delete_in_progress")
        self.assertEqual(self.cfn.deletes, [])

    def test_termination_protection_is_not_bypassed(self):
        self.cfn.stack["EnableTerminationProtection"] = True
        with self.assertRaisesRegex(ValueError, "cannot bypass"):
            guard.handler({"operation": "evaluate"}, None)
        self.assertEqual(self.cfn.deletes, [])

    def test_expiry_longer_than_authorized_72_hours_is_rejected(self):
        with patch.dict(os.environ, {"EXPIRES_AT_UTC": "2026-10-20T23:45:00Z"}):
            with self.assertRaisesRegex(ValueError, "within 72 hours"):
                guard.handler({"operation": "evaluate"}, None)
        self.assertEqual(self.cfn.deletes, [])


class DependencyTests(GuardTests):
    def setUp(self):
        super().setUp()
        self.cfn = FakeDependencyCFN()
        self.dms = FakeDMS()
        self.more_patchers = [
            patch.object(guard, "CFN", self.cfn), patch.object(guard, "DMS", self.dms),
            patch.dict(os.environ, {"MIGRATION_STACK_NAME": "fixture-lab-migration", "MIGRATION_STACK_ARN": MIGRATION,
                "CERTIFICATE_IDENTIFIER": "fixture-lab-rds-ca", "CERTIFICATE_ARN": CERT, "REPLICATION_TASK_ARN": TASK}),
        ]
        for patcher in self.more_patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def cleanup_event(self):
        return {"operation": "cleanup", "confirm_target_arn": ARN, "confirm_run_id": ENV["TARGET_RUN_ID"]}

    def test_running_task_is_stopped_before_any_stack_delete(self):
        self.dms.tasks = [{"ReplicationTaskArn": TASK, "ReplicationInstanceArn": RI, "Status": "running"}]
        result = guard.handler(self.cleanup_event(), None)
        self.assertEqual(result["dependencies"]["state"], "tasks_stopping")
        self.assertEqual(self.dms.stops, [{"ReplicationTaskArn": TASK}])
        self.assertEqual(self.cfn.deletes, [])

    def test_dependent_stack_is_deleted_before_principal(self):
        self.dms.tasks = [{"ReplicationTaskArn": TASK, "ReplicationInstanceArn": RI, "Status": "stopped"}]
        self.cfn.migration = {"StackId": MIGRATION, "StackStatus": "CREATE_COMPLETE", "Tags": self.dms.tags}
        result = guard.handler(self.cleanup_event(), None)
        self.assertEqual(result["dependencies"]["state"], "migration_deleting")
        self.assertEqual(self.cfn.deletes[0]["StackName"], MIGRATION)
        self.assertEqual(len(self.cfn.deletes), 1)

    def test_certificate_is_deleted_only_after_migration_absent(self):
        self.dms.certificates = [{"CertificateArn": CERT, "CertificateIdentifier": "fixture-lab-rds-ca"}]
        result = guard.handler(self.cleanup_event(), None)
        self.assertEqual(result["dependencies"]["state"], "certificate_delete_requested")
        self.assertEqual(self.dms.deletes, [{"CertificateArn": CERT}])
        self.assertEqual(self.cfn.deletes, [])

    def test_dependency_probe_performs_no_writes(self):
        self.dms.tasks = [{"ReplicationTaskArn": TASK, "ReplicationInstanceArn": RI, "Status": "running"}]
        result = guard.handler({"operation": "probe"}, None)
        self.assertEqual(result["state"], "probe")
        self.assertEqual(self.cfn.deletes + self.dms.stops + self.dms.deletes, [])

    def test_task_with_wrong_tags_blocks_all_deletes(self):
        self.dms.tasks = [{"ReplicationTaskArn": TASK, "ReplicationInstanceArn": RI, "Status": "running"}]
        self.dms.tags[0]["Value"] = "PRD"
        with self.assertRaisesRegex(ValueError, "Resource tags do not match"):
            guard.handler(self.cleanup_event(), None)
        self.assertEqual(self.cfn.deletes + self.dms.stops + self.dms.deletes, [])

    def test_partial_failed_main_without_instance_can_delete(self):
        self.cfn.stack["StackStatus"] = "ROLLBACK_FAILED"
        self.cfn.stack["Outputs"] = []
        self.cfn.replication_detail = {"ResourceStatus": "DELETE_COMPLETE"}
        result = guard.handler(self.cleanup_event(), None)
        self.assertEqual(result["state"], "delete_requested")
        self.assertEqual(self.cfn.deletes[0]["StackName"], ARN)

    def test_partial_failed_main_with_instance_uses_exact_resource(self):
        self.cfn.stack["StackStatus"] = "ROLLBACK_FAILED"
        self.cfn.stack["Outputs"] = []
        result = guard.handler(self.cleanup_event(), None)
        self.assertEqual(result["state"], "delete_requested")
        self.assertEqual(self.cfn.deletes[0]["StackName"], ARN)


class RealSDKAbsenceTests(unittest.TestCase):
    """Use botocore's actual modeled exceptions, without AWS network calls."""

    def setUp(self):
        self.cfn = FakeDependencyCFN()
        self.dms = guard.DMS
        FakeDateTime.current = dt.datetime(2026, 10, 15, 23, 45, tzinfo=dt.timezone.utc)
        env = {**ENV, "MIGRATION_STACK_NAME": "fixture-lab-migration", "MIGRATION_STACK_ARN": MIGRATION,
            "CERTIFICATE_IDENTIFIER": "fixture-lab-rds-ca", "CERTIFICATE_ARN": CERT, "REPLICATION_TASK_ARN": TASK}
        for patcher in [patch.dict(os.environ, env), patch.object(guard, "CFN", self.cfn), patch.object(guard.dt, "datetime", FakeDateTime)]:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.stubber = Stubber(self.dms)
        self.stubber.activate()
        self.addCleanup(self.stubber.deactivate)
        self.task_parameters = {"Filters": [{"Name": "replication-instance-arn", "Values": [RI]}], "WithoutSettings": True}
        self.cert_parameters = {"Filters": [{"Name": "certificate-id", "Values": ["fixture-lab-rds-ca"]}]}

    def add_missing_tasks(self):
        self.stubber.add_client_error("describe_replication_tasks", service_error_code="ResourceNotFoundFault",
            service_message="No Tasks found matching provided filters", expected_params=self.task_parameters)

    def test_real_missing_tasks_and_certificate_are_absence_with_zero_writes(self):
        self.add_missing_tasks()
        self.stubber.add_client_error("describe_certificates", service_error_code="ResourceNotFoundFault",
            service_message="No certificates found", expected_params=self.cert_parameters)
        result = guard.handler({"operation": "probe"}, None)
        self.assertEqual(result["dependencies"]["state"], "dependencies_absent")
        self.assertEqual(self.cfn.deletes, [])
        self.stubber.assert_no_pending_responses()

    def test_real_task_access_denied_is_not_absence(self):
        self.stubber.add_client_error("describe_replication_tasks", service_error_code="AccessDeniedException",
            service_message="Access denied", expected_params=self.task_parameters)
        with self.assertRaises(ClientError) as raised:
            guard.handler({"operation": "probe"}, None)
        self.assertEqual(raised.exception.response["Error"]["Code"], "AccessDeniedException")
        self.assertEqual(self.cfn.deletes, [])
        self.stubber.assert_no_pending_responses()

    def test_real_certificate_access_denied_is_not_absence(self):
        self.add_missing_tasks()
        self.stubber.add_client_error("describe_certificates", service_error_code="AccessDeniedException",
            service_message="Access denied", expected_params=self.cert_parameters)
        with self.assertRaises(ClientError) as raised:
            guard.handler({"operation": "probe"}, None)
        self.assertEqual(raised.exception.response["Error"]["Code"], "AccessDeniedException")
        self.assertEqual(self.cfn.deletes, [])
        self.stubber.assert_no_pending_responses()

    def test_real_task_tag_not_found_is_not_describe_absence(self):
        self.stubber.add_response("describe_replication_tasks", {"ReplicationTasks": [
            {"ReplicationTaskArn": TASK, "ReplicationInstanceArn": RI, "Status": "running"}]}, self.task_parameters)
        self.stubber.add_client_error("list_tags_for_resource", service_error_code="ResourceNotFoundFault",
            service_message="Task changed during tag lookup", expected_params={"ResourceArn": TASK})
        with self.assertRaises(self.dms.exceptions.ResourceNotFoundFault):
            guard.handler({"operation": "probe"}, None)
        self.assertEqual(self.cfn.deletes, [])
        self.stubber.assert_no_pending_responses()

    def test_real_certificate_tag_not_found_is_not_describe_absence(self):
        self.add_missing_tasks()
        self.stubber.add_response("describe_certificates", {"Certificates": [
            {"CertificateArn": CERT, "CertificateIdentifier": "fixture-lab-rds-ca"}]}, self.cert_parameters)
        self.stubber.add_client_error("list_tags_for_resource", service_error_code="ResourceNotFoundFault",
            service_message="Certificate changed during tag lookup", expected_params={"ResourceArn": CERT})
        with self.assertRaises(self.dms.exceptions.ResourceNotFoundFault):
            guard.handler({"operation": "probe"}, None)
        self.assertEqual(self.cfn.deletes, [])
        self.stubber.assert_no_pending_responses()

if __name__ == "__main__":
    unittest.main()
