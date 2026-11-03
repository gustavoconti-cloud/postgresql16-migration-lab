"""Offline semantic checks for verification gates and deterministic math."""
import json
import unittest
from datetime import datetime, timezone, timedelta
from decimal import Decimal as D
from pathlib import Path
import verify_cleanup as inventory
import estimate_runtime_cost as cost
import verify_tags as tags
from botocore.exceptions import ClientError
from types import SimpleNamespace


class SafetyTests(unittest.TestCase):
    def test_secret_projection_excludes_values(self):
        row = {"ARN": "arn:test", "Name": "metadata", "SecretString": "sentinel", "Password": "sentinel"}
        self.assertEqual(inventory.project(row, ("ARN", "Name")), {"ARN": "arn:test", "Name": "metadata"})

    def test_write_operation_refused_before_client_creation(self):
        query = inventory.Query("deny", "ec2", "delete_vpc", {}, "Vpcs", ())
        with self.assertRaises(ValueError):
            inventory.perform(query, {})

    def test_secret_value_operation_refused(self):
        query = inventory.Query("deny", "secretsmanager", "get_secret_value", {}, "SecretString", ())
        with self.assertRaises(ValueError):
            inventory.perform(query, {})

    def test_auth_error_never_counts_as_absence(self):
        query = inventory.Query("instance", "ec2", "describe_instances", {}, "Reservations.Instances", ())
        error = ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "permission"}}, "DescribeInstances")
        self.assertFalse(inventory.absent_error(error, query))

    def test_only_terminated_instance_is_retired(self):
        query = inventory.Query("instance", "ec2", "describe_instances", {}, "Reservations.Instances", ())
        self.assertFalse(inventory.live({"State": {"Name": "terminated"}}, query))
        self.assertTrue(inventory.live({"State": {"Name": "stopped"}}, query))

    def test_pending_secret_deletion_remains_residual(self):
        query = inventory.Query("secret", "secretsmanager", "describe_secret", {}, "_whole", ())
        self.assertTrue(inventory.live({"DeletedDate": "future"}, query))

    def test_discovered_ids_survive_tag_and_instance_removal(self):
        manifest = {"discovered": {"ebs_volume_ids": ["vol-old"]}}
        results = [{"rows": [{"DbiResourceId": "db-immutable", "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-new"}}]}]}]
        inventory.preserve_discovered(manifest, results)
        self.assertEqual(manifest["discovered"]["ebs_volume_ids"], ["vol-new", "vol-old"])
        self.assertEqual(manifest["discovered"]["rds_dbi_resource_ids"], ["db-immutable"])

    def test_global_iam_region_is_valid(self):
        query = inventory.Query("role", "iam", "get_role", {"RoleName": "example"}, "Role", ("RoleName",))
        client = SimpleNamespace(meta=SimpleNamespace(region_name="aws-global"), can_paginate=lambda _: False, get_role=lambda **_: {"Role": {"RoleName": "example"}})
        self.assertEqual(inventory.perform(query, {"iam": client}), [{"RoleName": "example"}])

    def test_global_region_not_allowed_for_regional_resource(self):
        query = inventory.Query("instance", "ec2", "describe_instances", {}, "Reservations.Instances", ())
        client = SimpleNamespace(meta=SimpleNamespace(region_name="aws-global"))
        with self.assertRaises(ValueError):
            inventory.perform(query, {"ec2": client})

    def test_no_automated_backup_is_absence(self):
        query = inventory.Query("backup", "rds", "describe_db_instance_automated_backups", {}, "DBInstanceAutomatedBackups", ())
        error = ClientError({"Error": {"Code": "DBInstanceAutomatedBackupNotFound", "Message": "No backups"}}, "DescribeDBInstanceAutomatedBackups")
        self.assertTrue(inventory.absent_error(error, query))


class CostTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 10, 15, tzinfo=timezone.utc)
        path = Path(__file__).resolve().parents[2] / "rates" / "cost-scenarios.json"
        self.rates = json.loads(path.read_text(encoding="utf-8"))["rates"]

    def test_positive_fraction_rounds_up(self):
        result = cost.calculate(self.start, self.start + timedelta(seconds=1), self.rates, D("0"), D("0"))
        self.assertEqual(result["rounded_component_hours"], "1")
        self.assertEqual(result["component_usd"]["One interface endpoint in one AZ"], "0.01")

    def test_72h_independent_formula(self):
        result = cost.calculate(self.start, self.start + timedelta(hours=72), self.rates, D("0"), D("0"))
        expected = D("72") * (D("0.0209") + D("0.032") + D("0.0745") + D("0.045") + D("0.005") + D("0.01")) + D("72") * (D("20") * D("0.08") + D("20") * D("0.115") + D("4") * D("0.40")) / D("730")
        self.assertEqual(result["base_runtime_usd"], cost.usd(expected))
        self.assertEqual(result["conservative_runtime_envelope_usd"], cost.usd(expected + D("72") * D("0.3") + D("20")))

    def test_invalid_durations_and_negative_data_refused(self):
        with self.assertRaises(ValueError):
            cost.calculate(self.start, self.start, self.rates, D("0"), D("0"))
        with self.assertRaises(ValueError):
            cost.calculate(self.start, self.start + timedelta(hours=1), self.rates, D("-1"), D("0"))


class TagAuditTests(unittest.TestCase):
    def test_diff_does_not_touch_reserved_or_guardduty_tags(self):
        current = {"GuardDutyManaged": "true", "aws:cloudformation:stack-name": "lab"}
        diff = tags.missing_tags(current, {"Environment": "HML"})
        self.assertEqual(diff, {"Environment": {"before": None, "after": "HML", "kind": "missing"}})
        self.assertEqual(current["GuardDutyManaged"], "true")

    def test_existing_wrong_tag_is_a_mismatch(self):
        diff = tags.missing_tags({"Environment": "hml"}, {"Environment": "HML"})
        self.assertEqual(diff["Environment"]["kind"], "mismatch")

    def test_tag_write_is_not_in_read_allowlist(self):
        with self.assertRaises(ValueError):
            tags.request({}, "dms", "add_tags_to_resource", {})

    def test_non_queue_resource_maps_without_queue_url(self):
        spec = tags.target_for_cfn({"ResourceType": "AWS::RDS::DBInstance", "PhysicalResourceId": "lab-db"})
        self.assertEqual(spec[0], "rds")


if __name__ == "__main__":
    unittest.main()
