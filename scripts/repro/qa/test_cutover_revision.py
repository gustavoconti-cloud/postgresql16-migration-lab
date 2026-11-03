"""Offline cutover regressions with in-memory proofs, SQL doubles and a fixed clock.

Loads the actual harness AST without its platform/SDK imports. No harness
constructor, credentials, database, network or historical evidence is used.
"""
import ast
import contextlib
import copy
import datetime
import decimal
import hashlib
import json
import math
from pathlib import Path
import socket
import types
import unittest
from unittest.mock import Mock, patch


def refuse_network(*args, **kwargs):
    raise AssertionError("OFFLINE_CUTOVER_NETWORK_REFUSED")


socket.create_connection = refuse_network
socket.socket.connect = refuse_network
socket.socket.connect_ex = refuse_network

SOURCE = Path(__file__).resolve().parents[1] / "scripts/harness/lab_harness.py"
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
KEEP = {"VERSION", "DATABASE", "TABLE", "COLUMNS", "WRITERS", "READERS", "SEED", "DDL", "SELECT_ROWS", "INSERT_ROW"}
NODES = []
for node in TREE.body:
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        NODES.append(node)
    elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in KEEP for target in node.targets):
        NODES.append(node)
NS = {"__name__": "cutover_harness_under_test", "contextlib": contextlib,
      "dt": datetime, "decimal": decimal, "hashlib": hashlib, "json": json,
      "math": math, "Path": Path}
exec(compile(ast.Module(body=NODES, type_ignores=[]), str(SOURCE), "exec"), NS)
Harness, GateError = NS["Harness"], NS["GateError"]


class FixedClock(datetime.datetime):
    calls = 0

    @classmethod
    def now(cls, tz=None):
        cls.calls += 1
        return NOW if tz is None else NOW.astimezone(tz)


NOW = FixedClock(2030, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
CLOCK = types.SimpleNamespace(datetime=FixedClock, timezone=datetime.timezone, date=datetime.date)
METRICS = ("CDCIncomingChanges", "CDCLatencySource", "CDCLatencyTarget")


def stamp(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def point(age):
    return {"timestamp_utc": stamp(NOW - datetime.timedelta(seconds=age)),
            **{metric: {"Maximum": 0} for metric in METRICS}}


class CutoverRevisionTests(unittest.TestCase):
    def setUp(self):
        FixedClock.calls = 0
        self.clock = patch.dict(NS, {"dt": CLOCK})
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.lab = Harness.__new__(Harness)
        self.lab.run_id = "synthetic-cutover-run"
        self.lab.cfg = {"dms_task_arn": "arn:aws:dms:us-east-1:111122223333:task:SYNTHETICCUTOVER"}
        rows = [{"id": key, "note": "synthetic"} for key in (102, 106, 201, 901)]
        by_id = {row["id"]: row for row in rows}
        self.lab.state = {"pending_dml": None, "target_exclusive_commit": False,
                          "completed": {
                              "T01": {"before": [], "after": [by_id[201]]},
                              "T02": {"before": [], "after": [by_id[102]]},
                              "T03": {"before": [{"id": 103}], "after": []},
                              "T04-diverge": {},
                              "T04-correct": {"before": [], "after": [by_id[106]]},
                              "T05-marker-901": {"before": [], "after": [by_id[901]],
                                                 "commit_ack_utc": stamp(NOW - datetime.timedelta(seconds=400))}}}
        self.lab.dms_state = Mock(return_value={"Status": "running"})
        self.lab.native_table = Mock(return_value={
            "ValidationState": "Validated", "ValidationPendingRecords": 0,
            "ValidationFailedRecords": 0, "ValidationSuspendedRecords": 0,
            "FullLoadErrorRows": 0, "TableState": "Table completed",
            "LastUpdateTime": NOW - datetime.timedelta(seconds=20)})
        self.lab.assert_frozen = Mock(return_value={})
        self.lab.negative_write = Mock(return_value={})
        self.lab.compare = Mock(return_value={"content_equal": True, "catalog_equal": True,
            "source": {"ids": sorted(by_id), "rows": rows, "sha256": "synthetic-content-digest"},
            "source_catalog": {"primary_key": ["id"]}})
        self.lab.event = Mock()
        self.lab.set_writer = Mock(return_value={"synthetic_grant": True})
        self.lab.dml = Mock(return_value={"test": "T07-return-write", "after": [{"id": 211}]})
        self.proof = {
            "checked_at_utc": stamp(NOW - datetime.timedelta(seconds=30)),
            "run_id": self.lab.run_id, "task_arn": self.lab.cfg["dms_task_arn"],
            "incoming_changes_zero": True, "latencies_stable": True, "logs_checked": True,
            "no_blocking_errors": True, "metrics_fresh_samples": 2,
            "evidence_ids": ["synthetic-evidence.json"],
            "final_revalidation_requested_at_utc": stamp(NOW - datetime.timedelta(seconds=25)),
            "native_revalidation_evidence_id": "synthetic-native.json",
            "divergence_native_failed": True, "divergence_detected_evidence_id": "synthetic-difference.json",
            "divergence_native_failure_evidence_id": "synthetic-failure.json", "marker_id": 901,
            "selected_metric_points": [point(180), point(120)]}

    def record(self):
        proof_bytes = json.dumps(self.proof).encode("utf-8")
        memory_path = Mock(return_value=types.SimpleNamespace(read_bytes=lambda: proof_bytes))
        with patch.dict(NS, {"Path": memory_path}):
            return self.lab.record_g6("memory-only-proof.json")

    def assert_rejected_without_approval(self):
        before = copy.deepcopy(self.lab.state)
        with self.assertRaises(GateError):
            self.record()
        self.assertEqual(self.lab.state, before)
        self.lab.event.assert_not_called()

    def historical_return(self):
        receipt = {"after": [{"id": 211}], "commit_ack_utc": "synthetic-historical-UTC"}
        self.lab.state["completed"]["T07-return-write"] = receipt
        self.lab.rows = Mock(return_value={"rows": [{"id": 211}]})
        self.lab.dms_state.return_value = {"Status": "stopped"}
        return receipt

    def test_both_fresh_share_the_exact_approval_instant_and_audit_ages(self):
        result = self.record()["g6"]
        self.assertEqual(FixedClock.calls, 1)
        self.assertEqual(result["approved_at_utc"], stamp(NOW))
        self.assertEqual(result["metric_freshness"]["checked_at_utc"], result["approved_at_utc"])
        self.assertEqual([p["age_seconds"] for p in result["metric_freshness"]["selected_samples"]], [180, 120])
        self.assertEqual(result["metric_freshness"]["maximum_age_seconds"], 240)
        self.assertEqual(result["metric_freshness"]["maximum_future_skew_seconds"], 5)
        self.assertEqual(result["proof_age_seconds"], 30)
        self.lab.event.assert_called_once_with("g6_approved", marker_id=901,
            approved_at_utc=result["approved_at_utc"], metric_freshness=result["metric_freshness"])

    def test_fresh_when_generated_but_stale_at_approval_is_rejected(self):
        self.proof["checked_at_utc"] = stamp(NOW - datetime.timedelta(seconds=100))
        self.proof["selected_metric_points"] = [point(241), point(181)]
        self.assertLess(241 - 100, 240)
        self.assert_rejected_without_approval()

    def test_three_stale_age_profiles_are_synthetic_regressions(self):
        for oldest, proof_age in [(294.048843, 71.076696), (242.732685, 49.401340), (275.094380, 98.612391)]:
            with self.subTest(oldest_age=oldest):
                self.proof["checked_at_utc"] = stamp(NOW - datetime.timedelta(seconds=proof_age))
                self.proof["selected_metric_points"] = [point(oldest), point(oldest - 60)]
                self.assert_rejected_without_approval()

    def test_one_expired_sample_cannot_hide_behind_a_fresh_sample(self):
        self.proof["selected_metric_points"] = [point(240.000001), point(180)]
        self.assert_rejected_without_approval()

    def test_exact_240_second_boundary_passes(self):
        self.proof["selected_metric_points"] = [point(240), point(180)]
        self.assertEqual(self.record()["g6"]["metric_freshness"]["selected_samples"][0]["age_seconds"], 240)

    def test_fresh_synthetic_profile_remains_acceptable(self):
        self.proof["selected_metric_points"] = [point(232.541167), point(172.541167)]
        self.assertEqual(len(self.record()["g6"]["metric_freshness"]["selected_samples"]), 2)

    def test_exact_future_skew_boundary_passes(self):
        self.proof["selected_metric_points"] = [point(180), point(-5)]
        self.assertEqual(self.record()["g6"]["metric_freshness"]["selected_samples"][-1]["age_seconds"], -5)

    def test_future_beyond_five_seconds_is_rejected(self):
        self.proof["selected_metric_points"] = [point(180), point(-5.000001)]
        self.assert_rejected_without_approval()

    def test_missing_or_wrong_point_population_is_rejected(self):
        for value in [None, {}, [], [point(120)], [point(180), point(120), point(60)]]:
            with self.subTest(value_type=type(value).__name__):
                self.proof["selected_metric_points"] = value
                self.assert_rejected_without_approval()
        self.proof.pop("selected_metric_points")
        self.assert_rejected_without_approval()

    def test_missing_malformed_and_naive_timestamps_are_rejected(self):
        for value in [None, True, 123, "", "invalid", "2030-01-02T03:04:00"]:
            with self.subTest(value=value):
                self.proof["selected_metric_points"] = [point(180), {**point(120), "timestamp_utc": value}]
                self.assert_rejected_without_approval()
        self.proof["selected_metric_points"] = [point(180), {k: v for k, v in point(120).items() if k != "timestamp_utc"}]
        self.assert_rejected_without_approval()

    def test_duplicate_normalized_timestamps_are_rejected(self):
        self.proof["selected_metric_points"] = [point(180), point(180)]
        self.assert_rejected_without_approval()
        self.proof["selected_metric_points"][1]["timestamp_utc"] = (NOW - datetime.timedelta(seconds=180)).astimezone(datetime.timezone(datetime.timedelta(hours=-5))).isoformat()
        self.assert_rejected_without_approval()

    def test_each_point_requires_all_three_valid_metric_maxima(self):
        for metric in METRICS:
            self.proof["selected_metric_points"] = [point(180), point(120)]
            del self.proof["selected_metric_points"][0][metric]
            self.assert_rejected_without_approval()
        for value in [None, True, "0", -1, float("nan"), float("inf")]:
            with self.subTest(value=value):
                self.proof["selected_metric_points"] = [point(180), point(120)]
                self.proof["selected_metric_points"][0][METRICS[0]]["Maximum"] = value
                self.assert_rejected_without_approval()

    def test_proof_ttl_600_remains_an_additional_guard(self):
        self.proof["checked_at_utc"] = stamp(NOW - datetime.timedelta(seconds=600.000001))
        self.assert_rejected_without_approval()

    def test_pending_target_outcome_blocks_historical_return_before_reads(self):
        self.historical_return()
        self.lab.state["pending_dml"] = {"test": "T08-insert", "side": "target"}
        before = copy.deepcopy(self.lab.state)
        with self.assertRaises(GateError):
            self.lab.prewrite_return()
        self.assertEqual(self.lab.state, before)
        self.lab.dms_state.assert_not_called()
        self.lab.assert_frozen.assert_not_called()
        self.lab.rows.assert_not_called()
        self.lab.set_writer.assert_not_called()
        self.lab.dml.assert_not_called()
        self.lab.event.assert_not_called()

    def test_pending_without_t07_cannot_open_the_source_before_dml_guard(self):
        self.lab.state["pending_dml"] = {"test": "T08-insert", "side": "target"}
        self.lab.check_stopped_g6 = Mock(return_value={"synthetic_marker": 901})
        with self.assertRaises(GateError):
            self.lab.prewrite_return()
        self.lab.check_stopped_g6.assert_not_called()
        self.lab.set_writer.assert_not_called()
        self.lab.dml.assert_not_called()
        self.lab.event.assert_not_called()

    def test_known_exclusive_commit_remains_blocked(self):
        self.historical_return()
        self.lab.state["target_exclusive_commit"] = True
        with self.assertRaises(GateError):
            self.lab.prewrite_return()
        self.lab.dms_state.assert_not_called()
        self.lab.set_writer.assert_not_called()
        self.lab.dml.assert_not_called()

    def test_clean_idempotent_readback_is_explicitly_historical_and_read_only(self):
        receipt = self.historical_return()
        before = copy.deepcopy(self.lab.state)
        result = self.lab.prewrite_return()
        self.assertEqual(self.lab.state, before)
        self.assertTrue(result["idempotent_readback"])
        self.assertTrue(result["historical_only"])
        self.assertFalse(result["current_return_authorized"])
        self.assertEqual(result["receipt_scope"], "historical_T07_return_commit")
        self.assertEqual(result["return_commit"], receipt)
        self.lab.set_writer.assert_not_called()
        self.lab.dml.assert_not_called()
        self.lab.event.assert_not_called()

    def test_historical_readback_still_rejects_an_open_target(self):
        self.historical_return()
        self.lab.assert_frozen.side_effect = GateError("Synthetic target writer is open.")
        with self.assertRaises(GateError):
            self.lab.prewrite_return()
        self.lab.set_writer.assert_not_called()
        self.lab.dml.assert_not_called()

    def test_legitimate_first_t07_transition_is_preserved(self):
        self.lab.state["g6"] = {"marker_id": 901}
        self.lab.check_stopped_g6 = Mock(return_value={"synthetic_gate": 901})
        self.lab.connection = Mock(side_effect=lambda side: contextlib.nullcontext(side))
        self.lab.identity = Mock(side_effect=lambda connection, side, username: {"side": side, "username": username})
        result = self.lab.prewrite_return()
        self.lab.check_stopped_g6.assert_called_once_with(901)
        self.lab.set_writer.assert_called_once_with("source", True)
        self.lab.dml.assert_called_once()
        self.assertEqual(self.lab.dml.call_args.args[:2], ("T07-return-write", "source"))
        self.assertNotIn("g6", self.lab.state)
        self.assertEqual(result["return_commit"], self.lab.dml.return_value)
        self.assertIn("Declared smoke-test failure", result["simulated_failure"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
