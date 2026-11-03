"""Synthetic fixtures only: never laboratory evidence or an approved G6."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("proof", HERE.parent / "make_g6_proof.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
RUN = "fixture-r01"
TASK = "arn:aws:dms:us-east-1:111122223333:task:TESTONLY"
NOW = datetime(2026, 10, 16, 1, 2, 30, tzinfo=timezone.utc)

def at(clock):
    return "2026-10-16T" + clock + "Z"

def env(command, data, clock):
    return {"success": True, "run_id": RUN, "command": command, "data": data,
            "evidence_kind": "observed", "finished_at_utc": at(clock),
            "aws_identity": {"account": "111122223333", "region": "us-east-1"}}

def freeze(side):
    return {"role_report": {"side": side, "roles": [{"rolname": "lab_writer_" + side,
        **{k: False for k in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls")}}],
        "memberships": [], "writer_sessions": [], "owners": {"schema_owner": "admin", "table_owner": "admin"},
        "writer_privileges": {k: False for k in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")},
        "column_writes": [{"attname": k, "can_insert": False, "can_update": False} for k in ("id", "customer_label", "status", "amount", "revision", "note")]},
        "negative_probe": {"passed": True, "sqlstate": "42501", "attempt_succeeded": False,
            "rollback_confirmed": True, "identity": {"side": side, "username": "lab_writer_" + side}}}

def native(failed, clock):
    return {"time": at(clock), "action": "inspect", "result": {
        "task": {"ReplicationTaskArn": TASK, "Status": "running"},
        "tables": {"ReplicationTaskArn": TASK, "TableStatistics": [{"SchemaName": "lab", "TableName": "orders_lab",
            "ValidationState": "Failed" if failed else "Validated", "ValidationPendingRecords": 0,
            "ValidationFailedRecords": failed, "ValidationSuspendedRecords": 0, "FullLoadErrorRows": 0,
            "TableState": "Table completed", "LastUpdateTime": at(clock)}]}}}

def fixture():
    row = {"id": 901, "note": "fixture-only"}
    comparison = {"counts_equal": True, "totals_equal": True, "content_equal": False,
        "source": {"row_count": 8, "amount_total": "937.31"}, "target": {"row_count": 8, "amount_total": "937.31"},
        "differences": [{"id": 106, "kind": "column", "column": "note", "source": "a", "target": "b"}]}
    docs = {
        "marker_evidence": env("marker-901", {"test": "T05-marker-901", "side": "source", "before": [], "after": [row], "commit_ack_utc": at("01:00:00")}, "01:00:01"),
        "source_freeze_evidence": env("freeze-source", freeze("source"), "01:00:10"),
        "target_freeze_evidence": env("freeze-target", freeze("target"), "01:00:20"),
        "marker_observe_evidence": env("observe", {"test": "T05-marker-901", "row_id": 901, "target_rows": [row], "commit_ack_utc": at("01:00:00"), "first_observation_utc": at("01:00:30")}, "01:00:30"),
        "revalidation_request": {"time": at("01:00:40"), "action": "revalidate", "result": {"ReplicationTaskArn": TASK}},
        "native_readback": native(0, "01:00:50"),
        "divergence_comparison": env("compare", comparison, "00:56:30"),
        "t04_revalidation_request": {"time": at("00:56:00"), "action": "revalidate", "result": {"ReplicationTaskArn": TASK}},
        "native_divergence_failure": native(1, "00:57:00"),
        "metrics_readback": {"time": at("01:02:25"), "action": "metrics", "result": {
            "dimensions": [{"Name": "ReplicationInstanceIdentifier", "Value": "fixture-lab-dms"}, {"Name": "ReplicationTaskIdentifier", "Value": "TESTONLY"}],
            "metrics": {m: {"Datapoints": [{"Timestamp": at(t), "Maximum": 0.0} for t in ("01:01:00", "01:02:00")]} for m in M.METRICS}}},
        "logs_readback": {"time": at("01:02:25"), "task_arn": TASK, "group": "dms-tasks-fixture-lab-dms", "stream": "dms-task-TESTONLY", "start_time_ms": int(M.stamp(at("01:00:05")).timestamp()*1000), "end_time_ms": int(M.stamp(at("01:02:20")).timestamp()*1000), "pagination_complete": True, "events": [{"message": "fixture-only normal event"}], "error_candidates": []},
    }
    manifest = {"run_id": RUN, "task_arn": TASK, "marker_id": 901, **{k: "r01-" + k + ".json" for k in M.FILES}}
    return manifest, docs

class Tests(unittest.TestCase):
    def run_case(self, mutate=None, now=NOW):
        manifest, docs = fixture()
        if mutate:
            mutate(manifest, docs)
        with tempfile.TemporaryDirectory(prefix="fixtures-", dir=HERE) as directory:
            for key, data in docs.items():
                (Path(directory) / manifest[key]).write_text(json.dumps(data), encoding="utf-8")
            return M.validate(manifest, directory, now)

    def test_good_fixture_is_deterministic(self):
        proof = self.run_case()
        self.assertEqual(proof, self.run_case())
        self.assertEqual(proof["metrics_fresh_samples"], 2)
        self.assertEqual(len(proof["evidence_sha256"]), 11)

    def test_reject_missing_counter(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["native_readback"]["result"]["tables"]["TableStatistics"][0].pop("ValidationPendingRecords"))

    def test_reject_wrong_run(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["source_freeze_evidence"].update(run_id="FOREIGN-RUN"))

    def test_reject_wrong_metric_dimension(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["metrics_readback"]["result"]["dimensions"][1].update(Value="OTHER"))

    def test_reject_unshared_metric_samples(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["metrics_readback"]["result"]["metrics"]["CDCLatencySource"]["Datapoints"].pop())

    def test_reject_logs_with_hidden_errors(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["logs_readback"]["events"].append({"message": "[E] fixture-only error"}))

    def test_reject_stale_metrics(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["metrics_readback"].update(time=at("00:50:00")))

    def test_reject_real_dms_error_format_with_empty_candidates(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["logs_readback"]["events"].append({"message": "[TARGET_APPLY    ]E: Failed to execute statement"}))

    def test_reject_stale_first_sample_with_fresh_last_sample(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(now=NOW + timedelta(minutes=3))

    def test_reject_incomplete_log_pagination(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["logs_readback"].update(pagination_complete=False))

    def test_reject_legacy_logs_without_completeness(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["logs_readback"].pop("pagination_complete"))

    def test_reject_log_window_before_last_metric(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["logs_readback"].update(end_time_ms=int(M.stamp(at("01:01:59")).timestamp()*1000)))

    def test_reject_native_failure_after_final_marker(self):
        with self.assertRaises(M.InvalidProof):
            self.run_case(lambda m,d: d["native_divergence_failure"]["result"]["tables"]["TableStatistics"][0].update(LastUpdateTime=at("01:00:10")))

if __name__ == "__main__":
    unittest.main()
