#!/usr/bin/python3
"""One-table PostgreSQL migration checks. Resolve secrets before this process."""
import argparse
import contextlib
import datetime as dt
import decimal
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import encrypt_password
from psycopg2.extras import RealDictCursor

VERSION = "1.1.0"
DATABASE = "migration_lab"
TABLE = "lab.orders_lab"
COLUMNS = ["id", "customer_label", "status", "amount", "revision", "note"]
WRITERS = {"source": "lab_writer_source", "target": "lab_writer_target"}
READERS = {"source": "lab_reader_source", "target": "lab_reader_target"}
ENV_KEYS = ["LAB_SOURCE_DMS_PASSWORD", "LAB_TARGET_DMS_PASSWORD", "LAB_CLIENT_PASSWORD",
            "LAB_RDS_MASTER_PASSWORD", "LAB_RDS_MASTER_USERNAME"]
SEED = [
    [101, "cliente-101", "new", "101.10", 1, "ação-validada"],
    [102, "cliente-102", "new", "102.20", 1, "atualizar-status"],
    [103, "cliente-103", "new", "103.30", 1, "excluir-no-cdc"],
    [104, "cliente-104", "new", "104.40", 1, "atualizar-pos-corte"],
    [105, "cliente-105", "new", "105.50", 1, "excluir-pos-corte"],
    [106, "cliente-106", "new", "106.60", 1, "referência-íntegra"],
    [107, "cliente-107", "new", "107.70", 1, ""],
    [108, "cliente-108", "new", "108.80", 1, None],
]
DDL = """CREATE TABLE lab.orders_lab (
 id integer PRIMARY KEY,
 customer_label varchar(64) NOT NULL,
 status varchar(32) NOT NULL,
 amount numeric(12,2) NOT NULL,
 revision integer NOT NULL,
 note varchar(160)
)"""
SELECT_ROWS = "SELECT id, customer_label, status, amount, revision, note FROM lab.orders_lab ORDER BY id"
INSERT_ROW = "INSERT INTO lab.orders_lab (id, customer_label, status, amount, revision, note) VALUES (%s,%s,%s,%s,%s,%s)"


class GateError(Exception):
    """Only fixed, credential-free explanations may be put in this exception."""


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def metric_freshness_at_approval(proof, approved_at):
    """Check the two shared metric points at the actual approval instant."""
    metrics = ("CDCIncomingChanges", "CDCLatencySource", "CDCLatencyTarget")
    points = proof.get("selected_metric_points")
    if not isinstance(points, list) or len(points) != 2:
        raise GateError("Approval requires exactly two shared metric points.")
    timestamps, samples = set(), []
    for point in points:
        if not isinstance(point, dict) or not isinstance(point.get("timestamp_utc"), str):
            raise GateError("A selected metric timestamp is missing or malformed.")
        try:
            timestamp = dt.datetime.fromisoformat(point["timestamp_utc"].replace("Z", "+00:00"))
            if timestamp.utcoffset() is None:
                raise ValueError("timezone required")
            timestamp = timestamp.astimezone(dt.timezone.utc)
        except (ValueError, TypeError, OverflowError):
            raise GateError("A selected metric timestamp is missing or malformed.") from None
        if timestamp in timestamps:
            raise GateError("The selected metric timestamps must be distinct.")
        timestamps.add(timestamp)
        for metric in metrics:
            reading = point.get(metric)
            value = reading.get("Maximum") if isinstance(reading, dict) else None
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise GateError("Each shared timestamp requires all three valid metric maxima.")
        age = (approved_at - timestamp).total_seconds()
        if age < -5 or age > 240:
            raise GateError("A selected metric sample is stale or future at approval.")
        samples.append({"timestamp_utc": timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                        "age_seconds": age})
    return {"checked_at_utc": approved_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "maximum_age_seconds": 240, "maximum_future_skew_seconds": 5,
            "shared_distinct_samples": 2, "metrics": list(metrics),
            "selected_samples": sorted(samples, key=lambda sample: sample["timestamp_utc"])}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=json_value)


def json_value(value):
    if isinstance(value, decimal.Decimal):
        return format(value, "f")
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    raise TypeError(type(value).__name__)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def rows_from_seed():
    return [dict(zip(COLUMNS, row)) for row in SEED]


def write_private(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        os.chmod(temporary, 0o600)
        handle.write(canonical(value) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


class Harness:
    def __init__(self, cfg, secrets):
        self.cfg, self.secrets = cfg, secrets
        if cfg.get("region") != "us-east-1" or cfg.get("database", DATABASE) != DATABASE:
            raise GateError("Only us-east-1 and migration_lab are authorized.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", cfg.get("run_id", "")):
            raise GateError("run_id must be a short, explicit identifier.")
        self.run_id = cfg["run_id"]
        self.source_ip = str(ipaddress.IPv4Address(cfg["source_host"]))
        self.target_host = cfg["rds_endpoint"]
        if not self.target_host.endswith(".us-east-1.rds.amazonaws.com"):
            raise GateError("The RDS DNS endpoint must belong to us-east-1.")
        self.account = cfg["expected_account_id"]
        for key in ("source_secret_arn", "target_secret_arn", "client_secret_arn", "master_secret_arn"):
            arn = cfg.get(key, "").split(":")
            if len(arn) < 7 or arn[2:5] != ["secretsmanager", "us-east-1", self.account]:
                raise GateError("All four secret identifiers must bind to the authorized account and region.")
        session = boto3.Session(region_name="us-east-1")
        client_config = Config(connect_timeout=5, read_timeout=15,
                               retries={"mode": "standard", "total_max_attempts": 3})
        identity = session.client("sts", config=client_config).get_caller_identity()
        if identity["Account"] != self.account:
            raise GateError("Effective AWS account differs from the authorized account.")
        self.aws_identity = {"account": identity["Account"], "principal_arn": identity["Arn"], "region": "us-east-1"}
        self.dms = session.client("dms", config=client_config)
        self.state_dir = Path(cfg.get("state_dir", "/opt/pg-lab/state"))
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        self.state_path = self.state_dir / (self.run_id + ".json")
        self.state = json.loads(self.state_path.read_text(encoding="utf-8")) if self.state_path.exists() else {
            "run_id": self.run_id, "version": VERSION, "events": [], "completed": {},
            "target_exclusive_commit": False,
        }
        if self.state["run_id"] != self.run_id:
            raise GateError("The ledger belongs to another run.")

    def event(self, kind, **data):
        self.state["events"].append({"at_utc": utc(), "kind": kind, **data})
        write_private(self.state_path, self.state)

    def password(self, key):
        value = self.secrets.get(key)
        if not value or value.startswith("{{resolve:"):
            raise GateError("A required secret environment reference was not resolved at runtime.")
        return value

    def connect(self, side, identity="reader", database=DATABASE):
        if side == "source" and identity == "admin":
            old_uid = os.geteuid()
            try:
                if old_uid == 0:
                    os.seteuid(pwd.getpwnam("postgres").pw_uid)
                connection = psycopg2.connect(host="/var/run/postgresql", dbname=database, user="postgres",
                    connect_timeout=10, application_name="pg-lab-admin-" + self.run_id)
            finally:
                if os.geteuid() != old_uid:
                    os.seteuid(old_uid)
        else:
            user = (WRITERS if identity == "writer" else READERS)[side]
            password_key = "LAB_CLIENT_PASSWORD"
            if identity == "admin":
                user = self.password("LAB_RDS_MASTER_USERNAME")
                password_key = "LAB_RDS_MASTER_PASSWORD"
            kwargs = {"host": "127.0.0.1" if side == "source" else self.target_host,
                      "port": 5432, "dbname": database, "user": user,
                      "password": self.password(password_key), "connect_timeout": 10,
                      "application_name": "pg-lab-" + side + "-" + identity + "-" + self.run_id,
                      "sslmode": "require" if side == "source" else "verify-full"}
            if side == "target":
                kwargs["sslrootcert"] = self.cfg["rds_ca_path"]
            connection = psycopg2.connect(**kwargs)
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute("SET statement_timeout = '30s'")
            cursor.execute("SET lock_timeout = '5s'")
            cursor.execute("SET idle_in_transaction_session_timeout = '30s'")
            cursor.execute("SET TIME ZONE 'UTC'")
            cursor.execute("SET client_encoding = 'UTF8'")
        return connection

    @contextlib.contextmanager
    def connection(self, side, identity="reader", database=DATABASE):
        connection = self.connect(side, identity, database)
        try:
            yield connection
        finally:
            connection.close()

    @staticmethod
    def query(connection, statement, parameters=None):
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(statement, parameters)
            return [dict(row) for row in cursor.fetchall()] if cursor.description else {"rowcount": cursor.rowcount}

    def identity(self, connection, side, expected_user):
        row = self.query(connection, """SELECT current_database() AS database, current_user AS username,
            inet_server_addr()::text AS server_address, inet_server_port() AS server_port,
            current_setting('server_version') AS server_version, pg_backend_pid() AS backend_pid,
            clock_timestamp() AS server_utc""")[0]
        if row["database"] != DATABASE or row["username"] != expected_user or not row["server_version"].startswith("16."):
            raise GateError("Database, login, or PostgreSQL major did not match the intended endpoint.")
        ssl = self.query(connection, "SELECT ssl, version, cipher, bits FROM pg_stat_ssl WHERE pid=pg_backend_pid()")[0]
        if expected_user != "postgres" and not ssl["ssl"]:
            raise GateError("A network database connection did not negotiate TLS.")
        return {"side": side, **row, "tls": ssl,
                "client_sslmode": "local-peer" if expected_user == "postgres" else ("require" if side == "source" else "verify-full")}

    def dms_state(self, required=None):
        task_arn = self.cfg.get("dms_task_arn")
        if not task_arn:
            raise GateError("dms_task_arn must be configured before test phases.")
        parts = task_arn.split(":")
        if len(parts) < 7 or parts[2:5] != ["dms", "us-east-1", self.account]:
            raise GateError("The DMS task must bind to the authorized account and region.")
        tasks = self.dms.describe_replication_tasks(Filters=[{"Name": "replication-task-arn", "Values": [task_arn]}],
                                                  WithoutSettings=True)["ReplicationTasks"]
        if len(tasks) != 1:
            raise GateError("Exactly one bound DMS task must exist.")
        task = tasks[0]
        if required and task["Status"] != required:
            raise GateError("The DMS task is not in the state required for this operation.")
        result = {key: task.get(key) for key in ("ReplicationTaskArn", "Status", "RecoveryCheckpoint", "StopReason")}
        result["has_last_failure_message"] = bool(task.get("LastFailureMessage"))
        return result

    def native_table(self):
        paginator = self.dms.get_paginator("describe_table_statistics")
        rows = [row for page in paginator.paginate(ReplicationTaskArn=self.cfg["dms_task_arn"])
                for row in page["TableStatistics"]]
        matching = [row for row in rows if row.get("SchemaName") == "lab" and row.get("TableName") == "orders_lab"]
        if len(rows) != 1 or len(matching) != 1:
            raise GateError("DMS statistics must contain exactly the selected table.")
        return matching[0]

    def rows(self, side):
        with self.connection(side) as connection:
            identity = self.identity(connection, side, READERS[side])
            data = self.query(connection, SELECT_ROWS)
        # Decimal is always a fixed-point string; None stays JSON null and "" stays empty.
        data = json.loads(canonical(data))
        return {"identity": identity, "observed_at_utc": utc(), "columns": COLUMNS,
                "rows": data, "row_count": len(data), "ids": [row["id"] for row in data],
                "amount_total": format(sum((decimal.Decimal(row["amount"]) for row in data), decimal.Decimal("0.00")), ".2f"),
                "serialization": "UTF-8; sorted keys; compact JSON; explicit columns; PK order; decimal fixed-point strings; JSON null",
                "sha256": digest(data)}

    def catalog(self, side):
        with self.connection(side) as connection:
            columns = self.query(connection, """SELECT a.attnum AS position, a.attname AS name,
                format_type(a.atttypid,a.atttypmod) AS type, a.attnotnull AS not_null,
                a.attidentity AS identity, a.attgenerated AS generated,
                pg_get_expr(d.adbin,d.adrelid) AS default_expression
                FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
                WHERE a.attrelid='lab.orders_lab'::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum""")
            constraints = self.query(connection, """SELECT contype AS type, pg_get_constraintdef(oid,true) AS definition
                FROM pg_constraint WHERE conrelid='lab.orders_lab'::regclass ORDER BY contype,conname""")
            structure = self.query(connection, """SELECT relkind, relispartition, relrowsecurity, relforcerowsecurity,
                (SELECT count(*) FROM pg_trigger WHERE tgrelid=c.oid AND NOT tgisinternal) AS user_triggers,
                (SELECT count(*) FROM pg_index WHERE indrelid=c.oid AND NOT indisprimary) AS secondary_indexes
                FROM pg_class c WHERE c.oid='lab.orders_lab'::regclass""")[0]
        return {"columns": columns, "constraints": constraints, "structure": structure}

    def compare(self):
        started = utc()
        source, target = self.rows("source"), self.rows("target")
        left, right = {row["id"]: row for row in source["rows"]}, {row["id"]: row for row in target["rows"]}
        differences = []
        for key in sorted(set(left) | set(right)):
            if key not in left:
                differences.append({"id": key, "kind": "target_only", "target": right[key]})
            elif key not in right:
                differences.append({"id": key, "kind": "source_only", "source": left[key]})
            else:
                for column in COLUMNS:
                    if left[key][column] != right[key][column]:
                        differences.append({"id": key, "kind": "column", "column": column,
                                            "source": left[key][column], "target": right[key][column]})
        source_catalog, target_catalog = self.catalog("source"), self.catalog("target")
        return {"started_at_utc": started, "finished_at_utc": utc(), "kind": "independent_full_comparison",
                "source": source, "target": target, "counts_equal": source["row_count"] == target["row_count"],
                "totals_equal": source["amount_total"] == target["amount_total"], "ids_equal": source["ids"] == target["ids"],
                "content_equal": not differences, "differences": differences,
                "catalog_equal": source_catalog == target_catalog, "source_catalog": source_catalog, "target_catalog": target_catalog,
                "limitation": "Sequential snapshots; stable-state claims require all relevant writers to be controlled."}

    def role_report(self, side):
        with self.connection(side, "admin") as connection:
            roles = self.query(connection, """SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,
                rolcanlogin,rolreplication,rolbypassrls FROM pg_roles
                WHERE rolname IN (%s,%s,%s) ORDER BY rolname""", (WRITERS[side], READERS[side], "dms_" + side))
            memberships = self.query(connection, """SELECT member_role.rolname AS member, parent.rolname AS parent,
                m.admin_option, m.inherit_option, m.set_option FROM pg_auth_members m
                JOIN pg_roles member_role ON member_role.oid=m.member JOIN pg_roles parent ON parent.oid=m.roleid
                WHERE member_role.rolname IN (%s,%s) ORDER BY member,parent""", (WRITERS[side], READERS[side]))
            writer = WRITERS[side]
            privileges = {priv: self.query(connection, "SELECT has_table_privilege(%s,'lab.orders_lab',%s) AS permitted", (writer, priv))[0]["permitted"]
                          for priv in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")}
            column_writes = self.query(connection, """SELECT attname,
                has_column_privilege(%s,'lab.orders_lab',attname,'INSERT') AS can_insert,
                has_column_privilege(%s,'lab.orders_lab',attname,'UPDATE') AS can_update
                FROM pg_attribute WHERE attrelid='lab.orders_lab'::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum""", (writer, writer))
            owners = self.query(connection, """SELECT pg_get_userbyid(c.relowner) AS table_owner,
                pg_get_userbyid(n.nspowner) AS schema_owner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE c.oid='lab.orders_lab'::regclass""")[0]
            sessions = self.query(connection, """SELECT pid, usename, application_name, state, xact_start, query_start,
                wait_event_type,wait_event FROM pg_stat_activity
                WHERE datname=%s AND usename=%s AND pid<>pg_backend_pid() ORDER BY pid""", (DATABASE, writer))
            defaults = self.query(connection, "SELECT datacl::text AS database_acl FROM pg_database WHERE datname=%s", (DATABASE,))[0]
            object_acl = self.query(connection, "SELECT relacl::text AS table_acl FROM pg_class WHERE oid='lab.orders_lab'::regclass")[0]
            schema_acl = self.query(connection, "SELECT nspacl::text AS schema_acl FROM pg_namespace WHERE nspname='lab'")[0]
        return {"side": side, "roles": roles, "memberships": memberships, "writer_privileges": privileges,
                "column_writes": column_writes, "owners": owners, "writer_sessions": sessions,
                **defaults, **object_acl, **schema_acl}

    @staticmethod
    def assert_nonadmin(report):
        writer = WRITERS[report["side"]]
        role = [row for row in report["roles"] if row["rolname"] == writer]
        if len(role) != 1 or any(role[0][flag] for flag in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls")):
            raise GateError("The business writer has an administrative attribute.")
        if report["memberships"] or writer in report["owners"].values():
            raise GateError("Business identities have a membership or ownership path.")

    def assert_frozen(self, side):
        report = self.role_report(side)
        self.assert_nonadmin(report)
        if any(report["writer_privileges"][p] for p in ("INSERT", "UPDATE", "DELETE", "TRUNCATE")):
            raise GateError("A business writer still has table write privileges.")
        if any(row["can_insert"] or row["can_update"] for row in report["column_writes"]):
            raise GateError("A business writer still has column write privileges.")
        if report["writer_sessions"]:
            raise GateError("A business writer still has an old connection.")
        return report

    def negative_write(self, side):
        with self.connection(side, "writer") as connection:
            identity = self.identity(connection, side, WRITERS[side])
            connection.autocommit = False
            passed, sqlstate = False, None
            try:
                with connection.cursor() as cursor:
                    cursor.execute(INSERT_ROW, [999, "negative-probe", "must-rollback", "0.00", 1, "barreira-sem-commit"])
                passed = True
            except psycopg2.Error as error:
                sqlstate = error.pgcode
            finally:
                connection.rollback()
        result = {"identity": identity, "attempted_id": 999, "attempt_succeeded": passed, "sqlstate": sqlstate,
                  "rollback_confirmed": True, "passed": not passed and sqlstate == "42501", "observed_at_utc": utc()}
        if not result["passed"]:
            raise GateError("The negative writer probe did not fail with insufficient_privilege; its transaction was rolled back.")
        return result

    def set_writer(self, side, enabled):
        if enabled and side == "source" and self.state.get("target_exclusive_commit"):
            raise GateError("Source reopening is blocked after a target-only commit in this run.")
        report = self.role_report(side)
        self.assert_nonadmin(report)
        with self.connection(side, "admin") as connection:
            writer = sql.Identifier(WRITERS[side])
            with connection.cursor() as cursor:
                cursor.execute(sql.SQL("REVOKE INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON lab.orders_lab FROM {}" ).format(writer))
                cursor.execute(sql.SQL("REVOKE INSERT ({}), UPDATE ({}) ON lab.orders_lab FROM {}" ).format(
                    sql.SQL(",").join(map(sql.Identifier, COLUMNS)), sql.SQL(",").join(map(sql.Identifier, COLUMNS)), writer))
                if enabled:
                    cursor.execute(sql.SQL("GRANT SELECT,INSERT,UPDATE,DELETE ON lab.orders_lab TO {}" ).format(writer))
                else:
                    cursor.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s AND usename=%s AND pid<>pg_backend_pid()", (DATABASE, WRITERS[side]))
        self.state[side + "_frozen"] = not enabled
        self.event("writer_permission_changed", side=side, enabled=enabled)
        if not enabled:
            return {"role_report": self.assert_frozen(side), "negative_probe": self.negative_write(side)}
        return self.role_report(side)

    def create_identities(self, connection, side):
        # Never emit SQL or exception text. Suppress server statement/error SQL logging before passwords.
        with connection.cursor() as cursor:
            cursor.execute("SET log_statement='none'")
            cursor.execute("SET log_min_error_statement='panic'")
            cursor.execute("SET log_min_duration_statement=-1")
            cursor.execute("SET log_min_duration_sample=-1")
            cursor.execute("SET password_encryption='scram-sha-256'")
            for role in ("dms_" + side, WRITERS[side], READERS[side]):
                cursor.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,))
                if not cursor.fetchone():
                    cursor.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(role)))
                # RDS's managed master is not a native SUPERUSER. Fresh target roles
                # already default to NOSUPERUSER/NOREPLICATION/NOBYPASSRLS; verify below.
                options = ("NOBYPASSRLS SUPERUSER REPLICATION" if role == "dms_source" else
                           "NOBYPASSRLS NOSUPERUSER NOREPLICATION" if side == "source" else "")
                password = self.password("LAB_" + side.upper() + "_DMS_PASSWORD") if role.startswith("dms_") else self.password("LAB_CLIENT_PASSWORD")
                # libpq computes a salted SCRAM verifier locally. Plaintext never enters
                # ALTER ROLE text, including pg_stat_activity or utility query statistics.
                verifier = encrypt_password(password, role, connection, algorithm="scram-sha-256")
                cursor.execute(sql.SQL("ALTER ROLE {} LOGIN NOINHERIT NOCREATEDB NOCREATEROLE " + options + " PASSWORD %s").format(sql.Identifier(role)),
                               (verifier,))
                if role != "dms_source":
                    cursor.execute("SELECT rolsuper,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s", (role,))
                    if any(cursor.fetchone()):
                        raise GateError("A prepared normal role retained an administrative attribute.")

    def diagnose_target_setup(self):
        """Read setup state and test only nonpersistent, credential-free SETs."""
        logging_names = ["log_statement", "log_min_error_statement", "log_min_duration_statement",
                         "log_min_duration_sample", "log_statement_sample_rate", "log_transaction_sample_rate",
                         "log_parameter_max_length", "log_parameter_max_length_on_error", "password_encryption",
                         "shared_preload_libraries", "rds.force_ssl", "rds.restrict_password_commands",
                         "pgaudit.log", "pgaudit.log_parameter", "pg_stat_statements.track", "pg_stat_statements.track_utility"]
        with self.connection("target", "admin", "postgres") as connection:
            identity = self.query(connection, """SELECT current_database() AS database,current_user AS username,
                current_setting('server_version') AS server_version,inet_server_addr()::text AS server_address,
                inet_server_port() AS server_port,clock_timestamp() AS server_utc,
                pg_has_role(current_user,'rds_superuser','MEMBER') AS rds_superuser_member""")[0]
            if identity["database"] != "postgres" or identity["username"] != self.password("LAB_RDS_MASTER_USERNAME"):
                raise GateError("The diagnostic connection did not match the intended managed master and postgres database.")
            tls = self.query(connection, "SELECT ssl,version,cipher,bits FROM pg_stat_ssl WHERE pid=pg_backend_pid()")[0]
            if not tls["ssl"]:
                raise GateError("The diagnostic target connection did not negotiate TLS.")
            before = self.query(connection, """SELECT name,setting,unit,context,source,pending_restart,boot_val,reset_val
                FROM pg_settings WHERE name=ANY(%s) ORDER BY name""", (logging_names,))
            roles = self.query(connection, """SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,
                rolcanlogin,rolreplication,rolbypassrls FROM pg_roles
                WHERE rolname IN (current_user,'dms_target','lab_writer_target','lab_reader_target') ORDER BY rolname""")
            database = self.query(connection, """SELECT datname,pg_get_userbyid(datdba) AS owner,datacl::text AS acl
                FROM pg_database WHERE datname=%s""", (DATABASE,))
            trials = []
            for name, value in (("log_statement", "none"), ("log_min_error_statement", "panic"),
                                ("log_min_duration_statement", "-1"), ("log_min_duration_sample", "-1")):
                trial = {"parameter": name, "requested_setting": value, "started_at_utc": utc()}
                try:
                    with connection.cursor() as cursor:
                        cursor.execute(sql.SQL("SET {} = %s").format(sql.Identifier(name)), (value,))
                    trial["set_succeeded"] = True
                    trial["sqlstate"] = None
                except psycopg2.Error as error:
                    trial["set_succeeded"] = False
                    trial["sqlstate"] = error.pgcode
                    trial["exception_type"] = type(error).__name__
                trial["effective_setting"] = self.query(connection, "SELECT current_setting(%s) AS value", (name,))[0]["value"]
                trial["finished_at_utc"] = utc()
                trials.append(trial)
            after = self.query(connection, """SELECT name,setting,unit,context,source,pending_restart,boot_val,reset_val
                FROM pg_settings WHERE name=ANY(%s) ORDER BY name""", (logging_names,))
        object_state = {"database_exists": bool(database), "schema_exists": None, "table_exists": None}
        if database:
            with self.connection("target", "admin") as connection:
                object_state.update(self.query(connection, """SELECT
                    EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='lab') AS schema_exists,
                    to_regclass('lab.orders_lab') IS NOT NULL AS table_exists""")[0])
        return {"identity": identity, "tls": tls, "client_sslmode": "verify-full", "settings_before": before,
                "session_set_trials": trials, "settings_after_in_same_session": after, "roles": roles,
                "database": database, "objects": object_state, "password_statements_executed": False,
                "persistent_database_changes": False,
                "session_change_scope": "Only four logging SET attempts; all revert when the diagnostic connection closes."}

    def diagnose_target_default_privileges(self):
        """Test the exact future-object grant in a transaction always rolled back."""
        default_query = """SELECT pg_get_userbyid(d.defaclrole) AS owner,n.nspname AS schema,
            d.defaclobjtype AS object_type,d.defaclacl::text AS acl
            FROM pg_default_acl d JOIN pg_namespace n ON n.oid=d.defaclnamespace
            WHERE pg_get_userbyid(d.defaclrole)='dms_target' AND n.nspname='lab'
            ORDER BY owner,schema,object_type"""
        with self.connection("target", "admin") as connection:
            identity = self.identity(connection, "target", self.password("LAB_RDS_MASTER_USERNAME"))
            objects = self.query(connection, """SELECT
                EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='lab') AS schema_exists,
                to_regclass('lab.orders_lab') IS NOT NULL AS table_exists""")[0]
            if not objects["schema_exists"] or not objects["table_exists"]:
                raise GateError("The default-grant diagnostic requires the exact precreated schema and table.")
            row_count_before = self.query(connection, "SELECT count(*) AS row_count FROM lab.orders_lab")[0]["row_count"]
            if row_count_before != 0:
                raise GateError("The target table must still be empty before setup diagnosis.")
            memberships = self.query(connection, """SELECT member_role.rolname AS member,parent.rolname AS parent,
                m.admin_option,m.inherit_option,m.set_option FROM pg_auth_members m
                JOIN pg_roles member_role ON member_role.oid=m.member JOIN pg_roles parent ON parent.oid=m.roleid
                WHERE member_role.rolname=current_user AND parent.rolname='dms_target' ORDER BY member,parent""")
            reader_select = self.query(connection, "SELECT has_table_privilege('lab_reader_target','lab.orders_lab','SELECT') AS permitted")[0]
            before = self.query(connection, default_query)
            trial = {"phase": "TARGET_ALTER_DEFAULT_PRIVILEGES_FOR_DMS_TARGET", "started_at_utc": utc()}
            connection.autocommit = False
            try:
                with connection.cursor() as cursor:
                    cursor.execute("ALTER DEFAULT PRIVILEGES FOR ROLE dms_target IN SCHEMA lab GRANT SELECT ON TABLES TO lab_reader_target")
                trial.update(statement_succeeded=True, sqlstate=None)
            except psycopg2.Error as error:
                trial.update(statement_succeeded=False, sqlstate=error.pgcode, exception_type=type(error).__name__)
            finally:
                connection.rollback()
            connection.autocommit = True
            after = self.query(connection, default_query)
            row_count_after = self.query(connection, "SELECT count(*) AS row_count FROM lab.orders_lab")[0]["row_count"]
            trial.update(rollback_confirmed=True, finished_at_utc=utc())
        if before != after or row_count_after != 0:
            raise GateError("The default-privilege diagnostic did not preserve its initial ACL state.")
        return {"identity": identity, "master_memberships_to_dms_target": memberships,
                "existing_reader_table_select": reader_select, "default_acl_before": before, "trial": trial,
                "default_acl_after_rollback": after, "acl_unchanged": before == after,
                "objects": objects, "table": TABLE, "default_grant_recipient": "lab_reader_target",
                "row_count_before": row_count_before, "row_count_after_rollback": row_count_after,
                "password_statements_executed": False, "persistent_database_changes": False}

    def target_control_schema_report(self, connection):
        schemas = self.query(connection, """SELECT nspname,pg_get_userbyid(nspowner) AS owner,nspacl::text AS acl
            FROM pg_namespace WHERE nspname IN ('public','lab') ORDER BY nspname""")
        privileges = []
        for role in ("dms_target", WRITERS["target"], READERS["target"]):
            privileges.extend(self.query(connection, """SELECT %s AS role,has_schema_privilege(%s,'public','USAGE') AS public_usage,
                has_schema_privilege(%s,'public','CREATE') AS public_create,
                has_schema_privilege(%s,'lab','USAGE') AS lab_usage,has_schema_privilege(%s,'lab','CREATE') AS lab_create""",
                (role, role, role, role, role)))
        controls = self.query(connection, """SELECT schemaname,tablename,tableowner FROM pg_tables
            WHERE schemaname IN ('public','lab') AND tablename ~ '^awsdms_' ORDER BY schemaname,tablename""")
        return {"database": DATABASE, "default_postgresql_control_schema": "public", "schemas": schemas,
                "effective_privileges": privileges, "control_tables": controls}

    def diagnose_target_control_schema(self):
        with self.connection("target", "admin") as connection:
            identity = self.identity(connection, "target", self.password("LAB_RDS_MASTER_USERNAME"))
            controls = self.target_control_schema_report(connection)
            row_count = self.query(connection, "SELECT count(*) AS row_count FROM lab.orders_lab")[0]["row_count"]
        return {"identity": identity, "controls": controls, "roles": self.role_report("target"),
                "business_writer_negative_probe": self.negative_write("target"),
                "business_table": TABLE, "row_count": row_count, "persistent_database_changes": False}

    def prepare_database(self, side):
        with self.connection(side, "admin", "postgres") as connection:
            self.create_identities(connection, side)
            exists = self.query(connection, "SELECT 1 FROM pg_database WHERE datname=%s", (DATABASE,))
            if not exists:
                with connection.cursor() as cursor:
                    cursor.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0 ENCODING 'UTF8'").format(sql.Identifier(DATABASE)))
        with self.connection(side, "admin") as connection:
            exists = self.query(connection, "SELECT to_regclass('lab.orders_lab') AS object")[0]["object"]
            if exists:
                rows = self.query(connection, SELECT_ROWS)
                permitted = rows_from_seed() if side == "source" else []
                if json.loads(canonical(rows)) != permitted:
                    raise GateError("Preparation will not overwrite a non-baseline existing table.")
            with connection.cursor() as cursor:
                cursor.execute("REVOKE ALL ON DATABASE migration_lab FROM PUBLIC")
                cursor.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
                cursor.execute("CREATE SCHEMA IF NOT EXISTS lab")
                cursor.execute("REVOKE ALL ON SCHEMA lab FROM PUBLIC")
                if not exists:
                    cursor.execute(DDL)
                    if side == "source":
                        cursor.executemany(INSERT_ROW, SEED)
                cursor.execute("REVOKE ALL ON lab.orders_lab FROM PUBLIC")
                for role in ("dms_" + side, WRITERS[side], READERS[side]):
                    cursor.execute(sql.SQL("GRANT CONNECT ON DATABASE migration_lab TO {}" ).format(sql.Identifier(role)))
                    cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA lab TO {}" ).format(sql.Identifier(role)))
                    cursor.execute(sql.SQL("GRANT SELECT ON lab.orders_lab TO {}" ).format(sql.Identifier(role)))
                if side == "target":
                    control_before = self.target_control_schema_report(connection)
                    if any(row["public_create"] for row in control_before["effective_privileges"] if row["role"] != "dms_target"):
                        raise GateError("Business identities must not have CREATE in the DMS control schema.")
                    cursor.execute("GRANT CREATE ON DATABASE migration_lab TO dms_target")
                    cursor.execute("GRANT CREATE ON SCHEMA lab TO dms_target")
                    # DMS PostgreSQL's default ControlSchema is public. Only its
                    # dedicated role may create apply/validation control tables.
                    cursor.execute("GRANT USAGE,CREATE ON SCHEMA public TO dms_target")
                    cursor.execute("GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON lab.orders_lab TO dms_target")
                    # The reader already has SELECT on the sole precreated table.
                    # Future-table defaults are outside this DO_NOTHING experiment.
                    control_after = self.target_control_schema_report(connection)
                    dms_control = next(row for row in control_after["effective_privileges"] if row["role"] == "dms_target")
                    if not dms_control["public_usage"] or not dms_control["public_create"]:
                        raise GateError("The dedicated DMS control-schema grant failed its effective privilege readback.")
                    if any(row["public_create"] for row in control_after["effective_privileges"] if row["role"] != "dms_target"):
                        raise GateError("Business identities acquired CREATE in the DMS control schema.")
                    self.state["target_control_schema_grant"] = {"before": control_before,
                        "planned_diff": {"role": "dms_target", "schema": "public", "grant": ["USAGE", "CREATE"]},
                        "after": control_after, "verified_at_utc": utc()}
                    self.event("target_dms_control_schema_verified")
                cursor.execute(sql.SQL("REVOKE ALL ON lab.orders_lab FROM {}" ).format(sql.Identifier(WRITERS[side])))
                cursor.execute(sql.SQL("GRANT SELECT ON lab.orders_lab TO {}" ).format(sql.Identifier(WRITERS[side])))
        self.state[side + "_prepared"] = True
        self.event("database_prepared", side=side)

    def configure_source(self):
        with self.connection("source", "admin", "postgres") as connection:
            paths = self.query(connection, "SELECT current_setting('config_file') AS config_file,current_setting('hba_file') AS hba_file,current_setting('data_directory') AS data_directory")[0]
            if not paths["config_file"].startswith("/etc/postgresql/16/main/"):
                raise GateError("Only the discovered fresh Ubuntu PostgreSQL 16/main cluster is supported.")
            cert_dir = Path(paths["config_file"]).parent
            cert, key = cert_dir / "lab-server.crt", cert_dir / "lab-server.key"
            if not cert.exists() or not key.exists():
                subprocess.run(["openssl", "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "7",
                    "-keyout", str(key), "-out", str(cert), "-subj", "/CN=" + self.source_ip,
                    "-addext", "subjectAltName=IP:" + self.source_ip], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                postgres = pwd.getpwnam("postgres")
                os.chown(key, postgres.pw_uid, postgres.pw_gid)
                os.chown(cert, postgres.pw_uid, postgres.pw_gid)
                os.chmod(key, 0o600)
                os.chmod(cert, 0o644)
            slots = int(self.query(connection, "SHOW max_replication_slots")[0]["max_replication_slots"])
            senders = int(self.query(connection, "SHOW max_wal_senders")[0]["max_wal_senders"])
            values = {"listen_addresses": "127.0.0.1," + self.source_ip, "wal_level": "logical",
                      "max_replication_slots": str(max(4, slots)), "max_wal_senders": str(max(4, senders)),
                      "wal_sender_timeout": "0", "max_slot_wal_keep_size": "2GB", "ssl": "on",
                      "ssl_cert_file": str(cert), "ssl_key_file": str(key), "password_encryption": "scram-sha-256"}
            with connection.cursor() as cursor:
                for name, value in values.items():
                    cursor.execute(sql.SQL("ALTER SYSTEM SET {} = %s").format(sql.Identifier(name)), (value,))
        self.configure_hba(reload=False)
        subprocess.run(["pg_ctlcluster", "16", "main", "restart"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        return paths

    def configure_hba(self, reload=True):
        dms_ip = str(ipaddress.IPv4Address(self.cfg["dms_private_ip"])) if self.cfg.get("dms_private_ip") else None
        with self.connection("source", "admin", "postgres") as connection:
            hba = Path(self.query(connection, "SHOW hba_file")[0]["hba_file"])
            if not str(hba).startswith("/etc/postgresql/16/main/"):
                raise GateError("The discovered HBA file is outside the dedicated PostgreSQL cluster.")
            backup = self.state_dir / "pg_hba.original.conf"
            if not backup.exists():
                backup.write_bytes(hba.read_bytes())
                os.chmod(backup, 0o600)
            lines = ["# Dedicated migration_lab; generated by lab_harness.py", "local all postgres peer", "local all all reject",
                     "hostssl migration_lab lab_writer_source,lab_reader_source 127.0.0.1/32 scram-sha-256"]
            if dms_ip:
                lines.append("hostssl migration_lab dms_source " + dms_ip + "/32 scram-sha-256")
            lines.extend(["host all all 0.0.0.0/0 reject", "host all all ::/0 reject"])
            hba.write_text("\n".join(lines) + "\n", encoding="utf-8")
            if reload:
                self.query(connection, "SELECT pg_reload_conf()")
            rules = self.query(connection, "SELECT rule_number,type,database,user_name,address,netmask,auth_method,error FROM pg_hba_file_rules ORDER BY rule_number")
        if any(row["error"] for row in rules):
            raise GateError("The effective HBA contains an invalid rule.")
        return {"hba_file": str(hba), "dms_private_ip": dms_ip, "rules": rules, "reloaded": reload}

    def inspect(self):
        result = {"comparison": self.compare(), "roles": {side: self.role_report(side) for side in ("source", "target")}, "ledger": self.state}
        with self.connection("source", "admin") as connection:
            result["source_parameters"] = self.query(connection, """SELECT name,setting,unit,pending_restart,source FROM pg_settings
                WHERE name IN ('server_version','wal_level','max_replication_slots','max_wal_senders','wal_sender_timeout',
                'max_slot_wal_keep_size','ssl','ssl_cert_file','ssl_key_file','listen_addresses','config_file','hba_file','data_directory') ORDER BY name""")
            result["source_slots"] = self.query(connection, """SELECT slot_name,plugin,slot_type,database,active,restart_lsn::text,
                confirmed_flush_lsn::text,wal_status,safe_wal_size,
                pg_wal_lsn_diff(pg_current_wal_lsn(),restart_lsn)::text AS retained_wal_bytes
                FROM pg_replication_slots ORDER BY slot_name""")
            result["hba"] = self.query(connection, "SELECT rule_number,type,database,user_name,address,netmask,auth_method,error FROM pg_hba_file_rules ORDER BY rule_number")
            directory = self.query(connection, "SHOW data_directory")[0]["data_directory"]
        disk = os.statvfs(directory)
        result["source_disk"] = {"data_directory": directory, "available_bytes": disk.f_bavail * disk.f_frsize, "total_bytes": disk.f_blocks * disk.f_frsize}
        with self.connection("target", "admin") as connection:
            result["target_parameters"] = self.query(connection, "SELECT name,setting,unit,source FROM pg_settings WHERE name IN ('server_version','rds.force_ssl','rds.logical_replication','ssl') ORDER BY name")
            result["dms_control_tables"] = self.query(connection, """SELECT schemaname,tablename,tableowner FROM pg_tables
                WHERE schemaname LIKE 'awsdms%' OR (schemaname IN ('public','lab') AND tablename ~ '^awsdms_')
                ORDER BY schemaname,tablename""")
        if self.cfg.get("dms_task_arn"):
            result["dms_task"] = self.dms_state()
            result["dms_table"] = self.native_table()
        return result

    def dml(self, test, side, operation, parameters, expected_before, expected_after, row_id):
        if side == "source" and self.state.get("target_exclusive_commit"):
            raise GateError("Source DML is blocked after a target-only commit.")
        pending = self.state.get("pending_dml") or {}
        if pending and pending.get("test") != test:
            raise GateError("A different DML outcome is still unknown; reconcile it before another test.")
        with self.connection(side, "writer" if test != "T04-diverge" else "admin") as connection:
            expected_user = WRITERS[side] if test != "T04-diverge" else self.password("LAB_RDS_MASTER_USERNAME")
            identity = self.identity(connection, side, expected_user)
            before = json.loads(canonical(self.query(connection, SELECT_ROWS.replace("ORDER BY id", "WHERE id=%s ORDER BY id"), (row_id,))))
            if test in self.state["completed"]:
                if before != expected_after:
                    raise GateError("A completed DML action no longer has its expected result.")
                return {"idempotent_readback": True, **self.state["completed"][test]}
            if pending.get("test") == test and before == expected_after:
                result = {"test": test, "side": side, "identity": identity, "before": expected_before,
                          "after": before, "transaction_id": None, "commit_ack_utc": None,
                          "reconciled_at_utc": utc(), "reconciled_unknown_commit": True}
            else:
                if before != expected_before:
                    raise GateError("The DML precondition does not match the expected row state.")
                self.state["pending_dml"] = {"test": test, "side": side, "row_id": row_id, "before": before,
                                             "expected_after": expected_after, "started_at_utc": utc()}
                self.event("dml_pending", test=test, side=side, row_id=row_id)
                connection.autocommit = False
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT txid_current()::text,clock_timestamp()")
                        transaction_id, transaction_start = cursor.fetchone()
                        cursor.execute(operation, parameters)
                        if cursor.rowcount != 1:
                            raise GateError("Exactly one row must change in each controlled DML commit.")
                    connection.commit()
                    commit_ack = utc()
                except Exception:
                    connection.rollback()
                    raise
                connection.autocommit = True
                after = json.loads(canonical(self.query(connection, SELECT_ROWS.replace("ORDER BY id", "WHERE id=%s ORDER BY id"), (row_id,))))
                if after != expected_after:
                    raise GateError("The committed DML readback differs from the expected row.")
                result = {"test": test, "side": side, "identity": identity, "before": before, "after": after,
                          "transaction_id": transaction_id, "transaction_start_utc": transaction_start,
                          "commit_ack_utc": commit_ack, "commit_time_definition": "UTC client timestamp immediately after commit acknowledgment"}
        if test.startswith("T08"):
            self.state["target_exclusive_commit"] = True
        self.state["pending_dml"] = None
        self.state["completed"][test] = result
        self.event("dml_confirmed", test=test, side=side, row_id=row_id, commit_ack_utc=result.get("commit_ack_utc"))
        return result

    def test(self, action):
        seeded = {row["id"]: row for row in rows_from_seed()}
        if action in ("t01", "t02", "t03", "correct-divergence", "marker-901", "marker-902"):
            self.dms_state("running")
            self.assert_frozen("target")
        if action == "t01":
            row = dict(zip(COLUMNS, [201, "cliente-201", "cdc-insert", "201.01", 1, "insert-origem-t01"]))
            return self.dml("T01", "source", INSERT_ROW, list(row.values()), [], [row], 201)
        if action == "t02":
            final = {**seeded[102], "status": "cdc-updated", "revision": 2}
            return self.dml("T02", "source", "UPDATE lab.orders_lab SET status=%s,revision=%s WHERE id=%s", ("cdc-updated", 2, 102), [seeded[102]], [final], 102)
        if action == "t03":
            return self.dml("T03", "source", "DELETE FROM lab.orders_lab WHERE id=%s", (103,), [seeded[103]], [], 103)
        if action == "diverge-target":
            self.dms_state("running")
            self.assert_frozen("target")
            comparison = self.compare()
            already_started = "T04-diverge" in self.state["completed"] or (self.state.get("pending_dml") or {}).get("test") == "T04-diverge"
            if not already_started and (not comparison["content_equal"] or not comparison["catalog_equal"]):
                raise GateError("The deliberate divergence requires a confirmed equal baseline.")
            final = {**seeded[106], "note": "divergencia-controlada-destino"}
            return self.dml("T04-diverge", "target", "UPDATE lab.orders_lab SET note=%s WHERE id=%s", (final["note"], 106), [seeded[106]], [final], 106)
        if action == "correct-divergence":
            if "T04-diverge" not in self.state["completed"]:
                raise GateError("The target divergence must be recorded before its source-directed correction.")
            final = {**seeded[106], "note": "correcao-autoritativa-origem", "revision": 2}
            return self.dml("T04-correct", "source", "UPDATE lab.orders_lab SET note=%s,revision=%s WHERE id=%s", (final["note"], 2, 106), [seeded[106]], [final], 106)
        if action in ("marker-901", "marker-902"):
            marker = int(action[-3:])
            if marker == 902 and "T07-return-write" not in self.state["completed"]:
                raise GateError("The second marker follows the demonstrated pre-write return.")
            note = "marcador-final-origem" if marker == 901 else "marcador-segundo-corte"
            row = dict(zip(COLUMNS, [marker, "marcador-" + str(marker), "cutover-marker", "0.00", 1, note]))
            return self.dml("T05-marker-" + str(marker), "source", INSERT_ROW, list(row.values()), [], [row], marker)
        if action.startswith("postwrite-"):
            self.dms_state("stopped")
            self.assert_frozen("source")
            if not self.state.get("target_opened"):
                raise GateError("Only the gated target writer may execute target-only commits.")
            if action == "postwrite-insert":
                row = dict(zip(COLUMNS, [301, "cliente-301", "target-only", "301.01", 1, "primeiro-commit-exclusivo-destino"]))
                return self.dml("T08-insert-301", "target", INSERT_ROW, list(row.values()), [], [row], 301)
            if not self.state.get("target_exclusive_commit"):
                raise GateError("The first target-only INSERT must be recorded first.")
            if action == "postwrite-update":
                final = {**seeded[104], "status": "target-updated", "revision": 2}
                return self.dml("T08-update-104", "target", "UPDATE lab.orders_lab SET status=%s,revision=%s WHERE id=%s", ("target-updated", 2, 104), [seeded[104]], [final], 104)
            return self.dml("T08-delete-105", "target", "DELETE FROM lab.orders_lab WHERE id=%s", (105,), [seeded[105]], [], 105)
        raise GateError("Unknown test action.")

    def observe(self, test_name, timeout):
        receipt = self.state["completed"].get(test_name)
        if not receipt or receipt["side"] != "source":
            raise GateError("A recorded source commit is required for destination observation.")
        row_id = (receipt["after"] or receipt["before"])[0]["id"]
        deadline, count = time.monotonic() + timeout, 0
        while True:
            with self.connection("target") as connection:
                data = json.loads(canonical(self.query(connection, SELECT_ROWS.replace("ORDER BY id", "WHERE id=%s ORDER BY id"), (row_id,))))
            count += 1
            observed = utc()
            if data == receipt["after"]:
                self.event("destination_first_observed", test=test_name, row_id=row_id, observed_at_utc=observed)
                return {"test": test_name, "row_id": row_id, "target_rows": data, "commit_ack_utc": receipt.get("commit_ack_utc"),
                        "first_observation_utc": observed, "poll_count": count, "poll_interval_seconds": 1,
                        "measurement_scope": "First matching poll after the observer began, not an exact DMS apply timestamp."}
            if time.monotonic() >= deadline:
                raise GateError("The expected target row was not observed before the bounded deadline.")
            time.sleep(1)

    def record_g6(self, proof_path):
        task = self.dms_state("running")
        native = self.native_table()
        counters = ("ValidationPendingRecords", "ValidationFailedRecords", "ValidationSuspendedRecords")
        if any(key not in native or not isinstance(native[key], int) for key in counters):
            raise GateError("All native validation counters must be present; missing is not zero.")
        if native.get("ValidationState") != "Validated" or any(native[key] != 0 for key in counters):
            raise GateError("Current DMS native validation is not clean and complete.")
        if native.get("FullLoadErrorRows", 0) or native.get("TableState", "").lower() != "table completed":
            raise GateError("The DMS table is not fully loaded without errors.")
        for side in ("source", "target"):
            self.assert_frozen(side)
            self.negative_write(side)
        comparison = self.compare()
        if not comparison["content_equal"] or not comparison["catalog_equal"]:
            raise GateError("The final independent comparison failed.")
        proof_bytes = Path(proof_path).read_bytes()
        proof = json.loads(proof_bytes)
        proof_at = dt.datetime.fromisoformat(proof["checked_at_utc"].replace("Z", "+00:00"))
        if proof.get("run_id") != self.run_id or proof.get("task_arn") != self.cfg["dms_task_arn"]:
            raise GateError("The drain/log attestation is stale or bound to a different run/task.")
        if any(proof.get(key) is not True for key in ("incoming_changes_zero", "latencies_stable", "logs_checked", "no_blocking_errors")) or proof.get("metrics_fresh_samples", 0) < 2 or not proof.get("evidence_ids"):
            raise GateError("The root drain/log attestation does not satisfy all required checks.")
        revalidated_at = dt.datetime.fromisoformat(proof["final_revalidation_requested_at_utc"].replace("Z", "+00:00"))
        native_updated_at = native.get("LastUpdateTime")
        if not isinstance(native_updated_at, dt.datetime) or native_updated_at < revalidated_at or not proof.get("native_revalidation_evidence_id"):
            raise GateError("The final native validation is not evidenced as newer than the revalidation request.")
        if proof.get("divergence_native_failed") is not True or not proof.get("divergence_detected_evidence_id") or not proof.get("divergence_native_failure_evidence_id"):
            raise GateError("The deliberate divergence needs both independent and new native failure evidence.")
        marker = proof.get("marker_id")
        expected_marker = 902 if "T07-return-write" in self.state["completed"] else 901
        if marker != expected_marker or marker not in comparison["source"]["ids"]:
            raise GateError("The final marker is missing or belongs to another cutover phase.")
        required = ("T01", "T02", "T03", "T04-diverge", "T04-correct", "T05-marker-" + str(marker))
        if any(test not in self.state["completed"] for test in required):
            raise GateError("One or more prerequisite test receipts are absent.")
        current_rows = {row["id"]: row for row in comparison["source"]["rows"]}
        for test in required:
            if test == "T04-diverge":
                continue
            receipt = self.state["completed"][test]
            row_id = (receipt["after"] or receipt["before"])[0]["id"]
            observed = [current_rows[row_id]] if row_id in current_rows else []
            if observed != receipt["after"]:
                raise GateError("A required CDC operation or marker no longer has its recorded final effect.")
        marker_commit = self.state["completed"]["T05-marker-" + str(marker)].get("commit_ack_utc")
        if not marker_commit or revalidated_at < dt.datetime.fromisoformat(marker_commit.replace("Z", "+00:00")):
            raise GateError("The final revalidation must be requested after the marker commit.")
        catalog_sha256 = digest(comparison["source_catalog"])
        proof_sha256 = hashlib.sha256(proof_bytes).hexdigest()
        approved_at = dt.datetime.now(dt.timezone.utc)
        proof_age = (approved_at - proof_at).total_seconds()
        if proof_age < -5 or proof_age > 600:
            raise GateError("The drain/log attestation is stale or bound to a different run/task.")
        freshness = metric_freshness_at_approval(proof, approved_at)
        self.state["g6"] = {"marker_id": marker, "approved_at_utc": freshness["checked_at_utc"],
                             "metric_freshness": freshness, "proof_age_seconds": proof_age,
                             "rows_sha256": comparison["source"]["sha256"],
                             "catalog_sha256": catalog_sha256, "drain_proof_sha256": proof_sha256,
                            "drain_proof": proof, "native_validation": native, "task": task}
        self.event("g6_approved", marker_id=marker, approved_at_utc=freshness["checked_at_utc"], metric_freshness=freshness)
        return {"g6": self.state["g6"], "independent_comparison": comparison,
                "external_check_kind": "Root attestation linked to actual CloudWatch and log evidence; not recomputed by this harness."}

    def check_stopped_g6(self, marker):
        task = self.dms_state("stopped")
        gate = self.state.get("g6", {})
        if gate.get("marker_id") != marker:
            raise GateError("This transition requires its matching recorded G6 decision.")
        for side in ("source", "target"):
            self.assert_frozen(side)
        comparison = self.compare()
        if not comparison["content_equal"] or comparison["source"]["sha256"] != gate["rows_sha256"] or digest(comparison["source_catalog"]) != gate["catalog_sha256"] or not comparison["catalog_equal"]:
            raise GateError("The stopped-task state changed after the recorded G6 decision.")
        return {"task": task, "comparison": comparison}

    def prewrite_return(self):
        if self.state.get("pending_dml"):
            raise GateError("An unresolved DML outcome blocks return; reconcile it before using a historical receipt or opening the source.")
        if self.state.get("target_exclusive_commit"):
            raise GateError("A simple return is blocked after a target-only commit.")
        if "T07-return-write" in self.state["completed"]:
            task = self.dms_state("stopped")
            self.assert_frozen("target")
            observed = [row for row in self.rows("source")["rows"] if row["id"] == 211]
            receipt = self.state["completed"]["T07-return-write"]
            if observed != receipt["after"]:
                raise GateError("The pre-write return receipt differs from its current source row.")
            return {"idempotent_readback": True, "receipt_scope": "historical_T07_return_commit",
                    "historical_only": True, "current_return_authorized": False,
                    "task": task, "return_commit": receipt}
        before = self.check_stopped_g6(901)
        with self.connection("target") as target:
            target_identity = self.identity(target, "target", READERS["target"])
        with self.connection("source") as source:
            source_identity = self.identity(source, "source", READERS["source"])
        self.event("simulated_readonly_target_smoke_failure", target_identity=target_identity)
        grant = self.set_writer("source", True)
        row = dict(zip(COLUMNS, [211, "cliente-211", "source-return", "211.01", 1, "retorno-pre-write-origem"]))
        commit = self.dml("T07-return-write", "source", INSERT_ROW, list(row.values()), [], [row], 211)
        self.state.pop("g6", None)
        self.event("prewrite_return_confirmed", source_writer_only=True)
        return {"before": before, "target_readonly_identity": target_identity, "source_return_identity": source_identity,
                "simulated_failure": "Declared smoke-test failure before target business writes", "source_grant": grant, "return_commit": commit,
                "next_step": "Resume the existing DMS checkpoint; observe id 211; commit marker 902; freeze; repeat the full G6."}

    def open_target(self):
        if self.state.get("target_opened"):
            self.dms_state("stopped")
            self.assert_frozen("source")
            return {"idempotent_readback": True, "role_report": self.role_report("target"),
                    "authority": "target writer only; source remains frozen"}
        before = self.check_stopped_g6(902)
        self.negative_write("source")
        with self.connection("target") as connection:
            identity = self.identity(connection, "target", READERS["target"])
        grant = self.set_writer("target", True)
        self.state["target_opened"] = True
        self.event("target_writer_authorized", source_writer_frozen=True)
        return {"before": before, "fresh_target_identity": identity, "grant_readback": grant,
                "authority": "target business writer only; DMS stopped; source writer frozen"}

    def reset_for_replay(self, archive_path, acknowledge):
        if not acknowledge:
            raise GateError("Clean replay requires explicit acknowledgment that synthetic data will be discarded.")
        self.dms_state("stopped")
        if self.state.get("completed") or self.state.get("target_exclusive_commit"):
            raise GateError("A clean replay must use a new run_id and a new ledger.")
        archived = Path(archive_path).read_bytes()
        old = json.loads(archived)
        if not old or old.get("run_id") == self.run_id:
            raise GateError("A readable evidence archive from the previous run must be preserved before reset.")
        before = self.compare()
        for side in ("source", "target"):
            self.set_writer(side, False)
        for side in ("target", "source"):
            with self.connection(side, "admin") as connection:
                connection.autocommit = False
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("TRUNCATE TABLE lab.orders_lab")
                        if side == "source":
                            cursor.executemany(INSERT_ROW, SEED)
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        self.state["replay_reset"] = True
        self.event("new_run_baseline_reset", prior_archive_sha256=hashlib.sha256(archived).hexdigest())
        return {"before": before, "after": self.compare(), "source_writer_frozen": True,
                "target_writer_frozen": True, "next_step": "Root reloads the bound DMS task; verify full load before open-source-for-replay."}

    def open_source_replay(self):
        self.dms_state("running")
        if not self.state.get("replay_reset") or self.state.get("target_exclusive_commit"):
            raise GateError("Source replay authorization requires the explicitly reset new run.")
        self.assert_frozen("target")
        comparison = self.compare()
        if not comparison["content_equal"] or comparison["source"]["rows"] != rows_from_seed():
            raise GateError("The clean full-load baseline is not identical to the initial eight rows.")
        return {"baseline": comparison, "grant": self.set_writer("source", True)}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Credential-free local JSON configuration")
    parser.add_argument("action", choices=["prepare-source", "prepare-target", "diagnose-target-setup", "diagnose-target-default-privileges", "diagnose-target-control-schema", "configure-hba", "inspect", "compare",
        "t01", "t02", "t03", "diverge-target", "correct-divergence", "marker-901", "marker-902", "freeze-source", "freeze-target",
        "record-g6", "prewrite-return", "open-target", "postwrite-insert", "postwrite-update", "postwrite-delete", "observe",
        "reset-for-replay", "open-source-for-replay"])
    parser.add_argument("--proof", help="Credential-free root drain/log attestation JSON")
    parser.add_argument("--test", help="Recorded source test identifier for observe")
    parser.add_argument("--timeout", type=int, default=45, help="Observation deadline, 1-55 seconds")
    parser.add_argument("--archived-evidence", help="Existing private previous-run JSON archive")
    parser.add_argument("--acknowledge-discard-synthetic-data", action="store_true")
    return parser.parse_args()


def main():
    started, args = utc(), parse_args()
    # Runtime wrapper resolves references. Never persist or print their values.
    secrets = {key: os.environ.pop(key, None) for key in ENV_KEYS}
    envelope = {"run_id": None, "command": args.action, "version": VERSION,
                "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "started_at_utc": started}
    lock_handle = None
    try:
        cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
        envelope["run_id"] = cfg.get("run_id")
        state_dir = Path(cfg.get("state_dir", "/opt/pg-lab/state"))
        state_dir.mkdir(parents=True, exist_ok=True)
        lock_handle = open(state_dir / ".lock", "a", encoding="utf-8")
        os.chmod(state_dir / ".lock", 0o600)
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        lab = Harness(cfg, secrets)
        envelope["aws_identity"] = lab.aws_identity
        if args.action == "prepare-source":
            paths = lab.configure_source()
            lab.prepare_database("source")
            result = {"paths": paths, "rows": lab.rows("source"), "writer": lab.set_writer("source", True), "hba": lab.configure_hba()}
        elif args.action == "prepare-target":
            lab.prepare_database("target")
            result = {"rows": lab.rows("target"), "writer_block": lab.set_writer("target", False), "catalog": lab.catalog("target"),
                      "control_schema_grant": lab.state.get("target_control_schema_grant")}
        elif args.action == "diagnose-target-setup":
            result = lab.diagnose_target_setup()
        elif args.action == "diagnose-target-default-privileges":
            result = lab.diagnose_target_default_privileges()
        elif args.action == "diagnose-target-control-schema":
            result = lab.diagnose_target_control_schema()
        elif args.action == "configure-hba":
            result = lab.configure_hba()
        elif args.action == "inspect":
            result = lab.inspect()
        elif args.action == "compare":
            result = lab.compare()
        elif args.action.startswith("freeze-"):
            result = lab.set_writer(args.action.split("-")[1], False)
        elif args.action == "record-g6":
            if not args.proof:
                raise GateError("record-g6 requires --proof.")
            result = lab.record_g6(args.proof)
        elif args.action == "prewrite-return":
            result = lab.prewrite_return()
        elif args.action == "open-target":
            result = lab.open_target()
        elif args.action == "observe":
            if not args.test or not 1 <= args.timeout <= 55:
                raise GateError("observe requires --test and a 1-55 second timeout.")
            result = lab.observe(args.test, args.timeout)
        elif args.action == "reset-for-replay":
            if not args.archived_evidence:
                raise GateError("A preserved previous-run evidence archive is required.")
            result = lab.reset_for_replay(args.archived_evidence, args.acknowledge_discard_synthetic_data)
        elif args.action == "open-source-for-replay":
            result = lab.open_source_replay()
        else:
            result = lab.test(args.action)
        envelope.update(success=True, evidence_kind="observed", data=result)
        code = 0
    except GateError as error:
        envelope.update(success=False, failure_class="gate", error=str(error))
        code = 2
    except ClientError as error:
        envelope.update(success=False, failure_class="aws", aws_error_code=error.response.get("Error", {}).get("Code"), exception_type=type(error).__name__)
        code = 3
    except psycopg2.Error as error:
        envelope.update(success=False, failure_class="database", sqlstate=error.pgcode, exception_type=type(error).__name__)
        code = 4
    except Exception as error:
        envelope.update(success=False, failure_class="runtime", exception_type=type(error).__name__)
        code = 5
    finally:
        if lock_handle:
            lock_handle.close()
        secrets.clear()
    envelope["finished_at_utc"] = utc()
    print(canonical(envelope), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
