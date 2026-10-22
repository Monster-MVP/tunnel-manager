from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from app.models.runtime import stopped_runtime, utc_now
from app.schemas.inputs import ServerInput, SettingsInput


class RepositoryError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 409):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = {}


MIGRATIONS = [
    """
    CREATE TABLE groups(id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                        created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE servers(
        id TEXT PRIMARY KEY, name TEXT NOT NULL,
        group_id TEXT REFERENCES groups(id) ON DELETE SET NULL,
        host TEXT NOT NULL, ssh_port INTEGER NOT NULL CHECK(ssh_port BETWEEN 1 AND 65535),
        user TEXT NOT NULL, remote_proxy_port INTEGER NOT NULL CHECK(remote_proxy_port BETWEEN 1024 AND 65535),
        mode TEXT NOT NULL CHECK(mode IN ('MAC_DIRECT','CLASH_HTTP','DISABLED')),
        management TEXT NOT NULL CHECK(management IN ('MANAGED','OBSERVED_EXTERNAL')),
        desired_state TEXT NOT NULL CHECK(desired_state IN ('STOPPED','RUNNING')),
        revision INTEGER NOT NULL CHECK(revision > 0),
        payload TEXT NOT NULL CHECK(json_valid(payload)),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted_at TEXT);
    CREATE INDEX servers_visible ON servers(deleted_at, group_id);
    CREATE TABLE runtime_state(server_id TEXT PRIMARY KEY REFERENCES servers(id),
        state TEXT NOT NULL CHECK(state IN ('STOPPED','STARTING','HEALTHY','DEGRADED','RECONNECTING',
                                          'FAILED','AUTH_REQUIRED','PORT_CONFLICT')),
        observed_at TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)));
    CREATE TABLE health_samples(id INTEGER PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id),
        observed_at TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)));
    CREATE INDEX samples_server_time ON health_samples(server_id,observed_at);
    CREATE TABLE state_events(id INTEGER PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id),
        occurred_at TEXT NOT NULL, from_state TEXT, to_state TEXT NOT NULL, reason_code TEXT,
        generation INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE logs(id INTEGER PRIMARY KEY, server_id TEXT REFERENCES servers(id),
        occurred_at TEXT NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL);
    CREATE INDEX logs_server_time ON logs(server_id,id);
    CREATE TABLE app_settings(key TEXT PRIMARY KEY, value_json TEXT NOT NULL CHECK(json_valid(value_json)),
        revision INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL);
    CREATE TABLE audit_events(id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL,
        action TEXT NOT NULL, server_id TEXT, result TEXT NOT NULL,
        redacted_details_json TEXT NOT NULL CHECK(json_valid(redacted_details_json)));
    CREATE TABLE operations(id TEXT PRIMARY KEY, server_id TEXT, actor_scope TEXT NOT NULL,
        action TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','CANCELLED')),
        request_sha256 TEXT NOT NULL, key_hash TEXT, payload TEXT NOT NULL CHECK(json_valid(payload)),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE(actor_scope,server_id,key_hash));
    CREATE TABLE artifacts(id TEXT PRIMARY KEY, filename TEXT NOT NULL, kind TEXT NOT NULL,
        created_at TEXT NOT NULL);
    """,
    """
    CREATE TABLE proxy_endpoints(id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL CHECK(kind IN ('MANAGED_TINYPROXY','EXTERNAL_TINYPROXY','EXTERNAL_HTTP')),
        ownership TEXT NOT NULL CHECK(ownership IN ('APP_OWNED','OBSERVED_EXTERNAL')),
        bind_host TEXT NOT NULL, port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
        config_ref TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE ssh_imports(id TEXT PRIMARY KEY, source_path_redacted TEXT, source_sha256 TEXT NOT NULL,
        diagnostics_json TEXT NOT NULL CHECK(json_valid(diagnostics_json)), created_at TEXT NOT NULL);
    """
]


def json_dumps(value) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def restricted_directory(path: Path) -> Path:
    path = Path(path).absolute()
    for component in (path, *path.parents):
        if component.is_symlink():
            raise RepositoryError("UNSAFE_STORAGE_PATH", "Storage must not contain symbolic links", 503)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.getuid():
        raise RepositoryError("UNSAFE_STORAGE_OWNER", "Storage must belong to the current user", 503)
    path.chmod(0o700)
    return path


def redact_text(value: str, sensitive: list[str] | None = None) -> str:
    value = str(value)[:8192]
    if "PRIVATE KEY" in value:
        return "[redacted private key material]"
    value = re.sub(r"(?i)(authorization\s*[:=]\s*|bearer\s+|(?:password|token|api[_-]?key|secret)\s*[:=]\s*)[^\s,;]+",
                   r"\1[redacted]", value)
    value = re.sub(r"(https?://[^\s?]+)\?[^\s]+", r"\1?[redacted]", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[address]", value)
    value = re.sub(r"(?<!\w)/(?:[^\s:,]+/)*[^\s:,]+", "[path]", value)
    for item in sorted(sensitive or [], key=len, reverse=True):
        if item:
            value = re.sub(r"(?<![\w.-])" + re.escape(item) + r"(?![\w.-])", "[redacted]", value)
    return value


def redact_details(value, sensitive: list[str] | None = None):
    if isinstance(value, dict):
        secret_fields = ("ticket", "csrf", "cookie", "authorization", "password", "token", "api_key",
                         "identity_file_ref", "host", "user", "path", "health_url", "ssh_alias")
        return {str(key): "[redacted]" if str(key).lower() in secret_fields else redact_details(item, sensitive)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact_details(item, sensitive) for item in value]
    if isinstance(value, str):
        return redact_text(value, sensitive)
    return value


class Repository:
    def __init__(self, data_dir: Path):
        self.data_dir = restricted_directory(data_dir)
        self.path = self.data_dir / "tunnel-manager.sqlite3"
        self.backup_dir = restricted_directory(self.data_dir / "backups")
        self.artifact_dir = restricted_directory(self.data_dir / "artifacts")
        for path in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            if path.is_symlink():
                raise RepositoryError("UNSAFE_STORAGE_PATH", "Database paths must not be symbolic links", 503)
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(self.path, check_same_thread=False, timeout=5)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        if self.connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            self.connection.close()
            raise RepositoryError("DATABASE_CORRUPT", "Database integrity check failed; preserve data for recovery", 503)
        self._migrate()
        self._restrict_files()
        self.update_settings(self.settings())
        # Persisted observations are historical facts after a backend restart.
        with self._transaction() as conn:
            for row in conn.execute("SELECT server_id,payload FROM runtime_state").fetchall():
                value = json.loads(row["payload"])
                value["stale"] = True
                value.update(state="STOPPED", reason_code="BACKEND_RESTARTED", process_alive=False,
                             ssh_connected=False, remote_listener="UNKNOWN", proxy_health="UNKNOWN", pid=None)
                conn.execute("UPDATE runtime_state SET payload=? WHERE server_id=?",
                             (json_dumps(value), row["server_id"]))
                conn.execute("UPDATE runtime_state SET state='STOPPED' WHERE server_id=?", (row["server_id"],))
            for row in conn.execute("SELECT id,payload FROM operations WHERE status IN ('QUEUED','RUNNING')").fetchall():
                value = json.loads(row["payload"])
                value.update(status="FAILED", error_code="BACKEND_INTERRUPTED", updated_at=utc_now(),
                             outcome={"message": "Backend restarted before the operation completed"})
                conn.execute("UPDATE operations SET status='FAILED',payload=?,updated_at=? WHERE id=?",
                             (json_dumps(value), value["updated_at"], row["id"]))

    def _restrict_files(self):
        for filename in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            if filename.exists():
                filename.chmod(0o600)

    def _migrate(self):
        self.connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations("
                                "version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)")
        versions = self.connection.execute("SELECT version,checksum FROM schema_migrations ORDER BY version").fetchall()
        for row in versions:
            version = row["version"]
            if version > len(MIGRATIONS) or hashlib.sha256(MIGRATIONS[version - 1].encode()).hexdigest() != row["checksum"]:
                raise RepositoryError("MIGRATION_MISMATCH", "Applied schema differs from this application; no writes allowed", 503)
        for version, statement in enumerate(MIGRATIONS, start=1):
            if version <= len(versions):
                continue
            checksum = hashlib.sha256(statement.encode()).hexdigest()
            try:
                self.connection.executescript("BEGIN IMMEDIATE;\n" + statement)
                self.connection.execute("INSERT INTO schema_migrations VALUES(?,?,?)", (version, checksum, utc_now()))
                self.connection.commit()
            except BaseException:
                self.connection.rollback()
                raise

    @contextmanager
    def _transaction(self):
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                yield self.connection
                self.connection.commit()
                self._restrict_files()
            except sqlite3.IntegrityError as error:
                self.connection.rollback()
                raise RepositoryError("CONSTRAINT_CONFLICT", "A duplicate name or missing referenced resource conflicts") from error
            except sqlite3.Error as error:
                self.connection.rollback()
                raise RepositoryError("STORAGE_UNAVAILABLE", "Database write failed; operation was not saved", 503) from error
            except BaseException:
                self.connection.rollback()
                raise

    def close(self):
        with self._lock:
            self.connection.close()

    def _server(self, row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        value = json.loads(row["payload"])
        for key in ("id", "name", "group_id", "host", "ssh_port", "user", "remote_proxy_port", "mode",
                    "management", "desired_state", "revision", "created_at", "updated_at"):
            value[key] = row[key]
        return value

    def list_servers(self) -> list[dict]:
        with self._lock:
            return [self._server(row) for row in self.connection.execute(
                "SELECT * FROM servers WHERE deleted_at IS NULL ORDER BY created_at,id").fetchall()]

    def get_server(self, server_id: str) -> dict | None:
        with self._lock:
            return self._server(self.connection.execute(
                "SELECT * FROM servers WHERE id=? AND deleted_at IS NULL", (server_id,)).fetchone())

    def _insert_server(self, conn, value: dict) -> dict:
        server = ServerInput.model_validate(value).model_dump()
        server.update(id=str(uuid4()), desired_state="STOPPED", revision=1, created_at=utc_now(), updated_at=utc_now())
        conn.execute("INSERT INTO servers(id,name,group_id,host,ssh_port,user,remote_proxy_port,mode,management,"
                     "desired_state,revision,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     tuple(server[key] for key in ("id", "name", "group_id", "host", "ssh_port", "user",
                                                  "remote_proxy_port", "mode", "management", "desired_state", "revision"))
                     + (json_dumps(server), server["created_at"], server["updated_at"]))
        runtime = stopped_runtime(server["id"])
        conn.execute("INSERT INTO runtime_state VALUES(?,?,?,?)",
                     (server["id"], runtime["state"], runtime["observed_at"], json_dumps(runtime)))
        return server

    def create_server(self, value: dict) -> dict:
        with self._transaction() as conn:
            return self._insert_server(conn, value)

    def import_servers(self, values: list[dict]) -> list[dict]:
        with self._transaction() as conn:
            return [self._insert_server(conn, value) for value in values]

    def import_configuration(self, config: dict) -> list[dict]:
        with self._transaction() as conn:
            group_map = {}
            for old in config.get("groups", []):
                existing = conn.execute("SELECT id FROM groups WHERE name=?", (old["name"],)).fetchone()
                group_id = existing[0] if existing else str(uuid4())
                if not existing:
                    conn.execute("INSERT INTO groups VALUES(?,?,?,?)", (group_id, old["name"], utc_now(), utc_now()))
                if old.get("id"):
                    group_map[old["id"]] = group_id
            values = []
            for old in config.get("servers", []):
                value = dict(old)
                if value.get("group_id"):
                    if value["group_id"] not in group_map:
                        raise RepositoryError("INVALID_GROUP_REFERENCE", "Imported server group is missing from configuration", 422)
                    value["group_id"] = group_map[value["group_id"]]
                values.append(self._insert_server(conn, value))
            if config.get("settings"):
                settings = SettingsInput.model_validate(config["settings"]).model_dump()
                for key, item in settings.items():
                    conn.execute("INSERT INTO app_settings VALUES(?,?,1,?) ON CONFLICT(key) DO UPDATE SET "
                                 "value_json=excluded.value_json,revision=app_settings.revision+1,updated_at=excluded.updated_at",
                                 (key, json_dumps(item), utc_now()))
            return values

    def update_server(self, server_id: str, value: dict, expected_revision=None) -> dict:
        with self._transaction() as conn:
            existing = self._server(conn.execute(
                "SELECT * FROM servers WHERE id=? AND deleted_at IS NULL", (server_id,)).fetchone())
            if existing is None:
                raise RepositoryError("NOT_FOUND", "Server does not exist", 404)
            if expected_revision is not None and existing["revision"] != expected_revision:
                raise RepositoryError("REVISION_CONFLICT", "Server changed; reload before updating")
            valid_fields = set(ServerInput.model_fields) | {"desired_state"}
            if set(value) - valid_fields:
                raise RepositoryError("INVALID_FIELDS", "Unknown server fields cannot be saved", 422)
            merged = {key: item for key, item in existing.items() if key in ServerInput.model_fields}
            merged.update({key: item for key, item in value.items() if key in ServerInput.model_fields})
            checked = ServerInput.model_validate(merged).model_dump()
            desired = value.get("desired_state", existing["desired_state"])
            if desired not in ("STOPPED", "RUNNING") or (checked["management"] == "OBSERVED_EXTERNAL" and desired != "STOPPED"):
                raise RepositoryError("INVALID_DESIRED_STATE", "External resources cannot be controlled", 403)
            checked.update(id=server_id, desired_state=desired, revision=existing["revision"] + 1,
                           created_at=existing["created_at"], updated_at=utc_now())
            conn.execute("UPDATE servers SET name=?,group_id=?,host=?,ssh_port=?,user=?,remote_proxy_port=?,mode=?,"
                         "management=?,desired_state=?,revision=?,payload=?,updated_at=? WHERE id=?",
                         tuple(checked[key] for key in ("name", "group_id", "host", "ssh_port", "user",
                                                        "remote_proxy_port", "mode", "management", "desired_state", "revision"))
                         + (json_dumps(checked), checked["updated_at"], server_id))
            return checked

    def delete_server(self, server_id: str):
        with self._transaction() as conn:
            server = self._server(conn.execute("SELECT * FROM servers WHERE id=? AND deleted_at IS NULL", (server_id,)).fetchone())
            if server is None:
                raise RepositoryError("NOT_FOUND", "Server does not exist", 404)
            runtime_row = conn.execute("SELECT payload FROM runtime_state WHERE server_id=?", (server_id,)).fetchone()
            runtime = json.loads(runtime_row[0]) if runtime_row else {}
            if server["management"] == "MANAGED" and (server["desired_state"] == "RUNNING" or runtime.get("process_alive")):
                raise RepositoryError("ACTIVE_RESOURCE", "Stop the managed tunnel before deleting its profile")
            conn.execute("UPDATE servers SET deleted_at=?,updated_at=?,revision=revision+1 WHERE id=?",
                         (utc_now(), utc_now(), server_id))

    def list_groups(self) -> list[dict]:
        with self._lock:
            return [dict(row) for row in self.connection.execute("SELECT * FROM groups ORDER BY name").fetchall()]

    def create_group(self, name) -> dict:
        name = name["name"] if isinstance(name, dict) else name
        group = {"id": str(uuid4()), "name": name.strip(), "created_at": utc_now(), "updated_at": utc_now()}
        if not group["name"] or len(group["name"]) > 120:
            raise RepositoryError("INVALID_GROUP", "Group name is required", 422)
        with self._transaction() as conn:
            conn.execute("INSERT INTO groups VALUES(?,?,?,?)", tuple(group.values()))
        return group

    def delete_group(self, group_id: str):
        with self._transaction() as conn:
            if conn.execute("DELETE FROM groups WHERE id=?", (group_id,)).rowcount == 0:
                raise RepositoryError("NOT_FOUND", "Group does not exist", 404)

    def save_runtime(self, value: dict):
        server_id = value["server_id"]
        with self._transaction() as conn:
            row = conn.execute("SELECT payload FROM runtime_state WHERE server_id=?", (server_id,)).fetchone()
            runtime = json.loads(row[0]) if row else stopped_runtime(server_id)
            before = runtime["state"]
            runtime.update(value)
            runtime["observed_at"] = value.get("observed_at", utc_now())
            conn.execute("INSERT INTO runtime_state VALUES(?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET "
                         "state=excluded.state,observed_at=excluded.observed_at,payload=excluded.payload",
                         (server_id, runtime["state"], runtime["observed_at"], json_dumps(runtime)))
            if before != runtime["state"]:
                conn.execute("INSERT INTO state_events(server_id,occurred_at,from_state,to_state,reason_code,generation) "
                             "VALUES(?,?,?,?,?,?)", (server_id, runtime["observed_at"], before, runtime["state"],
                                                   runtime.get("reason_code"), runtime.get("generation", 0)))

    def get_runtime(self, server_id: str) -> dict | None:
        with self._lock:
            row = self.connection.execute("SELECT payload FROM runtime_state WHERE server_id=?", (server_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def add_sample(self, server_id: str, value: dict):
        sample = dict(value)
        sample.setdefault("observed_at", utc_now())
        for key in ("total_ms", "tls_completed_ms", "tls_handshake_ms"):
            if sample.get(key) is not None and sample[key] < 0:
                raise RepositoryError("INVALID_SAMPLE", "Metric durations must not be negative", 422)
        if sample.get("http_status") is not None and not 100 <= sample["http_status"] <= 599:
            raise RepositoryError("INVALID_SAMPLE", "HTTP status is outside its valid range", 422)
        with self._transaction() as conn:
            conn.execute("INSERT INTO health_samples(server_id,observed_at,payload) VALUES(?,?,?)",
                         (server_id, sample["observed_at"], json_dumps(sample)))

    def samples(self, server_id: str, limit=500) -> list[dict]:
        with self._lock:
            rows = self.connection.execute("SELECT payload FROM health_samples WHERE server_id=? ORDER BY id DESC LIMIT ?",
                                           (server_id, min(max(int(limit), 1), 10000))).fetchall()
            return [json.loads(row[0]) for row in reversed(rows)]

    def samples_in_range(self, server_id: str, range_name: str = "1h") -> dict:
        """Return only observed samples in a bounded window with truthful aggregates."""
        windows = {"5m": timedelta(minutes=5), "1h": timedelta(hours=1),
                   "24h": timedelta(hours=24), "7d": timedelta(days=7)}
        if range_name not in windows:
            raise RepositoryError("INVALID_RANGE", "Range must be one of 5m, 1h, 24h or 7d", 422)
        end = datetime.now(UTC)
        start = end - windows[range_name]
        bucket_seconds = {"5m": 1, "1h": 5, "24h": 120, "7d": 900}[range_name]
        with self._lock:
            rows = self.connection.execute(
                "SELECT payload FROM health_samples WHERE id IN (SELECT MAX(id) FROM health_samples "
                "WHERE server_id=? AND julianday(observed_at)>=julianday(?) AND julianday(observed_at)<=julianday(?) "
                "GROUP BY CAST(unixepoch(observed_at)/? AS INTEGER)) ORDER BY observed_at ASC",
                (server_id, start.isoformat(), end.isoformat(), bucket_seconds)).fetchall()
            counts = self.connection.execute(
                "SELECT COUNT(*),SUM(CASE WHEN json_extract(payload,'$.state')='HEALTHY' AND "
                "COALESCE(json_extract(payload,'$.stale'),0)=0 THEN 1 ELSE 0 END), "
                "AVG(json_extract(payload,'$.total_ms')), MIN(observed_at), MAX(observed_at) FROM health_samples WHERE server_id=? "
                "AND julianday(observed_at)>=julianday(?) AND julianday(observed_at)<=julianday(?)",
                (server_id, start.isoformat(), end.isoformat())).fetchone()
            median = self.connection.execute(
                "WITH durations AS (SELECT json_extract(payload,'$.total_ms') AS ms FROM health_samples "
                "WHERE server_id=? AND julianday(observed_at)>=julianday(?) AND julianday(observed_at)<=julianday(?) "
                "AND json_type(payload,'$.total_ms') IN ('integer','real')), "
                "ranked AS (SELECT ms,ROW_NUMBER() OVER (ORDER BY ms) AS rn,COUNT(*) OVER () AS n FROM durations) "
                "SELECT AVG(ms) FROM ranked WHERE rn IN ((n+1)/2,(n+2)/2)",
                (server_id, start.isoformat(), end.isoformat())).fetchone()[0]
        samples = [json.loads(row[0]) for row in rows]
        summary = {
            "sample_count": counts[0],
            "success_count": counts[1] or 0,
            "success_ratio": ((counts[1] or 0) / counts[0]) if counts[0] else None,
            "avg_total_ms": counts[2],
            "p50_total_ms": median,
            "first_observed_at": counts[3],
            "last_observed_at": counts[4],
        }
        return {"server_id": server_id, "range": range_name, "from": start.isoformat(), "to": end.isoformat(),
                "sampling": {"strategy": "LATEST_OBSERVATION_PER_BUCKET", "bucket_seconds": bucket_seconds,
                             "displayed_count": len(samples), "summary_scope": "ALL_OBSERVATIONS"},
                "samples": samples, "summary": summary}

    def state_events(self, server_id: str, limit=200) -> list[dict]:
        with self._lock:
            return [dict(row) for row in self.connection.execute(
                "SELECT * FROM state_events WHERE server_id=? ORDER BY id DESC LIMIT ?", (server_id, min(limit, 1000))).fetchall()]

    def _sensitive(self) -> list[str]:
        return [server[key] for server in self.list_servers() for key in ("host", "user", "identity_file_ref", "ssh_alias")
                if server.get(key)]

    def append_log(self, server_id: str | None, level: str, message: str):
        message = redact_text(message, self._sensitive())
        with self._transaction() as conn:
            conn.execute("INSERT INTO logs(server_id,occurred_at,level,message) VALUES(?,?,?,?)",
                         (server_id, utc_now(), level[:16], message))
            # Bound database logs even if a misbehaving child streams forever.
            conn.execute("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 10000)")

    def logs(self, server_id: str | None, limit=200, q="") -> list[dict]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT id,occurred_at,level,message FROM logs WHERE server_id IS ? AND instr(message,?)>0 "
                "ORDER BY id DESC LIMIT ?", (server_id, q[:200], min(max(limit, 1), 1000))).fetchall()
            return [dict(row) for row in reversed(rows)]

    def settings(self) -> dict:
        defaults = SettingsInput().model_dump()
        with self._lock:
            for row in self.connection.execute("SELECT key,value_json FROM app_settings").fetchall():
                if row["key"] in defaults:
                    defaults[row["key"]] = json.loads(row["value_json"])
        return defaults

    def update_settings(self, value: dict) -> dict:
        updated = SettingsInput.model_validate(self.settings() | value).model_dump()
        with self._transaction() as conn:
            for key, item in updated.items():
                conn.execute("INSERT INTO app_settings VALUES(?,?,1,?) ON CONFLICT(key) DO UPDATE SET "
                             "value_json=excluded.value_json,revision=app_settings.revision+1,updated_at=excluded.updated_at",
                             (key, json_dumps(item), utc_now()))
        return updated

    def purge_history(self, now: datetime | None = None) -> dict[str, int]:
        settings = self.settings()
        current = (now or datetime.now(UTC)).astimezone(UTC)
        raw_cutoff = (current - timedelta(days=settings["raw_retention_days"])).isoformat()
        audit_cutoff = (current - timedelta(days=settings["audit_retention_days"])).isoformat()
        counts = {}
        with self._transaction() as conn:
            for table, column, cutoff in (
                ("health_samples", "observed_at", raw_cutoff),
                ("state_events", "occurred_at", raw_cutoff),
                ("logs", "occurred_at", raw_cutoff),
                ("audit_events", "occurred_at", audit_cutoff),
            ):
                counts[table] = conn.execute(
                    f"DELETE FROM {table} WHERE julianday({column}) < julianday(?)", (cutoff,)
                ).rowcount
            counts["operations"] = conn.execute(
                "DELETE FROM operations WHERE status IN ('SUCCEEDED','FAILED','CANCELLED') "
                "AND julianday(updated_at) < julianday(?)", (audit_cutoff,)
            ).rowcount
        return counts

    def audit(self, action: str, server_id: str | None, result: str, details):
        clean = redact_details(details, self._sensitive())
        with self._transaction() as conn:
            conn.execute("INSERT INTO audit_events(occurred_at,action,server_id,result,redacted_details_json) VALUES(?,?,?,?,?)",
                         (utc_now(), action[:120], server_id, result[:32], json_dumps(clean)))

    def audit_events(self, limit=200) -> list[dict]:
        with self._lock:
            events = []
            for row in self.connection.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (min(limit, 1000),)).fetchall():
                value = dict(row)
                value["details"] = json.loads(value.pop("redacted_details_json"))
                events.append(value)
            return events

    def activity_events(self, limit=30) -> list[dict]:
        """Merge durable user operations and actual connection-state transitions."""
        bounded = min(max(int(limit), 1), 200)
        audits = [{**item, "id": f"audit-{item['id']}"} for item in self.audit_events(bounded)]
        with self._lock:
            rows = self.connection.execute("SELECT * FROM state_events ORDER BY id DESC LIMIT ?", (bounded,)).fetchall()
        states = [{"id": f"state-{item['id']}", "occurred_at": item["occurred_at"], "action": "connection.state",
                   "server_id": item["server_id"], "result": item["to_state"],
                   "details": {"from_state": item["from_state"], "to_state": item["to_state"],
                               "reason_code": item["reason_code"], "generation": item["generation"]}}
                  for item in rows]
        return sorted(audits + states, key=lambda item: item["occurred_at"], reverse=True)[:bounded]

    def backup(self) -> Path:
        target = self.backup_dir / f"tunnel-manager-{uuid4()!s}.sqlite3"
        with self._lock:
            backup = sqlite3.connect(target)
            try:
                self.connection.backup(backup)
            finally:
                backup.close()
            target.chmod(0o600)
        return target

    def create_operation(self, server_id: str, action: str, actor_scope: str, key: str | None, request: dict) -> tuple[dict, bool]:
        digest = hashlib.sha256(json_dumps(request).encode()).hexdigest()
        key_hash = hashlib.sha256(key.encode()).hexdigest() if key else None
        with self._transaction() as conn:
            if key_hash:
                row = conn.execute("SELECT request_sha256,payload FROM operations WHERE actor_scope=? AND server_id=? AND key_hash=?",
                                   (actor_scope, server_id, key_hash)).fetchone()
                if row:
                    if row["request_sha256"] != digest:
                        raise RepositoryError("IDEMPOTENCY_CONFLICT", "Idempotency key was already used for another request")
                    return json.loads(row["payload"]), False
            operation = {"id": str(uuid4()), "server_id": server_id, "action": action, "status": "QUEUED",
                         "accepted_at": utc_now(), "error_code": None, "outcome": None, "correlation_id": str(uuid4())}
            operation["operation_id"] = operation["id"]
            conn.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (operation["id"], server_id, actor_scope, action, operation["status"], digest, key_hash,
                          json_dumps(operation), operation["accepted_at"], utc_now()))
            return operation, True

    def get_operation(self, operation_id: str) -> dict | None:
        with self._lock:
            row = self.connection.execute("SELECT payload FROM operations WHERE id=?", (operation_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def update_operation(self, operation_id: str, status: str, **fields) -> dict:
        with self._transaction() as conn:
            row = conn.execute("SELECT payload FROM operations WHERE id=?", (operation_id,)).fetchone()
            if row is None:
                raise RepositoryError("NOT_FOUND", "Operation does not exist", 404)
            operation = json.loads(row[0]) | fields | {"status": status, "updated_at": utc_now()}
            conn.execute("UPDATE operations SET status=?,payload=?,updated_at=? WHERE id=?",
                         (status, json_dumps(operation), operation["updated_at"], operation_id))
            return operation

    def save_artifact(self, content: dict, kind: str) -> dict:
        artifact_id = str(uuid4())
        filename = artifact_id + ".json"
        path = self.artifact_dir / filename
        with path.open("x", encoding="utf-8") as stream:
            json.dump(content, stream, ensure_ascii=True, indent=2, allow_nan=False)
        path.chmod(0o600)
        with self._transaction() as conn:
            conn.execute("INSERT INTO artifacts VALUES(?,?,?,?)", (artifact_id, filename, kind, utc_now()))
        return {"artifact_id": artifact_id, "kind": kind, "download_url": f"/api/v1/artifacts/{artifact_id}"}

    def get_artifact(self, artifact_id: str) -> Path | None:
        with self._lock:
            row = self.connection.execute("SELECT filename FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            if row is None:
                return None
            path = self.artifact_dir / row[0]
            if path.is_symlink() or path.parent != self.artifact_dir or not path.is_file():
                raise RepositoryError("UNSAFE_ARTIFACT", "Artifact is missing or unsafe", 503)
            return path

    def list_proxy_endpoints(self) -> list[dict]:
        with self._lock:
            return [dict(row) for row in self.connection.execute("SELECT * FROM proxy_endpoints ORDER BY name").fetchall()]

    def create_proxy_endpoint(self, value: dict) -> dict:
        endpoint = {"id": str(uuid4()), "name": str(value.get("name", "")).strip(),
                    "kind": value.get("kind", "EXTERNAL_HTTP"),
                    "ownership": value.get("ownership", "OBSERVED_EXTERNAL"),
                    "bind_host": value.get("bind_host", "127.0.0.1"), "port": int(value.get("port", 80)),
                    "config_ref": value.get("config_ref"), "created_at": utc_now(), "updated_at": utc_now()}
        if not endpoint["name"] or endpoint["port"] < 1 or endpoint["port"] > 65535:
            raise RepositoryError("INVALID_ENDPOINT", "Endpoint name and valid port are required", 422)
        if endpoint["kind"] == "MANAGED_TINYPROXY" and endpoint["bind_host"] not in ("127.0.0.1", "::1", "localhost"):
            raise RepositoryError("LOOPBACK_REQUIRED", "Managed proxy endpoints must bind to loopback", 422)
        with self._transaction() as conn:
            conn.execute("INSERT INTO proxy_endpoints VALUES(?,?,?,?,?,?,?,?,?)", tuple(endpoint.values()))
        return endpoint
