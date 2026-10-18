"""SQLite persistence with versioned migrations.

SQLite is the durable source of truth for the runnable edition (ADR-0001).
The schema mirrors the specification's PostgreSQL model so it can be ported.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
CREATE TABLE users (
  id TEXT PRIMARY KEY, email TEXT UNIQUE, display_name TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL DEFAULT 'builder', is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE projects (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL, slug TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  brief TEXT NOT NULL, selected_template TEXT NOT NULL, preferred_stack TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  archived_at TEXT
);
CREATE INDEX ix_projects_owner ON projects(owner_id, created_at);
CREATE TABLE project_versions (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
  version_number INTEGER NOT NULL, brief_snapshot TEXT NOT NULL,
  requirements TEXT, architecture TEXT, plan TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(project_id, version_number)
);
CREATE TABLE provider_configs (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
  provider_type TEXT NOT NULL, display_name TEXT NOT NULL, base_url TEXT,
  model_name TEXT NOT NULL, secret_reference TEXT, settings TEXT NOT NULL DEFAULT '{}',
  is_enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE runs (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
  project_version_id TEXT REFERENCES project_versions(id), status TEXT NOT NULL,
  current_stage TEXT NOT NULL, requested_by TEXT NOT NULL REFERENCES users(id),
  provider_key TEXT NOT NULL, model_name TEXT NOT NULL, provider_config_id TEXT,
  config_snapshot TEXT NOT NULL DEFAULT '{}', budget TEXT NOT NULL DEFAULT '{}',
  usage TEXT NOT NULL DEFAULT '{}', plan_version INTEGER NOT NULL DEFAULT 0,
  plan TEXT, repair_attempts INTEGER NOT NULL DEFAULT 0,
  started_at TEXT, finished_at TEXT, error_code TEXT, error_summary TEXT,
  cancel_requested_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX ix_runs_project ON runs(project_id, created_at);
CREATE INDEX ix_runs_status ON runs(status, created_at);
CREATE TABLE tasks (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), task_key TEXT NOT NULL,
  title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', agent_role TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', input TEXT NOT NULL DEFAULT '{}', output TEXT NOT NULL DEFAULT '{}',
  attempt_count INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 2,
  started_at TEXT, finished_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(run_id, task_key)
);
CREATE TABLE task_dependencies (
  task_id TEXT NOT NULL REFERENCES tasks(id), depends_on_task_id TEXT NOT NULL REFERENCES tasks(id),
  PRIMARY KEY (task_id, depends_on_task_id), CHECK (task_id != depends_on_task_id)
);
CREATE TABLE agent_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES runs(id), task_id TEXT,
  sequence_number INTEGER NOT NULL, event_type TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info',
  message TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
  UNIQUE(run_id, sequence_number)
);
CREATE INDEX ix_events_run ON agent_events(run_id, sequence_number);
CREATE TABLE approvals (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), approval_type TEXT NOT NULL,
  requested_by TEXT, decided_by TEXT, decision TEXT, comment TEXT, plan_version INTEGER NOT NULL DEFAULT 0,
  requested_at TEXT NOT NULL, decided_at TEXT
);
CREATE TABLE artifacts (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), artifact_type TEXT NOT NULL,
  display_name TEXT NOT NULL, storage_key TEXT NOT NULL, mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL, expires_at TEXT
);
CREATE TABLE audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT, run_id TEXT, action TEXT NOT NULL,
  resource_type TEXT NOT NULL, resource_id TEXT, outcome TEXT NOT NULL, correlation_id TEXT,
  details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;
CREATE TABLE jobs (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), step_id TEXT NOT NULL,
  attempt INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'queued',
  available_at REAL NOT NULL, lease_expires_at REAL, worker_id TEXT, last_error TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(run_id, step_id, attempt)
);
CREATE INDEX ix_jobs_status ON jobs(status, available_at);
CREATE TABLE verification_results (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), round INTEGER NOT NULL,
  check_name TEXT NOT NULL, command TEXT NOT NULL, exit_code INTEGER, status TEXT NOT NULL,
  duration_ms INTEGER NOT NULL, output_summary TEXT NOT NULL, sandbox TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE security_findings (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), severity TEXT NOT NULL,
  category TEXT NOT NULL, file_path TEXT, line INTEGER, message TEXT NOT NULL, evidence TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE policies (
  owner_id TEXT PRIMARY KEY REFERENCES users(id), data TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
  csrf_token TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, run_id TEXT, kind TEXT NOT NULL,
  message TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
""",
    ),
    (
        2,
        """
ALTER TABLE users ADD COLUMN password_hash TEXT;
ALTER TABLE users ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TEXT;
ALTER TABLE users ADD COLUMN password_changed_at TEXT;
ALTER TABLE sessions ADD COLUMN last_seen TEXT;
""",
    ),
    (
        3,
        """
ALTER TABLE users ADD COLUMN recovery_hash TEXT;
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
""",
    ),
]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id() -> str:
    return str(uuid.uuid4())


def dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str)


def loads(raw: str | None, default: Any = None) -> Any:
    if raw is None or raw == "":
        return default
    return json.loads(raw)


class Database:
    """Thread-safe-ish wrapper: one connection per thread, WAL, FK enforcement."""

    def __init__(self, path: str):
        self.path = path
        self._local = threading.local()
        self.migrate()

    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=30000")
            self._local.c = c
        return c

    def migrate(self) -> None:
        c = self.conn()
        c.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        done = {r["version"] for r in c.execute("SELECT version FROM schema_migrations")}
        for version, sql in MIGRATIONS:
            if version in done:
                continue
            c.execute("BEGIN IMMEDIATE")
            try:
                for stmt in _split_sql(sql):
                    c.execute(stmt)
                c.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (?,?)", (version, utcnow()))
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise

    # -- helpers ---------------------------------------------------------
    def one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        return self.conn().execute(sql, tuple(params)).fetchone()

    def all(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return self.conn().execute(sql, tuple(params)).fetchall()

    def run(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        return self.conn().execute(sql, tuple(params))

    def tx(self) -> "_Tx":
        return _Tx(self.conn())


def _split_sql(script: str) -> list[str]:
    """Split on semicolons while keeping CREATE TRIGGER ... END; blocks intact."""
    stmts: list[str] = []
    buf: list[str] = []
    in_trigger = False
    for line in script.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        buf.append(line)
        if stripped.upper().startswith("CREATE TRIGGER"):
            in_trigger = True
        if in_trigger:
            if stripped.upper().endswith("END;"):
                stmts.append("\n".join(buf))
                buf, in_trigger = [], False
        elif stripped.endswith(";"):
            stmts.append("\n".join(buf))
            buf = []
    if buf:
        stmts.append("\n".join(buf))
    return stmts


class _Tx:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def __enter__(self) -> sqlite3.Connection:
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> None:
        self.conn.execute("ROLLBACK" if exc_type else "COMMIT")
