"""Durable job worker backed by the `jobs` table (PostgreSQL/SQLite stays the source of truth)."""
from __future__ import annotations

import logging
import threading
import time
import uuid

from autoforge.core.db import utcnow
from autoforge.orchestration.engine import Engine

log = logging.getLogger("autoforge.worker")


class Worker:
    def __init__(self, engine: Engine, poll_seconds: float = 0.2, lease_seconds: int = 120):
        self.engine = engine
        self.db = engine.db
        self.poll, self.lease = poll_seconds, lease_seconds
        self.worker_id = f"worker-{uuid.uuid4().hex[:8]}"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def reclaim_expired(self) -> int:
        """Re-queue jobs whose worker died (lease expired). Steps are idempotent, so replay is safe."""
        cur = self.db.run(
            "UPDATE jobs SET status='queued', worker_id=NULL, lease_expires_at=NULL, updated_at=? "
            "WHERE status='running' AND lease_expires_at < ?", (utcnow(), time.time()))
        return cur.rowcount

    def claim(self) -> dict | None:
        self.reclaim_expired()
        with self.db.tx() as c:
            row = c.execute("SELECT * FROM jobs WHERE status='queued' AND available_at <= ? ORDER BY available_at, created_at LIMIT 1",
                            (time.time(),)).fetchone()
            if row is None:
                return None
            c.execute("UPDATE jobs SET status='running', worker_id=?, lease_expires_at=?, updated_at=? WHERE id=? AND status='queued'",
                      (self.worker_id, time.time() + self.lease, utcnow(), row["id"]))
            return dict(row)

    def run_once(self) -> bool:
        job = self.claim()
        if job is None:
            return False
        try:
            self.engine.process_job(job)
            self.db.run("UPDATE jobs SET status='done', updated_at=? WHERE id=?", (utcnow(), job["id"]))
        except Exception as exc:  # engine handles its own errors; this is a last resort
            log.exception("job %s crashed", job["id"])
            self.db.run("UPDATE jobs SET status='failed', last_error=?, updated_at=? WHERE id=?", (type(exc).__name__, utcnow(), job["id"]))
        return True

    def drain(self, limit: int = 1000) -> int:
        n = 0
        while n < limit and self.run_once():
            n += 1
        return n

    # -- background thread ---------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name=self.worker_id, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if not self.run_once():
                    self._stop.wait(self.poll)
            except Exception:  # noqa: BLE001
                log.exception("worker loop error")
                self._stop.wait(1.0)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
