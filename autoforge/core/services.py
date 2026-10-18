"""Core services: events, audit, notifications, centralized state transitions."""
from __future__ import annotations

import time
from typing import Any

from autoforge.core.db import Database, dumps, loads, new_id, utcnow
from autoforge.domain.states import (
    STAGE_FOR_STATUS,
    TERMINAL,
    IllegalTransition,
    RunStatus,
    can_transition,
)
from autoforge.security.redaction import redact

MAX_EVENT_PAYLOAD = 8_000


def _bounded_payload(payload: dict | None) -> str:
    text = dumps(redact(payload or {}))
    if len(text) > MAX_EVENT_PAYLOAD:
        text = dumps({"truncated": True, "preview": text[:MAX_EVENT_PAYLOAD // 2]})
    return text


def emit_event(db: Database, run_id: str, event_type: str, message: str, *, severity: str = "info",
               payload: dict | None = None, task_id: str | None = None) -> int:
    """Append a durable event with a per-run monotonically increasing sequence number."""
    from autoforge.security.redaction import redact_text

    c = db.conn()
    for _ in range(5):
        try:
            seq = c.execute("SELECT COALESCE(MAX(sequence_number),0)+1 FROM agent_events WHERE run_id=?", (run_id,)).fetchone()[0]
            c.execute(
                "INSERT INTO agent_events(run_id,task_id,sequence_number,event_type,severity,message,payload,created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (run_id, task_id, seq, event_type, severity, redact_text(message)[:2000], _bounded_payload(payload), utcnow()),
            )
            return seq
        except Exception as exc:  # unique(run_id, sequence_number) race -> retry
            if "UNIQUE" not in str(exc):
                raise
            time.sleep(0.01)
    raise RuntimeError("could not allocate event sequence")


def audit(db: Database, action: str, resource_type: str, resource_id: str | None, outcome: str, *,
          actor_id: str | None = None, run_id: str | None = None, correlation_id: str | None = None,
          details: dict | None = None) -> None:
    db.run(
        "INSERT INTO audit_logs(actor_id,run_id,action,resource_type,resource_id,outcome,correlation_id,details,created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (actor_id, run_id, action, resource_type, resource_id, outcome, correlation_id, _bounded_payload(details), utcnow()),
    )


def notify(db: Database, user_id: str, run_id: str | None, kind: str, message: str) -> None:
    db.run("INSERT INTO notifications(user_id,run_id,kind,message,created_at) VALUES (?,?,?,?,?)",
           (user_id, run_id, kind, message, utcnow()))


_NOTIFY_ON = {
    RunStatus.AWAITING_PLAN_APPROVAL: "approval_required",
    RunStatus.AWAITING_EXPORT_APPROVAL: "approval_required",
    RunStatus.SUCCEEDED: "run_completed",
    RunStatus.FAILED: "run_failed",
    RunStatus.CANCELLED: "run_cancelled",
    RunStatus.POLICY_BLOCKED: "run_failed",
}


def transition_run(db: Database, run_id: str, target: RunStatus, *, expected: RunStatus | None = None,
                   actor_id: str | None = None, message: str | None = None, error_code: str | None = None,
                   error_summary: str | None = None, extra: dict[str, Any] | None = None) -> None:
    """Centralized, validated, atomic state change (state + event + audit in one transaction).

    `expected` provides compare-and-swap semantics so concurrent writers cannot double-apply.
    """
    with db.tx() as c:
        row = c.execute("SELECT status, requested_by FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(run_id)
        current = RunStatus(row["status"])
        if expected is not None and current != expected:
            raise IllegalTransition(current.value, target.value)
        if not can_transition(current, target):
            raise IllegalTransition(current.value, target.value)
        now = utcnow()
        sets = ["status=?", "current_stage=?", "updated_at=?"]
        vals: list[Any] = [target.value, STAGE_FOR_STATUS[target], now]
        if target in TERMINAL:
            sets.append("finished_at=?")
            vals.append(now)
        if current == RunStatus.DRAFT:
            sets.append("started_at=?")
            vals.append(now)
        if error_code is not None:
            sets.append("error_code=?")
            vals.append(error_code)
        if error_summary is not None:
            sets.append("error_summary=?")
            vals.append(error_summary[:500])
        if current == RunStatus.FAILED:  # retry: clear error state
            sets += ["error_code=NULL", "error_summary=NULL", "finished_at=NULL"]
        for k, v in (extra or {}).items():
            if k not in {"plan", "plan_version", "repair_attempts", "usage"}:
                raise ValueError(f"unsupported column {k}")
            sets.append(f"{k}=?")
            vals.append(v if isinstance(v, (int, float, type(None))) else dumps(v))
        vals.append(run_id)
        c.execute(f"UPDATE runs SET {', '.join(sets)} WHERE id=?", vals)
        emit_event(db, run_id, "state_transition", message or f"{current.value} -> {target.value}",
                   payload={"from": current.value, "to": target.value})
        audit(db, "run.transition", "run", run_id, "allowed", actor_id=actor_id, run_id=run_id,
              details={"from": current.value, "to": target.value})
        kind = _NOTIFY_ON.get(target)
        if kind:
            notify(db, row["requested_by"], run_id, kind, message or f"Run is now {target.value}")


def get_run_status(db: Database, run_id: str) -> RunStatus:
    row = db.one("SELECT status FROM runs WHERE id=?", (run_id,))
    if row is None:
        raise KeyError(run_id)
    return RunStatus(row["status"])


def cancel_requested(db: Database, run_id: str) -> bool:
    row = db.one("SELECT cancel_requested_at FROM runs WHERE id=?", (run_id,))
    return bool(row and row["cancel_requested_at"])


def load_run(db: Database, run_id: str) -> dict:
    row = db.one("SELECT * FROM runs WHERE id=?", (run_id,))
    if row is None:
        raise KeyError(run_id)
    d = dict(row)
    for k in ("config_snapshot", "budget", "usage", "plan"):
        d[k] = loads(d.get(k), {} if k != "plan" else None)
    return d


def new_job(db: Database, run_id: str, step_id: str, delay: float = 0.0) -> str:
    """Enqueue a step. The attempt number is allocated per (run, step) so unique(run_id, step_id, attempt) holds."""
    jid = new_id()
    with db.tx() as c:
        attempt = c.execute("SELECT COALESCE(MAX(attempt),0)+1 FROM jobs WHERE run_id=? AND step_id=?", (run_id, step_id)).fetchone()[0]
        c.execute(
            "INSERT INTO jobs(id,run_id,step_id,attempt,status,available_at,created_at,updated_at) VALUES (?,?,?,?,'queued',?,?,?)",
            (jid, run_id, step_id, attempt, time.time() + delay, utcnow(), utcnow()),
        )
    return jid
