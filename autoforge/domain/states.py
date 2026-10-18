"""Run state machine rules (pure, no I/O)."""
from __future__ import annotations

from enum import Enum


class RunStatus(str, Enum):
    DRAFT = "DRAFT"
    PLANNING = "PLANNING"
    AWAITING_PLAN_APPROVAL = "AWAITING_PLAN_APPROVAL"
    GENERATING = "GENERATING"
    VERIFYING = "VERIFYING"
    REPAIRING = "REPAIRING"
    AWAITING_EXPORT_APPROVAL = "AWAITING_EXPORT_APPROVAL"
    PACKAGING = "PACKAGING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    POLICY_BLOCKED = "POLICY_BLOCKED"


TERMINAL = {RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.CANCELLED, RunStatus.POLICY_BLOCKED}

_S = RunStatus
ALLOWED: dict[RunStatus, set[RunStatus]] = {
    _S.DRAFT: {_S.PLANNING},
    _S.PLANNING: {_S.AWAITING_PLAN_APPROVAL},
    # change request -> PLANNING again with a new plan version
    _S.AWAITING_PLAN_APPROVAL: {_S.GENERATING, _S.PLANNING},
    _S.GENERATING: {_S.VERIFYING},
    _S.VERIFYING: {_S.REPAIRING, _S.AWAITING_EXPORT_APPROVAL},
    _S.REPAIRING: {_S.VERIFYING},
    _S.AWAITING_EXPORT_APPROVAL: {_S.PACKAGING},
    _S.PACKAGING: {_S.SUCCEEDED},
}
# Any non-terminal state may fail, be cancelled, or be blocked by policy.
for _state in list(RunStatus):
    if _state not in TERMINAL:
        ALLOWED.setdefault(_state, set()).update({_S.FAILED, _S.CANCELLED, _S.POLICY_BLOCKED})
for _t in TERMINAL:
    ALLOWED.setdefault(_t, set())
# Retry of an eligible failed run re-enters at a stage chosen by the retry service.
ALLOWED[_S.FAILED] = {_S.PLANNING, _S.GENERATING, _S.VERIFYING, _S.PACKAGING}

STAGE_FOR_STATUS = {
    RunStatus.DRAFT: "draft",
    RunStatus.PLANNING: "planning",
    RunStatus.AWAITING_PLAN_APPROVAL: "plan_approval",
    RunStatus.GENERATING: "generation",
    RunStatus.VERIFYING: "verification",
    RunStatus.REPAIRING: "repair",
    RunStatus.AWAITING_EXPORT_APPROVAL: "export_approval",
    RunStatus.PACKAGING: "packaging",
    RunStatus.SUCCEEDED: "done",
    RunStatus.FAILED: "failed",
    RunStatus.CANCELLED: "cancelled",
    RunStatus.POLICY_BLOCKED: "policy_blocked",
}


class IllegalTransition(Exception):
    def __init__(self, current: str, target: str):
        super().__init__(f"Illegal transition {current} -> {target}")
        self.current = current
        self.target = target


def can_transition(current: RunStatus, target: RunStatus) -> bool:
    return target in ALLOWED.get(current, set())


def validate_dag(tasks: list[dict]) -> list[str]:
    """Return a topological order of task keys; raise ValueError on cycles/unknown deps."""
    keys = [t["key"] for t in tasks]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate task keys")
    deps = {t["key"]: list(t.get("depends_on", [])) for t in tasks}
    for k, ds in deps.items():
        for d in ds:
            if d not in deps:
                raise ValueError(f"task {k} depends on unknown task {d}")
            if d == k:
                raise ValueError(f"task {k} depends on itself")
    order: list[str] = []
    state: dict[str, int] = {}

    def visit(k: str) -> None:
        if state.get(k) == 2:
            return
        if state.get(k) == 1:
            raise ValueError("task graph contains a cycle")
        state[k] = 1
        for d in sorted(deps[k]):
            visit(d)
        state[k] = 2
        order.append(k)

    for k in keys:
        visit(k)
    return order
