"""Durable orchestration engine.

The model proposes; deterministic code validates and executes. Every step is idempotent: it first
checks the run is in the status the step expects, so a replayed job (after a crash or retry) is a
safe no-op or a clean continuation.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Callable

from pydantic import ValidationError

from autoforge.agents.schemas import validate_output
from autoforge.core.config import Settings
from autoforge.core.db import Database, dumps, loads, new_id, utcnow
from autoforge.core.services import (
    audit, cancel_requested, emit_event, load_run, new_job, transition_run,
)
from autoforge.domain.states import IllegalTransition, RunStatus, validate_dag
from autoforge.providers.base import AgentRequest, ProviderError
from autoforge.providers.factory import build_provider
from autoforge.sandbox.runner import SandboxRunner, SandboxUnavailable
from autoforge.security.paths import PathViolation, validate_relative_path
from autoforge.storage.local import LocalArtifactStore
from autoforge.verification import report as rpt
from autoforge.verification.scanner import scan_workspace
from autoforge.workspace.manager import Workspace

log = logging.getLogger("autoforge.engine")

MAX_AGENT_ATTEMPTS = 3
MAX_TRANSIENT_RETRIES = 3

STEP_FAIL_CODE = {"plan": "PLANNING_FAILED", "generate": "GENERATION_FAILED", "verify": "VERIFICATION_FAILED",
                  "repair": "VERIFICATION_FAILED", "package": "PACKAGING_FAILED"}
RETRY_TARGET = {"plan": (RunStatus.PLANNING, "plan"), "generate": (RunStatus.GENERATING, "generate"),
                "verify": (RunStatus.VERIFYING, "verify"), "repair": (RunStatus.VERIFYING, "verify"),
                "package": (RunStatus.PACKAGING, "package")}


class AgentFailure(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class BudgetExceeded(Exception):
    pass


class RunCancelled(Exception):
    pass


class PolicyBlocked(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class Engine:
    def __init__(self, db: Database, settings: Settings, store: LocalArtifactStore, sandbox: SandboxRunner | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.db, self.settings, self.store = db, settings, store
        self.sandbox = sandbox or SandboxRunner(allow_weak=settings.allow_weak_sandbox)
        self.sleep = sleep

    # ------------------------------------------------------------------ plumbing
    def workspace(self, run_id: str) -> Workspace:
        return Workspace(self.settings.workspace_root, run_id)

    def process_job(self, job: dict) -> None:
        run_id, step = job["run_id"], job["step_id"]
        handler = {"plan": self.step_plan, "generate": self.step_generate, "verify": self.step_verify,
                   "repair": self.step_repair, "package": self.step_package}[step]
        try:
            if cancel_requested(self.db, run_id):
                raise RunCancelled()
            handler(run_id)
        except RunCancelled:
            self._cancel(run_id)
        except BudgetExceeded as exc:
            self._fail(run_id, step, "BUDGET_EXHAUSTED", str(exc))
        except PolicyBlocked as exc:
            self._block(run_id, exc.code, str(exc))
        except AgentFailure as exc:
            self._fail(run_id, step, STEP_FAIL_CODE[step], str(exc))
        except IllegalTransition as exc:
            log.warning("illegal transition during %s for %s: %s", step, run_id, exc)
        except Exception:  # noqa: BLE001 - never leak internals to clients
            log.exception("unexpected error in step %s of run %s", step, run_id)
            self._fail(run_id, step, "INTERNAL_ERROR", "Unexpected internal error; see server logs with the run id.")

    def _fail(self, run_id: str, step: str, code: str, message: str) -> None:
        run = load_run(self.db, run_id)
        status = RunStatus(run["status"])
        snap = run["config_snapshot"]
        snap["failed_step"] = step
        self.db.run("UPDATE runs SET config_snapshot=? WHERE id=?", (dumps(snap), run_id))
        try:
            transition_run(self.db, run_id, RunStatus.FAILED, expected=status, error_code=code, error_summary=message,
                           message=f"Run failed: {code}")
        except IllegalTransition:
            pass

    def _block(self, run_id: str, code: str, message: str) -> None:
        audit(self.db, "policy.blocked", "run", run_id, "denied", run_id=run_id, details={"code": code, "message": message})
        emit_event(self.db, run_id, "policy_blocked", message, severity="error", payload={"code": code})
        try:
            transition_run(self.db, run_id, RunStatus.POLICY_BLOCKED, error_code=code, error_summary=message,
                           message=f"Blocked by policy: {code}")
        except IllegalTransition:
            pass

    def _cancel(self, run_id: str) -> None:
        try:
            transition_run(self.db, run_id, RunStatus.CANCELLED, message="Run cancelled", error_code="CANCELLED")
        except IllegalTransition:
            return
        self.db.run("UPDATE tasks SET status='cancelled', updated_at=? WHERE run_id=? AND status IN ('pending','running')",
                    (utcnow(), run_id))
        audit(self.db, "run.cancelled", "run", run_id, "allowed", run_id=run_id)

    def _check_cancel(self, run_id: str) -> None:
        if cancel_requested(self.db, run_id):
            raise RunCancelled()

    # ------------------------------------------------------------------ agents & budgets
    def _provider(self, run: dict):
        cfg = run["config_snapshot"].get("provider", {})
        try:
            return build_provider(cfg.get("provider_type", "mock"), cfg.get("model_name", "mock-deterministic"),
                                  base_url=cfg.get("base_url"), secret_reference=cfg.get("secret_reference"),
                                  settings=cfg.get("settings"))
        except ProviderError as exc:
            raise AgentFailure(str(exc)) from None

    def _check_budget(self, run: dict) -> None:
        b, u = run["budget"], run["usage"]
        if u.get("model_calls", 0) >= b.get("max_model_calls", self.settings.max_model_calls):
            raise BudgetExceeded("Model call budget exhausted")
        started = run.get("started_at")
        if started:
            elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(started)).total_seconds()
            if elapsed > b.get("max_wall_time_seconds", self.settings.max_run_seconds):
                raise BudgetExceeded("Wall-clock budget exhausted")
        cost, cap = u.get("estimated_cost_usd"), b.get("max_estimated_cost_usd")
        if cost is not None and cap is not None and cost > cap:
            raise BudgetExceeded("Estimated cost budget exhausted")

    def _record_usage(self, run_id: str, usage) -> None:
        run = load_run(self.db, run_id)
        u = run["usage"]
        u["model_calls"] = u.get("model_calls", 0) + 1
        if usage.input_tokens is None or usage.output_tokens is None:
            u["tokens_known"] = False  # once unknown, totals are incomplete; never invent numbers
        else:
            u["input_tokens"] = (u.get("input_tokens") or 0) + usage.input_tokens
            u["output_tokens"] = (u.get("output_tokens") or 0) + usage.output_tokens
            u.setdefault("tokens_known", True)
        if usage.estimated_cost_usd is not None:
            u["estimated_cost_usd"] = (u.get("estimated_cost_usd") or 0) + usage.estimated_cost_usd
        u.setdefault("estimated_cost_usd", None)
        self.db.run("UPDATE runs SET usage=?, updated_at=? WHERE id=?", (dumps(u), utcnow(), run_id))

    def call_agent(self, run_id: str, role: str, schema_name: str, instructions: str, context: dict,
                   task_id: str | None = None) -> dict:
        """Provider call with budget enforcement, transient retry/backoff and output validation."""
        invalid_note = ""
        for attempt in range(1, MAX_AGENT_ATTEMPTS + 1):
            transient_tries = 0
            while True:
                self._check_cancel(run_id)
                run = load_run(self.db, run_id)
                self._check_budget(run)
                provider = self._provider(run)
                emit_event(self.db, run_id, "agent_call", f"{role} agent working", task_id=task_id,
                           payload={"role": role, "schema": schema_name, "attempt": attempt})
                try:
                    resp = provider.generate(AgentRequest(role, schema_name, instructions + invalid_note, context))
                    self._record_usage(run_id, resp.usage)
                    break
                except ProviderError as exc:
                    self._record_usage_failed(run_id)
                    if exc.transient and transient_tries < MAX_TRANSIENT_RETRIES:
                        transient_tries += 1
                        delay = min(0.5 * 2 ** transient_tries, 8)
                        emit_event(self.db, run_id, "provider_retry", f"Transient provider error; retrying in {delay:.1f}s",
                                   severity="warning", payload={"error": str(exc), "retry": transient_tries})
                        self.sleep(delay)
                        continue
                    kind = "transient (retries exhausted)" if exc.transient else "permanent"
                    raise AgentFailure(f"Provider error ({kind}): {exc}") from None
            try:
                return validate_output(schema_name, resp.data).model_dump()
            except ValidationError as exc:
                msgs = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:5])
                emit_event(self.db, run_id, "agent_invalid_output", f"{role} output failed schema validation",
                           severity="warning", task_id=task_id, payload={"errors": msgs})
                invalid_note = f"\n\nYour previous output was invalid ({msgs}). Return corrected JSON only."
        raise AgentFailure(f"{role} agent could not produce schema-valid output after {MAX_AGENT_ATTEMPTS} attempts")

    def _record_usage_failed(self, run_id: str) -> None:
        run = load_run(self.db, run_id)
        u = run["usage"]
        u["model_calls"] = u.get("model_calls", 0) + 1
        self.db.run("UPDATE runs SET usage=? WHERE id=?", (dumps(u), run_id))

    # ------------------------------------------------------------------ step: plan
    def step_plan(self, run_id: str) -> None:
        run = load_run(self.db, run_id)
        if run["status"] != RunStatus.PLANNING.value:
            return
        project = self.db.one("SELECT * FROM projects WHERE id=?", (run["project_id"],))
        pv = self.db.one("SELECT * FROM project_versions WHERE id=?", (run["project_version_id"],))
        snapshot = loads(pv["brief_snapshot"], {}) if pv else {}
        brief = snapshot.get("brief") or project["brief"]
        change = self.db.one("SELECT comment FROM approvals WHERE run_id=? AND decision='changes_requested' ORDER BY decided_at DESC LIMIT 1", (run_id,))
        ctx_base = {"brief": brief, "name": project["name"], "details": snapshot.get("details", {}),
                    "change_request": change["comment"] if change else None}
        reqs = self.call_agent(run_id, "requirements", "requirements", "Produce a structured SRS for this brief.", ctx_base)
        arch = self.call_agent(run_id, "architect", "architecture", "Design the architecture, data model and API.",
                               {**ctx_base, "requirements": reqs})
        plan = self.call_agent(run_id, "planner", "task_plan", "Produce a dependency-aware task DAG.",
                               {**ctx_base, "requirements": reqs, "architecture": arch})
        try:
            order = validate_dag([{"key": t["key"], "depends_on": t["depends_on"]} for t in plan["tasks"]])
            for t in plan["tasks"]:
                for f in t["expected_files"]:
                    validate_relative_path(f)
        except (ValueError, PathViolation) as exc:
            raise AgentFailure(f"Planner produced an invalid task graph: {exc}") from None
        plan_version = run["plan_version"] + 1
        full = {"version": plan_version, "requirements": reqs, "architecture": arch, "tasks": plan["tasks"], "order": order}
        with self.db.tx() as c:
            vnum = c.execute("SELECT COALESCE(MAX(version_number),0)+1 FROM project_versions WHERE project_id=?", (run["project_id"],)).fetchone()[0]
            pvid = new_id()
            c.execute("INSERT INTO project_versions(id,project_id,version_number,brief_snapshot,requirements,architecture,plan,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                      (pvid, run["project_id"], vnum, dumps(snapshot or {"brief": brief}), dumps(reqs), dumps(arch), dumps(plan), run["requested_by"], utcnow()))
            c.execute("UPDATE runs SET project_version_id=? WHERE id=?", (pvid, run_id))
            c.execute("DELETE FROM task_dependencies WHERE task_id IN (SELECT id FROM tasks WHERE run_id=?)", (run_id,))
            c.execute("DELETE FROM tasks WHERE run_id=?", (run_id,))
            ids = {}
            for t in plan["tasks"]:
                ids[t["key"]] = new_id()
                c.execute("INSERT INTO tasks(id,run_id,task_key,title,description,agent_role,status,input,max_attempts,created_at,updated_at) VALUES (?,?,?,?,?,?,'pending',?,?,?,?)",
                          (ids[t["key"]], run_id, t["key"], t["title"], t["description"], t["agent_role"], dumps(t), 2, utcnow(), utcnow()))
            for t in plan["tasks"]:
                for d in t["depends_on"]:
                    c.execute("INSERT INTO task_dependencies(task_id,depends_on_task_id) VALUES (?,?)", (ids[t["key"]], ids[d]))
            c.execute("INSERT INTO approvals(id,run_id,approval_type,requested_by,plan_version,requested_at) VALUES (?,?,?,?,?,?)",
                      (new_id(), run_id, "plan", run["requested_by"], plan_version, utcnow()))
        transition_run(self.db, run_id, RunStatus.AWAITING_PLAN_APPROVAL, expected=RunStatus.PLANNING,
                       message=f"Plan v{plan_version} ready for approval", extra={"plan": full, "plan_version": plan_version})

    # ------------------------------------------------------------------ step: generate
    def step_generate(self, run_id: str) -> None:
        run = load_run(self.db, run_id)
        if run["status"] != RunStatus.GENERATING.value:
            return
        plan = run["plan"]
        arch, project_name = plan["architecture"], self.db.one("SELECT name FROM projects WHERE id=?", (run["project_id"],))["name"]
        project = self.db.one("SELECT brief FROM projects WHERE id=?", (run["project_id"],))
        pv = self.db.one("SELECT brief_snapshot FROM project_versions WHERE id=?", (run["project_version_id"],))
        brief = (loads(pv["brief_snapshot"], {}) or {}).get("brief") or project["brief"]
        ws = self.workspace(run_id)
        done = self.db.one("SELECT COUNT(*) n FROM tasks WHERE run_id=? AND status='succeeded'", (run_id,))["n"]
        if done == 0 or not ws.exists():
            ws.create()
            self.db.run("UPDATE tasks SET status='pending' WHERE run_id=?", (run_id,))
        rows = {r["task_key"]: r for r in self.db.all("SELECT * FROM tasks WHERE run_id=?", (run_id,))}
        for key in plan["order"]:
            row = rows[key]
            if row["status"] == "succeeded":
                continue
            self._check_cancel(run_id)
            spec = loads(row["input"], {})
            self.db.run("UPDATE tasks SET status='running', started_at=?, attempt_count=attempt_count+1, updated_at=? WHERE id=?", (utcnow(), utcnow(), row["id"]))
            emit_event(self.db, run_id, "task_started", f"{key}: {row['title']}", task_id=row["id"])
            if spec["agent_role"] == "reviewer":
                result = self.call_agent(run_id, "reviewer", "review", "Review the generated code.",
                                         {"files": self._read_code(ws), "brief": brief}, task_id=row["id"])
                self.db.run("DELETE FROM security_findings WHERE run_id=? AND category='review'", (run_id,))
                for f in result["findings"]:
                    self.db.run("INSERT INTO security_findings(id,run_id,severity,category,file_path,line,message,evidence,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                                (new_id(), run_id, f["severity"], "review", f["file"], f["line"], f["message"], None, utcnow()))
                output = {"findings": len(result["findings"])}
            else:
                ctx = {"task_key": key, "title": spec["title"], "description": spec["description"], "expected_files": spec["expected_files"],
                       "data_model": arch["data_model"], "brief": brief, "project_name": project_name,
                       "existing_files": sorted(ws.list_files())}
                patch = self.call_agent(run_id, spec["agent_role"], "file_patch", f"Implement task {key}: {spec['title']}", ctx, task_id=row["id"])
                output = {"files": self._apply_patch(run_id, ws, patch["files"], set(spec["expected_files"]), row["id"])}
                if not output["files"]:
                    raise AgentFailure(f"Task {key} produced no accepted files")
            self.db.run("UPDATE tasks SET status='succeeded', output=?, finished_at=?, updated_at=? WHERE id=?", (dumps(output), utcnow(), utcnow(), row["id"]))
            emit_event(self.db, run_id, "task_finished", f"{key} finished", task_id=row["id"], payload=output)
        hashes = ws.snapshot("generated")
        emit_event(self.db, run_id, "snapshot", f"Generation snapshot saved ({len(hashes)} files)", payload={"files": len(hashes)})
        transition_run(self.db, run_id, RunStatus.VERIFYING, expected=RunStatus.GENERATING, message="Generation complete; verifying in sandbox")
        new_job(self.db, run_id, "verify")

    def _read_code(self, ws: Workspace, limit: int = 60_000) -> dict[str, str]:
        out, total = {}, 0
        for rel in ws.list_files():
            if rel.startswith("tests/") or rel.endswith((".md", ".txt")):
                continue
            text = ws.read_file(rel)
            if total + len(text) > limit:
                break
            out[rel] = text
            total += len(text)
        return out

    def _apply_patch(self, run_id: str, ws: Workspace, files: list[dict], owned: set[str] | None, task_id: str | None,
                     deny_prefixes: tuple[str, ...] = ()) -> list[dict]:
        accepted = []
        for f in files:
            try:
                rel = validate_relative_path(f["path"])
            except PathViolation as exc:
                audit(self.db, "workspace.write", "file", f["path"][:200], "denied", run_id=run_id, details={"reason": str(exc)})
                raise PolicyBlocked("PATH_VIOLATION", f"Agent attempted a forbidden write ({exc}); run blocked.") from None
            if (owned is not None and rel not in owned) or rel.startswith(deny_prefixes):
                audit(self.db, "workspace.write", "file", rel, "denied", run_id=run_id, details={"reason": "not owned by task or protected"})
                emit_event(self.db, run_id, "policy_denied", f"Write to {rel} denied (outside task ownership/protected)", severity="warning", task_id=task_id)
                continue
            try:
                res = ws.write_file(rel, f["content"])
            except PathViolation as exc:
                audit(self.db, "workspace.write", "file", rel, "denied", run_id=run_id, details={"reason": str(exc)})
                raise PolicyBlocked("PATH_VIOLATION", f"Write rejected by workspace policy ({exc}).") from None
            accepted.append(res)
        return accepted

    # ------------------------------------------------------------------ step: verify
    def step_verify(self, run_id: str) -> None:
        run = load_run(self.db, run_id)
        if run["status"] != RunStatus.VERIFYING.value:
            return
        try:
            info = self.sandbox.ensure_available()
        except SandboxUnavailable as exc:
            raise PolicyBlocked("SANDBOX_UNAVAILABLE", str(exc)) from None
        ws = self.workspace(run_id)
        if not ws.exists():
            raise AgentFailure("Workspace is missing; re-run generation")
        rnd = self.db.one("SELECT COALESCE(MAX(round),0)+1 n FROM verification_results WHERE run_id=?", (run_id,))["n"]
        statuses = {}
        for name in ("compile", "unittest"):
            self._check_cancel(run_id)
            if name == "unittest" and statuses.get("compile") != "passed":
                self._store_result(run_id, rnd, name, "python -I -m unittest discover -s tests -t .", None, "skipped", 0,
                                   "Skipped because the compile check did not pass.", info.as_dict())
                statuses[name] = "skipped"
                continue
            emit_event(self.db, run_id, "check_started", f"Running {name} in sandbox", payload={"round": rnd})
            res = self.sandbox.run(name, ws.root, cancelled=lambda: cancel_requested(self.db, run_id))
            if res.status == "cancelled":
                raise RunCancelled()
            self._store_result(run_id, rnd, name, res.command, res.exit_code, res.status, res.duration_ms, res.output_summary, res.sandbox)
            statuses[name] = res.status
            emit_event(self.db, run_id, "check_finished", f"{name}: {res.status}", severity="info" if res.status == "passed" else "error",
                       payload={"round": rnd, "exit_code": res.exit_code, "duration_ms": res.duration_ms})
        if all(s == "passed" for s in statuses.values()):
            self.db.run("DELETE FROM security_findings WHERE run_id=? AND category!='review'", (run_id,))
            findings = scan_workspace(ws)
            for f in findings:
                self.db.run("INSERT INTO security_findings(id,run_id,severity,category,file_path,line,message,evidence,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                            (new_id(), run_id, f["severity"], f["category"], f["file"], f["line"], f["message"], f["evidence"], utcnow()))
            emit_event(self.db, run_id, "security_scan", f"Security scan found {len(findings)} item(s)", payload={"count": len(findings)})
            if any(f["severity"] == "critical" for f in findings):
                raise PolicyBlocked("SECRET_DETECTED", "Critical security finding (possible hard-coded secret); export blocked.")
            self.db.run("INSERT INTO approvals(id,run_id,approval_type,requested_by,plan_version,requested_at) VALUES (?,?,?,?,?,?)",
                        (new_id(), run_id, "export", run["requested_by"], run["plan_version"], utcnow()))
            transition_run(self.db, run_id, RunStatus.AWAITING_EXPORT_APPROVAL, expected=RunStatus.VERIFYING,
                           message="All checks passed; export approval required")
            return
        max_repairs = run["budget"].get("max_repair_attempts", self.settings.max_repair_attempts)
        if run["repair_attempts"] < max_repairs:
            transition_run(self.db, run_id, RunStatus.REPAIRING, expected=RunStatus.VERIFYING,
                           message=f"Checks failed; repair attempt {run['repair_attempts'] + 1} of {max_repairs}")
            new_job(self.db, run_id, "repair")
        else:
            raise AgentFailure(f"Verification still failing after {run['repair_attempts']} repair attempt(s)")

    def _store_result(self, run_id, rnd, name, command, code, status, duration, output, sandbox) -> None:
        self.db.run("INSERT INTO verification_results(id,run_id,round,check_name,command,exit_code,status,duration_ms,output_summary,sandbox,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (new_id(), run_id, rnd, name, command, code, status, duration, output, dumps(sandbox), utcnow()))

    # ------------------------------------------------------------------ step: repair
    def step_repair(self, run_id: str) -> None:
        run = load_run(self.db, run_id)
        if run["status"] != RunStatus.REPAIRING.value:
            return
        ws = self.workspace(run_id)
        n = run["repair_attempts"] + 1
        last = self.db.one("SELECT MAX(round) r FROM verification_results WHERE run_id=?", (run_id,))["r"]
        failed = self.db.all("SELECT check_name, output_summary FROM verification_results WHERE run_id=? AND round=? AND status IN ('failed','timeout')", (run_id, last))
        failures = [f"{r['check_name']}: {r['output_summary'][-1500:]}" for r in failed]
        arch = run["plan"]["architecture"]
        pv = self.db.one("SELECT brief_snapshot FROM project_versions WHERE id=?", (run["project_version_id"],))
        brief = (loads(pv["brief_snapshot"], {}) or {}).get("brief", "")
        result = self.call_agent(run_id, "repair", "repair", "Propose a minimal patch that fixes the failing checks. Do not edit tests.",
                                 {"failures": failures, "files": self._read_code(ws), "data_model": arch["data_model"], "brief": brief})
        label = f"pre_repair_{n}"
        ws.snapshot(label)
        if result.get("modifies_tests"):
            audit(self.db, "repair.tests_modification", "run", run_id, "denied", run_id=run_id,
                  details={"reason": "repair agent flagged test changes; tests are protected"})
        accepted = self._apply_patch(run_id, ws, result["files"], None, None, deny_prefixes=("tests/",))
        changed = [a for a in accepted if a["action"] != "unchanged"]
        if not changed:
            self.db.run("UPDATE runs SET repair_attempts=? WHERE id=?", (n, run_id))
            raise AgentFailure("Repair agent produced no applicable changes; failing checks remain failed")
        diff = ws.diff_against(label)
        text = "".join(d["diff"] for d in diff).encode()
        key, sha, size = self.store.put(run_id, text)
        self.db.run("INSERT INTO artifacts(id,run_id,artifact_type,display_name,storage_key,mime_type,size_bytes,sha256,metadata,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (new_id(), run_id, "patch", f"repair-{n}.diff", key, "text/x-diff", size, sha,
                     dumps({"rationale": result["rationale"][:500], "attempt": n}), utcnow()))
        audit(self.db, "artifact.created", "artifact", None, "allowed", run_id=run_id, details={"name": f"repair-{n}.diff", "sha256": sha})
        emit_event(self.db, run_id, "repair_applied", f"Repair {n} applied to {len(changed)} file(s)", payload={"rationale": result["rationale"][:300], "files": [c["path"] for c in changed]})
        transition_run(self.db, run_id, RunStatus.VERIFYING, expected=RunStatus.REPAIRING, message="Repair applied; re-verifying",
                       extra={"repair_attempts": n})
        new_job(self.db, run_id, "verify")

    # ------------------------------------------------------------------ step: package
    def step_package(self, run_id: str) -> None:
        run = load_run(self.db, run_id)
        if run["status"] != RunStatus.PACKAGING.value:
            return
        ws = self.workspace(run_id)
        if not ws.exists():
            raise AgentFailure("Workspace is missing; cannot package")
        results = [dict(r) for r in self.db.all("SELECT * FROM verification_results WHERE run_id=? ORDER BY round, created_at", (run_id,))]
        findings = [dict(r) for r in self.db.all("SELECT severity,category,file_path AS file,line,message,evidence FROM security_findings WHERE run_id=?", (run_id,))]
        sandbox = loads(results[-1]["sandbox"], {}) if results else {}
        report = rpt.build_verification_report(run, results, findings, sandbox)
        if report["overall"] != "checks_passed":
            raise AgentFailure("Refusing to package: latest verification round did not pass")
        files = ws.list_files()
        extra = {"VERIFICATION_REPORT.md": rpt.report_markdown(report).encode(),
                 "verification-report.json": json.dumps(report, indent=2).encode(),
                 "TEST_REPORT.txt": rpt.test_report_text(results).encode()}
        if "README.md" not in files:
            extra["README.md"] = b"# Generated project\n\nGenerated by AutoForge AI. See VERIFICATION_REPORT.md for what was checked.\n"
        if ".env.example" not in files:
            extra[".env.example"] = b"# placeholders only\n"
        project = self.db.one("SELECT slug FROM projects WHERE id=?", (run["project_id"],))
        zip_bytes, manifest = rpt.build_zip(ws, extra, project["slug"])
        outputs = [
            ("source_zip", f"{project['slug']}-source.zip", "application/zip", zip_bytes),
            ("manifest", "MANIFEST.json", "application/json", json.dumps(manifest, indent=2).encode()),
            ("verification_report", "verification-report.json", "application/json", extra["verification-report.json"]),
            ("verification_report_md", "VERIFICATION_REPORT.md", "text/markdown", extra["VERIFICATION_REPORT.md"]),
            ("test_report", "TEST_REPORT.txt", "text/plain", extra["TEST_REPORT.txt"]),
        ]
        for atype, name, mime, data in outputs:
            key, sha, size = self.store.put(run_id, data)
            aid = new_id()
            self.db.run("INSERT INTO artifacts(id,run_id,artifact_type,display_name,storage_key,mime_type,size_bytes,sha256,metadata,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (aid, run_id, atype, name, key, mime, size, sha, dumps({"sbom": "unavailable"} if atype == "manifest" else {}), utcnow(), None))
            audit(self.db, "artifact.created", "artifact", aid, "allowed", run_id=run_id, details={"name": name, "sha256": sha, "size": size})
        transition_run(self.db, run_id, RunStatus.SUCCEEDED, expected=RunStatus.PACKAGING, message="Packaging complete")

    # ------------------------------------------------------------------ maintenance
    def purge_expired(self, days: int | None = None) -> dict:
        """Retention: delete artifacts and workspaces of finished runs older than `days`."""
        days = self.settings.retention_days if days is None else days
        cutoff = datetime.fromtimestamp(time.time() - days * 86400, timezone.utc).isoformat(timespec="milliseconds")
        rows = self.db.all("SELECT id FROM runs WHERE finished_at IS NOT NULL AND finished_at < ?", (cutoff,))
        purged = 0
        for r in rows:
            for a in self.db.all("SELECT id, storage_key FROM artifacts WHERE run_id=?", (r["id"],)):
                self.store.delete(a["storage_key"])
                self.db.run("DELETE FROM artifacts WHERE id=?", (a["id"],))
                purged += 1
            self.workspace(r["id"]).destroy()
            audit(self.db, "retention.purge", "run", r["id"], "allowed", run_id=r["id"])
        return {"runs": len(rows), "artifacts": purged}
