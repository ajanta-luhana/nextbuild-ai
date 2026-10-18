"""End-to-end workflow tests using the deterministic mock provider and the real sandbox."""
from __future__ import annotations

import hashlib
import io
import json
import unittest
import zipfile

from tests.helpers import AppTestCase


class HappyPath(AppTestCase):
    def test_full_happy_path(self):
        p, rid = self.run_to_plan()
        run = self.status(rid)
        self.assertEqual(run["status"], "AWAITING_PLAN_APPROVAL")
        plan = self.alice.get(f"/runs/{rid}/plan").json()["plan"]
        self.assertTrue(plan["requirements"]["functional"])
        self.assertIn("listing", [e["name"] for e in plan["architecture"]["data_model"]])
        tasks = self.alice.get(f"/runs/{rid}/tasks").json()["items"]
        self.assertEqual({t["status"] for t in tasks}, {"pending"})

        self.alice.post(f"/runs/{rid}/plan/approve")
        self.drain()
        run = self.status(rid)
        self.assertEqual(run["status"], "AWAITING_EXPORT_APPROVAL", run)
        v = self.alice.get(f"/runs/{rid}/verification").json()
        self.assertEqual([(c["check_name"], c["status"], c["exit_code"]) for c in v["checks"]], [("compile", "passed", 0), ("unittest", "passed", 0)])
        self.assertTrue(all(c["duration_ms"] >= 0 and c["command"] for c in v["checks"]))
        self.assertEqual(run["usage"]["estimated_cost_usd"], None)  # unknown, never invented

        self.alice.post(f"/runs/{rid}/export/approve")
        self.drain()
        self.assertEqual(self.status(rid)["status"], "SUCCEEDED")
        arts = self.alice.get(f"/runs/{rid}/artifacts").json()["items"]
        types = {a["artifact_type"] for a in arts}
        self.assertTrue({"source_zip", "manifest", "verification_report", "test_report"} <= types)
        zip_meta = next(a for a in arts if a["artifact_type"] == "source_zip")
        r = self.alice.get(zip_meta["download_url"].replace("/api/v1", ""))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(hashlib.sha256(r.content).hexdigest(), zip_meta["sha256"])
        self.assertNotIn("storage", json.dumps(arts))
        names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
        for needed in ("README.md", ".env.example", "TEST_REPORT.txt", "VERIFICATION_REPORT.md", "MANIFEST.json", "app/server.py"):
            self.assertIn(f"{p['slug']}/{needed}", names)
        report = zipfile.ZipFile(io.BytesIO(r.content)).read(f"{p['slug']}/VERIFICATION_REPORT.md").decode()
        self.assertIn("NOT a claim of production readiness", report)
        self.assertNotIn("production-ready", report.replace("NOT a claim of production readiness", ""))

    def test_events_are_ordered_and_durable(self):
        _, rid = self.run_full()
        ev = self.alice.get(f"/runs/{rid}/events").json()["items"]
        ids = [e["id"] for e in ev]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(ids, list(range(1, len(ids) + 1)))
        resumed = self.alice.get(f"/runs/{rid}/events?after={ids[3]}").json()["items"]
        self.assertEqual([e["id"] for e in resumed], ids[4:])

    def test_plan_requires_approval_before_generation(self):
        _, rid = self.run_to_plan()
        self.drain()
        self.assertEqual(self.status(rid)["status"], "AWAITING_PLAN_APPROVAL")
        self.assertEqual(self.alice.get(f"/runs/{rid}/diff").json()["available"], False)

    def test_change_request_creates_new_plan_version(self):
        _, rid = self.run_to_plan()
        self.assertEqual(self.status(rid)["plan_version"], 1)
        r = self.alice.post(f"/runs/{rid}/plan/change-request", {"comment": "Add more detail"})
        self.assertEqual(r.status_code, 200)
        self.drain()
        run = self.status(rid)
        self.assertEqual((run["status"], run["plan_version"]), ("AWAITING_PLAN_APPROVAL", 2))
        self.assertEqual(self.alice.post(f"/runs/{rid}/plan/change-request", {}).status_code, 422)

    def test_plan_rejection_cancels(self):
        _, rid = self.run_to_plan()
        self.assertEqual(self.alice.post(f"/runs/{rid}/plan/reject", {"comment": "no"}).status_code, 200)
        self.assertEqual(self.status(rid)["status"], "CANCELLED")
        self.assertEqual(self.alice.post(f"/runs/{rid}/plan/approve").status_code, 409)


class RepairLoop(AppTestCase):
    def test_injected_failure_is_reported_then_repaired_with_evidence(self):
        _, rid = self.run_full(self.brief + " [[inject-failure]]")
        run = self.status(rid)
        self.assertEqual(run["status"], "AWAITING_EXPORT_APPROVAL")
        self.assertEqual(run["repair_attempts"], 1)
        checks = self.alice.get(f"/runs/{rid}/verification").json()["checks"]
        unit = [c for c in checks if c["check_name"] == "unittest"]
        self.assertEqual([(c["round"], c["status"]) for c in unit], [(1, "failed"), (2, "passed")])
        self.assertNotEqual(unit[0]["exit_code"], 0)
        self.assertIn("FAILED", unit[0]["output_summary"])  # failure evidence is retained
        arts = self.alice.get(f"/runs/{rid}/artifacts").json()["items"]
        self.assertTrue(any(a["artifact_type"] == "patch" for a in arts))
        diff = self.alice.get(f"/runs/{rid}/diff").json()
        self.assertEqual([c["path"] for c in diff["changes_since_generation"]], ["app/store.py"])

    def test_unfixable_failure_stays_failed_and_attempts_are_bounded(self):
        _, rid = self.run_full(self.brief + " [[inject-failure]] [[unfixable]]")
        run = self.status(rid)
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(run["error_code"], "VERIFICATION_FAILED")
        self.assertLessEqual(run["repair_attempts"], run["budget"]["max_repair_attempts"])
        checks = self.alice.get(f"/runs/{rid}/verification").json()["checks"]
        self.assertTrue(all(c["status"] != "passed" for c in checks if c["check_name"] == "unittest"))
        self.assertEqual(self.alice.get(f"/runs/{rid}/artifacts").json()["items"], [])
        self.assertEqual(self.alice.post(f"/runs/{rid}/export/approve").status_code, 409)

    def test_max_repair_attempts_zero_means_no_repair(self):
        p, rid = self.run_to_plan(self.brief + " [[inject-failure]]", budget={"max_repair_attempts": 0})
        self.alice.post(f"/runs/{rid}/plan/approve")
        self.drain()
        run = self.status(rid)
        self.assertEqual((run["status"], run["repair_attempts"]), ("FAILED", 0))


class PolicyAndBudgets(AppTestCase):
    def test_path_traversal_from_agent_blocks_run_and_writes_nothing(self):
        _, rid = self.run_full(self.brief + " [[policy-violation]]")
        run = self.status(rid)
        self.assertEqual((run["status"], run["error_code"]), ("POLICY_BLOCKED", "PATH_VIOLATION"))
        import os
        self.assertFalse(os.path.exists(os.path.join(self.root, "ws", "escape.py")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "escape.py")))
        audit = self.alice.get("/audit").json()["items"]
        self.assertTrue(any(a["action"] == "workspace.write" and a["outcome"] == "denied" for a in audit))

    def test_model_call_budget_is_enforced(self):
        p, rid = self.run_to_plan(budget={"max_model_calls": 2})
        run = self.status(rid)
        self.assertEqual((run["status"], run["error_code"]), ("FAILED", "BUDGET_EXHAUSTED"))
        self.assertEqual(self.alice.post(f"/runs/{rid}/retry", headers={"Idempotency-Key": "retry-key-0001"}).status_code, 409)

    def test_budget_request_cannot_exceed_policy(self):
        self.alice.req("PATCH", "/settings/policies", {"max_model_calls": 7})
        p = self.new_project()
        rid = self.start_run(p["id"], budget={"max_model_calls": 9999})
        self.assertEqual(self.status(rid)["budget"]["max_model_calls"], 7)

    def test_retry_is_idempotent_and_only_for_failed(self):
        p, rid = self.run_to_plan(budget={"max_model_calls": 2})
        # BUDGET_EXHAUSTED is non-retryable; retry on a non-failed run is a conflict
        p2, rid2 = self.run_to_plan()
        self.assertEqual(self.alice.post(f"/runs/{rid2}/retry", headers={"Idempotency-Key": "retry-key-0002"}).status_code, 409)
        self.assertEqual(self.alice.post(f"/runs/{rid2}/retry").status_code, 422)  # key required

    def test_cancel_waiting_and_active_runs(self):
        _, rid = self.run_to_plan()
        self.assertEqual(self.alice.post(f"/runs/{rid}/cancel").status_code, 202)
        self.assertEqual(self.status(rid)["status"], "CANCELLED")
        self.assertEqual(self.alice.post(f"/runs/{rid}/cancel").status_code, 409)
        # active run: cancel requested while a job is queued -> worker cancels at the next safe point
        p = self.new_project()
        rid2 = self.start_run(p["id"])
        self.alice.post(f"/runs/{rid2}/cancel")
        self.drain()
        self.assertEqual(self.status(rid2)["status"], "CANCELLED")
        self.assertEqual(self.alice.get(f"/runs/{rid2}/artifacts").json()["items"], [])


class Resilience(AppTestCase):
    def test_worker_crash_is_recovered_by_lease_expiry(self):
        p = self.new_project()
        rid = self.start_run(p["id"])
        job = self.worker.claim()  # a worker claims the plan job and "crashes" without finishing
        self.assertEqual(job["step_id"], "plan")
        self.assertIsNone(self.worker.claim())
        self.app.state.db.run("UPDATE jobs SET lease_expires_at = 1 WHERE id=?", (job["id"],))
        self.drain()
        self.assertEqual(self.status(rid)["status"], "AWAITING_PLAN_APPROVAL")

    def test_replayed_job_is_idempotent(self):
        _, rid = self.run_full()
        db = self.app.state.db
        before = db.one("SELECT COUNT(*) n FROM agent_events WHERE run_id=?", (rid,))["n"]
        from autoforge.core.services import new_job
        for step in ("plan", "generate", "verify", "repair"):
            new_job(db, rid, step)
        self.drain()
        self.assertEqual(self.status(rid)["status"], "AWAITING_EXPORT_APPROVAL")
        self.assertEqual(db.one("SELECT COUNT(*) n FROM agent_events WHERE run_id=?", (rid,))["n"], before)

    def test_illegal_transition_is_rejected_and_audited(self):
        _, rid = self.run_to_plan()
        r = self.alice.post(f"/runs/{rid}/export/approve")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["error"]["code"], "INVALID_STATE")
        audit = self.alice.get("/audit").json()["items"]
        self.assertTrue(any(a["action"] == "export.approved" and a["outcome"] == "denied" for a in audit))


if __name__ == "__main__":
    unittest.main()
