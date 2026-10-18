from __future__ import annotations

import json
import tempfile
import time
import unittest

from pydantic import ValidationError

from autoforge.agents import analysis
from autoforge.agents.schemas import validate_output
from autoforge.domain.states import ALLOWED, TERMINAL, RunStatus, can_transition, validate_dag
from autoforge.providers.mock import MockProvider
from autoforge.providers.base import AgentRequest
from autoforge.verification.scanner import scan_workspace
from autoforge.workspace.manager import Workspace
from tests.helpers import AppTestCase


class StateMachine(unittest.TestCase):
    def test_terminal_states_have_no_exits_except_retry_from_failed(self):
        for s in TERMINAL - {RunStatus.FAILED}:
            self.assertEqual(ALLOWED[s], set(), s)
        self.assertEqual(ALLOWED[RunStatus.FAILED], {RunStatus.PLANNING, RunStatus.GENERATING, RunStatus.VERIFYING, RunStatus.PACKAGING})

    def test_gates_cannot_be_skipped(self):
        self.assertFalse(can_transition(RunStatus.PLANNING, RunStatus.GENERATING))
        self.assertFalse(can_transition(RunStatus.VERIFYING, RunStatus.PACKAGING))
        self.assertFalse(can_transition(RunStatus.AWAITING_EXPORT_APPROVAL, RunStatus.SUCCEEDED))
        self.assertTrue(can_transition(RunStatus.AWAITING_PLAN_APPROVAL, RunStatus.GENERATING))

    def test_every_active_state_can_be_cancelled_failed_or_blocked(self):
        for s in set(RunStatus) - TERMINAL:
            for t in (RunStatus.CANCELLED, RunStatus.FAILED, RunStatus.POLICY_BLOCKED):
                self.assertTrue(can_transition(s, t), (s, t))


class Dag(unittest.TestCase):
    def test_order_and_errors(self):
        order = validate_dag([{"key": "B", "depends_on": ["A"]}, {"key": "A"}, {"key": "C", "depends_on": ["A", "B"]}])
        self.assertEqual(order, ["A", "B", "C"])
        for bad in ([{"key": "A", "depends_on": ["B"]}, {"key": "B", "depends_on": ["A"]}],
                    [{"key": "A", "depends_on": ["A"]}], [{"key": "A", "depends_on": ["X"]}], [{"key": "A"}, {"key": "A"}]):
            with self.assertRaises(ValueError):
                validate_dag(bad)


class Schemas(unittest.TestCase):
    def setUp(self):
        self.mock = MockProvider()

    def test_mock_outputs_validate_for_every_role(self):
        ents = [{"name": "listing", "fields": [{"name": "name", "type": "text"}]}]
        cases = {"requirements": {"brief": "x with widgets"}, "architecture": {"brief": "x with widgets"}, "task_plan": {},
                 "file_patch": {"task_key": "T2", "data_model": ents, "brief": ""}, "repair": {"failures": ["delete"], "data_model": ents, "brief": ""},
                 "review": {}}
        for schema, ctx in cases.items():
            validate_output(schema, self.mock.generate(AgentRequest("r", schema, "", ctx)).data)

    def test_extra_and_invalid_fields_are_rejected(self):
        data = self.mock.generate(AgentRequest("r", "requirements", "", {"brief": "a with b"})).data
        with self.assertRaises(ValidationError):
            validate_output("requirements", {**data, "surprise": 1})
        data["functional"][0]["id"] = "BAD"
        with self.assertRaises(ValidationError):
            validate_output("requirements", data)
        with self.assertRaises(ValidationError):
            validate_output("architecture", {"components": [{"name": "a", "responsibility": "b"}], "mermaid": "not a diagram at all", "adrs": [],
                                             "data_model": [], "api_contract": []})


class EntityExtraction(unittest.TestCase):
    def test_extraction(self):
        self.assertEqual(analysis.extract_entities("Build a portal with job listings, applications, and candidates."), ["listing", "application", "candidate"])
        self.assertEqual(analysis.extract_entities("Something vague"), ["item"])
        self.assertIn("order_record", analysis.extract_entities("A shop managing orders and products"))
        self.assertEqual(analysis.extract_entities("with " + ", ".join(f"thing{c}" for c in "abcdefgh"))[:1], ["thinga"])
        self.assertLessEqual(len(analysis.extract_entities("with " + ", ".join(f"thing{c}" for c in "abcdefgh"))), 4)


class Scanner(unittest.TestCase):
    def test_findings(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Workspace(d, "r")
            ws.create()
            ws.write_file("app/a.py", 'import os\nos.system("ls")\nx = eval(input())\nKEY = "AKIAABCDEFGHIJKLMNOP"\n')
            ws.write_file("requirements.txt", "flask\nrequests==2.0.0\n")
            cats = {(f["category"], f["severity"]) for f in scan_workspace(ws)}
            self.assertIn(("secret", "critical"), cats)
            self.assertIn(("command-injection", "high"), cats)
            self.assertIn(("code-execution", "high"), cats)
            self.assertIn(("dependency", "low"), cats)
            self.assertIn(("hygiene", "low"), cats)
            self.assertNotIn("AKIAABCDEFGHIJKLMNOP", json.dumps(scan_workspace(ws)))


class ApiBehaviour(AppTestCase):
    def test_project_crud_pagination_and_archive(self):
        for i in range(5):
            self.new_project(name=f"P{i}")
        page1 = self.alice.get("/projects?limit=2").json()
        self.assertEqual(len(page1["items"]), 2)
        page2 = self.alice.get(f"/projects?limit=2&cursor={page1['next_cursor']}").json()
        page3 = self.alice.get(f"/projects?limit=2&cursor={page2['next_cursor']}").json()
        names = [p["name"] for p in page1["items"] + page2["items"] + page3["items"]]
        self.assertEqual(names, ["P4", "P3", "P2", "P1", "P0"])
        self.assertIsNone(page3["next_cursor"])
        pid = page1["items"][0]["id"]
        self.assertEqual(self.alice.req("PATCH", f"/projects/{pid}", {"name": "Renamed"}).json()["slug"], "renamed")
        self.assertEqual(self.alice.req("DELETE", f"/projects/{pid}").status_code, 200)
        self.assertEqual(len(self.alice.get("/projects?limit=50").json()["items"]), 4)
        self.assertEqual(self.alice.post(f"/projects/{pid}/runs").status_code, 409)  # archived
        self.assertEqual(self.alice.req("PATCH", f"/projects/{pid}", {}).status_code, 422)

    def test_invalid_inputs(self):
        self.assertEqual(self.alice.post("/projects", {"name": "x", "brief": "short"}).status_code, 422)
        self.assertEqual(self.alice.post("/projects", {"name": "x", "brief": "long enough brief", "selected_template": "nope"}).status_code, 422)
        r = self.alice.c.post("/api/v1/projects", content=b"{not json", headers={"X-CSRF-Token": self.alice.csrf, "Content-Type": "application/json"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.alice.req("PATCH", "/settings/policies", {"execution_mode": "host"}).status_code, 422)
        self.assertEqual(self.alice.req("PATCH", "/settings/policies", {"bogus": 1}).status_code, 422)

    def test_sse_replays_durable_events_and_resumes(self):
        _, rid = self.run_full()
        self.alice.post(f"/runs/{rid}/export/approve")
        self.drain()  # terminal run: the stream replays history, sends stream_end and closes
        with self.alice.c.stream("GET", f"/api/v1/runs/{rid}/events/stream") as r:
            self.assertEqual(r.headers["content-type"].split(";")[0], "text/event-stream")
            text = "".join(r.iter_text())
        ids = [int(l[4:]) for l in text.splitlines() if l.startswith("id: ")]
        total = len(self.alice.get(f"/runs/{rid}/events").json()["items"])
        self.assertEqual(ids, list(range(1, total + 1)))
        with self.alice.c.stream("GET", f"/api/v1/runs/{rid}/events/stream", headers={"Last-Event-ID": str(ids[-3])}) as r:
            resumed = "".join(r.iter_text())
        self.assertEqual([int(l[4:]) for l in resumed.splitlines() if l.startswith("id: ")], ids[-2:])
        self.assertIn("event: stream_end", text)
        self.assertIn("event: stream_end", resumed)

    def test_health_endpoints_leak_nothing(self):
        r = self.alice.c.get("/api/v1/health/ready")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(self.settings.session_secret, r.text)
        self.assertNotIn(self.root, r.text)
        self.assertEqual(r.json()["status"], "ready")

    def test_retention_purges_artifacts_and_workspace(self):
        import os
        _, rid = self.run_full()
        self.alice.post(f"/runs/{rid}/export/approve")
        self.drain()
        self.assertEqual(self.status(rid)["status"], "SUCCEEDED")
        eng = self.app.state.engine
        self.assertEqual(eng.purge_expired(days=30), {"runs": 0, "artifacts": 0})
        res = eng.purge_expired(days=-1)
        self.assertEqual(res["runs"], 1)
        self.assertGreaterEqual(res["artifacts"], 5)
        self.assertEqual(self.alice.get(f"/runs/{rid}/artifacts").json()["items"], [])
        self.assertFalse(os.path.exists(os.path.join(self.settings.workspace_root, rid)))

    def test_projects_have_versions_and_plan_snapshots(self):
        p, rid = self.run_to_plan()
        proj = self.alice.get(f"/projects/{p['id']}").json()
        self.assertEqual([v["version_number"] for v in proj["versions"]], [1, 2])
        self.assertEqual(self.alice.post(f"/projects/{p['id']}/versions", {"brief": "A revised brief that is long enough"}).status_code, 201)


if __name__ == "__main__":
    unittest.main()
