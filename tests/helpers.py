from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from starlette.testclient import TestClient

from autoforge.api.app import create_app
from autoforge.core.config import Settings


def make_settings(root: str, **over) -> Settings:
    base = dict(database_path=os.path.join(root, "t.db"), artifact_root=os.path.join(root, "artifacts"),
                workspace_root=os.path.join(root, "ws"), session_secret="x" * 40, inline_worker=False, run_creation_per_minute=1000,
                allow_registration=True, allowed_hosts=("testserver", "127.0.0.1", "localhost"))
    base.update(over)
    os.makedirs(base["artifact_root"], exist_ok=True)
    os.makedirs(base["workspace_root"], exist_ok=True)
    return Settings(**base)


PASSWORD = "Correct-Horse-42"


class Api:
    """Thin authenticated client around Starlette's TestClient (one per simulated user)."""

    def __init__(self, app, name: str):
        self.c = TestClient(app, base_url="http://testserver")
        r = self.c.post("/api/v1/auth/register", json={"display_name": name, "password": PASSWORD})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf_token"]
        self.user = r.json()["user"]

    def req(self, method: str, path: str, json=None, headers=None, csrf=True):
        h = dict(headers or {})
        if csrf:
            h["X-CSRF-Token"] = self.csrf
        return self.c.request(method, "/api/v1" + path, json=json, headers=h)

    def get(self, p, **k):
        return self.req("GET", p, **k)

    def post(self, p, json=None, **k):
        return self.req("POST", p, json=json or {}, **k)


class AppTestCase(unittest.TestCase):
    brief = "Build a recruitment portal with job listings, applications and candidates."

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="aftest-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.settings = make_settings(self.root)
        self.app = create_app(self.settings, start_worker=False, sleep=lambda s: None)
        self.worker = self.app.state.worker
        self.alice = Api(self.app, "alice")

    def drain(self):
        return self.worker.drain()

    def new_project(self, api=None, brief=None, name="Recruitment Portal"):
        api = api or self.alice
        r = api.post("/projects", {"name": name, "brief": brief or self.brief})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def start_run(self, project_id, api=None, **body):
        api = api or self.alice
        r = api.post(f"/projects/{project_id}/runs", body)
        self.assertEqual(r.status_code, 202, r.text)
        return r.json()["id"]

    def status(self, run_id, api=None):
        return (api or self.alice).get(f"/runs/{run_id}").json()

    def run_to_plan(self, brief=None, **body):
        p = self.new_project(brief=brief)
        rid = self.start_run(p["id"], **body)
        self.drain()
        return p, rid

    def run_full(self, brief=None):
        p, rid = self.run_to_plan(brief)
        self.assertEqual(self.status(rid)["status"], "AWAITING_PLAN_APPROVAL")
        self.assertEqual(self.alice.post(f"/runs/{rid}/plan/approve").status_code, 200)
        self.drain()
        return p, rid
