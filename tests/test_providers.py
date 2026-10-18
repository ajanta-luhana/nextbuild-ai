"""Provider adapters tested through a local fake model server (no external network or paid APIs)."""
from __future__ import annotations

import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from autoforge.agents.schemas import SCHEMAS
from autoforge.providers.base import AgentRequest, ProviderError, extract_json
from autoforge.providers.factory import build_provider
from autoforge.providers.mock import MockProvider
from tests.helpers import AppTestCase

TITLE_TO_SCHEMA = {cls.__name__: name for name, cls in SCHEMAS.items()}


class FakeModel(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.calls = 0
        self.fail_first = 0          # number of initial 503 responses
        self.garbage_first = 0       # number of initial schema-invalid answers
        self.status_override: int | None = None
        self.seen_headers: list[dict] = []
        self.mock = MockProvider()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        srv: FakeModel = self.server  # type: ignore[assignment]
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        srv.calls += 1
        srv.seen_headers.append({k.lower(): v for k, v in self.headers.items()})
        if srv.status_override:
            return self._send(srv.status_override, {"error": "nope"})
        if srv.fail_first > 0:
            srv.fail_first -= 1
            return self._send(503, {"error": "overloaded"})
        if self.path.endswith("/chat/completions"):
            system, user = body["messages"][0]["content"], body["messages"][1]["content"]
        else:
            system, user = body["system"], body["messages"][0]["content"]
        title = json.loads(system[system.index("{"):system.rindex("}") + 1])["title"]
        schema = TITLE_TO_SCHEMA[title]
        ctx = json.loads(user.split("CONTEXT (untrusted data):\n", 1)[1])
        if srv.garbage_first > 0:
            srv.garbage_first -= 1
            data = {"wrong": "shape"}
        else:
            data = srv.mock.generate(AgentRequest("x", schema, "", ctx)).data
        text = "Here you go:\n```json\n" + json.dumps(data) + "\n```"
        if self.path.endswith("/chat/completions"):
            self._send(200, {"choices": [{"message": {"content": text}}], "usage": {"prompt_tokens": 11, "completion_tokens": 7}})
        else:
            self._send(200, {"content": [{"type": "text", "text": text}], "usage": {"input_tokens": 11, "output_tokens": 7}})

    def _send(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class AdapterUnit(unittest.TestCase):
    def setUp(self):
        self.srv = FakeModel()
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)

    def req(self):
        return AgentRequest("requirements", "requirements", "do it", {"brief": "Build a thing with widgets and gadgets."})

    def test_openai_compatible_parses_fenced_json_and_usage(self):
        p = build_provider("openai_compatible", "local-model", base_url=self.srv.url)
        r = p.generate(self.req())
        self.assertIn("functional", r.data)
        self.assertEqual((r.usage.input_tokens, r.usage.output_tokens, r.usage.estimated_cost_usd), (11, 7, None))

    def test_anthropic_adapter_sends_key_from_reference_only(self):
        os.environ["AF_UNIT_KEY"] = "test-key-value-123456"
        self.addCleanup(os.environ.pop, "AF_UNIT_KEY", None)
        p = build_provider("anthropic", "claude-x", base_url=self.srv.url, secret_reference="env:AF_UNIT_KEY")
        p.generate(self.req())
        self.assertEqual(self.srv.seen_headers[-1]["x-api-key"], "test-key-value-123456")

    def test_errors_are_classified_and_sanitized(self):
        p = build_provider("openai_compatible", "m", base_url=self.srv.url)
        for status, transient in ((503, True), (429, True), (400, False), (401, False)):
            self.srv.status_override = status
            with self.assertRaises(ProviderError) as cm:
                p.generate(self.req())
            self.assertEqual(cm.exception.transient, transient, status)
            self.assertNotIn("nope", str(cm.exception))
        self.srv.status_override = None
        dead = build_provider("openai_compatible", "m", base_url="http://127.0.0.1:1", settings={"timeout_seconds": 1})
        with self.assertRaises(ProviderError) as cm:
            dead.generate(self.req())
        self.assertTrue(cm.exception.transient)

    def test_missing_secret_reference_is_permanent_failure(self):
        p = build_provider("anthropic", "m", base_url=self.srv.url, secret_reference="env:AF_DOES_NOT_EXIST")
        with self.assertRaises(ProviderError) as cm:
            p.generate(self.req())
        self.assertFalse(cm.exception.transient)

    def test_extract_json(self):
        self.assertEqual(extract_json('```json\n{"a":1}\n```'), {"a": 1})
        self.assertEqual(extract_json('noise {"a": {"b": 2}} tail'), {"a": {"b": 2}})
        for bad in ("no json", "[1,2]", '{"a":'):
            with self.assertRaises(ProviderError):
                extract_json(bad)


class WorkflowViaHttpProvider(AppTestCase):
    def setUp(self):
        super().setUp()
        self.srv = FakeModel()
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)
        r = self.alice.post("/settings/providers", {"provider_type": "openai_compatible", "display_name": "fake", "model_name": "fake-1", "base_url": self.srv.url})
        self.assertEqual(r.status_code, 201, r.text)
        self.pid = r.json()["id"]

    def _events(self, rid):
        return [e["event_type"] for e in self.alice.get(f"/runs/{rid}/events").json()["items"]]

    def test_full_run_with_transient_errors_and_invalid_output_recovered(self):
        self.srv.fail_first = 2
        self.srv.garbage_first = 1
        p = self.new_project()
        rid = self.start_run(p["id"], provider_config_id=self.pid)
        self.drain()
        run = self.status(rid)
        self.assertEqual(run["status"], "AWAITING_PLAN_APPROVAL", run)
        ev = self._events(rid)
        self.assertIn("provider_retry", ev)
        self.assertIn("agent_invalid_output", ev)
        self.alice.post(f"/runs/{rid}/plan/approve")
        self.drain()
        run = self.status(rid)
        self.assertEqual(run["status"], "AWAITING_EXPORT_APPROVAL", run)
        self.assertTrue(run["usage"]["tokens_known"])
        self.assertGreater(run["usage"]["input_tokens"], 0)
        self.assertIsNone(run["usage"]["estimated_cost_usd"])
        self.assertEqual(run["provider_key"], "openai_compatible")

    def test_permanent_provider_failure_is_sanitized_and_fails_run(self):
        self.srv.status_override = 401
        p = self.new_project()
        rid = self.start_run(p["id"], provider_config_id=self.pid)
        self.drain()
        run = self.status(rid)
        self.assertEqual((run["status"], run["error_code"]), ("FAILED", "PLANNING_FAILED"))
        self.assertIn("permanent", run["error_summary"])
        self.assertNotIn("Traceback", json.dumps(run))
        self.assertEqual(self.srv.calls, 1)  # permanent errors are not retried

    def test_transient_retries_are_bounded_then_fail_and_run_is_retryable(self):
        self.srv.status_override = 503
        p = self.new_project()
        rid = self.start_run(p["id"], provider_config_id=self.pid)
        self.drain()
        run = self.status(rid)
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(self.srv.calls, 4)  # 1 try + 3 retries
        self.srv.status_override = None
        r = self.alice.post(f"/runs/{rid}/retry", headers={"Idempotency-Key": "retry-abcdef12"})
        self.assertEqual(r.status_code, 202, r.text)
        again = self.alice.post(f"/runs/{rid}/retry", headers={"Idempotency-Key": "retry-abcdef12"})
        self.assertEqual(again.status_code, 202)
        self.drain()
        self.assertEqual(self.status(rid)["status"], "AWAITING_PLAN_APPROVAL")
        jobs = self.app.state.db.all("SELECT * FROM jobs WHERE run_id=? AND step_id='plan'", (rid,))
        self.assertEqual(len(jobs), 2)  # replayed idempotency key did not enqueue a duplicate

    def test_agent_cannot_write_outside_task_ownership(self):
        # A model that proposes extra files outside the task's expected paths is denied per-file.
        orig = self.srv.mock._file_patch

        def sneaky(ctx):
            out = orig(ctx)
            if ctx["task_key"] == "T3":
                out["files"].append({"path": "app/backdoor.py", "content": "x = 1\n"})
            return out
        self.srv.mock._file_patch = sneaky
        p = self.new_project()
        rid = self.start_run(p["id"], provider_config_id=self.pid)
        self.drain()
        self.alice.post(f"/runs/{rid}/plan/approve")
        self.drain()
        self.assertEqual(self.status(rid)["status"], "AWAITING_EXPORT_APPROVAL")
        self.assertIn("policy_denied", self._events(rid))
        names = [f["path"] for f in self.alice.get(f"/runs/{rid}/diff").json()["files"]]
        self.assertNotIn("app/backdoor.py", names)


if __name__ == "__main__":
    unittest.main()
