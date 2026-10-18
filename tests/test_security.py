"""Security acceptance tests: auth, CSRF, IDOR, secrets, sandbox isolation, path safety."""
from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest

from starlette.testclient import TestClient

from autoforge.sandbox.runner import CommandDenied, SandboxRunner, SandboxUnavailable, probe
from autoforge.security.paths import PathViolation, resolve_in_workspace, validate_relative_path
from autoforge.security.redaction import redact, redact_text
from autoforge.workspace.manager import Workspace
from tests.helpers import Api, AppTestCase


class AuthAndAccess(AppTestCase):
    def test_unauthenticated_requests_are_rejected(self):
        from starlette.testclient import TestClient
        anon = TestClient(self.app)
        for path in ("/api/v1/projects", "/api/v1/dashboard", "/api/v1/settings/providers"):
            self.assertEqual(anon.get(path).status_code, 401)
        self.assertEqual(anon.get("/api/v1/health/live").status_code, 200)

    def test_csrf_token_required_for_mutations(self):
        r = self.alice.post("/projects", {"name": "x", "brief": "a long enough brief"}, csrf=False)
        self.assertEqual(r.status_code, 403)
        r = self.alice.req("POST", "/projects", {"name": "x", "brief": "a long enough brief"}, headers={"X-CSRF-Token": "wrong"}, csrf=False)
        self.assertEqual(r.status_code, 403)
        r = self.alice.req("POST", "/projects", {"name": "x", "brief": "a long enough brief"}, headers={"Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_cookie_flags(self):
        r = self.alice.c.post("/api/v1/auth/login", json={"display_name": "alice", "password": "Correct-Horse-42"})
        cookie = r.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)

    def test_cross_user_access_is_denied_everywhere(self):
        p, rid = self.run_full()
        self.alice.post(f"/runs/{rid}/export/approve")
        self.drain()
        art = self.alice.get(f"/runs/{rid}/artifacts").json()["items"][0]
        bob = Api(self.app, "bob")
        probes = [("GET", f"/projects/{p['id']}"), ("PATCH", f"/projects/{p['id']}"), ("DELETE", f"/projects/{p['id']}"),
                  ("POST", f"/projects/{p['id']}/runs"), ("GET", f"/runs/{rid}"), ("GET", f"/runs/{rid}/tasks"),
                  ("GET", f"/runs/{rid}/events"), ("GET", f"/runs/{rid}/events/stream"), ("GET", f"/runs/{rid}/diff"),
                  ("GET", f"/runs/{rid}/file?path=app/store.py"), ("GET", f"/runs/{rid}/verification"),
                  ("POST", f"/runs/{rid}/cancel"), ("POST", f"/runs/{rid}/plan/approve"), ("POST", f"/runs/{rid}/export/approve"),
                  ("GET", f"/runs/{rid}/artifacts"), ("GET", f"/artifacts/{art['id']}/download")]
        for method, path in probes:
            r = bob.req(method, path, json={} if method != "GET" else None)
            self.assertEqual(r.status_code, 404, f"{method} {path} -> {r.status_code}")
        self.assertEqual(bob.get("/projects").json()["items"], [])
        self.assertEqual(self.alice.get(f"/runs/{rid}").json()["status"], "AWAITING_EXPORT_APPROVAL" if False else "SUCCEEDED")
        # denied attempts are audited for the owner
        self.assertTrue(any(a["action"] == "access.denied" for a in self.alice.get("/audit").json()["items"]))

    def test_error_format_has_no_stack_traces(self):
        r = self.alice.get("/projects/not-a-real-id")
        self.assertEqual(r.status_code, 404)
        body = r.json()["error"]
        self.assertEqual(set(body), {"code", "message", "details", "request_id"})
        self.assertNotIn("Traceback", r.text)
        r = self.alice.post("/projects", {"name": "", "brief": "x"})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.json()["error"]["code"], "VALIDATION_ERROR")

    def test_security_headers_and_request_id(self):
        r = self.alice.get("/about")
        self.assertIn("default-src 'self'", r.headers["content-security-policy"])
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertTrue(r.headers["x-request-id"])

    def test_rate_limit_on_run_creation(self):
        self.app.state.service.limiter.per_minute = 2
        p = self.new_project()
        self.start_run(p["id"])
        self.start_run(p["id"])
        self.assertEqual(self.alice.post(f"/projects/{p['id']}/runs").status_code, 429)

    def test_provider_secrets_are_references_only_and_never_returned(self):
        r = self.alice.post("/settings/providers", {"provider_type": "anthropic", "display_name": "x", "model_name": "m", "secret_reference": "sk-ant-abcdefghijklmnop"})
        self.assertEqual(r.status_code, 422)
        os.environ["AF_TEST_KEY"] = "sk-ant-SUPERSECRETVALUE123456"
        self.addCleanup(os.environ.pop, "AF_TEST_KEY", None)
        r = self.alice.post("/settings/providers", {"provider_type": "anthropic", "display_name": "x", "model_name": "m", "secret_reference": "env:AF_TEST_KEY"})
        self.assertEqual(r.status_code, 201, r.text)
        p = self.new_project()
        rid = self.start_run(p["id"], provider_config_id=r.json()["id"])
        blob = json.dumps([self.alice.get("/settings/providers").json(), self.status(rid), self.alice.get("/audit").json()])
        self.assertNotIn("SUPERSECRET", blob)
        self.assertNotIn("SUPERSECRET", open(self.settings.database_path, "rb").read().decode("latin-1"))

    def test_audit_log_is_append_only(self):
        db = self.app.state.db
        db.run("INSERT INTO audit_logs(action,resource_type,outcome,created_at) VALUES ('t','t','ok','now')")
        with self.assertRaises(Exception):
            db.run("UPDATE audit_logs SET outcome='x'")
        with self.assertRaises(Exception):
            db.run("DELETE FROM audit_logs")

    def test_exported_artifacts_contain_no_secrets(self):
        _, rid = self.run_full()
        self.alice.post(f"/runs/{rid}/export/approve")
        self.drain()
        for a in self.alice.get(f"/runs/{rid}/artifacts").json()["items"]:
            data = self.alice.get(a["download_url"].replace("/api/v1", "")).content
            self.assertNotIn(self.settings.session_secret.encode(), data)

    def test_secret_in_generated_code_blocks_export(self):
        from autoforge.core.services import load_run
        # Simulate a compromised agent output by planting a secret into the workspace before verification.
        _, rid = self.run_to_plan()
        self.alice.post(f"/runs/{rid}/plan/approve")
        # run generation only
        while True:
            job = self.worker.claim()
            if job is None:
                break
            self.app.state.engine.process_job(job)
            self.app.state.db.run("UPDATE jobs SET status='done' WHERE id=?", (job["id"],))
            if job["step_id"] == "generate":
                ws = Workspace(self.settings.workspace_root, rid)
                ws.write_file("app/config.py", 'API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz123456"\n')
        run = self.status(rid)
        self.assertEqual((run["status"], run["error_code"]), ("POLICY_BLOCKED", "SECRET_DETECTED"))
        findings = self.alice.get(f"/runs/{rid}/verification").json()["security_findings"]
        crit = [f for f in findings if f["severity"] == "critical"]
        self.assertTrue(crit)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", json.dumps(findings))


class Redaction(unittest.TestCase):
    def test_text_patterns(self):
        for s in ("sk-ant-api03-abcdefghijklmnop", "Authorization: Bearer abcdefghijklmnopqrstuv", "AKIAABCDEFGHIJKLMNOP",
                  "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "api_key = 'abcdefghijk123'"):
            self.assertNotIn(s.split()[-1].strip("'"), redact_text(s), s)

    def test_nested_structures(self):
        out = redact({"headers": {"Authorization": "Bearer abc"}, "password": "hunter2hunter2", "ok": "fine", "list": ["token=abcdef123456"]})
        self.assertEqual(out["headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(out["password"], "[REDACTED]")
        self.assertEqual(out["ok"], "fine")
        self.assertNotIn("abcdef123456", json.dumps(out))


class PathSafety(unittest.TestCase):
    def test_validation(self):
        for bad in ("../x", "a/../../x", "/etc/passwd", "a\\b", "~/x", ".git/config", ".env", "a/.git/x", "", "a//b", "./a", "x\x00y"):
            with self.assertRaises(PathViolation, msg=bad):
                validate_relative_path(bad)
        self.assertEqual(validate_relative_path("app/store.py"), "app/store.py")

    def test_symlink_escape_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d) / "ws"
            root.mkdir()
            outside = pathlib.Path(d) / "outside"
            outside.mkdir()
            os.symlink(outside, root / "link")
            with self.assertRaises(PathViolation):
                resolve_in_workspace(root, "link/evil.py")
            ws = Workspace(d, "r1")
            ws.create()
            os.symlink(outside, ws.root / "sneaky")
            with self.assertRaises(PathViolation):
                ws.write_file("sneaky/evil.py", "x")
            self.assertEqual(list(outside.iterdir()), [])

    def test_workspace_limits(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Workspace(d, "r")
            ws.create()
            with self.assertRaises(PathViolation):
                ws.write_file("a.py", "x" * 300_000)
            with self.assertRaises(PathViolation):
                ws.write_file("a.bin", "a\x00b")


@unittest.skipUnless(probe().isolation == "namespaces", "namespace sandbox unavailable on this host")
class SandboxIsolation(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ws = pathlib.Path(self.d)
        (self.ws / "app").mkdir()
        (self.ws / "app" / "__init__.py").write_text("")
        (self.ws / "tests").mkdir()
        (self.ws / "tests" / "__init__.py").write_text("")
        self.runner = SandboxRunner(timeout_seconds=15)

    def _test(self, body: str):
        (self.ws / "tests" / "test_probe.py").write_text("import unittest\nclass T(unittest.TestCase):\n    def test_x(self):\n" + "".join(f"        {l}\n" for l in body.splitlines()))
        return self.runner.run("unittest", self.ws)

    def test_network_is_denied(self):
        res = self._test("import socket\nwith self.assertRaises(OSError):\n    socket.create_connection(('192.0.2.1', 80), 2)")
        self.assertEqual(res.status, "passed", res.output_summary)

    def test_no_host_secrets_docker_socket_or_control_plane_env(self):
        os.environ["AUTOFORGE_CONTROL_SECRET"] = "should-not-leak"
        self.addCleanup(os.environ.pop, "AUTOFORGE_CONTROL_SECRET", None)
        res = self._test("import os\nself.assertNotIn('AUTOFORGE_CONTROL_SECRET', os.environ)\n"
                         "self.assertFalse([k for k in os.environ if 'TOKEN' in k or 'KEY' in k or 'SECRET' in k])\n"
                         "for p in ('/var/run/docker.sock', '/root', '/home', '/etc/shadow', '/proc/1/environ'):\n    self.assertFalse(os.path.exists(p), p)")
        self.assertEqual(res.status, "passed", res.output_summary)

    def test_system_dirs_are_read_only_and_only_workspace_is_writable(self):
        res = self._test("with self.assertRaises(OSError):\n    open('/usr/evil', 'w')\nopen('/work/ok.txt', 'w').write('x')")
        self.assertEqual(res.status, "passed", res.output_summary)

    def test_timeout_kills_runaway_process(self):
        runner = SandboxRunner(timeout_seconds=2)
        (self.ws / "tests" / "test_loop.py").write_text("import unittest, time\nclass T(unittest.TestCase):\n    def test_x(self):\n        time.sleep(60)\n")
        res = runner.run("unittest", self.ws)
        self.assertEqual(res.status, "timeout")
        self.assertLess(res.duration_ms, 10_000)

    def test_output_is_capped(self):
        res = self._test("print('A' * 5_000_000)")
        self.assertLessEqual(len(res.output_summary), 4000)

    def test_only_allowlisted_commands(self):
        for name in ("sh", "rm -rf /", "unittest; id", "pip", ""):
            with self.assertRaises(CommandDenied):
                self.runner.run(name, self.ws)

    def test_weak_sandbox_is_refused_by_default(self):
        import autoforge.sandbox.runner as r
        saved = r._probe_cache
        r._probe_cache = r.SandboxInfo("none", False, False, "simulated")
        try:
            with self.assertRaises(SandboxUnavailable):
                SandboxRunner().run("unittest", self.ws)
        finally:
            r._probe_cache = saved


class ConfigValidation(unittest.TestCase):
    def test_production_rejects_insecure_defaults(self):
        from autoforge.core.config import ConfigError, Settings
        with self.assertRaises(ConfigError):
            Settings(app_env="production", auth_mode="local", session_secret="x" * 40).validate()
        with self.assertRaises(ConfigError):
            Settings(app_env="production", auth_mode="proxy", session_secret="short").validate()
        with self.assertRaises(ConfigError):
            Settings(app_env="production", auth_mode="proxy", session_secret="x" * 40, allow_weak_sandbox=True).validate()
        with self.assertRaises(ConfigError):  # default localhost-only allowlist is rejected in production
            Settings(app_env="production", auth_mode="proxy", session_secret="x" * 40).validate()
        Settings(app_env="production", auth_mode="proxy", session_secret="x" * 40, allowed_hosts=("app.example.com",)).validate()


class PasswordAuth(AppTestCase):
    def fresh(self, **over):
        import os, tempfile, shutil
        from autoforge.api.app import create_app
        from tests.helpers import make_settings
        root = tempfile.mkdtemp(prefix="afauth-"); self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return create_app(make_settings(root, **over), start_worker=False, sleep=lambda s: None)

    def test_first_run_only_then_registration_closed(self):
        app = self.fresh(allow_registration=False)
        c = TestClient(app, base_url="http://testserver")
        self.assertTrue(c.get("/api/v1/auth/status").json()["setup_required"])
        self.assertEqual(c.post("/api/v1/auth/register", json={"display_name": "owner", "password": "Correct-Horse-42"}).status_code, 200)
        self.assertFalse(c.get("/api/v1/auth/status").json()["setup_required"])
        c2 = TestClient(app, base_url="http://testserver")
        self.assertEqual(c2.post("/api/v1/auth/register", json={"display_name": "mallory", "password": "Correct-Horse-42"}).status_code, 403)

    def test_weak_password_rejected(self):
        c = TestClient(self.fresh(), base_url="http://testserver")
        self.assertGreaterEqual(c.post("/api/v1/auth/register", json={"display_name": "owner", "password": "password"}).status_code, 400)

    def test_generic_error_and_lockout(self):
        app = self.fresh(max_failed_logins=3)
        c = TestClient(app, base_url="http://testserver")
        c.post("/api/v1/auth/register", json={"display_name": "owner", "password": "Correct-Horse-42"})
        c = TestClient(app, base_url="http://testserver")
        bad = c.post("/api/v1/auth/login", json={"display_name": "owner", "password": "wrong-pass-123"})
        ghost = c.post("/api/v1/auth/login", json={"display_name": "nobody", "password": "wrong-pass-123"})
        self.assertEqual(bad.status_code, 401)
        self.assertEqual(bad.json()["error"]["message"], ghost.json()["error"]["message"])
        for _ in range(3):
            c.post("/api/v1/auth/login", json={"display_name": "owner", "password": "wrong-pass-123"})
        self.assertNotEqual(c.post("/api/v1/auth/login", json={"display_name": "owner", "password": "Correct-Horse-42"}).status_code, 200)

    def test_login_ip_throttle(self):
        c = TestClient(self.fresh(login_per_minute_per_ip=3), base_url="http://testserver")
        codes = [c.post("/api/v1/auth/login", json={"display_name": "x", "password": "y"}).status_code for _ in range(6)]
        self.assertIn(429, codes)

    def test_bad_host_header_blocked(self):
        c = TestClient(self.app, base_url="http://evil.example")
        r = c.get("/api/v1/health/live")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"]["code"], "HOST_NOT_ALLOWED")

    def test_json_content_type_required(self):
        r = self.alice.c.post("/api/v1/projects", content='{"name":"x"}', headers={"X-CSRF-Token": self.alice.csrf, "Content-Type": "text/plain"})
        self.assertEqual(r.status_code, 415)

    def test_change_password_revokes_other_sessions(self):
        other = TestClient(self.app, base_url="http://testserver")
        r = other.post("/api/v1/auth/login", json={"display_name": "alice", "password": "Correct-Horse-42"})
        self.assertEqual(r.status_code, 200)
        r = self.alice.post("/auth/password", {"current_password": "Correct-Horse-42", "new_password": "Another-Strong-Pass-9"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(other.get("/api/v1/projects").status_code, 401)
        self.assertEqual(self.alice.get("/projects").status_code, 200)

    def test_idle_timeout(self):
        self.alice.c.app.state.db.run("UPDATE sessions SET last_seen='2000-01-01T00:00:00.000+00:00'")
        r = self.alice.get("/projects")
        self.assertEqual(r.status_code, 401)

    def test_login_is_case_insensitive_and_email_names_work(self):
        app = self.fresh()
        c = TestClient(app, base_url="http://testserver")
        r = c.post("/api/v1/auth/register", json={"display_name": "Rakesh.Lohana@gmail.com", "password": "Correct-Horse-42"})
        self.assertEqual(r.status_code, 200, r.text)
        c2 = TestClient(app, base_url="http://testserver")
        r = c2.post("/api/v1/auth/login", json={"display_name": "  rakesh.lohana@GMAIL.com ", "password": "Correct-Horse-42"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(c2.get("/api/v1/auth/me").json()["user"]["display_name"], "Rakesh.Lohana@gmail.com")

    def test_old_passwordless_database_can_be_claimed_and_login_works(self):
        import sqlite3
        app = self.fresh()
        db = app.state.db
        db.run("INSERT INTO users(id,display_name,role,created_at,updated_at) VALUES ('u-old','alice','builder','2026-01-01','2026-01-01')")
        c = TestClient(app, base_url="http://testserver")
        self.assertTrue(c.get("/api/v1/auth/status").json()["setup_required"])
        self.assertEqual(c.post("/api/v1/auth/register", json={"display_name": "Alice", "password": "Correct-Horse-42"}).status_code, 200)
        self.assertEqual(db.one("SELECT id FROM users WHERE display_name='alice'")["id"], "u-old")

    def test_static_files_are_revalidated(self):
        r = TestClient(self.app, base_url="http://testserver").get("/app.js")
        self.assertEqual(r.headers["cache-control"], "no-cache")

    def test_admin_reset_password_unlocks(self):
        import io, os
        from unittest import mock
        from autoforge import admin
        app = self.fresh(max_failed_logins=2)
        c = TestClient(app, base_url="http://testserver")
        c.post("/api/v1/auth/register", json={"display_name": "owner", "password": "Correct-Horse-42"})
        c = TestClient(app, base_url="http://testserver")
        for _ in range(2):
            c.post("/api/v1/auth/login", json={"display_name": "owner", "password": "bad-password-1"})
        self.assertEqual(c.post("/api/v1/auth/login", json={"display_name": "owner", "password": "Correct-Horse-42"}).status_code, 401)  # locked
        path = app.state.settings.database_path
        with mock.patch.dict(os.environ, {"DATABASE_PATH": path, "ARTIFACT_ROOT": app.state.settings.artifact_root, "WORKSPACE_ROOT": app.state.settings.workspace_root}), \
             mock.patch("getpass.getpass", return_value="Brand-New-Pass-77"):
            self.assertEqual(admin.main(["reset-password", "OWNER"]), 0)
        self.assertEqual(c.post("/api/v1/auth/login", json={"display_name": "owner", "password": "Brand-New-Pass-77"}).status_code, 200)

    def test_recovery_code_resets_password_once_and_rotates(self):
        app = self.fresh()
        c = TestClient(app, base_url="http://testserver")
        r = c.post("/api/v1/auth/register", json={"display_name": "owner", "password": "Correct-Horse-42"})
        code = r.json()["recovery_code"]
        self.assertRegex(code, r"^[A-Z2-7]{4}(-[A-Z2-7]{4}){4}$")
        c = TestClient(app, base_url="http://testserver")
        bad = c.post("/api/v1/auth/recover", json={"display_name": "owner", "recovery_code": "AAAA-AAAA-AAAA-AAAA-AAAA", "new_password": "Fresh-Pass-Word-9"})
        self.assertEqual(bad.status_code, 401)
        ok = c.post("/api/v1/auth/recover", json={"display_name": "OWNER", "recovery_code": code.lower(), "new_password": "Fresh-Pass-Word-9"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertNotEqual(ok.json()["recovery_code"], code)
        again = c.post("/api/v1/auth/recover", json={"display_name": "owner", "recovery_code": code, "new_password": "Another-Pass-Word-8"})
        self.assertEqual(again.status_code, 401)  # old code is dead
        self.assertEqual(c.post("/api/v1/auth/login", json={"display_name": "owner", "password": "Fresh-Pass-Word-9"}).status_code, 200)

    def test_recovery_attempts_are_limited(self):
        app = self.fresh(max_failed_logins=3)
        c = TestClient(app, base_url="http://testserver")
        code = c.post("/api/v1/auth/register", json={"display_name": "owner", "password": "Correct-Horse-42"}).json()["recovery_code"]
        for _ in range(3):
            c.post("/api/v1/auth/recover", json={"display_name": "owner", "recovery_code": "BBBB-BBBB-BBBB-BBBB-BBBB", "new_password": "Fresh-Pass-Word-9"})
        r = c.post("/api/v1/auth/recover", json={"display_name": "owner", "recovery_code": code, "new_password": "Fresh-Pass-Word-9"})
        self.assertEqual(r.status_code, 401)  # locked even with the right code

    def test_two_factor_login_flow(self):
        from autoforge.security import totp
        app = self.fresh()
        c = TestClient(app, base_url="http://testserver")
        c.post("/api/v1/auth/register", json={"display_name": "owner", "password": "Correct-Horse-42"})
        csrf = c.get("/api/v1/auth/me").json()["csrf_token"]
        H = {"X-CSRF-Token": csrf}
        sec = c.post("/api/v1/auth/totp/begin", json={}, headers=H).json()
        self.assertTrue(sec["otpauth_uri"].startswith("otpauth://totp/"))
        step = int(__import__("time").time() // 30)
        self.assertEqual(c.post("/api/v1/auth/totp/enable", json={"code": "000000"}, headers=H).status_code, 422)
        self.assertEqual(c.post("/api/v1/auth/totp/enable", json={"code": totp.code_at(sec["secret"], step)}, headers=H).status_code, 200)
        c2 = TestClient(app, base_url="http://testserver")
        r = c2.post("/api/v1/auth/login", json={"display_name": "owner", "password": "Correct-Horse-42"})
        self.assertEqual(r.json(), {"mfa_required": True})
        self.assertEqual(c2.get("/api/v1/projects").status_code, 401)  # no session yet
        self.assertEqual(c2.post("/api/v1/auth/login", json={"display_name": "owner", "password": "Correct-Horse-42", "otp": "123456"}).status_code, 401)
        good = totp.code_at(sec["secret"], step + 1)  # next step: not yet used, accepted within drift window
        self.assertEqual(c2.post("/api/v1/auth/login", json={"display_name": "owner", "password": "Correct-Horse-42", "otp": good}).status_code, 200)
        c3 = TestClient(app, base_url="http://testserver")  # the same code cannot be replayed
        self.assertEqual(c3.post("/api/v1/auth/login", json={"display_name": "owner", "password": "Correct-Horse-42", "otp": good}).status_code, 401)

    def test_totp_known_vector(self):
        from autoforge.security import totp
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()  # RFC 6238 test secret
        self.assertEqual(totp.code_at(secret, 59 // 30), "287082")

    def test_remote_bind_refused_without_opt_in(self):
        import os
        from unittest import mock
        from autoforge.api import app as appmod
        with mock.patch.dict(os.environ, {"HOST": "0.0.0.0", "DATABASE_PATH": os.path.join(self.root, "b.db"),
                                          "ARTIFACT_ROOT": self.root, "WORKSPACE_ROOT": self.root}):
            with self.assertRaises(SystemExit):
                appmod.main()


if __name__ == "__main__":
    unittest.main()
