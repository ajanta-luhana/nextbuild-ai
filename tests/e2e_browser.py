"""Browser end-to-end test (Playwright + Chromium) against a real server process.

Run:  python tests/e2e_browser.py        (skips with exit code 0 and a message if Playwright is missing)
Journey: sign in -> create project -> start run -> review plan -> approve -> watch live events ->
inspect verification -> approve export -> download artifact and check its SHA-256.
"""
from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

try:
    from playwright.sync_api import expect, sync_playwright
except ImportError:  # pragma: no cover
    print("SKIP: playwright is not installed")
    sys.exit(0)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="afe2e-")
    port = free_port()
    env = {**os.environ, "DATABASE_PATH": f"{tmp}/db.sqlite", "ARTIFACT_ROOT": f"{tmp}/art", "WORKSPACE_ROOT": f"{tmp}/ws",
           "PORT": str(port), "WORKER_POLL_SECONDS": "0.1", "PYTHONPATH": ROOT}
    srv = subprocess.Popen([sys.executable, "-m", "autoforge.api.app"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/api/v1/health/live", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not start")
        problems: list[str] = []
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)
            ctx = browser.new_context(accept_downloads=True, viewport={"width": 1200, "height": 900})
            page = ctx.new_page()
            # the journey deliberately submits a weak password (422) and a wrong password (401); those network errors are expected
            expected = ("status of 422", "status of 401")
            page.on("console", lambda m: problems.append(m.text) if m.type == "error" and not any(x in m.text for x in expected) else None)
            page.on("pageerror", lambda e: problems.append(str(e)))
            shots = os.environ.get("SHOTS_DIR") or tmp
            os.makedirs(shots, exist_ok=True)
            shot = lambda n: page.screenshot(path=os.path.join(shots, n + ".png"))
            page.goto(base)
            expect(page.get_by_role("heading", name="Create your workspace")).to_be_visible()
            expect(page.get_by_text("Protected workspace · Secure session")).to_be_visible()
            page.wait_for_timeout(600); shot("01-setup")
            page.get_by_label("Email or user name").fill("e2e@example.com")
            page.get_by_label("Password", exact=True).fill("password123")
            page.get_by_label("Confirm password").fill("password123")
            page.get_by_role("button", name="Create account").click()
            expect(page.locator(".af-error")).to_contain_text("common")  # weak password refused
            page.get_by_label("Password", exact=True).fill("Correct-Horse-42")
            page.get_by_label("Confirm password").fill("Correct-Horse-42")
            # show/hide toggle
            page.get_by_role("button", name="Show password").first.click()
            assert page.get_by_label("Password", exact=True).get_attribute("type") == "text"
            page.get_by_role("button", name="Create account").click()
            expect(page.get_by_role("heading", name="Your account is ready")).to_be_visible()
            recovery = page.locator(".recovery").inner_text().strip()
            assert len(recovery) == 24, recovery
            expect(page.get_by_role("button", name="Continue")).to_be_disabled()
            page.get_by_label("I have saved my recovery code").check()
            shot("01b-recovery")
            page.get_by_role("button", name="Continue").click()
            expect(page.get_by_role("heading", name="Dashboard")).to_be_visible()
            page.get_by_role("button", name="Sign out").click()
            expect(page.get_by_role("heading", name="Sign in", exact=True)).to_be_visible()
            page.wait_for_timeout(600); shot("02-signin")
            page.get_by_label("Email or user name").fill("e2e@example.com")
            page.get_by_label("Password", exact=True).fill("wrong-password-1")
            page.get_by_role("button", name="Sign in").click()
            expect(page.locator(".af-error")).to_contain_text("Sign-in failed")
            # forgot password with the recovery code
            page.get_by_role("link", name="Forgot password?").click()
            expect(page.get_by_role("heading", name="Reset your password")).to_be_visible()
            page.get_by_label("Email or user name").fill("e2e@example.com")
            page.get_by_label("Recovery code").fill(recovery)
            page.get_by_label("New password").fill("Brand-New-Passphrase-7")
            page.get_by_role("button", name="Reset password").click()
            expect(page.get_by_role("heading", name="Password changed")).to_be_visible()
            page.get_by_label("I have saved my recovery code").check()
            page.get_by_role("button", name="Continue").click()
            expect(page.get_by_text("Password changed. Sign in with your new password.")).to_be_visible()
            page.get_by_label("Email or user name").fill("E2E@example.com")
            page.get_by_label("Password", exact=True).fill("Brand-New-Passphrase-7")
            page.get_by_role("button", name="Sign in").click()
            expect(page.get_by_role("heading", name="Dashboard")).to_be_visible()

            page.get_by_role("link", name="New project").first.click()
            page.get_by_label("Project name").fill("Recruitment Portal")
            page.get_by_label("Brief").fill("Build a recruitment portal with job listings, applications and candidates.")
            page.get_by_role("button", name="Create project").click()
            expect(page.get_by_role("heading", name="Recruitment Portal")).to_be_visible()

            page.get_by_role("button", name="Start planning").click()
            expect(page.get_by_text("The plan is ready")).to_be_visible(timeout=30000)  # live via SSE
            page.wait_for_timeout(600); shot("04-run-plan-gate")
            page.get_by_role("tab", name="plan").click()
            expect(page.get_by_role("heading", name="Task graph")).to_be_visible()
            expect(page.get_by_text("graph TD")).to_be_visible()
            page.get_by_role("button", name="Approve plan v1 and generate").click()

            expect(page.get_by_text("All checks passed. Review code")).to_be_visible(timeout=60000)
            page.wait_for_timeout(600); shot("05-run-export-gate")
            page.get_by_role("tab", name="verification").click()
            expect(page.get_by_text("round 1 · unittest")).to_be_visible()
            expect(page.get_by_text("passed", exact=True).first).to_be_visible()
            page.get_by_role("tab", name="code").click()
            page.get_by_role("button", name="app/store.py").first.click()
            expect(page.get_by_text("class Store")).to_be_visible()
            page.get_by_role("tab", name="verification").click()
            page.get_by_role("button", name="Approve export and package").click()

            expect(page.get_by_role("heading", name="Artifacts")).to_be_visible(timeout=30000)
            row = page.locator("tr", has_text="source.zip")
            expect(row).to_be_visible(timeout=30000)
            with page.expect_download() as dl:
                row.get_by_role("link", name="Download").click()
            path = dl.value.path()
            digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
            expect(row.locator("code")).to_have_text(digest[:16] + "…")

            page.get_by_role("link", name="Dashboard").click()
            expect(page.get_by_role("heading", name="Dashboard")).to_be_visible()
            page.wait_for_timeout(300); shot("03-dashboard")
            page.get_by_role("link", name="Security & audit").click()
            expect(page.get_by_role("heading", name="Recent audit events")).to_be_visible()
            expect(page.get_by_text("isolated (")).to_be_visible()
            shot("06-audit")
            browser.close()
        if problems:
            print("Browser console/page errors:", *problems, sep="\n  ")
            return 1
        print("E2E OK: full browser journey passed, artifact SHA-256 verified, no console errors")
        return 0
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except subprocess.TimeoutExpired:
            srv.kill()


if __name__ == "__main__":
    sys.exit(main())
