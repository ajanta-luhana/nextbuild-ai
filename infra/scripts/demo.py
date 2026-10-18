"""Drive the full AutoForge workflow against a running server and print the evidence.

Usage: python infra/scripts/demo.py [base_url] [--inject-failure]
Needs the server running (make run). Uses the deterministic mock provider; no credentials.
"""
import hashlib
import http.cookiejar
import json
import sys
import os
import time
import urllib.request

base = next((a for a in sys.argv[1:] if a.startswith("http")), "http://127.0.0.1:8000")
inject = "--inject-failure" in sys.argv
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = ""


def call(method, path, body=None, raw=False):
    req = urllib.request.Request(base + "/api/v1" + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", "X-CSRF-Token": csrf})
    with opener.open(req) as r:
        data = r.read()
        return data if raw else json.loads(data)


def wait_for(run_id, statuses, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        run = call("GET", f"/runs/{run_id}")
        if run["status"] in statuses or run["status"] in ("FAILED", "CANCELLED", "POLICY_BLOCKED"):
            return run
        time.sleep(0.3)
    raise SystemExit("timed out waiting for " + str(statuses))


_pw = os.environ.get("DEMO_PASSWORD", "Demo-Passphrase-2026")
_st = call("GET", "/auth/status")
csrf = call("POST", "/auth/register" if _st["setup_required"] else "/auth/login", {"display_name": "demo", "password": _pw})["csrf_token"]
brief = "Build a recruitment portal with job listings, applications and candidates."
project = call("POST", "/projects", {"name": "Recruitment Portal", "brief": brief + (" [[inject-failure]]" if inject else "")})
run = call("POST", f"/projects/{project['id']}/runs", {})
print("run", run["id"], run["status"])
run = wait_for(run["id"], {"AWAITING_PLAN_APPROVAL"})
plan = call("GET", f"/runs/{run['id']}/plan")["plan"]
print("plan v%d: %d functional reqs, entities=%s, %d tasks" % (plan["version"], len(plan["requirements"]["functional"]),
      [e["name"] for e in plan["architecture"]["data_model"]], len(plan["tasks"])))
call("POST", f"/runs/{run['id']}/plan/approve", {})
run = wait_for(run["id"], {"AWAITING_EXPORT_APPROVAL"})
print("status after generation/verification:", run["status"], "| repair attempts:", run["repair_attempts"])
for c in call("GET", f"/runs/{run['id']}/verification")["checks"]:
    print("  round %d %-8s %-7s exit=%s %dms" % (c["round"], c["check_name"], c["status"], c["exit_code"], c["duration_ms"]))
if run["status"] != "AWAITING_EXPORT_APPROVAL":
    raise SystemExit("run did not reach export approval: %s %s" % (run["status"], run.get("error_summary")))
call("POST", f"/runs/{run['id']}/export/approve", {})
run = wait_for(run["id"], {"SUCCEEDED"})
for a in call("GET", f"/runs/{run['id']}/artifacts")["items"]:
    data = call("GET", a["download_url"].replace("/api/v1", ""), raw=True)
    ok = hashlib.sha256(data).hexdigest() == a["sha256"]
    print("  artifact %-28s %7d B sha256 %s %s" % (a["display_name"], a["size_bytes"], a["sha256"][:12], "verified" if ok else "MISMATCH"))
print("final:", run["status"])
