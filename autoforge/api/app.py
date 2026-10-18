"""Starlette HTTP API (v1) + static dashboard."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from autoforge.core.app_service import AppService, RateLimiter
from autoforge.core.config import Settings, load_settings
from autoforge.core.db import Database, utcnow
from autoforge.core.errors import AppError, Forbidden, NotFound, Unauthenticated, ValidationFailed
from autoforge.core.services import audit
from autoforge.domain.states import TERMINAL, IllegalTransition, RunStatus
from autoforge.orchestration.engine import Engine
from autoforge.orchestration.worker import Worker
from autoforge.sandbox.runner import probe
from autoforge.storage.local import LocalArtifactStore

log = logging.getLogger("autoforge.api")
VERSION = "1.0.0"
COOKIE = "af_session"
SESSION_HOURS = 12
TOUCH_EVERY_SECONDS = 60
MAX_BODY = 1_000_000
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
_REQ_ID = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class Ctx:
    def __init__(self, app, request: Request, body):
        self.app, self.request, self.body = app, request, body
        self.svc: AppService = app.state.service
        self.user: dict | None = None
        self.session: dict | None = None
        self.params = request.path_params
        self.query = request.query_params
        self.request_id = request.state.request_id


def _hash_token(settings: Settings, token: str) -> str:
    return hmac.new(settings.session_secret.encode(), token.encode(), hashlib.sha256).hexdigest()


def _authenticate(ctx: Ctx, mutating: bool) -> None:
    s: Settings = ctx.app.state.settings
    if s.auth_mode == "proxy":  # behind an authenticated reverse proxy that sets the header
        name = ctx.request.headers.get("x-forwarded-user", "")
        if not name:
            raise Unauthenticated("Authentication required")
        ctx.user = ctx.svc.ensure_user(name)
        return
    token = ctx.request.cookies.get(COOKIE)
    if not token:
        raise Unauthenticated("Authentication required")
    db: Database = ctx.app.state.db
    row = db.one("SELECT s.*, u.display_name, u.role, u.is_active FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (_hash_token(s, token),))
    now = datetime.now(timezone.utc)
    if row is None or row["expires_at"] < now.isoformat(timespec="milliseconds") or not row["is_active"]:
        raise Unauthenticated("Session expired or invalid")
    last = datetime.fromisoformat(row["last_seen"] or row["created_at"])
    if s.idle_timeout_minutes and (now - last).total_seconds() > s.idle_timeout_minutes * 60:
        db.run("DELETE FROM sessions WHERE token_hash=?", (row["token_hash"],))
        raise Unauthenticated("Session timed out after inactivity. Sign in again.")
    if (now - last).total_seconds() > TOUCH_EVERY_SECONDS:
        db.run("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now.isoformat(timespec="milliseconds"), row["token_hash"]))
    if mutating:
        origin = ctx.request.headers.get("origin")
        if origin and origin.split("://", 1)[-1] != ctx.request.headers.get("host", ""):
            audit(db, "csrf.blocked", "session", None, "denied", actor_id=row["user_id"], correlation_id=ctx.request_id)
            raise Forbidden("Cross-origin request rejected")
        sent = ctx.request.headers.get("x-csrf-token", "")
        if not sent or not hmac.compare_digest(sent, row["csrf_token"]):
            audit(db, "csrf.blocked", "session", None, "denied", actor_id=row["user_id"], correlation_id=ctx.request_id)
            raise Forbidden("Missing or invalid CSRF token")
    ctx.user = {"id": row["user_id"], "display_name": row["display_name"], "role": row["role"]}
    ctx.session = dict(row)


def endpoint(fn=None, *, auth: bool = True, mutating: bool | None = None):
    def deco(f):
        async def handler(request: Request):
            body = None
            is_mut = request.method in ("POST", "PUT", "PATCH", "DELETE") if mutating is None else mutating
            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                origin = request.headers.get("origin")
                if origin and origin.split("://", 1)[-1].lower() != request.headers.get("host", "").lower():
                    return _error(403, "FORBIDDEN", "Cross-origin request rejected", request)
                raw = await request.body()
                if raw.strip() and not request.headers.get("content-type", "").lower().startswith("application/json"):
                    return _error(415, "UNSUPPORTED_MEDIA_TYPE", "Send JSON with Content-Type: application/json", request)
                if len(raw) > MAX_BODY:
                    return _error(413, "PAYLOAD_TOO_LARGE", "Request body too large", request)
                if raw.strip():
                    try:
                        body = json.loads(raw)
                    except ValueError:
                        return _error(400, "BAD_JSON", "Request body is not valid JSON", request)
                    if not isinstance(body, dict):
                        return _error(422, "VALIDATION_ERROR", "Request body must be a JSON object", request)
            ctx = Ctx(request.app, request, body if body is not None else {})

            def work():
                if auth:
                    _authenticate(ctx, is_mut)
                return f(ctx)

            result = await run_in_threadpool(work)
            if isinstance(result, Response):
                return result
            status, payload = result
            return JSONResponse(payload, status_code=status)
        handler.__name__ = f.__name__
        return handler
    return deco(fn) if fn else deco


def _error(status: int, code: str, message: str, request: Request, details=None) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message, "details": details or [], "request_id": getattr(request.state, "request_id", None)}}, status_code=status)


# ----------------------------------------------------------------------------- handlers
@endpoint(auth=False)
def health_live(ctx):
    return 200, {"status": "ok", "version": VERSION}


@endpoint(auth=False)
def health_ready(ctx):
    checks, ok = {}, True
    try:
        ctx.app.state.db.one("SELECT 1")
        checks["database"] = "ok"
    except Exception:  # noqa: BLE001
        checks["database"], ok = "unavailable", False
    worker = ctx.app.state.worker
    checks["worker"] = "ok" if (worker and worker._thread and worker._thread.is_alive()) else ("external" if not ctx.app.state.settings.inline_worker else "stopped")
    info = probe()
    checks["sandbox"] = "isolated" if info.isolation == "namespaces" else "unavailable (untrusted execution disabled)"
    checks["provider_mode"] = ctx.app.state.settings.model_provider
    return (200 if ok else 503), {"status": "ready" if ok else "degraded", "checks": checks}


def _client_ip(ctx) -> str:
    return (ctx.request.client.host if ctx.request.client else "unknown")


def _start_session(ctx, user: dict) -> JSONResponse:
    s: Settings = ctx.app.state.settings
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    exp = (now + timedelta(hours=SESSION_HOURS)).isoformat(timespec="milliseconds")
    db: Database = ctx.app.state.db
    # one active session per browser: drop an old cookie's session, and cap sessions per user
    old = ctx.request.cookies.get(COOKIE)
    if old:
        db.run("DELETE FROM sessions WHERE token_hash=?", (_hash_token(s, old),))
    db.run("DELETE FROM sessions WHERE user_id=? AND expires_at < ?", (user["id"], now.isoformat(timespec="milliseconds")))
    db.run("DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC LIMIT -1 OFFSET 9)", (user["id"],))
    db.run("INSERT INTO sessions(token_hash,user_id,csrf_token,created_at,last_seen,expires_at) VALUES (?,?,?,?,?,?)",
           (_hash_token(s, token), user["id"], csrf, utcnow(), utcnow(), exp))
    resp = JSONResponse({"user": {"id": user["id"], "display_name": user["display_name"], "role": user["role"]}, "csrf_token": csrf})
    secure = s.is_production or ctx.request.url.scheme == "https"
    resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure, max_age=SESSION_HOURS * 3600, path="/")
    return resp


@endpoint(auth=False)
def auth_status(ctx):
    s: Settings = ctx.app.state.settings
    return 200, {"auth_mode": s.auth_mode, "setup_required": ctx.svc.setup_required() if s.auth_mode == "password" else False,
                 "registration_open": s.allow_registration, "min_password_length": 10}


@endpoint(auth=False)
def auth_register(ctx):
    s: Settings = ctx.app.state.settings
    if s.auth_mode != "password":
        raise Forbidden("Accounts are managed by the identity provider in this deployment")
    ctx.app.state.login_limiter.check(_client_ip(ctx))
    user = ctx.svc.register(ctx.body.get("display_name", ""), ctx.body.get("password", ""), ctx.request_id)
    resp = _start_session(ctx, user)
    return _with_extra(resp, {"recovery_code": user["recovery_code"]})


@endpoint(auth=False)
def auth_login(ctx):
    s: Settings = ctx.app.state.settings
    if s.auth_mode != "password":
        raise Forbidden("Sign-in is handled by the identity provider in this deployment")
    ctx.app.state.login_limiter.check(_client_ip(ctx))
    user = ctx.svc.authenticate(ctx.body.get("display_name", ""), ctx.body.get("password", ""), ctx.request_id, ctx.body.get("otp"))
    if user.get("mfa_required"):
        return 200, {"mfa_required": True}
    return _start_session(ctx, user)


def _with_extra(resp: JSONResponse, extra: dict) -> JSONResponse:
    data = json.loads(resp.body)
    data.update(extra)
    new = JSONResponse(data)
    for k, v in resp.raw_headers:
        if k.lower() == b"set-cookie":
            new.raw_headers.append((k, v))
    return new


@endpoint(auth=False)
def auth_recover(ctx):
    ctx.app.state.login_limiter.check(_client_ip(ctx))
    out = ctx.svc.recover_password(ctx.body.get("display_name", ""), ctx.body.get("recovery_code", ""), ctx.body.get("new_password", ""), ctx.request_id)
    return 200, {"recovered": True, **out}


@endpoint
def auth_security(ctx):
    return 200, ctx.svc.security_info(ctx.user["id"])


@endpoint
def auth_recovery_code(ctx):
    return 200, {"recovery_code": ctx.svc.regenerate_recovery_code(ctx.user["id"], ctx.body.get("password", ""))}


@endpoint
def auth_totp_begin(ctx):
    return 200, ctx.svc.totp_begin(ctx.user["id"])


@endpoint
def auth_totp_enable(ctx):
    ctx.svc.totp_enable(ctx.user["id"], ctx.body.get("code", ""))
    return 200, {"totp_enabled": True}


@endpoint
def auth_totp_disable(ctx):
    ctx.svc.totp_disable(ctx.user["id"], ctx.body.get("password", ""))
    return 200, {"totp_enabled": False}


@endpoint
def auth_change_password(ctx):
    token = ctx.request.cookies.get(COOKIE)
    keep = _hash_token(ctx.app.state.settings, token) if token else None
    ctx.svc.change_password(ctx.user["id"], ctx.body.get("current_password", ""), ctx.body.get("new_password", ""), keep)
    return 200, {"changed": True, "other_sessions_signed_out": True}


@endpoint(auth=False)
def auth_me(ctx):
    """Session probe: 200 with user=null when signed out (avoids noisy 401s in the browser console)."""
    try:
        _authenticate(ctx, False)
    except Unauthenticated:
        return 200, {"user": None, "auth_mode": ctx.app.state.settings.auth_mode}
    out = {"user": ctx.user, "auth_mode": ctx.app.state.settings.auth_mode}
    if ctx.session:
        out["csrf_token"] = ctx.session["csrf_token"]
    return 200, out


@endpoint
def auth_logout(ctx):
    token = ctx.request.cookies.get(COOKIE)
    if token:
        ctx.app.state.db.run("DELETE FROM sessions WHERE token_hash=?", (_hash_token(ctx.app.state.settings, token),))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/")
    return resp


@endpoint
def projects_create(ctx):
    return 201, ctx.svc.create_project(ctx.user["id"], ctx.body)


@endpoint
def projects_list(ctx):
    try:
        limit = int(ctx.query.get("limit", "20"))
    except ValueError:
        raise ValidationFailed("Request could not be validated.", [{"field": "limit", "issue": "Must be an integer"}]) from None
    return 200, ctx.svc.list_projects(ctx.user["id"], ctx.query.get("cursor"), limit, ctx.query.get("include_archived") == "1")


@endpoint
def projects_get(ctx):
    return 200, ctx.svc.get_project(ctx.user["id"], ctx.params["project_id"])


@endpoint
def projects_patch(ctx):
    return 200, ctx.svc.update_project(ctx.user["id"], ctx.params["project_id"], ctx.body)


@endpoint
def projects_delete(ctx):
    ctx.svc.archive_project(ctx.user["id"], ctx.params["project_id"])
    return 200, {"archived": True}


@endpoint
def projects_version(ctx):
    return 201, ctx.svc.add_version(ctx.user["id"], ctx.params["project_id"], ctx.body)


@endpoint
def runs_create(ctx):
    return 202, ctx.svc.create_run(ctx.user["id"], ctx.params["project_id"], ctx.body)


@endpoint
def runs_get(ctx):
    return 200, ctx.svc.get_run(ctx.user["id"], ctx.params["run_id"])


@endpoint
def runs_plan(ctx):
    return 200, {"plan": ctx.svc.get_plan(ctx.user["id"], ctx.params["run_id"])}


@endpoint
def runs_tasks(ctx):
    return 200, {"items": ctx.svc.list_tasks(ctx.user["id"], ctx.params["run_id"])}


@endpoint
def runs_events(ctx):
    try:
        after = int(ctx.query.get("after", "0"))
    except ValueError:
        after = 0
    return 200, ctx.svc.list_events(ctx.user["id"], ctx.params["run_id"], after)


@endpoint
def plan_approve(ctx):
    return 200, ctx.svc.plan_approve(ctx.user["id"], ctx.params["run_id"], ctx.body.get("comment"))


@endpoint
def plan_reject(ctx):
    return 200, ctx.svc.plan_reject(ctx.user["id"], ctx.params["run_id"], ctx.body.get("comment"))


@endpoint
def plan_change(ctx):
    return 200, ctx.svc.plan_change_request(ctx.user["id"], ctx.params["run_id"], ctx.body.get("comment"))


@endpoint
def runs_cancel(ctx):
    return 202, ctx.svc.cancel(ctx.user["id"], ctx.params["run_id"])


@endpoint
def runs_retry(ctx):
    return 202, ctx.svc.retry(ctx.user["id"], ctx.params["run_id"], ctx.request.headers.get("idempotency-key"))


@endpoint
def runs_diff(ctx):
    return 200, ctx.svc.diff(ctx.user["id"], ctx.params["run_id"])


@endpoint
def runs_file(ctx):
    return 200, ctx.svc.read_file(ctx.user["id"], ctx.params["run_id"], ctx.query.get("path", ""))


@endpoint
def runs_verification(ctx):
    return 200, ctx.svc.verification(ctx.user["id"], ctx.params["run_id"])


@endpoint
def runs_approvals(ctx):
    return 200, {"items": ctx.svc.list_approvals(ctx.user["id"], ctx.params["run_id"])}


@endpoint
def export_approve(ctx):
    return 200, ctx.svc.export_approve(ctx.user["id"], ctx.params["run_id"], ctx.body.get("comment"))


@endpoint
def runs_artifacts(ctx):
    return 200, {"items": ctx.svc.list_artifacts(ctx.user["id"], ctx.params["run_id"])}


@endpoint
def artifact_download(ctx):
    fh, name, mime, size, sha = ctx.svc.open_artifact(ctx.user["id"], ctx.params["artifact_id"])
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)

    def chunks():
        with fh:
            while True:
                b = fh.read(65536)
                if not b:
                    break
                yield b
    return StreamingResponse(chunks(), media_type=mime, headers={"Content-Disposition": f'attachment; filename="{safe}"', "Content-Length": str(size),
                                                                  "X-Artifact-SHA256": sha, "Cache-Control": "private, no-store"})


@endpoint
def providers_list(ctx):
    return 200, {"items": ctx.svc.list_providers(ctx.user["id"])}


@endpoint
def providers_create(ctx):
    return 201, ctx.svc.create_provider(ctx.user["id"], ctx.body)


@endpoint
def providers_patch(ctx):
    return 200, ctx.svc.update_provider(ctx.user["id"], ctx.params["provider_id"], ctx.body)


@endpoint
def providers_delete(ctx):
    ctx.svc.delete_provider(ctx.user["id"], ctx.params["provider_id"])
    return 200, {"deleted": True}


@endpoint
def policies_get(ctx):
    return 200, ctx.svc.get_policies(ctx.user["id"])


@endpoint
def policies_patch(ctx):
    return 200, ctx.svc.patch_policies(ctx.user["id"], ctx.body)


@endpoint
def dashboard(ctx):
    return 200, ctx.svc.dashboard(ctx.user["id"])


@endpoint
def notifications(ctx):
    return 200, {"items": ctx.svc.notifications(ctx.user["id"], ctx.query.get("mark_read") == "1")}


@endpoint
def audit_list(ctx):
    return 200, {"items": ctx.svc.audit_list(ctx.user["id"])}


@endpoint
def about(ctx):
    s = ctx.app.state.settings
    return 200, {"version": VERSION, "app_env": s.app_env, "provider_mode": s.model_provider, "sandbox": probe().as_dict(),
                 "limits": {"max_repair_attempts": s.max_repair_attempts, "max_model_calls": s.max_model_calls, "max_run_seconds": s.max_run_seconds}}


# ----------------------------------------------------------------------------- SSE
async def runs_stream(request: Request):
    app = request.app
    ctx = Ctx(app, request, {})
    run_id = request.path_params["run_id"]
    try:
        await run_in_threadpool(_authenticate, ctx, False)
        await run_in_threadpool(app.state.service.assert_run_access, ctx.user["id"], run_id)
    except AppError as exc:
        return _error(exc.status, exc.code, exc.message, request)
    try:
        last = int(request.headers.get("last-event-id") or request.query_params.get("after") or 0)
    except ValueError:
        last = 0
    poll = app.state.sse_poll

    async def gen():
        nonlocal last
        idle = 0.0
        yield "retry: 2000\n\n"
        while True:
            if await request.is_disconnected():
                return
            events = await run_in_threadpool(app.state.service.events_after, run_id, last, 200)
            for ev in events:
                last = ev["id"]
                yield f"id: {ev['id']}\nevent: {ev['event_type']}\ndata: {json.dumps(ev)}\n\n"
            if events:
                idle = 0.0
                continue
            row = await run_in_threadpool(app.state.db.one, "SELECT status FROM runs WHERE id=?", (run_id,))
            if row and RunStatus(row["status"]) in TERMINAL:
                yield f"event: stream_end\ndata: {json.dumps({'status': row['status']})}\n\n"
                return
            idle += poll
            if idle >= 15:
                idle = 0.0
                yield ": heartbeat\n\n"
            await asyncio.sleep(poll)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# ----------------------------------------------------------------------------- middleware
class RequestContextMiddleware:
    """Request id, security headers, and structured access log (no bodies, no secrets)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        rid = headers.get(b"x-request-id", b"").decode()
        rid = rid if _REQ_ID.match(rid) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = rid
        allowed = scope["app"].state.settings.allowed_hosts
        host = headers.get(b"host", b"").decode().lower()
        hostname = host[:host.rindex("]") + 1] if host.startswith("[") and "]" in host else host.rsplit(":", 1)[0]
        if hostname not in allowed:
            body = json.dumps({"error": {"code": "HOST_NOT_ALLOWED", "message": "This host name is not allowed. Open the app via its configured address.", "details": [], "request_id": rid}}).encode()
            await send({"type": "http.response.start", "status": 400, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"x-request-id", rid.encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        https = scope.get("scheme") == "https" or headers.get(b"x-forwarded-proto", b"") == b"https"
        start = time.monotonic()
        path = scope["path"]

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                hdrs = message.setdefault("headers", [])
                hdrs.append((b"x-request-id", rid.encode()))
                for k, v in SECURITY_HEADERS.items():
                    hdrs.append((k.lower().encode(), v.encode()))
                if path.startswith("/api/"):
                    hdrs.append((b"cache-control", b"no-store"))
                else:  # always revalidate the UI files so an old cached app.js can never talk to a newer server
                    hdrs.append((b"cache-control", b"no-cache"))
                if https:
                    hdrs.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                log.info("request", extra={"request_id": rid, "method": scope["method"], "path": path, "status": message["status"],
                                           "duration_ms": int((time.monotonic() - start) * 1000)})
            await send(message)
        await self.app(scope, receive, send_wrapper)


async def _app_error(request: Request, exc: AppError):
    return _error(exc.status, exc.code, exc.message, request, exc.details)


async def _illegal(request: Request, exc: IllegalTransition):
    return _error(409, "INVALID_STATE", f"Run cannot move from {exc.current} to {exc.target}", request)


async def _unhandled(request: Request, exc: Exception):
    log.exception("unhandled error", extra={"request_id": getattr(request.state, "request_id", None)})
    return _error(500, "INTERNAL_ERROR", "Unexpected error. Quote the request id when reporting it.", request)


async def _not_found(request: Request, exc):
    return _error(404, "NOT_FOUND", "Resource not found", request)


async def _method_not_allowed(request: Request, exc):
    return _error(405, "METHOD_NOT_ALLOWED", "Method not allowed", request)


# ----------------------------------------------------------------------------- factory
def create_app(settings: Settings | None = None, *, start_worker: bool | None = None, sleep=time.sleep, sse_poll: float = 0.4) -> Starlette:
    settings = settings or load_settings()
    db = Database(settings.database_path)
    store = LocalArtifactStore(settings.artifact_root)
    service = AppService(db, settings, store)
    engine = Engine(db, settings, store, sleep=sleep)
    worker = Worker(engine, settings.worker_poll_seconds, settings.lease_seconds)
    run_worker = settings.inline_worker if start_worker is None else start_worker

    @contextlib.asynccontextmanager
    async def lifespan(app):
        if run_worker:
            worker.start()
        try:
            yield
        finally:
            worker.stop()

    P = "/api/v1"
    routes = [
        Route(f"{P}/health/live", health_live), Route(f"{P}/health/ready", health_ready),
        Route(f"{P}/auth/status", auth_status), Route(f"{P}/auth/register", auth_register, methods=["POST"]),
        Route(f"{P}/auth/login", auth_login, methods=["POST"]), Route(f"{P}/auth/password", auth_change_password, methods=["POST"]),
        Route(f"{P}/auth/recover", auth_recover, methods=["POST"]), Route(f"{P}/auth/security", auth_security),
        Route(f"{P}/auth/recovery-code", auth_recovery_code, methods=["POST"]), Route(f"{P}/auth/totp/begin", auth_totp_begin, methods=["POST"]),
        Route(f"{P}/auth/totp/enable", auth_totp_enable, methods=["POST"]), Route(f"{P}/auth/totp/disable", auth_totp_disable, methods=["POST"]),
        Route(f"{P}/auth/me", auth_me),
        Route(f"{P}/auth/logout", auth_logout, methods=["POST"]),
        Route(f"{P}/projects", projects_create, methods=["POST"]), Route(f"{P}/projects", projects_list, methods=["GET"]),
        Route(f"{P}/projects/{{project_id}}", projects_get, methods=["GET"]),
        Route(f"{P}/projects/{{project_id}}", projects_patch, methods=["PATCH"]),
        Route(f"{P}/projects/{{project_id}}", projects_delete, methods=["DELETE"]),
        Route(f"{P}/projects/{{project_id}}/versions", projects_version, methods=["POST"]),
        Route(f"{P}/projects/{{project_id}}/runs", runs_create, methods=["POST"]),
        Route(f"{P}/runs/{{run_id}}", runs_get), Route(f"{P}/runs/{{run_id}}/plan", runs_plan),
        Route(f"{P}/runs/{{run_id}}/tasks", runs_tasks), Route(f"{P}/runs/{{run_id}}/events", runs_events),
        Route(f"{P}/runs/{{run_id}}/events/stream", runs_stream),
        Route(f"{P}/runs/{{run_id}}/plan/approve", plan_approve, methods=["POST"]),
        Route(f"{P}/runs/{{run_id}}/plan/reject", plan_reject, methods=["POST"]),
        Route(f"{P}/runs/{{run_id}}/plan/change-request", plan_change, methods=["POST"]),
        Route(f"{P}/runs/{{run_id}}/cancel", runs_cancel, methods=["POST"]),
        Route(f"{P}/runs/{{run_id}}/retry", runs_retry, methods=["POST"]),
        Route(f"{P}/runs/{{run_id}}/diff", runs_diff), Route(f"{P}/runs/{{run_id}}/file", runs_file),
        Route(f"{P}/runs/{{run_id}}/verification", runs_verification),
        Route(f"{P}/runs/{{run_id}}/approvals", runs_approvals),
        Route(f"{P}/runs/{{run_id}}/export/approve", export_approve, methods=["POST"]),
        Route(f"{P}/runs/{{run_id}}/artifacts", runs_artifacts),
        Route(f"{P}/artifacts/{{artifact_id}}/download", artifact_download),
        Route(f"{P}/settings/providers", providers_list, methods=["GET"]),
        Route(f"{P}/settings/providers", providers_create, methods=["POST"]),
        Route(f"{P}/settings/providers/{{provider_id}}", providers_patch, methods=["PATCH"]),
        Route(f"{P}/settings/providers/{{provider_id}}", providers_delete, methods=["DELETE"]),
        Route(f"{P}/settings/policies", policies_get, methods=["GET"]),
        Route(f"{P}/settings/policies", policies_patch, methods=["PATCH"]),
        Route(f"{P}/dashboard", dashboard), Route(f"{P}/notifications", notifications),
        Route(f"{P}/audit", audit_list), Route(f"{P}/about", about),
        Mount("/", app=StaticFiles(directory=str(STATIC_DIR), html=True), name="static"),
    ]
    app = Starlette(routes=routes, middleware=[Middleware(RequestContextMiddleware)], lifespan=lifespan,
                    exception_handlers={AppError: _app_error, IllegalTransition: _illegal, 404: _not_found, 405: _method_not_allowed, Exception: _unhandled})
    app.state.settings, app.state.db, app.state.service, app.state.engine = settings, db, service, engine
    app.state.worker, app.state.sse_poll = worker, sse_poll
    app.state.login_limiter = RateLimiter(settings.login_per_minute_per_ip)
    return app


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = load_settings()
    if settings.host not in ("127.0.0.1", "localhost", "::1"):
        if not settings.allow_remote_bind:
            raise SystemExit(f"Refusing to listen on {settings.host}: this app binds to localhost by default. "
                             "Set ALLOW_REMOTE_BIND=1 (and ALLOWED_HOSTS) only behind a TLS-terminating reverse proxy.")
        logging.getLogger("autoforge").warning("Listening on %s. Keep it behind TLS; allowed hosts: %s", settings.host, ",".join(settings.allowed_hosts))
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
