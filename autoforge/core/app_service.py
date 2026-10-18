"""Application service: authorization, validation and use-cases behind the HTTP API."""
from __future__ import annotations

import hmac
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from autoforge.agents.analysis import slugify
from autoforge.core.config import Settings
from autoforge.core.db import Database, dumps, loads, new_id, utcnow
from autoforge.core.errors import Conflict, Forbidden, NotFound, RateLimited, Unauthenticated, ValidationFailed
from autoforge.core.services import (
    audit, cancel_requested, emit_event, load_run, new_job, transition_run,
)
from autoforge.domain.states import IllegalTransition, RunStatus
from autoforge.providers.factory import PROVIDER_TYPES
from autoforge.sandbox.runner import probe
from autoforge.security.passwords import hash_password, policy_problems, verify_password
from autoforge.security import totp
from autoforge.security.paths import PathViolation, validate_relative_path
from autoforge.security.redaction import redact
from autoforge.storage.local import LocalArtifactStore
from autoforge.workspace.manager import Workspace, WorkspaceError

TEMPLATES = ("python-service",)
BRIEF_MAX = 20_000

DEFAULT_POLICY = {
    "execution_mode": "sandbox",
    "max_repair_attempts": 2,
    "max_model_calls": 120,
    "max_wall_time_seconds": 3600,
    "max_estimated_cost_usd": 5,
    "retention_days": 30,
    "allowed_provider_types": list(PROVIDER_TYPES),
}
_SECRET_REF = re.compile(r"^env:[A-Z_][A-Z0-9_]{0,63}$")


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.per_minute:
                raise RateLimited("Too many run creation requests; try again shortly.")
            q.append(now)


def _need_text(data: dict, key: str, max_len: int, required: bool = True) -> str | None:
    v = data.get(key)
    if v is None or v == "":
        if required:
            raise ValidationFailed("Request could not be validated.", [{"field": key, "issue": "Field is required"}])
        return None
    if not isinstance(v, str):
        raise ValidationFailed("Request could not be validated.", [{"field": key, "issue": "Must be a string"}])
    if len(v) > max_len:
        raise ValidationFailed("Request could not be validated.", [{"field": key, "issue": f"Must be at most {max_len} characters"}])
    return v.strip()


class AppService:
    def __init__(self, db: Database, settings: Settings, store: LocalArtifactStore):
        self.db, self.settings, self.store = db, settings, store
        self.limiter = RateLimiter(settings.run_creation_per_minute)

    # ------------------------------------------------------------------ users / sessions
    def ensure_user(self, display_name: str) -> dict:
        name = (display_name or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9 _.\-]{2,40}", name):
            raise ValidationFailed("Request could not be validated.", [{"field": "display_name", "issue": "2-60 characters: letters, digits, spaces and . _ - @ +"}])
        row = self.db.one("SELECT * FROM users WHERE display_name=?", (name,))
        if row:
            return dict(row)
        uid = new_id()
        self.db.run("INSERT INTO users(id,display_name,role,created_at,updated_at) VALUES (?,?,?,?,?)", (uid, name, "builder", utcnow(), utcnow()))
        return dict(self.db.one("SELECT * FROM users WHERE id=?", (uid,)))

    # ------------------------------------------------------------------ accounts & sessions
    _NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.@+\-]{1,59}")
    GENERIC_LOGIN_ERROR = "Sign-in failed. Check your user name and password. After several failed attempts the account is locked for a while."

    def setup_required(self) -> bool:
        return self.db.one("SELECT 1 FROM users WHERE password_hash IS NOT NULL LIMIT 1") is None

    def register(self, display_name: str, password: str, correlation_id: str | None = None) -> dict:
        name = (display_name or "").strip()
        if not self._NAME_RE.fullmatch(name):
            raise ValidationFailed("Request could not be validated.", [{"field": "display_name", "issue": "2-60 characters: letters, digits, spaces and . _ - @ +"}])
        setup = self.setup_required()
        if not setup and not self.settings.allow_registration:
            audit(self.db, "auth.register", "user", None, "denied", correlation_id=correlation_id, details={"reason": "registration closed"})
            raise Forbidden("Registration is closed. Ask an administrator to create your account.")
        problems = policy_problems(password, name)
        if problems:
            raise ValidationFailed("Request could not be validated.", [{"field": "password", "issue": p} for p in problems])
        existing = self.db.one("SELECT * FROM users WHERE lower(display_name)=lower(?)", (name,))
        if existing and existing["password_hash"]:
            raise ValidationFailed("Request could not be validated.", [{"field": "display_name", "issue": "This user name is not available."}])
        pw, now = hash_password(password), utcnow()
        recovery = totp.new_recovery_code()
        if existing:  # first-run setup may claim a pre-password account so earlier projects are kept
            uid = existing["id"]
            self.db.run("UPDATE users SET password_hash=?, role='admin', password_changed_at=?, updated_at=?, recovery_hash=? WHERE id=?", (pw, now, now, totp.recovery_hash(recovery), uid))
        else:
            uid = new_id()
            self.db.run("INSERT INTO users(id,display_name,role,password_hash,password_changed_at,recovery_hash,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                        (uid, name, "admin" if setup else "builder", pw, now, totp.recovery_hash(recovery), now, now))
        audit(self.db, "auth.register", "user", uid, "allowed", actor_id=uid, correlation_id=correlation_id, details={"first_run_setup": setup})
        out = dict(self.db.one("SELECT * FROM users WHERE id=?", (uid,)))
        out["recovery_code"] = recovery  # shown to the person exactly once; only its hash is stored
        return out

    def authenticate(self, display_name: str, password: str, correlation_id: str | None = None, otp: str | None = None) -> dict:
        """Verify credentials with per-account lockout. The error never reveals whether the user exists."""
        name = (display_name or "").strip()
        row = self.db.one("SELECT * FROM users WHERE lower(display_name)=lower(?)", (name,)) if isinstance(display_name, str) else None
        now = datetime.now(timezone.utc)
        locked = bool(row and row["locked_until"] and row["locked_until"] > now.isoformat(timespec="milliseconds"))
        ok = verify_password(password if isinstance(password, str) else "", row["password_hash"] if row else None)  # always hash: equal timing
        if ok and row and row["totp_enabled"] and not locked and row["is_active"]:
            if not otp:
                return {"mfa_required": True}  # password was right; ask for the authenticator code (counted only if the code is wrong)
            step = totp.verify(row["totp_secret"] or "", otp, row["totp_last_step"])
            if step is None:
                ok = False
            else:
                self.db.run("UPDATE users SET totp_last_step=? WHERE id=?", (step, row["id"]))
        if row is None or not ok or locked or not row["is_active"]:
            if row is not None and not locked:
                failed = row["failed_logins"] + 1
                if failed >= self.settings.max_failed_logins:
                    until = (now + timedelta(minutes=self.settings.lockout_minutes)).isoformat(timespec="milliseconds")
                    self.db.run("UPDATE users SET failed_logins=0, locked_until=? WHERE id=?", (until, row["id"]))
                    audit(self.db, "auth.lockout", "user", row["id"], "denied", actor_id=row["id"], correlation_id=correlation_id, details={"minutes": self.settings.lockout_minutes})
                else:
                    self.db.run("UPDATE users SET failed_logins=? WHERE id=?", (failed, row["id"]))
            audit(self.db, "auth.login", "user", row["id"] if row else None, "denied", actor_id=row["id"] if row else None,
                  correlation_id=correlation_id, details={"locked": locked, "known_user": row is not None})
            raise Unauthenticated(self.GENERIC_LOGIN_ERROR)
        self.db.run("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?", (row["id"],))
        audit(self.db, "auth.login", "user", row["id"], "allowed", actor_id=row["id"], correlation_id=correlation_id)
        return dict(row)

    def recover_password(self, display_name: str, recovery_code: str, new_password: str, correlation_id: str | None = None) -> dict:
        """Reset a forgotten password with the one-time recovery code shown at sign-up. Rotates the code and signs out all sessions."""
        name = (display_name or "").strip() if isinstance(display_name, str) else ""
        row = self.db.one("SELECT * FROM users WHERE lower(display_name)=lower(?)", (name,)) if name else None
        now = datetime.now(timezone.utc)
        locked = bool(row and row["locked_until"] and row["locked_until"] > now.isoformat(timespec="milliseconds"))
        stored = (row["recovery_hash"] if row else None) or "0" * 64
        good = hmac.compare_digest(totp.recovery_hash(recovery_code if isinstance(recovery_code, str) else ""), stored) and bool(row and row["recovery_hash"])
        if not good or locked:
            if row is not None and not locked:
                failed = row["failed_logins"] + 1
                if failed >= self.settings.max_failed_logins:
                    until = (now + timedelta(minutes=self.settings.lockout_minutes)).isoformat(timespec="milliseconds")
                    self.db.run("UPDATE users SET failed_logins=0, locked_until=? WHERE id=?", (until, row["id"]))
                else:
                    self.db.run("UPDATE users SET failed_logins=? WHERE id=?", (failed, row["id"]))
            audit(self.db, "auth.recover", "user", row["id"] if row else None, "denied", correlation_id=correlation_id)
            raise Unauthenticated("Recovery failed. Check the user name and recovery code.")
        problems = policy_problems(new_password, row["display_name"])
        if problems:
            raise ValidationFailed("Request could not be validated.", [{"field": "new_password", "issue": p} for p in problems])
        fresh, ts = totp.new_recovery_code(), utcnow()
        self.db.run("UPDATE users SET password_hash=?, password_changed_at=?, recovery_hash=?, failed_logins=0, locked_until=NULL, updated_at=? WHERE id=?",
                    (hash_password(new_password), ts, totp.recovery_hash(fresh), ts, row["id"]))
        self.db.run("DELETE FROM sessions WHERE user_id=?", (row["id"],))
        audit(self.db, "auth.recover", "user", row["id"], "allowed", actor_id=row["id"], correlation_id=correlation_id)
        return {"recovery_code": fresh}

    def regenerate_recovery_code(self, user_id: str, password: str) -> str:
        row = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        if row is None or not verify_password(password if isinstance(password, str) else "", row["password_hash"]):
            raise ValidationFailed("Request could not be validated.", [{"field": "password", "issue": "Password is incorrect."}])
        code = totp.new_recovery_code()
        self.db.run("UPDATE users SET recovery_hash=?, updated_at=? WHERE id=?", (totp.recovery_hash(code), utcnow(), user_id))
        audit(self.db, "auth.recovery_code_regenerated", "user", user_id, "allowed", actor_id=user_id)
        return code

    def security_info(self, user_id: str) -> dict:
        row = self.db.one("SELECT role, totp_enabled, recovery_hash FROM users WHERE id=?", (user_id,))
        return {"role": row["role"], "totp_enabled": bool(row["totp_enabled"]), "has_recovery_code": bool(row["recovery_hash"])}

    def totp_begin(self, user_id: str) -> dict:
        row = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        if row["totp_enabled"]:
            raise Conflict("Two-factor authentication is already on.")
        secret = totp.new_secret()
        self.db.run("UPDATE users SET totp_secret=?, totp_last_step=0 WHERE id=?", (secret, user_id))
        return {"secret": secret, "otpauth_uri": totp.otpauth_uri(secret, row["display_name"])}

    def totp_enable(self, user_id: str, code: str) -> None:
        row = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        step = totp.verify(row["totp_secret"] or "", code) if row["totp_secret"] else None
        if step is None:
            raise ValidationFailed("Request could not be validated.", [{"field": "code", "issue": "That code is not valid. Check your authenticator app's clock and try the next code."}])
        self.db.run("UPDATE users SET totp_enabled=1, totp_last_step=? WHERE id=?", (step, user_id))
        audit(self.db, "auth.totp_enabled", "user", user_id, "allowed", actor_id=user_id)

    def totp_disable(self, user_id: str, password: str) -> None:
        row = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        if not verify_password(password if isinstance(password, str) else "", row["password_hash"]):
            raise ValidationFailed("Request could not be validated.", [{"field": "password", "issue": "Password is incorrect."}])
        self.db.run("UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?", (user_id,))
        audit(self.db, "auth.totp_disabled", "user", user_id, "allowed", actor_id=user_id)

    def change_password(self, user_id: str, current: str, new: str, keep_token_hash: str | None) -> None:
        row = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        if row is None or not verify_password(current if isinstance(current, str) else "", row["password_hash"]):
            audit(self.db, "auth.change_password", "user", user_id, "denied", actor_id=user_id)
            raise ValidationFailed("Request could not be validated.", [{"field": "current_password", "issue": "Current password is incorrect."}])
        problems = policy_problems(new, row["display_name"])
        if verify_password(new if isinstance(new, str) else "", row["password_hash"]):
            problems.append("Choose a password you have not used on this account.")
        if problems:
            raise ValidationFailed("Request could not be validated.", [{"field": "new_password", "issue": p} for p in problems])
        now = utcnow()
        self.db.run("UPDATE users SET password_hash=?, password_changed_at=?, updated_at=? WHERE id=?", (hash_password(new), now, now, user_id))
        # sign out every other session so a stolen cookie does not survive a password change
        self.db.run("DELETE FROM sessions WHERE user_id=? AND token_hash != ?", (user_id, keep_token_hash or ""))
        audit(self.db, "auth.change_password", "user", user_id, "allowed", actor_id=user_id)

    # ------------------------------------------------------------------ projects
    def _project(self, user_id: str, project_id: str) -> dict:
        row = self.db.one("SELECT * FROM projects WHERE id=?", (project_id,))
        if row is None or row["owner_id"] != user_id:
            if row is not None:
                audit(self.db, "access.denied", "project", project_id, "denied", actor_id=user_id)
            raise NotFound("Project not found")
        return dict(row)

    @staticmethod
    def _project_out(r: dict) -> dict:
        d = {k: r[k] for k in ("id", "name", "slug", "description", "brief", "selected_template", "status", "created_at", "updated_at", "archived_at")}
        d["preferred_stack"] = loads(r["preferred_stack"], {})
        return d

    def create_project(self, user_id: str, data: dict) -> dict:
        name = _need_text(data, "name", 120)
        brief = _need_text(data, "brief", BRIEF_MAX)
        if len(brief) < 10:
            raise ValidationFailed("Request could not be validated.", [{"field": "brief", "issue": "Brief must be at least 10 characters"}])
        template = data.get("selected_template") or "python-service"
        if template not in TEMPLATES:
            raise ValidationFailed("Request could not be validated.", [{"field": "selected_template", "issue": f"Supported templates: {', '.join(TEMPLATES)}"}])
        stack = data.get("preferred_stack") or {}
        if not isinstance(stack, dict):
            raise ValidationFailed("Request could not be validated.", [{"field": "preferred_stack", "issue": "Must be an object"}])
        pid, now = new_id(), utcnow()
        with self.db.tx() as c:
            c.execute("INSERT INTO projects(id,owner_id,name,slug,description,brief,selected_template,preferred_stack,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (pid, user_id, name, slugify(name), _need_text(data, "description", 2000, False) or "", brief, template, dumps(stack), now, now))
            c.execute("INSERT INTO project_versions(id,project_id,version_number,brief_snapshot,created_by,created_at) VALUES (?,?,?,?,?,?)",
                      (new_id(), pid, 1, dumps({"brief": brief, "details": data.get("details") or {}}), user_id, now))
        audit(self.db, "project.create", "project", pid, "allowed", actor_id=user_id)
        return self._project_out(self._project(user_id, pid))

    def list_projects(self, user_id: str, cursor: str | None, limit: int, include_archived: bool = False) -> dict:
        limit = max(1, min(limit, 100))
        sql, params = "SELECT * FROM projects WHERE owner_id=?", [user_id]
        if not include_archived:
            sql += " AND archived_at IS NULL"
        if cursor:
            try:
                created, cid = cursor.split("|", 1)
            except ValueError:
                raise ValidationFailed("Request could not be validated.", [{"field": "cursor", "issue": "Invalid cursor"}]) from None
            sql += " AND (created_at < ? OR (created_at = ? AND id < ?))"
            params += [created, created, cid]
        rows = self.db.all(sql + " ORDER BY created_at DESC, id DESC LIMIT ?", params + [limit + 1])
        more = len(rows) > limit
        rows = rows[:limit]
        nxt = f"{rows[-1]['created_at']}|{rows[-1]['id']}" if more and rows else None
        return {"items": [self._project_out(dict(r)) for r in rows], "next_cursor": nxt}

    def get_project(self, user_id: str, project_id: str) -> dict:
        out = self._project_out(self._project(user_id, project_id))
        out["versions"] = [{"version_number": v["version_number"], "created_at": v["created_at"]} for v in
                           self.db.all("SELECT version_number, created_at FROM project_versions WHERE project_id=? ORDER BY version_number", (project_id,))]
        out["runs"] = [self._run_brief(dict(r)) for r in self.db.all("SELECT * FROM runs WHERE project_id=? ORDER BY created_at DESC LIMIT 50", (project_id,))]
        return out

    def update_project(self, user_id: str, project_id: str, data: dict) -> dict:
        p = self._project(user_id, project_id)
        sets, vals = [], []
        if "name" in data:
            sets += ["name=?", "slug=?"]
            n = _need_text(data, "name", 120)
            vals += [n, slugify(n)]
        if "description" in data:
            sets.append("description=?")
            vals.append(_need_text(data, "description", 2000, False) or "")
        if "brief" in data:
            b = _need_text(data, "brief", BRIEF_MAX)
            if len(b) < 10:
                raise ValidationFailed("Request could not be validated.", [{"field": "brief", "issue": "Brief must be at least 10 characters"}])
            sets.append("brief=?")
            vals.append(b)
        if "preferred_stack" in data:
            if not isinstance(data["preferred_stack"], dict):
                raise ValidationFailed("Request could not be validated.", [{"field": "preferred_stack", "issue": "Must be an object"}])
            sets.append("preferred_stack=?")
            vals.append(dumps(data["preferred_stack"]))
        if not sets:
            raise ValidationFailed("Request could not be validated.", [{"field": "*", "issue": "No updatable fields supplied"}])
        sets.append("updated_at=?")
        vals += [utcnow(), project_id]
        self.db.run(f"UPDATE projects SET {', '.join(sets)} WHERE id=?", vals)
        audit(self.db, "project.update", "project", project_id, "allowed", actor_id=user_id)
        return self._project_out(self._project(user_id, project_id))

    def archive_project(self, user_id: str, project_id: str) -> None:
        self._project(user_id, project_id)
        self.db.run("UPDATE projects SET archived_at=?, status='archived', updated_at=? WHERE id=?", (utcnow(), utcnow(), project_id))
        audit(self.db, "project.archive", "project", project_id, "allowed", actor_id=user_id)

    def add_version(self, user_id: str, project_id: str, data: dict) -> dict:
        p = self._project(user_id, project_id)
        brief = _need_text(data, "brief", BRIEF_MAX) if "brief" in data else p["brief"]
        with self.db.tx() as c:
            n = c.execute("SELECT COALESCE(MAX(version_number),0)+1 FROM project_versions WHERE project_id=?", (project_id,)).fetchone()[0]
            vid = new_id()
            c.execute("INSERT INTO project_versions(id,project_id,version_number,brief_snapshot,created_by,created_at) VALUES (?,?,?,?,?,?)",
                      (vid, project_id, n, dumps({"brief": brief, "details": data.get("details") or {}}), user_id, utcnow()))
        return {"id": vid, "version_number": n}

    # ------------------------------------------------------------------ settings
    def get_policies(self, user_id: str) -> dict:
        row = self.db.one("SELECT data FROM policies WHERE owner_id=?", (user_id,))
        return {**DEFAULT_POLICY, **loads(row["data"], {})} if row else dict(DEFAULT_POLICY)

    def patch_policies(self, user_id: str, data: dict) -> dict:
        cur = self.get_policies(user_id)
        errors = []
        for key, val in data.items():
            if key not in DEFAULT_POLICY:
                errors.append({"field": key, "issue": "Unknown policy"})
            elif key == "execution_mode" and val != "sandbox":
                errors.append({"field": key, "issue": "Only 'sandbox' execution is supported"})
            elif key == "allowed_provider_types":
                if not isinstance(val, list) or not val or any(v not in PROVIDER_TYPES for v in val):
                    errors.append({"field": key, "issue": f"Must be a non-empty list of {list(PROVIDER_TYPES)}"})
            elif key != "execution_mode" and (isinstance(val, bool) or not isinstance(val, (int, float)) or val < 0):
                errors.append({"field": key, "issue": "Must be a non-negative number"})
        if errors:
            raise ValidationFailed("Request could not be validated.", errors)
        cur.update(data)
        self.db.run("INSERT INTO policies(owner_id,data,updated_at) VALUES (?,?,?) ON CONFLICT(owner_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
                    (user_id, dumps(cur), utcnow()))
        audit(self.db, "policy.update", "policy", user_id, "allowed", actor_id=user_id, details=data)
        return cur

    def _provider_out(self, r) -> dict:
        d = {k: r[k] for k in ("id", "provider_type", "display_name", "base_url", "model_name", "secret_reference", "is_enabled", "created_at", "updated_at")}
        d["settings"] = loads(r["settings"], {})
        d["is_enabled"] = bool(d["is_enabled"])
        return d

    def _validate_provider(self, data: dict, partial: bool) -> dict:
        out: dict[str, Any] = {}
        errs = []
        if not partial or "provider_type" in data:
            if data.get("provider_type") not in PROVIDER_TYPES:
                errs.append({"field": "provider_type", "issue": f"Must be one of {list(PROVIDER_TYPES)}"})
            out["provider_type"] = data.get("provider_type")
        if not partial or "model_name" in data:
            if not isinstance(data.get("model_name"), str) or not 1 <= len(data["model_name"]) <= 120:
                errs.append({"field": "model_name", "issue": "Required (1-120 chars)"})
            out["model_name"] = data.get("model_name")
        if not partial or "display_name" in data:
            if not isinstance(data.get("display_name"), str) or not 1 <= len(data["display_name"]) <= 80:
                errs.append({"field": "display_name", "issue": "Required (1-80 chars)"})
            out["display_name"] = data.get("display_name")
        if "base_url" in data and data["base_url"] is not None:
            if not isinstance(data["base_url"], str) or not data["base_url"].startswith(("http://", "https://")) or len(data["base_url"]) > 300:
                errs.append({"field": "base_url", "issue": "Must be an http(s) URL"})
            out["base_url"] = data["base_url"]
        if "secret_reference" in data and data["secret_reference"] not in (None, ""):
            if not isinstance(data["secret_reference"], str) or not _SECRET_REF.match(data["secret_reference"]):
                errs.append({"field": "secret_reference", "issue": "Use an environment reference such as env:MY_API_KEY; raw secrets are never accepted"})
            out["secret_reference"] = data["secret_reference"]
        if "settings" in data:
            if not isinstance(data["settings"], dict):
                errs.append({"field": "settings", "issue": "Must be an object"})
            out["settings"] = data["settings"]
        if "is_enabled" in data:
            out["is_enabled"] = 1 if data["is_enabled"] else 0
        if not partial and out.get("provider_type") == "openai_compatible" and not out.get("base_url"):
            errs.append({"field": "base_url", "issue": "Required for openai_compatible"})
        if errs:
            raise ValidationFailed("Request could not be validated.", errs)
        return out

    def list_providers(self, user_id: str) -> list[dict]:
        rows = [self._provider_out(r) for r in self.db.all("SELECT * FROM provider_configs WHERE owner_id=? ORDER BY created_at", (user_id,))]
        return [{"id": "mock", "provider_type": "mock", "display_name": "Deterministic mock (built-in)", "base_url": None,
                 "model_name": "mock-deterministic", "secret_reference": None, "is_enabled": True, "settings": {}, "builtin": True}] + rows

    def create_provider(self, user_id: str, data: dict) -> dict:
        v = self._validate_provider(data, partial=False)
        pid = new_id()
        self.db.run("INSERT INTO provider_configs(id,owner_id,provider_type,display_name,base_url,model_name,secret_reference,settings,is_enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (pid, user_id, v["provider_type"], v["display_name"], v.get("base_url"), v["model_name"], v.get("secret_reference"),
                     dumps(v.get("settings", {})), v.get("is_enabled", 1), utcnow(), utcnow()))
        audit(self.db, "provider.create", "provider", pid, "allowed", actor_id=user_id, details={"provider_type": v["provider_type"], "model": v["model_name"]})
        return self._provider_out(self._provider_row(user_id, pid))

    def _provider_row(self, user_id: str, pid: str):
        r = self.db.one("SELECT * FROM provider_configs WHERE id=?", (pid,))
        if r is None or r["owner_id"] != user_id:
            raise NotFound("Provider not found")
        return r

    def update_provider(self, user_id: str, pid: str, data: dict) -> dict:
        self._provider_row(user_id, pid)
        v = self._validate_provider(data, partial=True)
        if not v:
            raise ValidationFailed("Request could not be validated.", [{"field": "*", "issue": "No updatable fields supplied"}])
        if "settings" in v:
            v["settings"] = dumps(v["settings"])
        sets = ", ".join(f"{k}=?" for k in v) + ", updated_at=?"
        self.db.run(f"UPDATE provider_configs SET {sets} WHERE id=?", list(v.values()) + [utcnow(), pid])
        audit(self.db, "provider.update", "provider", pid, "allowed", actor_id=user_id)
        return self._provider_out(self._provider_row(user_id, pid))

    def delete_provider(self, user_id: str, pid: str) -> None:
        self._provider_row(user_id, pid)
        self.db.run("DELETE FROM provider_configs WHERE id=?", (pid,))
        audit(self.db, "provider.delete", "provider", pid, "allowed", actor_id=user_id)

    # ------------------------------------------------------------------ runs
    def _run(self, user_id: str, run_id: str) -> dict:
        row = self.db.one("SELECT r.*, p.owner_id AS owner_id, p.slug AS project_slug, p.name AS project_name FROM runs r JOIN projects p ON p.id=r.project_id WHERE r.id=?", (run_id,))
        if row is None or row["owner_id"] != user_id:
            if row is not None:
                audit(self.db, "access.denied", "run", run_id, "denied", actor_id=user_id, run_id=run_id)
            raise NotFound("Run not found")
        d = dict(row)
        for k in ("config_snapshot", "budget", "usage", "plan"):
            d[k] = loads(d.get(k), {} if k != "plan" else None)
        return d

    @staticmethod
    def _run_brief(r: dict) -> dict:
        return {k: r[k] for k in ("id", "project_id", "status", "current_stage", "created_at", "updated_at", "started_at", "finished_at", "error_code", "error_summary")}

    def _run_out(self, r: dict) -> dict:
        out = self._run_brief(r)
        out.update({"project_name": r.get("project_name"), "provider_key": r["provider_key"], "model_name": r["model_name"],
                    "budget": r["budget"], "usage": r["usage"], "plan_version": r["plan_version"], "repair_attempts": r["repair_attempts"],
                    "cancel_requested": bool(r["cancel_requested_at"]), "project_version_id": r["project_version_id"],
                    "links": {"self": f"/api/v1/runs/{r['id']}", "events": f"/api/v1/runs/{r['id']}/events",
                              "stream": f"/api/v1/runs/{r['id']}/events/stream"}})
        return out

    def create_run(self, user_id: str, project_id: str, data: dict) -> dict:
        project = self._project(user_id, project_id)
        if project["archived_at"]:
            raise Conflict("Archived projects cannot start runs")
        self.limiter.check(user_id)
        policy = self.get_policies(user_id)
        # provider
        pcid = data.get("provider_config_id")
        if pcid in (None, "", "mock"):
            cfg = {"provider_type": "mock", "model_name": self.settings.model_name if self.settings.model_provider == "mock" else "mock-deterministic",
                   "base_url": None, "secret_reference": None, "settings": {}}
            if self.settings.model_provider != "mock":
                cfg = {"provider_type": self.settings.model_provider, "model_name": self.settings.model_name, "base_url": None, "secret_reference": None, "settings": {}}
        else:
            r = self._provider_row(user_id, pcid)
            if not r["is_enabled"]:
                raise Conflict("Provider is disabled")
            cfg = {"provider_type": r["provider_type"], "model_name": r["model_name"], "base_url": r["base_url"],
                   "secret_reference": r["secret_reference"], "settings": loads(r["settings"], {})}
        if cfg["provider_type"] not in policy["allowed_provider_types"]:
            audit(self.db, "provider.blocked", "run", None, "denied", actor_id=user_id, details={"provider_type": cfg["provider_type"]})
            raise Forbidden("Provider type is not allowed by policy")
        # budget: request may only tighten the policy
        req_budget = data.get("budget") or {}
        if not isinstance(req_budget, dict):
            raise ValidationFailed("Request could not be validated.", [{"field": "budget", "issue": "Must be an object"}])
        budget = {}
        for key in ("max_wall_time_seconds", "max_repair_attempts", "max_model_calls", "max_estimated_cost_usd"):
            cap = policy[key]
            val = req_budget.get(key, cap)
            if isinstance(val, bool) or not isinstance(val, (int, float)) or val < 0:
                raise ValidationFailed("Request could not be validated.", [{"field": f"budget.{key}", "issue": "Must be a non-negative number"}])
            budget[key] = min(val, cap)
        # project version
        vid = data.get("project_version_id")
        if vid:
            v = self.db.one("SELECT id FROM project_versions WHERE id=? AND project_id=?", (vid, project_id))
            if v is None:
                raise NotFound("Project version not found")
        else:
            vid = self.db.one("SELECT id FROM project_versions WHERE project_id=? ORDER BY version_number DESC LIMIT 1", (project_id,))["id"]
        rid, now = new_id(), utcnow()
        snapshot = {"provider": cfg, "template": project["selected_template"], "sandbox": probe().as_dict()}
        self.db.run("INSERT INTO runs(id,project_id,project_version_id,status,current_stage,requested_by,provider_key,model_name,config_snapshot,budget,usage,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rid, project_id, vid, "DRAFT", "draft", user_id, cfg["provider_type"], cfg["model_name"], dumps(redact(snapshot)),
                     dumps(budget), dumps({"model_calls": 0, "estimated_cost_usd": None}), now, now))
        audit(self.db, "run.create", "run", rid, "allowed", actor_id=user_id, run_id=rid,
              details={"provider": cfg["provider_type"], "model": cfg["model_name"], "budget": budget})
        transition_run(self.db, rid, RunStatus.PLANNING, expected=RunStatus.DRAFT, actor_id=user_id, message="Planning started")
        new_job(self.db, rid, "plan")
        return self._run_out(self._run(user_id, rid))

    def get_run(self, user_id: str, run_id: str) -> dict:
        return self._run_out(self._run(user_id, run_id))

    def get_plan(self, user_id: str, run_id: str) -> dict | None:
        return self._run(user_id, run_id)["plan"]

    def list_tasks(self, user_id: str, run_id: str) -> list[dict]:
        self._run(user_id, run_id)
        out = []
        for t in self.db.all("SELECT * FROM tasks WHERE run_id=? ORDER BY task_key", (run_id,)):
            deps = [d["task_key"] for d in self.db.all("SELECT t2.task_key FROM task_dependencies d JOIN tasks t2 ON t2.id=d.depends_on_task_id WHERE d.task_id=?", (t["id"],))]
            spec = loads(t["input"], {})
            out.append({"id": t["id"], "key": t["task_key"], "title": t["title"], "agent_role": t["agent_role"], "status": t["status"],
                        "depends_on": sorted(deps), "expected_files": spec.get("expected_files", []), "risk": spec.get("risk"),
                        "requirement_ids": spec.get("requirement_ids", []), "attempt_count": t["attempt_count"], "output": loads(t["output"], {})})
        return out

    def list_events(self, user_id: str, run_id: str, after: int = 0, limit: int = 200) -> dict:
        self._run(user_id, run_id)
        return {"items": self.events_after(run_id, after, limit)}

    def events_after(self, run_id: str, after: int, limit: int = 200) -> list[dict]:
        rows = self.db.all("SELECT * FROM agent_events WHERE run_id=? AND sequence_number>? ORDER BY sequence_number LIMIT ?", (run_id, after, max(1, min(limit, 500))))
        return [{"id": r["sequence_number"], "task_id": r["task_id"], "event_type": r["event_type"], "severity": r["severity"], "message": r["message"],
                 "payload": loads(r["payload"], {}), "created_at": r["created_at"]} for r in rows]

    def assert_run_access(self, user_id: str, run_id: str) -> None:
        self._run(user_id, run_id)

    def list_approvals(self, user_id: str, run_id: str) -> list[dict]:
        self._run(user_id, run_id)
        return [dict(r) for r in self.db.all("SELECT id, approval_type, decision, comment, plan_version, requested_at, decided_at, decided_by FROM approvals WHERE run_id=? ORDER BY requested_at", (run_id,))]

    # -- decisions --------------------------------------------------------------
    def _decide(self, user_id: str, run_id: str, approval_type: str, expected: RunStatus, decision: str, comment: str | None) -> None:
        run = self._run(user_id, run_id)
        if RunStatus(run["status"]) != expected:
            audit(self.db, f"{approval_type}.{decision}", "run", run_id, "denied", actor_id=user_id, run_id=run_id,
                  details={"reason": "illegal state", "status": run["status"]})
            raise Conflict(f"Run is {run['status']}; expected {expected.value}")
        row = self.db.one("SELECT id FROM approvals WHERE run_id=? AND approval_type=? AND decision IS NULL ORDER BY requested_at DESC LIMIT 1", (run_id, approval_type))
        if row is None:
            raise Conflict("No pending approval request")
        self.db.run("UPDATE approvals SET decision=?, comment=?, decided_by=?, decided_at=? WHERE id=?", (decision, comment, user_id, utcnow(), row["id"]))
        audit(self.db, f"{approval_type}.{decision}", "run", run_id, "allowed", actor_id=user_id, run_id=run_id, details={"comment": comment})

    def plan_approve(self, user_id: str, run_id: str, comment: str | None = None) -> dict:
        self._decide(user_id, run_id, "plan", RunStatus.AWAITING_PLAN_APPROVAL, "approved", comment)
        transition_run(self.db, run_id, RunStatus.GENERATING, expected=RunStatus.AWAITING_PLAN_APPROVAL, actor_id=user_id, message="Plan approved; generation started")
        new_job(self.db, run_id, "generate")
        return self.get_run(user_id, run_id)

    def plan_reject(self, user_id: str, run_id: str, comment: str | None = None) -> dict:
        self._decide(user_id, run_id, "plan", RunStatus.AWAITING_PLAN_APPROVAL, "rejected", comment)
        transition_run(self.db, run_id, RunStatus.CANCELLED, expected=RunStatus.AWAITING_PLAN_APPROVAL, actor_id=user_id,
                       message="Plan rejected", error_code="PLAN_REJECTED", error_summary=(comment or "Plan rejected by user")[:500])
        return self.get_run(user_id, run_id)

    def plan_change_request(self, user_id: str, run_id: str, comment: str | None) -> dict:
        if not comment or not comment.strip():
            raise ValidationFailed("Request could not be validated.", [{"field": "comment", "issue": "Describe the change you want"}])
        if len(comment) > 5000:
            raise ValidationFailed("Request could not be validated.", [{"field": "comment", "issue": "Too long"}])
        self._decide(user_id, run_id, "plan", RunStatus.AWAITING_PLAN_APPROVAL, "changes_requested", comment.strip())
        transition_run(self.db, run_id, RunStatus.PLANNING, expected=RunStatus.AWAITING_PLAN_APPROVAL, actor_id=user_id, message="Change requested; re-planning")
        new_job(self.db, run_id, "plan")
        return self.get_run(user_id, run_id)

    def export_approve(self, user_id: str, run_id: str, comment: str | None = None) -> dict:
        self._decide(user_id, run_id, "export", RunStatus.AWAITING_EXPORT_APPROVAL, "approved", comment)
        transition_run(self.db, run_id, RunStatus.PACKAGING, expected=RunStatus.AWAITING_EXPORT_APPROVAL, actor_id=user_id, message="Export approved; packaging")
        new_job(self.db, run_id, "package")
        return self.get_run(user_id, run_id)

    def cancel(self, user_id: str, run_id: str) -> dict:
        run = self._run(user_id, run_id)
        status = RunStatus(run["status"])
        from autoforge.domain.states import TERMINAL
        if status in TERMINAL:
            raise Conflict(f"Run is already {status.value}")
        audit(self.db, "run.cancel_requested", "run", run_id, "allowed", actor_id=user_id, run_id=run_id)
        self.db.run("UPDATE runs SET cancel_requested_at=?, updated_at=? WHERE id=?", (utcnow(), utcnow(), run_id))
        emit_event(self.db, run_id, "cancel_requested", "Cancellation requested", severity="warning")
        if status in (RunStatus.AWAITING_PLAN_APPROVAL, RunStatus.AWAITING_EXPORT_APPROVAL, RunStatus.DRAFT):
            try:
                transition_run(self.db, run_id, RunStatus.CANCELLED, actor_id=user_id, message="Run cancelled", error_code="CANCELLED")
            except IllegalTransition:
                pass
        # otherwise the worker observes cancel_requested_at at the next safe point and terminates active sandbox work
        return self.get_run(user_id, run_id)

    def retry(self, user_id: str, run_id: str, idempotency_key: str | None) -> dict:
        from autoforge.orchestration.engine import RETRY_TARGET
        if not idempotency_key or not re.fullmatch(r"[A-Za-z0-9_\-]{8,80}", idempotency_key):
            raise ValidationFailed("Request could not be validated.", [{"field": "idempotency_key", "issue": "Provide an Idempotency-Key (8-80 chars)"}])
        run = self._run(user_id, run_id)
        keys = run["config_snapshot"].setdefault("retry_keys", [])
        if idempotency_key in keys:
            return self._run_out(run)  # replayed request: no duplicate work
        if run["status"] != RunStatus.FAILED.value:
            raise Conflict(f"Only FAILED runs can be retried (run is {run['status']})")
        step = run["config_snapshot"].get("failed_step")
        if run["error_code"] == "BUDGET_EXHAUSTED" or step not in RETRY_TARGET:
            raise Conflict("This failure is not eligible for retry; start a new run with a larger budget")
        keys.append(idempotency_key)
        self.db.run("UPDATE runs SET config_snapshot=? WHERE id=?", (dumps(run["config_snapshot"]), run_id))
        target, job_step = RETRY_TARGET[step]
        audit(self.db, "run.retry", "run", run_id, "allowed", actor_id=user_id, run_id=run_id, details={"stage": job_step})
        transition_run(self.db, run_id, target, expected=RunStatus.FAILED, actor_id=user_id, message=f"Retrying stage {job_step}")
        new_job(self.db, run_id, job_step)
        return self.get_run(user_id, run_id)

    # -- review data --------------------------------------------------------------
    def verification(self, user_id: str, run_id: str) -> dict:
        self._run(user_id, run_id)
        checks = [{k: r[k] for k in ("round", "check_name", "command", "exit_code", "status", "duration_ms", "output_summary", "created_at")}
                  for r in self.db.all("SELECT * FROM verification_results WHERE run_id=? ORDER BY round, created_at", (run_id,))]
        findings = [{k: r[k] for k in ("severity", "category", "file_path", "line", "message", "evidence")}
                    for r in self.db.all("SELECT * FROM security_findings WHERE run_id=? ORDER BY created_at", (run_id,))]
        return {"checks": checks, "security_findings": findings, "sandbox": probe().as_dict()}

    def diff(self, user_id: str, run_id: str) -> dict:
        run = self._run(user_id, run_id)
        ws = Workspace(self.settings.workspace_root, run_id)
        if not ws.exists():
            return {"files": [], "repair_diffs": [], "available": False}
        files = [{"path": p, **meta} for p, meta in ws.list_files().items()]
        generated = ws.diff_against("generated") if (ws.snap_root / "generated").is_dir() else []
        return {"available": True, "files": files, "changes_since_generation": generated}

    def read_file(self, user_id: str, run_id: str, path: str) -> dict:
        self._run(user_id, run_id)
        try:
            validate_relative_path(path)
            return {"path": path, "content": Workspace(self.settings.workspace_root, run_id).read_file(path)}
        except (PathViolation, WorkspaceError):
            raise NotFound("File not found") from None

    # -- artifacts ------------------------------------------------------------------
    @staticmethod
    def _artifact_out(r) -> dict:
        return {"id": r["id"], "artifact_type": r["artifact_type"], "display_name": r["display_name"], "mime_type": r["mime_type"],
                "size_bytes": r["size_bytes"], "sha256": r["sha256"], "created_at": r["created_at"], "expires_at": r["expires_at"],
                "download_url": f"/api/v1/artifacts/{r['id']}/download"}

    def list_artifacts(self, user_id: str, run_id: str) -> list[dict]:
        self._run(user_id, run_id)
        return [self._artifact_out(r) for r in self.db.all("SELECT * FROM artifacts WHERE run_id=? ORDER BY created_at", (run_id,))]

    def open_artifact(self, user_id: str, artifact_id: str):
        r = self.db.one("SELECT a.*, p.owner_id FROM artifacts a JOIN runs ru ON ru.id=a.run_id JOIN projects p ON p.id=ru.project_id WHERE a.id=?", (artifact_id,))
        if r is None or r["owner_id"] != user_id:
            if r is not None:
                audit(self.db, "artifact.download", "artifact", artifact_id, "denied", actor_id=user_id, run_id=r["run_id"])
            raise NotFound("Artifact not found")
        try:
            fh = self.store.open(r["storage_key"])
        except FileNotFoundError:
            raise NotFound("Artifact no longer available (retention)") from None
        audit(self.db, "artifact.download", "artifact", artifact_id, "allowed", actor_id=user_id, run_id=r["run_id"], details={"sha256": r["sha256"]})
        return fh, r["display_name"], r["mime_type"], r["size_bytes"], r["sha256"]

    # -- dashboard ------------------------------------------------------------------
    def dashboard(self, user_id: str) -> dict:
        runs = self.db.all("SELECT r.*, p.name AS project_name FROM runs r JOIN projects p ON p.id=r.project_id WHERE p.owner_id=? ORDER BY r.created_at DESC LIMIT 30", (user_id,))
        approvals = [self._run_brief(dict(r)) | {"project_name": r["project_name"]} for r in runs if r["status"] in ("AWAITING_PLAN_APPROVAL", "AWAITING_EXPORT_APPROVAL")]
        usage_calls = sum(loads(r["usage"], {}).get("model_calls", 0) for r in runs)
        return {"recent_runs": [self._run_brief(dict(r)) | {"project_name": r["project_name"]} for r in runs[:10]],
                "approval_queue": approvals, "model_calls_recent": usage_calls}

    def notifications(self, user_id: str, mark_read: bool = False) -> list[dict]:
        rows = [dict(r) for r in self.db.all("SELECT id, run_id, kind, message, read, created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50", (user_id,))]
        if mark_read:
            self.db.run("UPDATE notifications SET read=1 WHERE user_id=?", (user_id,))
        return rows

    def audit_list(self, user_id: str, limit: int = 100) -> list[dict]:
        rows = self.db.all("SELECT a.* FROM audit_logs a LEFT JOIN runs r ON r.id=a.run_id LEFT JOIN projects p ON p.id=r.project_id "
                           "WHERE a.actor_id=? OR p.owner_id=? ORDER BY a.id DESC LIMIT ?", (user_id, user_id, max(1, min(limit, 500))))
        return [{"id": r["id"], "action": r["action"], "resource_type": r["resource_type"], "resource_id": r["resource_id"], "run_id": r["run_id"],
                 "outcome": r["outcome"], "details": loads(r["details"], {}), "created_at": r["created_at"]} for r in rows]
