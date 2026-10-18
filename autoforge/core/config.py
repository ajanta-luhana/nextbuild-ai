"""Validated settings loaded from environment variables."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    pass


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value < 0:
        raise ConfigError(f"{name} must be >= 0")
    return value


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_env: str = "development"
    database_path: str = "./data/autoforge.db"
    artifact_root: str = "./data/artifacts"
    workspace_root: str = "./data/workspaces"
    auth_mode: str = "password"
    session_secret: str = field(default="", repr=False)
    host: str = "127.0.0.1"
    port: int = 8000
    sandbox_network: str = "none"
    allow_weak_sandbox: bool = False
    max_run_seconds: int = 3600
    max_repair_attempts: int = 2
    max_model_calls: int = 120
    model_provider: str = "mock"
    model_name: str = "mock-deterministic"
    run_creation_per_minute: int = 20
    worker_poll_seconds: float = 0.2
    lease_seconds: int = 120
    retention_days: int = 30
    inline_worker: bool = True
    cors_origins: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "[::1]")
    allow_registration: bool = False
    allow_remote_bind: bool = False
    idle_timeout_minutes: int = 30
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    login_per_minute_per_ip: int = 20

    @property
    def is_production(self) -> bool:
        return self.app_env in {"production", "cloud", "staging"}

    def validate(self) -> None:
        if self.is_production:
            if len(self.session_secret) < 32:
                raise ConfigError("SESSION_SECRET must be set (>=32 chars) in production")
            if self.allow_weak_sandbox:
                raise ConfigError("ALLOW_WEAK_SANDBOX is not allowed in production")
        if self.auth_mode not in {"password", "proxy"}:
            raise ConfigError("AUTH_MODE must be 'password' or 'proxy'")
        if self.is_production and self.allowed_hosts == ("127.0.0.1", "localhost", "[::1]"):
            raise ConfigError("Set ALLOWED_HOSTS to the public host name(s) when APP_ENV is production/cloud")
        if self.sandbox_network not in {"none", "host"}:
            raise ConfigError("SANDBOX_NETWORK must be 'none' or 'host'")
        if self.sandbox_network == "host" and self.is_production:
            raise ConfigError("SANDBOX_NETWORK=host is not allowed in production")


def _dev_secret(database_path: str) -> str:
    """Development session secret persisted next to the database (0600) so sessions survive restarts."""
    path = Path(database_path).parent / ".session_secret"
    try:
        if path.is_file():
            value = path.read_text().strip()
            if len(value) >= 32:
                return value
        path.parent.mkdir(parents=True, exist_ok=True)
        value = secrets.token_urlsafe(48)
        path.write_text(value)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return value
    except OSError:
        return secrets.token_urlsafe(48)


def load_settings() -> Settings:
    env = os.environ.get
    secret = env("SESSION_SECRET", "")
    app_env = env("APP_ENV", "development")
    if not secret and app_env not in {"production", "cloud", "staging"}:
        secret = _dev_secret(env("DATABASE_PATH", "./data/autoforge.db"))
    s = Settings(
        app_env=app_env,
        database_path=env("DATABASE_PATH", "./data/autoforge.db"),
        artifact_root=env("ARTIFACT_ROOT", "./data/artifacts"),
        workspace_root=env("WORKSPACE_ROOT", "./data/workspaces"),
        auth_mode={"local": "password"}.get(env("AUTH_MODE", "password"), env("AUTH_MODE", "password")),
        session_secret=secret,
        host=env("HOST", "127.0.0.1"),
        port=_int("PORT", 8000),
        sandbox_network=env("SANDBOX_NETWORK", "none"),
        allow_weak_sandbox=_bool("ALLOW_WEAK_SANDBOX", False),
        max_run_seconds=_int("MAX_RUN_SECONDS", 3600),
        max_repair_attempts=_int("MAX_REPAIR_ATTEMPTS", 2),
        max_model_calls=_int("MAX_MODEL_CALLS", 120),
        model_provider=env("MODEL_PROVIDER", "mock"),
        model_name=env("MODEL_NAME", "mock-deterministic"),
        run_creation_per_minute=_int("RUN_CREATION_PER_MINUTE", 20),
        worker_poll_seconds=float(env("WORKER_POLL_SECONDS", "0.2")),
        lease_seconds=_int("LEASE_SECONDS", 120),
        retention_days=_int("RETENTION_DAYS", 30),
        inline_worker=_bool("INLINE_WORKER", True),
        cors_origins=tuple(o for o in env("CORS_ORIGINS", "").split(",") if o),
        allowed_hosts=tuple(h.strip().lower() for h in env("ALLOWED_HOSTS", "127.0.0.1,localhost,[::1]").split(",") if h.strip()),
        allow_registration=_bool("ALLOW_REGISTRATION", False),
        allow_remote_bind=_bool("ALLOW_REMOTE_BIND", False),
        idle_timeout_minutes=_int("IDLE_TIMEOUT_MINUTES", 30),
        max_failed_logins=_int("MAX_FAILED_LOGINS", 5),
        lockout_minutes=_int("LOCKOUT_MINUTES", 15),
        login_per_minute_per_ip=_int("LOGIN_PER_MINUTE_PER_IP", 20),
    )
    s.validate()
    Path(s.artifact_root).mkdir(parents=True, exist_ok=True)
    Path(s.workspace_root).mkdir(parents=True, exist_ok=True)
    Path(s.database_path).parent.mkdir(parents=True, exist_ok=True)
    return s
