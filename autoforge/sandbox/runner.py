"""Sandbox runner.

Only *named* commands from a fixed allowlist can run; argv is built from constants, never from
model output. Isolation (when available): new user/mount/net/pid namespaces, minimal chroot
containing only read-only system dirs plus the run workspace, scrubbed environment, rlimits,
wall-clock timeout with process-group kill, and capped output.
"""
from __future__ import annotations

import os
import shutil
import sys
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

try:  # POSIX only; Windows has no `resource` module
    import resource
except ImportError:  # pragma: no cover - exercised on Windows
    resource = None  # type: ignore[assignment]

IS_POSIX = os.name == "posix"
WRAPPER = str(Path(__file__).with_name("wrapper.sh"))
PYTHON = os.path.realpath(sys.executable)  # resolve symlinks: the chroot has no /etc/alternatives

ALLOWLIST: dict[str, list[str]] = {
    "compile": ["-I", "-m", "compileall", "-q", "app", "tests"],
    "unittest": ["-I", "-m", "unittest", "discover", "-s", "tests", "-t", "."],
}
MAX_OUTPUT_BYTES = 1_000_000
SUMMARY_CHARS = 4000


class SandboxUnavailable(RuntimeError):
    pass


class CommandDenied(ValueError):
    pass


@dataclass
class SandboxInfo:
    isolation: str  # "namespaces" | "none"
    network_denied: bool
    filesystem_isolated: bool
    detail: str = ""

    def as_dict(self) -> dict:
        return {"isolation": self.isolation, "network_denied": self.network_denied,
                "filesystem_isolated": self.filesystem_isolated, "detail": self.detail}


@dataclass
class CommandResult:
    name: str
    command: str
    exit_code: int | None
    status: str  # passed | failed | timeout | cancelled | error
    duration_ms: int
    output_summary: str
    sandbox: dict = field(default_factory=dict)


def _namespace_prefix() -> list[str]:
    return ["unshare", "--mount", "--net", "--pid", "--fork", "--map-root-user", "sh", WRAPPER]


_probe_cache: SandboxInfo | None = None


def probe(refresh: bool = False) -> SandboxInfo:
    """Detect whether strong isolation works on this host by actually running a probe."""
    global _probe_cache
    if _probe_cache is not None and not refresh:
        return _probe_cache
    info = SandboxInfo("none", False, False, "namespace isolation unavailable on this host")
    if shutil.which("unshare") and os.path.exists(WRAPPER):
        with tempfile.TemporaryDirectory() as ws:
            try:
                p = subprocess.run(_namespace_prefix() + [ws, PYTHON, "-I", "-c",
                                    "import os,socket\n"
                                    "assert not os.path.exists('/root') and not os.path.exists('/var/run/docker.sock')\n"
                                    "try:\n socket.create_connection(('192.0.2.1',9),1)\n raise SystemExit(3)\nexcept OSError:\n pass\n"],
                                   capture_output=True, timeout=20, env={"PATH": "/usr/bin:/bin"})
                if p.returncode == 0:
                    info = SandboxInfo("namespaces", True, True, "user+mount+net+pid namespaces, minimal chroot")
                else:
                    info = SandboxInfo("none", False, False, f"namespace probe failed (exit {p.returncode})")
            except (subprocess.SubprocessError, OSError) as exc:
                info = SandboxInfo("none", False, False, f"namespace probe error: {type(exc).__name__}")
    _probe_cache = info
    return info


def _limits() -> None:
    os.setsid()
    if resource is None:
        return
    for res, soft in ((resource.RLIMIT_CPU, 120), (resource.RLIMIT_FSIZE, 50_000_000),
                      (resource.RLIMIT_NOFILE, 512), (resource.RLIMIT_CORE, 0)):
        try:
            resource.setrlimit(res, (soft, soft))
        except (ValueError, OSError):
            pass
    try:  # address-space cap; skipped silently if the platform refuses
        resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    except (ValueError, OSError):
        pass


class SandboxRunner:
    def __init__(self, *, allow_weak: bool = False, timeout_seconds: int = 120):
        self.allow_weak = allow_weak
        self.timeout = timeout_seconds

    def info(self) -> SandboxInfo:
        return probe()

    def ensure_available(self) -> SandboxInfo:
        info = probe()
        if info.isolation == "none" and not self.allow_weak:
            raise SandboxUnavailable(
                "Strong sandbox isolation is unavailable on this host; untrusted code execution is disabled. "
                "Set ALLOW_WEAK_SANDBOX=1 only for local development you trust.")
        return info

    def run(self, name: str, workspace: Path, *, cancelled=lambda: False) -> CommandResult:
        if name not in ALLOWLIST:
            raise CommandDenied(f"command {name!r} is not allowlisted")
        info = self.ensure_available()
        workspace = Path(os.path.realpath(workspace))
        argv_tail = [PYTHON] + ALLOWLIST[name]
        display = "python " + " ".join(ALLOWLIST[name])
        env = {"PATH": "/usr/bin:/bin", "HOME": "/work", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONHASHSEED": "0"}
        if not IS_POSIX:  # Windows needs a few system variables to start Python; nothing else is passed through
            root = os.environ.get("SYSTEMROOT", r"C:\Windows")
            env = {"SYSTEMROOT": root, "PATH": root + r"\System32", "TEMP": tempfile.gettempdir(), "TMP": tempfile.gettempdir(),
                   "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0", "PYTHONIOENCODING": "utf-8"}
        if info.isolation == "namespaces":
            argv = _namespace_prefix() + [str(workspace)] + argv_tail
            cwd = None
        else:  # explicitly-allowed weak mode: scrubbed env + rlimits only
            argv, cwd = argv_tail, str(workspace)
        out_file = tempfile.NamedTemporaryFile(prefix="afout-", delete=False)
        start = time.monotonic()
        status, code = "error", None
        proc = None
        try:
            popen_kw: dict = {"preexec_fn": _limits} if IS_POSIX else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out_file,
                                    stderr=subprocess.STDOUT, **popen_kw)  # noqa: PLW1509
            deadline = start + self.timeout
            while True:
                try:
                    code = proc.wait(timeout=0.2)
                    status = "passed" if code == 0 else "failed"
                    break
                except subprocess.TimeoutExpired:
                    if time.monotonic() > deadline:
                        status = "timeout"
                        break
                    if cancelled():
                        status = "cancelled"
                        break
            if proc.poll() is None:
                self._kill(proc)
        except OSError as exc:
            status = "error"
            out_file.write(f"failed to start sandbox: {type(exc).__name__}".encode())
        finally:
            if proc is not None and proc.poll() is None:
                self._kill(proc)
            out_file.close()
        output = self._read_tail(out_file.name)
        os.unlink(out_file.name)
        from autoforge.security.redaction import redact_text

        return CommandResult(name, display, code, status, int((time.monotonic() - start) * 1000),
                             redact_text(output), info.as_dict())

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        if not IS_POSIX:  # kill the whole process tree on Windows
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            return
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(proc.pid, sig)
            except (ProcessLookupError, PermissionError):
                break
            try:
                proc.wait(timeout=2)
                break
            except subprocess.TimeoutExpired:
                continue

    @staticmethod
    def _read_tail(path: str) -> str:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size > MAX_OUTPUT_BYTES:
                fh.seek(-MAX_OUTPUT_BYTES, os.SEEK_END)
            data = fh.read()
        text = data.decode("utf-8", errors="replace")
        return text[-SUMMARY_CHARS:] if len(text) > SUMMARY_CHARS else text
