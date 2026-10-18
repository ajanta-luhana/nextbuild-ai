"""RFC 6238 time-based one-time passwords (stdlib only) and recovery codes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def code_at(secret: str, step: int, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 15
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def verify(secret: str, code: str, last_step: int = 0, now: float | None = None) -> int | None:
    """Return the matched time step (accepting +-1 step of clock drift) or None. Steps <= last_step are rejected (no replay)."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != 6:
        return None
    cur = int((now if now is not None else time.time()) // STEP)
    for step in (cur, cur - 1, cur + 1):
        if step > last_step and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def otpauth_uri(secret: str, account: str, issuer: str = "NextBuild AI") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}&digits=6&period={STEP}"


def new_recovery_code() -> str:
    raw = base64.b32encode(secrets.token_bytes(15)).decode()[:20]
    return "-".join(raw[i:i + 4] for i in range(0, 20, 4))


def recovery_hash(code: str) -> str:
    norm = "".join(ch for ch in str(code or "").upper() if ch.isalnum())
    return hashlib.sha256(("nextbuild-recovery:" + norm).encode()).hexdigest()
