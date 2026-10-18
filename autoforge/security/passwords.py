"""Password hashing (scrypt, stdlib) and password policy."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

# scrypt cost: ~64 MiB, tens of milliseconds. Parameters are stored in each hash so they can be raised later.
_N, _R, _P = 2 ** 15, 8, 1
_MAXMEM = 128 * 1024 * 1024
MIN_LENGTH = 10
MAX_LENGTH = 200
_COMMON = {
    "password", "password1", "password123", "passw0rd", "12345678", "123456789", "1234567890", "qwertyuiop", "qwerty123",
    "iloveyou1", "admin12345", "letmein123", "welcome123", "changeme123", "nextbuildai", "nextbuild123", "autoforge1",
    "abcdefghij", "1q2w3e4r5t", "pakistan123", "00000000000",
}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=_MAXMEM, dklen=32)
    return "scrypt${}${}${}${}${}".format(_N, _R, _P, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time verification. Always spends hashing time, even for unknown users (stored=None)."""
    if not stored or not stored.startswith("scrypt$"):
        hashlib.scrypt(password.encode(), salt=b"\x00" * 16, n=_N, r=_R, p=_P, maxmem=_MAXMEM, dklen=32)  # equalize timing
        return False
    try:
        _, n, r, p, salt_b64, dk_b64 = stored.split("$")
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), maxmem=_MAXMEM, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


def policy_problems(password: str, username: str = "") -> list[str]:
    """Return human-readable problems; empty list means acceptable."""
    problems = []
    if not isinstance(password, str) or len(password) < MIN_LENGTH:
        problems.append(f"Use at least {MIN_LENGTH} characters.")
        return problems
    if len(password) > MAX_LENGTH:
        problems.append(f"Use at most {MAX_LENGTH} characters.")
    low = password.lower()
    if low in _COMMON or len(set(low)) < 5:
        problems.append("This password is too common or too repetitive.")
    if username and (low == username.lower() or username.lower() in low and len(username) >= 4):
        problems.append("The password must not contain your user name.")
    classes = sum(bool(x) for x in (any(c.islower() for c in password), any(c.isupper() for c in password),
                                    any(c.isdigit() for c in password), any(not c.isalnum() for c in password)))
    if classes < 2 and len(password) < 16:
        problems.append("Mix letters, numbers or symbols, or use a passphrase of 16+ characters.")
    return problems
