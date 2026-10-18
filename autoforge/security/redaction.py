"""Secret redaction applied to logs, events, reports and API payloads."""
from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{12,}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd)(\s*[:=]\s*)(['\"]?)[^\s'\",;]{6,}\3"),
]

_SENSITIVE_KEYS = re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|authorization|cookie)")


def redact_text(text: str) -> str:
    if not text:
        return text
    out = text
    for pat in _PATTERNS:
        if pat.groups >= 2:
            out = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", out)
        else:
            out = pat.sub(REDACTED, out)
    return out


def redact(value: Any) -> Any:
    """Recursively redact strings and sensitive-looking dict keys."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            k: (REDACTED if isinstance(k, str) and _SENSITIVE_KEYS.search(k) and v not in (None, "") and not isinstance(v, (dict, list))
                else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value
