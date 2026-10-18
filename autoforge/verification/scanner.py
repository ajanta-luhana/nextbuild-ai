"""Static security scan of a generated workspace: secrets, risky constructs, dependency hygiene."""
from __future__ import annotations

import re

from autoforge.security.redaction import REDACTED, _PATTERNS, redact_text
from autoforge.workspace.manager import Workspace

_RISKY = [
    (re.compile(r"\beval\s*\("), "high", "code-execution", "Use of eval()"),
    (re.compile(r"\bexec\s*\("), "high", "code-execution", "Use of exec()"),
    (re.compile(r"os\.system\s*\("), "high", "command-injection", "os.system() runs a shell command"),
    (re.compile(r"shell\s*=\s*True"), "high", "command-injection", "subprocess with shell=True"),
    (re.compile(r"pickle\.loads?\s*\("), "high", "deserialization", "Unsafe deserialization with pickle"),
    (re.compile(r"\.execute\([^)]*(?:\bf[\"']|\.format\(|[\"']\s*%\s)"), "low", "sql-injection",
     "SQL built with string formatting; confirm interpolated values are fixed identifiers, not user input"),
    (re.compile(r"(?i)verify\s*=\s*False"), "medium", "tls", "TLS verification disabled"),
]
_TEXT_EXT = {".py", ".txt", ".md", ".env", ".example", ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ""}


def scan_workspace(ws: Workspace) -> list[dict]:
    findings: list[dict] = []
    for rel in ws.list_files():
        name = rel.rsplit("/", 1)[-1]
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        if ext not in _TEXT_EXT and name not in {"Dockerfile", ".gitignore"}:
            continue
        text = ws.read_file(rel)
        for lineno, line in enumerate(text.splitlines(), 1):
            for pat in _PATTERNS:
                if pat.search(line):
                    findings.append({"severity": "critical", "category": "secret", "file": rel, "line": lineno,
                                     "message": "Possible hard-coded secret", "evidence": redact_text(line.strip())[:200] or REDACTED})
                    break
            if rel.startswith("tests/"):
                continue  # risky-construct rules target shipped code
            for pat, sev, cat, msg in _RISKY:
                if pat.search(line):
                    findings.append({"severity": sev, "category": cat, "file": rel, "line": lineno,
                                     "message": msg, "evidence": redact_text(line.strip())[:200]})
    reqs = ws.root / "requirements.txt"
    if reqs.is_file():
        for lineno, line in enumerate(reqs.read_text().splitlines(), 1):
            s = line.strip()
            if s and not s.startswith("#") and "==" not in s:
                findings.append({"severity": "low", "category": "dependency", "file": "requirements.txt", "line": lineno,
                                 "message": "Dependency is not pinned to an exact version", "evidence": s[:100]})
    if not (ws.root / ".gitignore").is_file():
        findings.append({"severity": "low", "category": "hygiene", "file": None, "line": None,
                         "message": ".gitignore is missing", "evidence": None})
    return findings
