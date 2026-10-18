"""Truthful verification reporting + safe ZIP packaging."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile

from autoforge.security.redaction import redact_text
from autoforge.workspace.manager import Workspace

# Fixed timestamp keeps the ZIP byte-reproducible for identical content.
_ZIP_DATE = (2026, 1, 1, 0, 0, 0)


def build_verification_report(run: dict, results: list[dict], findings: list[dict], sandbox: dict | None) -> dict:
    last_round = max((r["round"] for r in results), default=0)
    latest = [r for r in results if r["round"] == last_round]
    all_passed = bool(latest) and all(r["status"] == "passed" for r in latest)
    return {
        "run_id": run["id"],
        "overall": "checks_passed" if all_passed else "checks_failed_or_missing",
        "statement": ("All configured automated checks passed in the final verification round. "
                      "This is NOT a claim of production readiness; human review, security review and "
                      "domain testing are still required." if all_passed else
                      "One or more configured checks did not pass."),
        "repair_attempts": run.get("repair_attempts", 0),
        "rounds": last_round,
        "checks": [{k: r[k] for k in ("round", "check_name", "command", "exit_code", "status", "duration_ms", "output_summary")}
                   for r in results],
        "security_findings": findings,
        "sandbox": sandbox or {},
        "not_verified": ["Runtime behaviour under load", "Authentication/authorization (not generated)",
                         "Dependency vulnerabilities (stdlib-only; no external audit tooling run)",
                         "SBOM (no SBOM tooling available in this edition)"],
        "usage": run.get("usage", {}),
    }


def report_markdown(report: dict) -> str:
    lines = [f"# Verification report", "", f"Run: `{report['run_id']}`", "", f"**Overall:** {report['overall']}", "",
             report["statement"], "", f"Repair attempts used: {report['repair_attempts']} (verification rounds: {report['rounds']})", "",
             "## Checks", "", "| Round | Check | Command | Exit | Status | Duration |", "|---|---|---|---|---|---|"]
    for c in report["checks"]:
        lines.append(f"| {c['round']} | {c['check_name']} | `{c['command']}` | {c['exit_code']} | {c['status']} | {c['duration_ms']} ms |")
    lines += ["", "## Security findings", ""]
    if not report["security_findings"]:
        lines.append("None detected by the built-in scanner (not a guarantee).")
    for f in report["security_findings"]:
        loc = f"{f.get('file') or '-'}:{f.get('line') or '-'}"
        lines.append(f"- **{f['severity']}** [{f['category']}] {f['message']} ({loc})")
    lines += ["", "## Not verified", ""] + [f"- {x}" for x in report["not_verified"]]
    lines += ["", f"## Sandbox", "", f"`{json.dumps(report['sandbox'])}`", ""]
    return redact_text("\n".join(lines))


def test_report_text(results: list[dict]) -> str:
    out = []
    for r in results:
        out.append(f"=== round {r['round']} :: {r['check_name']} :: {r['status']} (exit {r['exit_code']}, {r['duration_ms']} ms)")
        out.append(f"$ {r['command']}")
        out.append(r["output_summary"].rstrip())
        out.append("")
    return redact_text("\n".join(out))


def build_zip(ws: Workspace, extra: dict[str, bytes], root_name: str) -> tuple[bytes, dict]:
    """Create a ZIP of workspace files (+ extra generated docs + MANIFEST.json). Entries are validated."""
    entries: dict[str, bytes] = {}
    for rel in ws.list_files():
        entries[rel] = (ws.root / rel).read_bytes()
    entries.update(extra)
    for rel in entries:
        if rel.startswith("/") or ".." in rel.split("/") or "\\" in rel:
            raise ValueError(f"unsafe archive entry {rel!r}")
    manifest = {"root": root_name, "files": [
        {"path": rel, "size": len(entries[rel]), "sha256": hashlib.sha256(entries[rel]).hexdigest()} for rel in sorted(entries)],
        "note": "MANIFEST.json lists every other file in this archive with its SHA-256."}
    entries["MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in sorted(entries):
            info = zipfile.ZipInfo(f"{root_name}/{rel}", date_time=_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, entries[rel])
    return buf.getvalue(), manifest
