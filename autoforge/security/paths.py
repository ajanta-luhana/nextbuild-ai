"""Workspace path safety: traversal and symlink-escape protection."""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath


class PathViolation(ValueError):
    pass


_FORBIDDEN_NAMES = {".git", ".env"}


def validate_relative_path(rel: str) -> str:
    """Validate a repo-relative POSIX path supplied by an untrusted source."""
    if not isinstance(rel, str) or not rel or len(rel) > 300:
        raise PathViolation("invalid path")
    if "\x00" in rel or "\\" in rel:
        raise PathViolation("invalid characters in path")
    p = PurePosixPath(rel)
    if str(p) != rel:
        raise PathViolation("path must be canonical")
    if p.is_absolute() or rel.startswith("~"):
        raise PathViolation("absolute paths are not allowed")
    parts = p.parts
    if any(part in {"..", "."} or part == "" for part in parts):
        raise PathViolation("path traversal is not allowed")
    if parts[0] in _FORBIDDEN_NAMES or ".git" in parts:
        raise PathViolation("protected path")
    if p.name == ".env":
        raise PathViolation("protected path")
    return str(p)


def resolve_in_workspace(root: Path, rel: str) -> Path:
    """Return the canonical path for rel inside root; reject escapes via symlinks."""
    rel = validate_relative_path(rel)
    root_real = Path(os.path.realpath(root))
    candidate = root_real.joinpath(rel)
    # Reject any symlink component along the way (even ones that stay inside).
    cur = root_real
    for part in PurePosixPath(rel).parts:
        cur = cur / part
        if cur.is_symlink():
            raise PathViolation("symlinks are not allowed in the workspace")
    real = Path(os.path.realpath(candidate))
    if real != root_real and root_real not in real.parents:
        raise PathViolation("path escapes workspace")
    return candidate
