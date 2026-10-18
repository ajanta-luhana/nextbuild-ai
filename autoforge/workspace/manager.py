"""Per-run workspace: bounded, validated file operations plus snapshots and diffs."""
from __future__ import annotations

import difflib
import hashlib
import os
import shutil
from pathlib import Path

from autoforge.security.paths import PathViolation, resolve_in_workspace

MAX_FILE_BYTES = 200_000
MAX_FILES = 500
MAX_TOTAL_BYTES = 5_000_000


class WorkspaceError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Workspace:
    def __init__(self, root: str | Path, run_id: str):
        self.root = Path(root).resolve() / run_id
        self.snap_root = Path(root).resolve() / f"{run_id}.snapshots"

    def create(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.snap_root, ignore_errors=True)
        self.root.mkdir(parents=True)
        self.snap_root.mkdir(parents=True)

    def exists(self) -> bool:
        return self.root.is_dir()

    def destroy(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.snap_root, ignore_errors=True)

    # -- file operations -----------------------------------------------------
    def write_file(self, rel: str, content: str) -> dict:
        target = resolve_in_workspace(self.root, rel)  # raises PathViolation
        data = content.encode("utf-8")
        if b"\x00" in data:
            raise PathViolation("binary content is not allowed")
        if len(data) > MAX_FILE_BYTES:
            raise PathViolation("file too large")
        files = self.list_files()
        if target.relative_to(self.root).as_posix() not in files and len(files) >= MAX_FILES:
            raise PathViolation("too many files")
        if sum(f["size"] for f in files.values()) + len(data) > MAX_TOTAL_BYTES:
            raise PathViolation("workspace size limit reached")
        existed = target.exists()
        before = target.read_bytes() if existed else None
        target.parent.mkdir(parents=True, exist_ok=True)
        # re-validate after mkdir (a parent could not have become a symlink, but be strict)
        resolve_in_workspace(self.root, rel)
        target.write_bytes(data)
        action = "created" if not existed else ("unchanged" if before == data else "modified")
        return {"path": rel, "action": action, "sha256": sha256_bytes(data), "size": len(data)}

    def read_file(self, rel: str) -> str:
        target = resolve_in_workspace(self.root, rel)
        if not target.is_file():
            raise WorkspaceError("file not found")
        return target.read_text("utf-8", errors="replace")

    def list_files(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        if not self.root.is_dir():
            return out
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            for name in sorted(filenames):
                p = Path(dirpath) / name
                if p.is_symlink() or "__pycache__" in p.parts:
                    continue
                rel = p.relative_to(self.root).as_posix()
                data = p.read_bytes()
                out[rel] = {"size": len(data), "sha256": sha256_bytes(data)}
        return out

    # -- snapshots & diffs ---------------------------------------------------
    def snapshot(self, label: str) -> dict[str, str]:
        dest = self.snap_root / label
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True)
        hashes = {}
        for rel, meta in self.list_files().items():
            src = self.root / rel
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest / rel)
            hashes[rel] = meta["sha256"]
        return hashes

    def diff_against(self, label: str) -> list[dict]:
        base = self.snap_root / label
        changes = []
        current = self.list_files()
        seen = set()
        for rel in sorted(current):
            seen.add(rel)
            old_path = base / rel
            new = (self.root / rel).read_text("utf-8", errors="replace")
            if not old_path.exists():
                changes.append({"path": rel, "status": "added", "diff": _udiff("", new, rel)})
                continue
            old = old_path.read_text("utf-8", errors="replace")
            if old != new:
                changes.append({"path": rel, "status": "modified", "diff": _udiff(old, new, rel)})
        if base.is_dir():
            for dirpath, _, filenames in os.walk(base):
                for n in filenames:
                    rel = (Path(dirpath) / n).relative_to(base).as_posix()
                    if rel not in seen:
                        changes.append({"path": rel, "status": "deleted", "diff": ""})
        return changes


def _udiff(old: str, new: str, rel: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{rel}", f"b/{rel}", n=3))
