"""Local filesystem artifact store (adapter interface is `put/open/delete`)."""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import BinaryIO


class LocalArtifactStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, run_id: str, data: bytes) -> tuple[str, str, int]:
        """Store bytes; returns (opaque storage_key, sha256, size). The key never leaves the server."""
        key = f"{run_id}/{uuid.uuid4().hex}"
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
        return key, hashlib.sha256(data).hexdigest(), len(data)

    def open(self, key: str) -> BinaryIO:
        return open(self._path(key), "rb")

    def delete(self, key: str) -> None:
        try:
            self._path(key).unlink()
        except FileNotFoundError:
            pass

    def _path(self, key: str) -> Path:
        p = (self.root / key).resolve()
        if self.root not in p.parents:
            raise ValueError("invalid storage key")
        return p
