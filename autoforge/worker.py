"""Stand-alone worker process: `python -m autoforge.worker` (use with INLINE_WORKER=0 on the API)."""
from __future__ import annotations

import logging
import signal
import threading

from autoforge.core.config import load_settings
from autoforge.core.db import Database
from autoforge.orchestration.engine import Engine
from autoforge.orchestration.worker import Worker
from autoforge.storage.local import LocalArtifactStore


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    s = load_settings()
    worker = Worker(Engine(Database(s.database_path), s, LocalArtifactStore(s.artifact_root)), s.worker_poll_seconds, s.lease_seconds)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    worker.start()
    logging.getLogger("autoforge").info("worker %s started", worker.worker_id)
    stop.wait()
    worker.stop()  # graceful: finishes the current job, un-leased jobs stay queued


if __name__ == "__main__":
    main()
