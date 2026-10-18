# Operator runbook

## Start / stop
`make run` (API + dashboard + inline worker, http://127.0.0.1:8000). Separate worker: `INLINE_WORKER=0 make run` and `make worker`.
Stop with SIGTERM; the worker finishes its current job, unfinished leases expire and are re-queued automatically.

## Health
`GET /api/v1/health/live`, `GET /api/v1/health/ready` (database, worker, sandbox mode; no secrets). The *Audit & About* page shows the same.

## Sandbox unavailable
Symptom: runs end `POLICY_BLOCKED / SANDBOX_UNAVAILABLE`. Cause: no `unshare`, user namespaces disabled, or running in a container that blocks them.
Fix: run on a host/VM that allows unprivileged user namespaces. Only for trusted local experiments: `ALLOW_WEAK_SANDBOX=1`
(scrubbed env + rlimits, **no network or filesystem isolation**; rejected when `APP_ENV=production`).

## Stuck run
1. `GET /runs/{id}/events` for the last event. 2. `SELECT * FROM jobs WHERE run_id=?` — a `running` job with an expired lease is re-queued by the next worker poll. 3. If the run is `FAILED`, retry with `POST /runs/{id}/retry` and an `Idempotency-Key` header. 4. Otherwise cancel it.

## Provider outage
Transient errors (timeouts, 429, 5xx) retry 3× with backoff; then the run fails `*_FAILED` and is retryable. Permanent errors (401/400, missing key reference) fail immediately with a sanitized message.

## Backup / restore
Stop writers, then copy `DATABASE_PATH` (plus `-wal`/`-shm` if present, or use `sqlite3 db ".backup file"`) and `ARTIFACT_ROOT`. Restore by replacing both with the service stopped. Test a restore periodically: start the app on the copy and open a finished run's artifacts (hashes must match).

## Retention
`RETENTION_DAYS` (policy editable in Settings) and `Engine.purge_expired()` delete artifacts and workspaces of finished runs older than the limit and write audit rows. Wire it to cron: `python -c "from autoforge.core.config import load_settings as L;from autoforge.core.db import Database;from autoforge.orchestration.engine import Engine;from autoforge.storage.local import LocalArtifactStore as S;s=L();print(Engine(Database(s.database_path),s,S(s.artifact_root)).purge_expired())"`.

## Compromised credential
Rotate the provider key in the server environment (the app stores only `env:NAME`), set a new `SESSION_SECRET` (invalidates all sessions), review *Audit* for `provider.*` and `access.denied` events.

## Storage exhaustion
Run retention with a smaller window; workspaces live under `WORKSPACE_ROOT/<run_id>` and can be deleted for finished runs without affecting artifacts.
