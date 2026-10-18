# ADR-0001: Runnable edition uses Starlette + SQLite + stdlib instead of FastAPI/PostgreSQL/Next.js

Status: accepted (October 2026)

## Context
The specification recommends Next.js, FastAPI, SQLAlchemy/Alembic, PostgreSQL, Redis and Celery. The environment this
edition was built in blocks PyPI and npm, so those packages could not be installed or tested. Only Starlette, Pydantic,
Uvicorn, `sqlite3` and `unittest` were available.

## Decision
Build a complete, *tested* edition on what is available, keeping the specification's module boundaries, data model, API
contract, state machine and security rules unchanged:

| Spec | This edition | Port path |
|---|---|---|
| FastAPI | Starlette (FastAPI is a thin layer over it) + Pydantic v2 schemas | Wrap handlers with FastAPI routers; schemas already Pydantic |
| SQLAlchemy/Alembic/PostgreSQL | `sqlite3`, versioned SQL migrations in `core/db.py`, same tables/constraints | Translate migration 1 to Alembic; `Database` is the only SQL entry point |
| Redis + Celery | `jobs` table + lease-based worker (`orchestration/worker.py`) | Replace `Worker.claim` with a Celery task calling `Engine.process_job` |
| Next.js | Dependency-free SPA in `autoforge/static` | UI only calls `/api/v1`; any frontend can replace it |
| Docker sandbox | Linux user/mount/net/pid namespaces + chroot (`sandbox/`) | Add a Docker/gVisor backend behind `SandboxRunner.run` |

## Consequences
+ Everything claimed in the README is executed by the test-suite.
- SQLite limits concurrency to one writer; single-node only. Not for multi-tenant cloud use.
- `jobs`-table queue is simple and durable but not horizontally scalable.
