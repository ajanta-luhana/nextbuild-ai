# Implementation plan and acceptance checklist

Legend: ✅ implemented and covered by an executed test · ⚠️ implemented, partially/untested · ❌ not implemented.
Last full run: 63 unit/API/security/sandbox tests OK + 1 browser E2E OK (Chromium, no console errors).

## Phases
- ✅ 0 Foundation: ADRs, threat model, architecture, repo skeleton.
- ✅ 1 Platform: config validation, migrations, auth/session, project CRUD, health, dashboard shell. ⚠️ Compose file written but not executed (no Docker daemon).
- ✅ 2 Planning: brief wizard, provider interface, deterministic mock, SRS/architecture/task schemas, approve/reject/change-request, plan versions.
- ✅ 3 Orchestration: durable jobs with leases, state machine, DAG, events, SSE with resume, budgets, cancellation, idempotent retry.
- ✅ 4 Generation: curated `python-service` template, safe workspace, snapshots, diffs. ⚠️ Only one template; serial (not parallel) task execution.
- ✅ 5 Verification: namespace sandbox, allowlisted compile/unittest, real exit codes/durations, bounded repair loop.
- ✅ 6 Security/export: scanner, audit (append-only), export approval, ZIP, manifest, SHA-256, verification report. ❌ SBOM (no tooling; manifest says "unavailable"). ❌ Dependency audit tooling (template is stdlib-only; unpinned deps are flagged).
- ✅ 7 Providers: OpenAI-compatible and Anthropic adapters, retry/backoff, usage normalization — tested against a local fake server. ⚠️ **Never run against a live paid API** here.
- ⚠️ 8 Polish: keyboard/ARIA basics, responsive layout, dark mode, CI file, runbook. Not done: automated accessibility audit, load tests, cloud deployment guide, release images.

## Acceptance criteria (AC) status
| AC | Status | Evidence |
|---|---|---|
| 01 compose up | ⚠️ | `compose.yaml`/`Dockerfile` not executed; `make run` is verified |
| 02 project CRUD/archive | ✅ | `test_project_crud_pagination_and_archive` |
| 03 durable run + versioned plan | ✅ | `test_full_happy_path`, `test_projects_have_versions…` |
| 04 explicit plan approval | ✅ | `test_plan_requires_approval_before_generation` |
| 05 mock happy path, no creds | ✅ | `test_full_happy_path`, `demo.py` |
| 06 SSE + reconnect | ✅ | `test_sse_replays_durable_events_and_resumes`; E2E watches live updates |
| 07 illegal transitions/unauthorized audited | ✅ | `test_illegal_transition…`, `access.denied` test |
| 08 budgets/timeouts/retries/cancel | ✅ | `PolicyAndBudgets`, `test_timeout_kills_runaway_process`, provider retry tests |
| 09 commands only in allowlisted sandbox | ✅ | `test_only_allowlisted_commands` |
| 10 traversal blocked, no docker socket/host secrets | ✅ | `PathSafety`, `SandboxIsolation` |
| 11 reports carry command/exit/duration/output | ✅ | `test_full_happy_path` |
| 12 failed stays failed until real rerun passes | ✅ | `RepairLoop.test_unfixable…` |
| 13 repair ≤ max | ✅ | `RepairLoop` |
| 14 diffs + findings before export | ✅ | Code/Verification tabs, E2E |
| 15 export contents + SHA-256 | ✅ | `test_full_happy_path` |
| 16 ownership on downloads, no paths | ✅ | `test_cross_user_access…` |
| 17 no secrets in payloads/logs/exports | ✅ | `test_provider_secrets…`, `test_exported_artifacts_contain_no_secrets` (logs: request log records only method/path/status) |
| 18 provider failure sanitized + classified | ✅ | `WorkflowViaHttpProvider` |
| 19 CI without paid creds | ✅ | `.github/workflows/ci.yml` (written; not run on GitHub) |
| 20 README complete | ✅ | README.md |
| 21 E2E for critical journeys | ✅ | `tests/e2e_browser.py` + API workflow tests |
| 22 no unearned "production-ready" claim | ✅ | report wording asserted in a test |

## Next steps (not done)
Second template, parallel generation with file ownership locks, Postgres/Redis adapters (ADR-0001), Docker/gVisor sandbox backend with cgroup limits, SBOM + dependency audit, password/SSO auth, live-provider smoke test, accessibility audit.
