# Threat model and security controls

Scope: the AutoForge control plane (API, worker, dashboard) and the sandbox that runs generated code.
Trust boundaries: browser ↔ API; API/worker ↔ model provider; worker ↔ sandbox; generated project ↔ user.

| # | Threat | Control | Evidence (test) |
|---|---|---|---|
| T1 | Prompt injection in briefs/files/logs | All model input labelled untrusted; output only accepted through strict schemas; model never selects commands | `test_workflow`, `test_units.Schemas` |
| T2 | Malicious generated code | Runs only in namespace sandbox; no network; no host FS; env scrubbed; rlimits; timeout kill | `test_security.SandboxIsolation` |
| T3 | Path traversal / symlink escape | Canonical relative paths only; symlink components rejected; size/binary caps; violation ⇒ `POLICY_BLOCKED` + audit | `PathSafety`, `test_path_traversal_from_agent_blocks_run…` |
| T4 | Shell/SQL injection from model text | Commands are allowlisted names → constant argv; no shell; DB access via parameterized queries | `test_only_allowlisted_commands` |
| T5 | Secret exfiltration/leakage | Provider keys referenced as `env:NAME`, never stored/returned; redaction on events, audit, logs, reports; sandbox env scrubbed; critical secret finding blocks export | `test_provider_secrets_…`, `Redaction`, `test_secret_in_generated_code_blocks_export` |
| T6 | Cross-project access (IDOR) | Ownership join on every project/run/artifact/file/event/stream read and write; 404 (not 403) for foreign IDs; denials audited | `test_cross_user_access_is_denied_everywhere` |
| T7 | CSRF | SameSite=Strict HttpOnly cookie, per-session CSRF token header, Origin check | `test_csrf_token_required_for_mutations` |
| T8 | Test-weakening "repairs" | Repair writes to `tests/` denied and audited | `RepairLoop` |
| T9 | Runaway cost/time | Per-run budgets (calls, wall time, repairs, cost if known) capped by policy; bounded retries; rate limit | `PolicyAndBudgets` |
| T10 | Insecure download | Opaque storage keys, ownership check, `attachment` + `nosniff`, SHA-256 header | `test_full_happy_path` |
| T11 | Accidental deployment | No deployment code exists; export is a ZIP only, behind a human approval gate | design |
| T12 | Audit tampering | `audit_logs` has DB triggers rejecting UPDATE/DELETE | `test_audit_log_is_append_only` |
| T14 | Credential guessing / DNS rebinding | scrypt, lockout, per-IP throttle, generic errors, Host allowlist, loopback bind guard | `PasswordAuth` |
| T13 | Unsafe production config | `Settings.validate` rejects short secret, default allowed hosts, weak sandbox, host networking in production | `ConfigValidation` |

## Known limitations (read before exposing this anywhere)
- Same-kernel isolation: a kernel/namespace escape bug would defeat the sandbox. Use a dedicated VM for untrusted briefs.
- No cgroup memory/PID limits; rlimits are best-effort. A fork bomb is bounded by timeout and process-group kill, not prevented.
- No MFA/SSO; TLS must be terminated by a reverse proxy when exposed beyond localhost.
- SQLite single-writer; one node.
- The built-in scanner is regex-based and not a replacement for SAST, dependency audit or human review. No SBOM tooling in this edition (the manifest says so).
- Rate limiting is in-memory (per process).
- Egress to model providers sends brief and code context to the configured endpoint; the mock provider sends nothing.
