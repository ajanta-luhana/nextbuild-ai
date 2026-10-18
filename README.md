# NextBuild AI

Turn a product brief into a **reviewed, sandbox-verified, downloadable software project** — with every "tests passed" claim
backed by a command that actually ran (exit code, duration, output).

> This is the *runnable edition* of the AutoForge specification. It keeps the spec's data model, API, state machine and
> security rules, but uses Starlette + SQLite + a dependency-free dashboard because FastAPI/Postgres/Next.js could not be
> installed where it was built. See [ADR-0001](docs/adr/0001-runnable-edition-stack.md) for the mapping and port path.
> It is **not** a promise that any brief becomes production software: the mock provider generates a generic CRUD API
> from the entities named in the brief; quality with real models depends on the model.

## Quick start
Requires Python 3.12+ (tested on 3.13), Linux for the sandbox.
```bash
pip install -r requirements.txt
make run                 # http://127.0.0.1:9100  (mock provider, no credentials)
make test                # 63 tests: API, security, sandbox, providers, workflow
make e2e                 # optional browser journey (playwright + chromium)
make demo                # drives a full run against a running server; add --inject-failure to see repair
```
Open the dashboard, create a workspace name, **New project**, describe what you want
(e.g. *"a recruitment portal with job listings, applications and candidates"*), **Start planning**, review the plan,
approve, watch it generate and verify, approve export, download the ZIP.

## Workflow
`plan → (you approve) → generate → verify in sandbox → repair (≤ N attempts) → (you approve export) → package`.
Two human gates; nothing is deployed, ever. Details: [system overview](docs/architecture/system-overview.md).

## Providers
- **Mock** (default): deterministic, free, used by tests/CI. `[[inject-failure]]` in a brief plants a bug the repair loop must fix;
  `[[unfixable]]` makes it unfixable (run ends `FAILED`); `[[policy-violation]]` simulates a path-traversal attempt.
- **OpenAI-compatible** (local Ollama/vLLM/LM Studio or hosted): Settings → add provider with base URL and model.
- **Anthropic**: Settings → add provider type `anthropic`.
API keys are **never typed into the UI or stored**: give a reference like `env:ANTHROPIC_API_KEY` and export that variable in the server's environment.
With a non-mock provider your brief and code context leave the machine for that endpoint. The adapters are tested against a local fake server only; run a live smoke test yourself before relying on them.

## Security model (summary — full detail in [threat-model.md](docs/threat-model.md))
Model output is untrusted and schema-validated; commands are allowlisted names, never shell strings; generated code runs in
user/mount/net/pid namespaces with no network, no host filesystem, scrubbed env and limits; if that isolation can't be proven at
startup, execution is disabled. Sessions use HttpOnly SameSite=Strict cookies + CSRF tokens; every resource read is ownership-checked;
audit log is append-only; secrets are redacted everywhere.

## Limitations (honest list)
- One template (`python-service`); generated apps have **no authentication** (flagged in every plan and review).
- Same-kernel sandbox, no cgroup limits; use a dedicated VM for untrusted input. Linux only.
- Password accounts (scrypt, lockout, idle timeout, Host allowlist) make it safe beyond one trusted user, but it still binds to localhost by default; exposing it needs `ALLOW_REMOTE_BIND=1`, `ALLOWED_HOSTS` and a TLS reverse proxy. SQLite, single node.
- No SBOM, no dependency audit tooling, regex-based scanner only. Mermaid is shown as source (strict CSP forbids remote scripts).
- Docker files and CI workflow are written but were **not executed** in the authoring environment.
- Providers never exercised against live APIs.

## Layout
```
autoforge/{api,core,domain,agents,providers,orchestration,sandbox,verification,workspace,storage,templates,static}
tests/        unit, API, security, sandbox, provider and workflow tests + browser E2E
docs/         architecture, ADRs, threat model, runbook, implementation plan / acceptance checklist
infra/scripts/demo.py   end-to-end demo
```
Troubleshooting: see the [runbook](docs/runbook.md) (sandbox unavailable, stuck runs, provider outages, backup/restore).

## Forgot the password / locked out
Self-service: "Forgot password?" on the sign-in page with the recovery code shown at sign-up (Account security can create a new one). Optional two-step verification (authenticator app) is in Account security.

Without a recovery code:
On the machine running the server: `python -m autoforge.admin reset-password` (asks for the user name and a new password, also clears the lockout),
`python -m autoforge.admin unlock "user name"`, or `python -m autoforge.admin list`. Set the same `DATABASE_PATH` you start the server with.

## Docker and the sandbox
`compose.yaml` runs generated code inside the container without namespace isolation (Docker Desktop blocks it); the top bar then shows "Sandbox: not isolated".
For the strong sandbox try `docker compose -f compose.yaml -f compose.strong.yaml up --build -d`. To refuse running generated code set `ALLOW_WEAK_SANDBOX=0` in `.env`.
