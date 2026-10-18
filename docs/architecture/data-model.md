# Data model
Defined in `autoforge/core/db.py` (migration 1). IDs are UUID strings, timestamps are UTC ISO-8601.

users · projects · project_versions (brief/requirements/architecture/plan snapshots, unique per project+version) ·
provider_configs (**secret references only**) · runs (status, stage, budget, usage, plan JSON, repair_attempts, error code) ·
tasks + task_dependencies (DAG, `CHECK task_id != depends_on`) · agent_events (unique run+sequence, redacted, size-bounded) ·
approvals (plan/export, decision, plan_version) · artifacts (opaque `storage_key` never returned, `sha256`) ·
audit_logs (append-only via triggers) · jobs (durable queue, unique run+step+attempt, lease) ·
verification_results (command, exit code, duration, output summary, sandbox info) · security_findings ·
policies · sessions (hashed token) · notifications.

Differences from the PostgreSQL design in the spec: SQLite types (JSON stored as TEXT), no JSONB indexes, `jobs`,
`verification_results`, `security_findings`, `policies`, `sessions`, `notifications` added to avoid external services.
