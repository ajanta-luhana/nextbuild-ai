# ADR-0002: The model proposes; deterministic services validate and execute
Agent output is parsed into strict Pydantic schemas (`extra=forbid`). File patches pass path validation, task ownership
checks, size/binary limits and symlink checks before touching the workspace. Commands are *names* from an allowlist
(`compile`, `unittest`) mapped to constant argv arrays; model text never reaches a shell, SQL or deployment action.
Repair agents may not modify `tests/` (denied and audited), so a failing check cannot be "fixed" by weakening it.
