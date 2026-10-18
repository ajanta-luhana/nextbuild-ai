"""Deterministic mock provider: no network, no credentials, repeatable output.

It produces generic CRUD-API plans and code derived from entities found in the brief.
It exists so that the default install and CI exercise the whole workflow for free.
"""
from __future__ import annotations

from autoforge.agents import analysis
from autoforge.providers.base import AgentRequest, ProviderError, ProviderResponse, Usage
from autoforge.templates import python_service as tpl


class MockProvider:
    key = "mock"

    def __init__(self, model: str = "mock-deterministic"):
        self.model = model

    # Usage is unknown for a mock: report None rather than invent numbers.
    def generate(self, request: AgentRequest) -> ProviderResponse:
        handler = getattr(self, f"_{request.schema_name}", None)
        if handler is None:
            raise ProviderError(f"mock provider has no handler for {request.schema_name}", transient=False)
        return ProviderResponse(data=handler(request.context), usage=Usage())

    # -- requirements -----------------------------------------------------
    def _requirements(self, ctx: dict) -> dict:
        entities = analysis.extract_entities(ctx["brief"])
        fr = [{"id": f"FR-{i:03d}", "text": f"Users can create, list, view, update and delete {e} records via the API.", "priority": "must"}
              for i, e in enumerate(entities, 1)]
        fr.append({"id": f"FR-{len(fr) + 1:03d}", "text": "The service exposes a health endpoint.", "priority": "must"})
        nfr = [
            {"id": "NFR-001", "text": "All input is validated and rejected with a consistent error format.", "priority": "must"},
            {"id": "NFR-002", "text": "The project ships with automated tests that pass in an isolated environment.", "priority": "must"},
            {"id": "NFR-003", "text": "No secrets are committed; configuration uses environment variables.", "priority": "must"},
        ]
        return {
            "schema_version": 1, "functional": fr, "non_functional": nfr,
            "assumptions": ["Single-tenant service; authentication is out of scope for the generated v1 and must be added before public exposure.",
                            "Entities are inferred from the brief and use generic fields (name, description, status)."],
            "open_questions": ["Which fields does each entity need beyond the generic defaults?",
                               "Which roles require authentication and authorization?"],
            "risks": [{"id": "RISK-001", "text": "Generated CRUD scaffold does not encode domain-specific business rules.", "severity": "medium"},
                      {"id": "RISK-002", "text": "No authentication in generated v1.", "severity": "high"}],
            "acceptance_criteria": [f"All {len(entities)} entity endpoints pass create/read/update/delete tests.",
                                    "Unit tests exit with code 0 in the sandbox."],
        }

    # -- architecture -----------------------------------------------------
    def _architecture(self, ctx: dict) -> dict:
        entities = analysis.extract_entities(ctx["brief"])
        data_model = [{"name": e, "fields": [{"name": "name", "type": "text"}, {"name": "description", "type": "text"},
                                              {"name": "status", "type": "text"}]} for e in entities]
        routes = [{"method": "GET", "path": "/health", "summary": "Liveness"}]
        for e in entities:
            p = "/api/" + tpl.plural(e)
            routes += [
                {"method": "GET", "path": p, "summary": f"List {e} records"},
                {"method": "POST", "path": p, "summary": f"Create a {e}"},
                {"method": "GET", "path": p + "/{id}", "summary": f"Get a {e}"},
                {"method": "PATCH", "path": p + "/{id}", "summary": f"Update a {e}"},
                {"method": "DELETE", "path": p + "/{id}", "summary": f"Delete a {e}"},
            ]
        mermaid = "graph TD\n  Client[HTTP client] --> API[WSGI API]\n  API --> Store[Store layer]\n  Store --> DB[(SQLite)]"
        return {
            "schema_version": 1,
            "components": [{"name": "WSGI API", "responsibility": "Routing, validation, JSON error format"},
                           {"name": "Store", "responsibility": "Persistence and field validation"},
                           {"name": "SQLite", "responsibility": "Durable storage"}],
            "mermaid": mermaid,
            "adrs": [{"id": "ADR-001", "title": "Stdlib-only generated service",
                      "decision": "Generate a dependency-free Python service.",
                      "rationale": "Verifiable in a network-less sandbox; no supply-chain exposure."}],
            "data_model": data_model, "api_contract": routes,
            "security_boundaries": ["Request body limited to 64 KiB", "All writes validated against entity schema"],
            "deployment_topology": "Single container running `python -m app`; deployment is a separate approved workflow.",
        }

    # -- task plan --------------------------------------------------------
    def _task_plan(self, ctx: dict) -> dict:
        def t(key, title, role, deps, files, reqs, risk="low"):
            return {"key": key, "title": title, "description": title, "agent_role": role, "depends_on": deps,
                    "expected_files": files, "risk": risk, "requirement_ids": reqs}
        return {"schema_version": 1, "tasks": [
            t("T1", "Project scaffold", "implementer", [], ["app/__init__.py", "app/__main__.py", "requirements.txt", ".env.example", ".gitignore", "Dockerfile"], ["NFR-003"]),
            t("T2", "Storage layer", "implementer", ["T1"], ["app/store.py"], ["FR-001", "NFR-001"], "medium"),
            t("T3", "HTTP API", "implementer", ["T2"], ["app/server.py"], ["FR-001"], "medium"),
            t("T4", "Automated tests", "test", ["T3"], ["tests/__init__.py", "tests/helpers.py", "tests/test_api.py"], ["NFR-002"]),
            t("T5", "Documentation", "packaging", ["T1"], ["README.md"], []),
            t("T6", "Code review", "reviewer", ["T4", "T5"], [], ["NFR-001"]),
        ]}

    # -- implementation ---------------------------------------------------
    def _file_patch(self, ctx: dict) -> dict:
        entities = ctx["data_model"]
        fl = analysis.flags(ctx.get("brief", ""))
        files = tpl.render(ctx.get("project_name", "app"), entities, buggy_delete=fl["inject_failure"])
        keys = {
            "T1": ["app/__init__.py", "app/__main__.py", "requirements.txt", ".env.example", ".gitignore", "Dockerfile"],
            "T2": ["app/store.py"], "T3": ["app/server.py"],
            "T4": ["tests/__init__.py", "tests/helpers.py", "tests/test_api.py"],
        }
        if ctx["task_key"] == "T5":
            readme = f"# {ctx.get('project_name', 'Generated project')}\n\nGenerated by AutoForge AI.\n\n## Run\n\n```\npython -m app\n```\n\n## Test\n\n```\npython -m unittest discover -s tests -t .\n```\n"
            out = [{"path": "README.md", "content": readme}]
        else:
            out = [{"path": p, "content": files[p]} for p in keys.get(ctx["task_key"], [])]
        if fl["path_attack"] and ctx["task_key"] == "T1":
            out.append({"path": "../escape.py", "content": "print('escaped')\n"})
        if not out:
            raise ProviderError(f"no files for task {ctx['task_key']}", transient=False)
        return {"schema_version": 1, "files": out}

    # -- repair -----------------------------------------------------------
    def _repair(self, ctx: dict) -> dict:
        fl = analysis.flags(ctx.get("brief", ""))
        failures = " ".join(ctx.get("failures", []))
        if fl["unfixable"] or "delete" not in failures:
            return {"schema_version": 1, "rationale": "No safe minimal fix identified.", "files": [], "modifies_tests": False}
        store = tpl.render_store(ctx["data_model"], buggy_delete=False)
        return {"schema_version": 1, "rationale": "delete() reported success without deleting the row; execute the DELETE statement.",
                "files": [{"path": "app/store.py", "content": store}], "modifies_tests": False}

    # -- review -----------------------------------------------------------
    def _review(self, ctx: dict) -> dict:
        return {"schema_version": 1, "findings": [
            {"severity": "medium", "file": "app/server.py", "line": None,
             "message": "No authentication or rate limiting; do not expose publicly before adding both."}]}
