"""Versioned Pydantic schemas for every agent output (SCHEMA_VERSION 1)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = 1


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Requirement(_Strict):
    id: str = Field(pattern=r"^(FR|NFR)-\d{3}$")
    text: str = Field(min_length=3, max_length=600)
    priority: Literal["must", "should", "could"] = "must"


class Risk(_Strict):
    id: str = Field(pattern=r"^RISK-\d{3}$")
    text: str = Field(min_length=3, max_length=600)
    severity: Literal["low", "medium", "high"] = "medium"


class Requirements(_Strict):
    schema_version: int = SCHEMA_VERSION
    functional: list[Requirement] = Field(min_length=1)
    non_functional: list[Requirement] = Field(min_length=1)
    assumptions: list[str] = []
    open_questions: list[str] = []
    risks: list[Risk] = []
    acceptance_criteria: list[str] = Field(min_length=1)


class Component(_Strict):
    name: str
    responsibility: str


class ADR(_Strict):
    id: str = Field(pattern=r"^ADR-\d{3}$")
    title: str
    decision: str
    rationale: str


class Field_(_Strict):
    name: str = Field(pattern=r"^[a-z_][a-z0-9_]*$")
    type: Literal["text", "integer", "boolean", "timestamp"]


class Entity(_Strict):
    name: str = Field(pattern=r"^[a-z_][a-z0-9_]*$")
    fields: list[Field_] = Field(min_length=1)


class ApiRoute(_Strict):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str = Field(pattern=r"^/[A-Za-z0-9_/{}\-]*$")
    summary: str


class Architecture(_Strict):
    schema_version: int = SCHEMA_VERSION
    components: list[Component] = Field(min_length=1)
    mermaid: str = Field(min_length=10, max_length=4000)
    adrs: list[ADR] = Field(min_length=1)
    data_model: list[Entity] = Field(min_length=1)
    api_contract: list[ApiRoute] = Field(min_length=1)
    security_boundaries: list[str] = []
    deployment_topology: str = ""

    @field_validator("mermaid")
    @classmethod
    def _mermaid_header(cls, v: str) -> str:
        if not v.lstrip().startswith(("graph", "flowchart", "sequenceDiagram", "classDiagram", "erDiagram")):
            raise ValueError("mermaid source must start with a diagram keyword")
        return v


class PlanTask(_Strict):
    key: str = Field(pattern=r"^T\d{1,3}$")
    title: str
    description: str = ""
    agent_role: Literal["implementer", "test", "packaging", "reviewer"]
    depends_on: list[str] = []
    expected_files: list[str] = []
    risk: Literal["low", "medium", "high"] = "low"
    requirement_ids: list[str] = []


class TaskPlan(_Strict):
    schema_version: int = SCHEMA_VERSION
    tasks: list[PlanTask] = Field(min_length=1)


class FileOut(_Strict):
    path: str
    content: str = Field(max_length=200_000)


class FilePatch(_Strict):
    schema_version: int = SCHEMA_VERSION
    files: list[FileOut] = Field(min_length=1, max_length=40)


class RepairProposal(_Strict):
    schema_version: int = SCHEMA_VERSION
    rationale: str
    files: list[FileOut] = Field(max_length=40)
    modifies_tests: bool = False


class ReviewFinding(_Strict):
    severity: Literal["info", "low", "medium", "high", "critical"]
    file: str | None = None
    line: int | None = None
    message: str


class ReviewResult(_Strict):
    schema_version: int = SCHEMA_VERSION
    findings: list[ReviewFinding] = []


SCHEMAS = {
    "requirements": Requirements,
    "architecture": Architecture,
    "task_plan": TaskPlan,
    "file_patch": FilePatch,
    "repair": RepairProposal,
    "review": ReviewResult,
}


def validate_output(schema_name: str, data: dict) -> BaseModel:
    return SCHEMAS[schema_name].model_validate(data)
