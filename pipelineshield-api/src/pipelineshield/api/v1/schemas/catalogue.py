"""Pydantic v2 request and response models for the Catalogue API.

Only the four allowed mutatable fields (weight, enabled, severity,
reference_tools) are accepted by ChangeFields — all others raise 422.
Response models are declared with ``model_config.populate_by_name``
so that FastAPI auto-filters undeclared internal fields.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Shared sub-models
# ---------------------------------------------------------------------------


class GradeBandOut(BaseModel):
    grade: str
    min_score: int
    max_score: int


class ControlOut(BaseModel):
    id: str
    category_id: str
    severity: str
    enabled: bool
    reference_tools: list[str]


class CategoryOut(BaseModel):
    id: str
    name: str
    weight: int
    enabled: bool


# ---------------------------------------------------------------------------
# GET /api/v1/catalogue response
# ---------------------------------------------------------------------------


class CatalogueGetResponse(BaseModel):
    version: int
    status: str
    created_at: datetime
    created_by: str
    grade_bands: list[GradeBandOut]
    categories: list[CategoryOut]
    controls: list[ControlOut]


# ---------------------------------------------------------------------------
# PATCH /api/v1/catalogue request
# ---------------------------------------------------------------------------


class ChangeFields(BaseModel):
    """Constrained field map — only these four fields may be patched.

    ``extra="forbid"`` ensures any unrecognised field name is rejected
    at the Pydantic boundary with a 422, not silently ignored.
    """

    model_config = ConfigDict(extra="forbid")

    weight: int | None = Field(None, ge=0, le=100)
    enabled: bool | None = None
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None
    reference_tools: list[str] | None = None


class ChangeOp(BaseModel):
    """Single change operation within a PATCH change set."""

    target: Literal["category", "control"]
    id: str = Field(..., min_length=1, max_length=64)
    fields: ChangeFields


class CataloguePatchRequest(BaseModel):
    base_version: int = Field(..., ge=1)
    rationale: str = Field(..., min_length=1, max_length=2000)
    changes: list[ChangeOp] = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# PATCH /api/v1/catalogue response
# ---------------------------------------------------------------------------


class DiffEntry(BaseModel):
    path: str
    old_value: Any
    new_value: Any


class CataloguePatchResponse(BaseModel):
    version: int
    created_at: datetime
    created_by: str
    diff: list[DiffEntry]
    snapshot: CatalogueGetResponse


# ---------------------------------------------------------------------------
# RFC 7807-style error body
# ---------------------------------------------------------------------------


class FieldError(BaseModel):
    field: str
    message: str


class ErrorResponse(BaseModel):
    type: str
    title: str
    status: int
    detail: str
    errors: list[FieldError] = Field(default_factory=list)
