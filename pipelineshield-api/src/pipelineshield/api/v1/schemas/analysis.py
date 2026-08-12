"""Pydantic v2 request and response models for the Analysis ingestion API.

Request A (paste):
    POST /api/v1/analyses  Content-Type: application/json
    Body: PasteAnalysisRequest

Request B (upload):
    POST /api/v1/analyses  Content-Type: multipart/form-data
    Parts: file (UploadFile) + optional declared_format field

Response 201:
    AnalysisResponse

All error responses follow RFC 7807 with an additional constraint field.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "PipelineFormat",
    "PasteAnalysisRequest",
    "AnalysisResponse",
    "AnalysisSummaryResponse",
    "FormatConfirmationRequest",
    "FormatConfirmationResponse",
    "IngestionErrorResponse",
    "PAYLOAD_MAX_BYTES",
    "ADVISORY_DISCLAIMER",
]

PAYLOAD_MAX_BYTES: int = 512 * 1024  # 512 KB

ADVISORY_DISCLAIMER: str = (
    "This analysis is provided for informational purposes only. "
    "PipelineShield findings are advisory and do not constitute a guarantee "
    "of security or compliance. Validate all findings with your security team "
    "before making deployment decisions."
)


class PipelineFormat(str, Enum):
    github_actions = "github_actions"
    gitlab_ci = "gitlab_ci"
    jenkins = "jenkins"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class PasteAnalysisRequest(BaseModel):
    """Request model for text-paste ingestion (application/json)."""

    model_config = ConfigDict(extra="forbid")

    definition_text: str = Field(
        ...,
        description=(
            "Full text of the pipeline definition. Must be non-empty and "
            "at most 512 KB (524,288 bytes) encoded as UTF-8."
        ),
    )
    filename: str | None = Field(
        None,
        description="Optional original filename (e.g. .github/workflows/ci.yml).",
        max_length=255,
    )
    declared_format: PipelineFormat | None = Field(
        None,
        description=(
            "Optional caller-declared format. When provided and the detected "
            "format differs, format_confirmation_required is set to true."
        ),
    )

    @field_validator("definition_text")
    @classmethod
    def _not_empty_and_within_size(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError(
                "definition_text must not be empty or whitespace-only. "
                "constraint=non_empty_content"
            )
        encoded = v.encode("utf-8", errors="replace")
        if len(encoded) > PAYLOAD_MAX_BYTES:
            raise ValueError(
                f"definition_text exceeds the 512 KB limit "
                f"({len(encoded)} > {PAYLOAD_MAX_BYTES} bytes). "
                "constraint=max_bytes=524288"
            )
        return v


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class AnalysisResponse(BaseModel):
    """201 response for a successfully created analysis."""

    analysis_id: uuid.UUID
    workspace_id: uuid.UUID
    catalogue_version_id: uuid.UUID
    created_at: datetime
    detected_format: str
    format_confidence: float = Field(ge=0.0, le=1.0)
    format_confirmation_required: bool
    coverage_report: dict[str, Any]
    advisory_disclaimer: str


# ---------------------------------------------------------------------------
# Error response (RFC 7807)
# ---------------------------------------------------------------------------


class AnalysisSummaryResponse(BaseModel):
    """Summary-scoped analysis response for the engineering_manager persona.

    Omits per-finding evidence, definition excerpts, and coverage details.
    Selected by the service layer when the actor's scope is analysis:read:summary;
    never by conditional field stripping inside a router.
    """

    analysis_id: uuid.UUID
    workspace_id: uuid.UUID
    catalogue_version_id: uuid.UUID
    created_at: datetime
    detected_format: str
    score: int
    grade: str


# ---------------------------------------------------------------------------
# Error response (RFC 7807)
# ---------------------------------------------------------------------------


class FormatConfirmationRequest(BaseModel):
    """Request body for POST /api/v1/analyses/{id}/format-confirmation."""

    model_config = ConfigDict(extra="forbid")

    confirmed_format: PipelineFormat = Field(
        ...,
        description=(
            "The user-confirmed pipeline format. "
            "Must be one of: github_actions, gitlab_ci, jenkins."
        ),
    )


class FormatConfirmationResponse(BaseModel):
    """200 response for a successful format confirmation."""

    analysis_id: uuid.UUID
    confirmed_format: str
    format_confirmed_by_user: bool


# ---------------------------------------------------------------------------
# Error response (RFC 7807)
# ---------------------------------------------------------------------------


class IngestionErrorResponse(BaseModel):
    """RFC 7807 structured error body for all 4xx/5xx responses."""

    type: str
    title: str
    status: int
    detail: str
    correlation_id: str
    constraint: str | None = None
    parse_line: int | None = None
    parse_column: int | None = None
    errors: list[dict[str, Any]] = Field(default_factory=list)
