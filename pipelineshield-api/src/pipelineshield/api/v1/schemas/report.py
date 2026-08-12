"""Pydantic v2 models for the AnalysisReport response payload (WO-021).

AnalysisReport is the single source of truth for:

- GET /api/v1/analyses/{id} response_model
- POST /api/v1/analyses response_model (embedded in AnalysisCreatedReport)
- JSON/SARIF/PDF export downstream consumers
- OpenAPI schema -> generated TypeScript client

Business rule BR-02: No field, label, or narrative may claim a pipeline is
secure, compliant, or certified. The advisory_disclaimer field must always
be populated from ADVISORY_DISCLAIMER; model validation rejects blank.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from pipelineshield.api.v1.schemas.analysis import ADVISORY_DISCLAIMER

__all__ = [
    "AnchorDetail",
    "FindingSummary",
    "CategoryScoreItem",
    "SeverityDistribution",
    "CoverageLimitationItem",
    "HumanReviewItem",
    "AnalysisReport",
    "ADVISORY_DISCLAIMER",
]


# ---------------------------------------------------------------------------
# Nested models
# ---------------------------------------------------------------------------


class AnchorDetail(BaseModel):
    """Source location anchor for a finding."""

    model_config = ConfigDict(frozen=True)

    start_line: int = Field(
        ...,
        ge=1,
        description="1-indexed start line.",
    )
    end_line: int | None = Field(
        None,
        ge=1,
        description="1-indexed end line (optional).",
    )
    excerpt: str = Field(
        "",
        description="Source text excerpt (secret-masked).",
    )

    @field_validator("end_line")
    @classmethod
    def _end_line_not_before_start_line(
        cls,
        value: int | None,
        info,
    ) -> int | None:
        if value is None:
            return value

        start_line = info.data.get("start_line")
        if start_line is not None and value < start_line:
            raise ValueError("end_line must be greater than or equal to start_line.")

        return value


class FindingSummary(BaseModel):
    """Single finding from the analysis, safe for API response.

    Only deterministic-source findings contribute to scored severity buckets.
    AI-sourced findings always appear in requires_human_review regardless of
    whether they are also listed here.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: uuid.UUID
    control_id: str = Field(
        ...,
        description="Catalogue control identifier (e.g. 'sh-001').",
    )
    category: str = Field(
        ...,
        description="Catalogue category identifier (e.g. 'secrets_hygiene').",
    )
    severity: str = Field(
        ...,
        description="Finding severity: critical, high, medium, low, info.",
    )
    title: str
    anchor: AnchorDetail | None = None
    source: str = Field(
        ...,
        description="Finding origin: 'deterministic' or 'ai'.",
    )
    requires_human_review: bool


class CategoryScoreItem(BaseModel):
    """Per-category scoring breakdown."""

    model_config = ConfigDict(frozen=True)

    category: str = Field(
        ...,
        description="Catalogue category identifier.",
    )
    earned: float = Field(
        ...,
        ge=0.0,
        description="Weighted credit earned.",
    )
    possible: float = Field(
        ...,
        ge=0.0,
        description=(
            "Maximum possible credit "
            "(excludes NOT_ASSESSABLE)."
        ),
    )
    excluded_count: int = Field(
        ...,
        ge=0,
        description="NOT_ASSESSABLE controls excluded.",
    )


class SeverityDistribution(BaseModel):
    """Count of deterministic findings by severity level.

    AI-sourced findings are never counted here — they appear in
    requires_human_review only.
    """

    model_config = ConfigDict(frozen=True)

    critical: int = Field(0, ge=0)
    high: int = Field(0, ge=0)
    medium: int = Field(0, ge=0)
    low: int = Field(0, ge=0)
    informational: int = Field(0, ge=0)


class CoverageLimitationItem(BaseModel):
    """One unresolved fragment that limited assessment coverage.

    The controls listed in affected_control_ids were evaluated as
    NOT_ASSESSABLE because this fragment could not be resolved. Grade
    language describes assessed-control coverage only; these gaps are not
    treated as missing.
    """

    model_config = ConfigDict(frozen=True)

    kind: str = Field(
        ...,
        description=(
            "Fragment kind: scripted_groovy, unresolved_include, "
            "unresolved_extends, unresolved_reference, "
            "unresolved_composite_action, unresolved_reusable_workflow, etc."
        ),
    )
    location: str = Field(
        ...,
        description="File path, line reference, or block identifier.",
    )
    reason: str = Field(
        ...,
        description=(
            "Human-readable explanation of why this fragment was unresolved."
        ),
    )
    affected_control_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Catalogue control IDs rendered NOT_ASSESSABLE "
            "by this limitation."
        ),
    )


class HumanReviewItem(BaseModel):
    """An item that requires human review before action.

    Includes AI-sourced findings (advisory) and NOT_ASSESSABLE controls
    (coverage gaps that cannot be automatically evaluated).
    """

    model_config = ConfigDict(frozen=True)

    finding_id: uuid.UUID | None = Field(
        None,
        description="Finding ID if this is an AI advisory finding.",
    )
    control_id: str = Field(
        ...,
        description="Catalogue control identifier.",
    )
    reason: str = Field(
        ...,
        description=(
            "'ai_advisory' — AI-sourced finding requiring human validation. "
            "'not_assessable' — control could not be automatically evaluated."
        ),
    )


# ---------------------------------------------------------------------------
# Root AnalysisReport model
# ---------------------------------------------------------------------------


class AnalysisReport(BaseModel):
    """Full risk assessment report payload returned by GET /api/v1/analyses/{id}.

    This model is the single source of truth for the API response shape.
    The advisory_disclaimer field is required and non-nullable; model
    validation rejects blank or missing values.

    BR-02 compliance: no field or string in this model asserts that a
    pipeline is secure, compliant, or certified. Grade language describes
    coverage of assessed controls only.
    """

    model_config = ConfigDict(frozen=True)

    analysis_id: uuid.UUID
    workspace_id: uuid.UUID

    format: str = Field(
        ...,
        description=(
            "Detected pipeline format: "
            "github_actions, gitlab_ci, jenkins."
        ),
    )
    format_confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
    )
    catalogue_version: int = Field(
        ...,
        ge=0,
        description="Integer version of the catalogue used for this analysis.",
    )

    # ------------------------------------------------------------------
    # Scoring output
    # ------------------------------------------------------------------

    total_score: float | None = Field(
        None,
        ge=0.0,
        le=100.0,
        description=(
            "Weighted 0-100 score representing coverage of assessed "
            "controls. Null when all controls are NOT_ASSESSABLE "
            "(unscorable)."
        ),
    )
    letter_grade: str | None = Field(
        None,
        description=(
            "Letter grade (A–F) representing assessed-control coverage. "
            "Null when unscorable. A grade does not imply the pipeline is "
            "secure or compliant."
        ),
    )
    unscorable_reason: str | None = Field(
        None,
        description=(
            "Reason scoring could not be performed "
            "(e.g. 'all_not_assessable')."
        ),
    )

    # ------------------------------------------------------------------
    # Category breakdown
    # ------------------------------------------------------------------

    category_scores: list[CategoryScoreItem] = Field(
        default_factory=list,
        description=(
            "Per-category scoring breakdown sorted by category identifier."
        ),
    )

    # ------------------------------------------------------------------
    # Severity distribution
    # ------------------------------------------------------------------

    severity_distribution: SeverityDistribution

    # ------------------------------------------------------------------
    # Findings and coverage
    # ------------------------------------------------------------------

    findings: list[FindingSummary] = Field(
        default_factory=list,
    )

    coverage_limitations: list[CoverageLimitationItem] = Field(
        default_factory=list,
        description=(
            "Unresolved fragments that caused controls to be "
            "NOT_ASSESSABLE. Detection coverage is per-format so "
            "Jenkins gaps are not hidden in aggregate numbers."
        ),
    )

    requires_human_review: list[HumanReviewItem] = Field(
        default_factory=list,
        description=(
            "Items requiring human review: AI advisory findings and "
            "NOT_ASSESSABLE controls. Always present (possibly empty)."
        ),
    )

    # ------------------------------------------------------------------
    # Required non-dismissible disclaimer (BR-02)
    # ------------------------------------------------------------------

    advisory_disclaimer: str = Field(
        ...,
        description=(
            "Non-dismissible advisory disclaimer. Always present. "
            "Populated from the server-side ADVISORY_DISCLAIMER constant."
        ),
    )

    created_at: datetime

    @field_validator("advisory_disclaimer")
    @classmethod
    def _disclaimer_must_not_be_blank(cls, value: str) -> str:
        """Reject blank disclaimer values and enforce the server disclaimer."""

        if not value or not value.strip():
            raise ValueError(
                "advisory_disclaimer must not be blank; "
                "populate from ADVISORY_DISCLAIMER constant."
            )

        if value != ADVISORY_DISCLAIMER:
            raise ValueError(
                "advisory_disclaimer must match the server-side "
                "ADVISORY_DISCLAIMER constant."
            )

        return value

    @field_validator("letter_grade")
    @classmethod
    def _validate_letter_grade(cls, value: str | None) -> str | None:
        """Validate the persisted grade without making completeness claims."""

        if value is None:
            return None

        normalized = value.strip().upper()

        if normalized not in {"A", "B", "C", "D", "E", "F"}:
            raise ValueError("letter_grade must be one of A, B, C, D, E, or F.")

        return normalized
