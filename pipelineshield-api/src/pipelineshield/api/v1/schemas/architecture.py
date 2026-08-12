"""Pydantic v2 response schemas for the architecture blueprint endpoint (WO-026).

GET /api/v1/analyses/{analysis_id}/architecture

BR-02: No field or string may assert the pipeline is secure, compliant, or
certified.  The advisory_disclaimer field is always non-empty.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from pipelineshield.api.v1.schemas.analysis import ADVISORY_DISCLAIMER


class ReferenceToolOut(BaseModel):
    """A named reference tool for a control gap."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Name of the reference tool.")
    purpose: str = Field("", description="Optional purpose annotation.")


class ControlOut(BaseModel):
    """Blueprint entry for a single catalogue control."""

    model_config = ConfigDict(frozen=True)

    control_id: str = Field(..., description="Catalogue control identifier.")
    category: str = Field(..., description="Catalogue category identifier.")
    severity: str = Field(..., description="critical | high | medium | low | info.")
    status: str = Field(
        ...,
        description="satisfied | partial | missing | not_assessable.",
    )
    reference_tools: list[ReferenceToolOut] = Field(
        default_factory=list,
        description=(
            "At least one entry for every missing/partial control; "
            "empty for not_assessable controls."
        ),
    )
    rationale: str = Field(
        ...,
        description="Factual description of the control status.",
    )
    advisory_narrative_present: bool = Field(
        False,
        description="True when a persisted AI advisory narrative exists.",
    )


class StageOut(BaseModel):
    """All controls mapped to one lifecycle stage."""

    model_config = ConfigDict(frozen=True)

    stage_id: str = Field(..., description="Stable lifecycle stage identifier.")
    display_name: str = Field(..., description="Human-readable stage name.")
    order: int = Field(..., ge=1, description="Sort order (1 = first stage).")
    controls: list[ControlOut] = Field(
        default_factory=list,
        description="Controls for this stage, sorted by severity then control_id.",
    )


class GapSummaryOut(BaseModel):
    """Aggregate counts of gap statuses across all stages."""

    model_config = ConfigDict(frozen=True)

    missing_count: int = Field(..., ge=0)
    partial_count: int = Field(..., ge=0)
    not_assessable_count: int = Field(..., ge=0)


class CoverageLimitationOut(BaseModel):
    """A coverage limitation inherited from the normalization phase."""

    model_config = ConfigDict(frozen=True)

    scope: str = Field(..., description="Fragment scope identifier (kind:locator).")
    reason: str = Field(..., description="Why this fragment was unresolvable.")


class ArchitectureResponse(BaseModel):
    """Full architecture blueprint response.

    This is the response_model for GET /api/v1/analyses/{id}/architecture.
    The blueprint is deterministic: two calls with the same inputs return
    identical JSON apart from generated_at.
    """

    model_config = ConfigDict(frozen=True)

    analysis_id: str = Field(..., description="Analysis UUID.")
    catalogue_version: int = Field(
        ..., description="Catalogue version used to generate this blueprint."
    )
    generated_at: str = Field(..., description="ISO-8601 UTC timestamp of generation.")
    advisory_disclaimer: str = Field(
        ...,
        description="Non-dismissible advisory disclaimer.  Always non-empty.",
    )
    coverage_limitations: list[CoverageLimitationOut] = Field(
        default_factory=list,
        description="Coverage limitations inherited from the normalization phase.",
    )
    stages: list[StageOut] = Field(
        ...,
        description="Lifecycle stages ordered by stage order ascending.",
    )
    gap_summary: GapSummaryOut

    @field_validator("advisory_disclaimer")
    @classmethod
    def _disclaimer_must_not_be_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError(
                "advisory_disclaimer must not be blank; "
                "populate from ADVISORY_DISCLAIMER constant."
            )
        return v

    @field_validator("stages")
    @classmethod
    def _stages_ordered_by_order(cls, v: list[StageOut]) -> list[StageOut]:
        for i in range(1, len(v)):
            if v[i].order <= v[i - 1].order:
                raise ValueError(
                    f"stages must be ordered by ascending 'order'; "
                    f"found {v[i].order} after {v[i - 1].order}."
                )
        return v
