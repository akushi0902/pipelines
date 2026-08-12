"""ExplanationBundle — single source of truth for model output and server validation.

This schema is used simultaneously as:
  - The structured-output schema sent to the model (formatting pass)
  - The server-side validation model for incoming AI output

AC-1: No second hand-written shape exists.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


class RemediationDetail(BaseModel):
    """Remediation action for a single finding, linked to one tool."""

    model_config = ConfigDict(frozen=True)

    tool: str
    """Name of the recommended tool.  Validated against ReferenceTool enum post-parse."""

    change_summary: str
    """Plain-language description of the required configuration change."""

    config_snippet: Optional[str] = None
    """Optional before/after YAML or shell snippet illustrating the fix."""


class FindingExplanation(BaseModel):
    """Why-it-matters narrative for one deterministic finding."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    """Reference key matching the deterministic finding (assigned by the explanation pass)."""

    why_it_matters: str
    """Plain-language explanation of the security impact."""

    business_impact: str
    """Business-level framing — what goes wrong for the organisation if unaddressed."""

    attack_scenario: str
    """Concrete attack scenario illustrating exploitation of this weakness."""

    reference_tools: list[str] = []
    """Approved tool names that can detect or remediate this weakness.

    Critical and High findings must contain at least one approved tool.
    Invalid tool names are dropped and replaced by a deterministic fallback.
    """

    remediation: RemediationDetail
    """Primary remediation action."""

    @field_validator("why_it_matters", "business_impact", "attack_scenario", mode="before")
    @classmethod
    def _no_certification_language(cls, v: str) -> str:
        """Guard against BR-02 language (no completeness / certification claims)."""
        # The SLSA sanitizer and content guard handle the full set; this is a
        # fast-fail for the most egregious patterns.
        lower = v.lower()
        for phrase in ("fully secure", "is secure", "certified secure", "guaranteed secure"):
            if phrase in lower:
                raise ValueError(
                    f"Narrative may not assert that a pipeline is '{phrase}'. "
                    "Use factual, non-certifying language."
                )
        return v


class CandidateAnchor(BaseModel):
    """Source location cited by an AI-proposed candidate finding."""

    model_config = ConfigDict(frozen=True)

    start_line: int
    """1-indexed start line of the suspicious section."""

    end_line: int
    """1-indexed end line (inclusive).  May equal start_line for single-line issues."""

    excerpt: str
    """Verbatim excerpt from the definition at this anchor.

    The anchor validator verifies this string appears as a substring of the
    target line in the redacted document.  If it does not match, the candidate
    is suppressed.
    """


class CandidateFindingItem(BaseModel):
    """AI-proposed long-tail candidate finding requiring human review."""

    model_config = ConfigDict(frozen=True)

    title: str
    """Short finding title."""

    category: str
    """One of the nine control categories (e.g. secrets_hygiene, signing_provenance)."""

    anchor: CandidateAnchor
    """Line anchor that the AI validator must resolve before this candidate is accepted."""

    rationale: str
    """Explanation of why this constitutes a security risk."""


class ExplanationBundle(BaseModel):
    """Full model output for the explanation pass.

    Produced by the formatting pass as strict JSON.
    Validated server-side via Pydantic v2 before any item is persisted.
    """

    model_config = ConfigDict(frozen=True)

    finding_explanations: list[FindingExplanation] = []
    """One explanation per deterministic finding (may be a subset if the model skips some)."""

    candidate_findings: list[CandidateFindingItem] = []
    """Advisory long-tail candidates proposed by the model.

    All must pass ExplanationAnchorValidator before being persisted.
    Each is persisted with source='ai', requires_human_review=True, weight=0.
    """
