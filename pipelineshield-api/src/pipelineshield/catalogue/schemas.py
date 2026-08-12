"""Pydantic v2 schemas for the versioned control catalogue.

Validation rules enforced at the Pydantic boundary (not ad-hoc if-blocks):
- Enabled category weights must sum to exactly 100.
- Category IDs must be unique across the snapshot.
- Control IDs must be unique across the snapshot.
- Severity must be a member of the Severity enum.
- Grade bands must cover 0-100 contiguously with no overlaps or gaps.
- At least one category must be enabled.
- AI-advisory controls must carry weight_contribution == 0.
- Critical and High controls must have at least one entry in reference_tools.
"""
from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class CatalogueValidationError(ValueError):
    """Raised when a CatalogueSnapshot fails domain validation.

    Carries a machine-readable field path and the offending value so the
    API layer can map it to an RFC 7807-style 400 response.
    """

    def __init__(self, message: str, field: str = "", value: Any = None) -> None:
        super().__init__(message)
        self.field = field
        self.value = value


class CatalogueVersionConflictError(RuntimeError):
    """Raised when create_version is called with an already-used version number.

    Callers should treat this as a retryable conflict (HTTP 409).
    """


class CatalogueIntegrityError(RuntimeError):
    """Raised when a stored catalogue checksum does not match the computed one.

    Fails the analysis closed with a 503 and a correlation id rather than
    scoring against a possibly tampered catalogue.
    """


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ControlSource(str, enum.Enum):
    """Source policy for a control definition.

    deterministic — rule-engine evaluated; may carry non-zero weight.
    ai_advisory   — AI-generated advisory; structurally constrained to
                    weight_contribution == 0 so no AI-sourced control
                    can influence the organisational score.
    """

    DETERMINISTIC = "deterministic"
    AI_ADVISORY = "ai_advisory"


class ControlDefinition(BaseModel):
    """A single security control within a category."""

    id: str = Field(..., min_length=1, max_length=64)
    category_id: str = Field(..., min_length=1, max_length=64)
    severity: Severity
    enabled: bool = True
    reference_tools: list[str] = Field(default_factory=list)
    remediation_template_ref: str | None = None
    source: ControlSource = ControlSource.DETERMINISTIC
    weight_contribution: float = Field(default=0.0, ge=0.0)

    model_config = {"frozen": True}


class ControlCategory(BaseModel):
    """One of the nine scoring categories.

    ``weight`` is the category's contribution to the 100-point score.
    Disabled categories are excluded from the weight total check and the
    scoring denominator so they do not silently skew results.
    """

    id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=255)
    weight: int = Field(..., ge=0, le=100)
    enabled: bool = True
    description: str = ""
    controls: list[ControlDefinition] = Field(default_factory=list)

    model_config = {"frozen": True}


class GradeBand(BaseModel):
    """Maps an integer score range [min_score, max_score] to a letter grade.

    Ranges are inclusive on both ends.  The full set of grade bands across
    a snapshot must cover 0-100 exactly with no overlaps or gaps.
    """

    grade: str = Field(..., min_length=1, max_length=2)
    min_score: int = Field(..., ge=0, le=100)
    max_score: int = Field(..., ge=0, le=100)

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def _min_lte_max(self) -> "GradeBand":
        if self.min_score > self.max_score:
            raise ValueError(
                f"GradeBand {self.grade!r}: min_score {self.min_score} "
                f"exceeds max_score {self.max_score}"
            )
        return self


class CatalogueSnapshot(BaseModel):
    """Complete, validated catalogue snapshot stored as a single JSONB document.

    This is the unit of immutability: every publish produces a new snapshot
    row; existing rows are never mutated.
    """

    categories: list[ControlCategory]
    grade_bands: list[GradeBand]

    model_config = {"frozen": True}

    # ------------------------------------------------------------------
    # Model validators — run in definition order after field validation.
    # Each raises ValueError so Pydantic wraps them in ValidationError.
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def _at_least_one_enabled_category(self) -> "CatalogueSnapshot":
        if not any(c.enabled for c in self.categories):
            raise ValueError(
                "CatalogueSnapshot must have at least one enabled category; "
                "all categories are disabled."
            )
        return self

    @model_validator(mode="after")
    def _enabled_weights_total_100(self) -> "CatalogueSnapshot":
        total = sum(c.weight for c in self.categories if c.enabled)
        if total != 100:
            raise ValueError(
                f"Enabled category weights must total exactly 100; got {total}."
            )
        return self

    @model_validator(mode="after")
    def _unique_category_ids(self) -> "CatalogueSnapshot":
        ids = [c.id for c in self.categories]
        seen: set[str] = set()
        dupes = {i for i in ids if i in seen or seen.add(i)}  # type: ignore[func-returns-value]
        if dupes:
            raise ValueError(f"Duplicate category IDs: {sorted(dupes)}")
        return self

    @model_validator(mode="after")
    def _unique_control_ids(self) -> "CatalogueSnapshot":
        all_ids: list[str] = [
            ctrl.id for cat in self.categories for ctrl in cat.controls
        ]
        seen: set[str] = set()
        dupes = {i for i in all_ids if i in seen or seen.add(i)}  # type: ignore[func-returns-value]
        if dupes:
            raise ValueError(f"Duplicate control IDs: {sorted(dupes)}")
        return self

    @model_validator(mode="after")
    def _ai_advisory_controls_have_zero_weight(self) -> "CatalogueSnapshot":
        violations = [
            ctrl.id
            for cat in self.categories
            for ctrl in cat.controls
            if ctrl.source == ControlSource.AI_ADVISORY and ctrl.weight_contribution != 0.0
        ]
        if violations:
            raise ValueError(
                f"AI-advisory controls must have weight_contribution == 0; "
                f"non-zero weight found on: {sorted(violations)}"
            )
        return self

    @model_validator(mode="after")
    def _critical_high_controls_have_reference_tools(self) -> "CatalogueSnapshot":
        _high_severity = {Severity.CRITICAL, Severity.HIGH}
        violations = [
            ctrl.id
            for cat in self.categories
            for ctrl in cat.controls
            if ctrl.severity in _high_severity and not ctrl.reference_tools
        ]
        if violations:
            raise ValueError(
                f"Critical and High severity controls must specify at least one "
                f"reference_tool; empty reference_tools found on: {sorted(violations)}"
            )
        return self

    @model_validator(mode="after")
    def _grade_bands_cover_0_to_100(self) -> "CatalogueSnapshot":
        if not self.grade_bands:
            raise ValueError("grade_bands must not be empty.")
        bands = sorted(self.grade_bands, key=lambda b: b.min_score)
        if bands[0].min_score != 0:
            raise ValueError(
                f"Grade bands must start at 0; first band starts at {bands[0].min_score}."
            )
        if bands[-1].max_score != 100:
            raise ValueError(
                f"Grade bands must end at 100; last band ends at {bands[-1].max_score}."
            )
        for i in range(1, len(bands)):
            expected_next = bands[i - 1].max_score + 1
            if bands[i].min_score != expected_next:
                raise ValueError(
                    f"Grade band gap or overlap between "
                    f"{bands[i-1].grade!r} (ends {bands[i-1].max_score}) "
                    f"and {bands[i].grade!r} (starts {bands[i].min_score}); "
                    f"expected next band to start at {expected_next}."
                )
        return self
