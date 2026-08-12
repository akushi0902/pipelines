"""Value objects for the architecture blueprint (WO-026).

All models are frozen dataclasses — no SQLAlchemy, FastAPI, or Pydantic
imports.  These are the pure-domain representations produced by
ArchitectureRecommender.recommend().  The API layer converts them to
Pydantic response models in api/v1/schemas/architecture.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ReferenceToolEntry:
    """A named reference tool with an optional purpose annotation."""

    name: str
    purpose: str = ""


@dataclass(frozen=True)
class ControlEntry:
    """Status of a single catalogue control within a lifecycle stage.

    status values:
      satisfied     — evidence confirms the control is in place.
      partial       — some evidence satisfied, some violated.
      missing       — evidence of violation; control not in place.
      not_assessable — fragment could not be inspected; no verdict possible.

    Reference tools are always present for missing/partial controls (enforced
    by ArchitectureRecommender).  They are empty for not_assessable controls
    and may be present for satisfied controls as informational guidance.
    """

    control_id: str
    category: str
    severity: str
    status: str  # satisfied | partial | missing | not_assessable
    reference_tools: tuple[ReferenceToolEntry, ...]
    rationale: str
    advisory_narrative_present: bool = False


@dataclass(frozen=True)
class StageBlueprint:
    """All controls mapped to one lifecycle stage, ordered deterministically."""

    stage_id: str
    display_name: str
    order: int
    controls: tuple[ControlEntry, ...]


@dataclass(frozen=True)
class GapSummary:
    """Aggregate counts of gap statuses across all stages."""

    missing_count: int
    partial_count: int
    not_assessable_count: int


@dataclass(frozen=True)
class CoverageLimitationRef:
    """A single coverage limitation inherited from the normalization phase."""

    scope: str   # fragment_id (kind:locator) or kind string
    reason: str  # human-readable explanation


@dataclass(frozen=True)
class ArchitectureBlueprint:
    """Full deterministic secure-pipeline blueprint for one analysis.

    This value object is the return type of ArchitectureRecommender.recommend().
    Two calls with the same inputs produce byte-identical blueprints.
    LLM output may only populate advisory_narrative_present=True on individual
    ControlEntry objects; it may never alter stage membership, status, or tools.
    """

    analysis_id: str
    catalogue_version: int
    generated_at: str          # ISO-8601 UTC timestamp set by the service layer
    advisory_disclaimer: str
    stages: tuple[StageBlueprint, ...]
    coverage_limitations: tuple[CoverageLimitationRef, ...]
    gap_summary: GapSummary
