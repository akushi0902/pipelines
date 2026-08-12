"""Architecture recommender — deterministic secure-pipeline blueprint engine.

Converts analysis evaluation results into a stage-by-stage secure-pipeline
blueprint.  All logic is pure (no DB, HTTP, or model imports) so the module
is framework-agnostic and fully unit-testable with hand-built fixtures.
"""
from .models import (
    ArchitectureBlueprint,
    ControlEntry,
    CoverageLimitationRef,
    GapSummary,
    ReferenceToolEntry,
    StageBlueprint,
)
from .recommender import ArchitectureRecommender
from .stage_mapping import CONTROL_STAGE_MAP, STAGE_DEFINITIONS, StageDefinition

__all__ = [
    "ArchitectureBlueprint",
    "ArchitectureRecommender",
    "CONTROL_STAGE_MAP",
    "ControlEntry",
    "CoverageLimitationRef",
    "GapSummary",
    "ReferenceToolEntry",
    "STAGE_DEFINITIONS",
    "StageBlueprint",
    "StageDefinition",
]
