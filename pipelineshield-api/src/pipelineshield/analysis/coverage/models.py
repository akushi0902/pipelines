"""Data models for the control coverage state machine (WO-018).

These models are in a separate module from pipelineshield.analysis.ir.pipeline_ir
to avoid confusion with the IR-level CoverageReport. Fully qualified imports
distinguish them:
  analysis.coverage.models.CoverageReport  — evaluator output
  analysis.ir.pipeline_ir.CoverageReport   — normalizer output
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from pipelineshield.analysis.rule_engine.protocol import EvidenceAnchor


class CoverageEvaluationError(Exception):
    """Raised when an outcome references a control_id absent from the catalogue.

    Analysis is failed closed with a 422 rather than producing a partial
    evaluation against a mismatched catalogue.
    """


class ControlState(str, enum.Enum):
    PRESENT = "present"
    PARTIAL = "partial"
    MISSING = "missing"
    NOT_ASSESSABLE = "not_assessable"


class ExclusionReason(str, enum.Enum):
    SCRIPTED_GROOVY = "scripted_groovy"
    UNRESOLVED_INCLUDE = "unresolved_include"
    UNRESOLVED_EXTENDS = "unresolved_extends"
    UNRESOLVED_REFERENCE = "unresolved_reference"
    UNRESOLVED_COMPOSITE_ACTION = "unresolved_composite_action"
    UNRESOLVED_REUSABLE_WORKFLOW = "unresolved_reusable_workflow"
    NO_APPLICABLE_RULE = "no_applicable_rule"
    METADATA_MISSING = "metadata_missing"


@dataclass(frozen=True)
class ControlEvaluation:
    """Result for one enabled control — exactly one per enabled control."""

    control_id: str
    category_id: str
    state: ControlState
    anchors: tuple[EvidenceAnchor, ...]
    unassessable_reason: str | None = None
    weight_contribution: float = 0.0


@dataclass(frozen=True)
class ExcludedFragment:
    """An unresolvable IR fragment that limited coverage assessment.

    fragment_id is derived from kind + ":" + locator for stable cross-analysis
    identity. Duplicates with the same fragment_id are collapsed into one entry.
    """

    fragment_id: str
    exclusion_reason: ExclusionReason
    affected_control_ids: tuple[str, ...]
    anchor: EvidenceAnchor | None = None
    detail: str = ""


@dataclass(frozen=True)
class BannerPayload:
    """Coverage-limitation banner shown when at least one fragment is excluded."""

    summary: str
    affected_control_count: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CoverageStats:
    """Per-format coverage statistics for operational metrics."""

    source_format: str
    assessable_controls: int
    unassessable_controls: int
    excluded_fragment_count: int


@dataclass(frozen=True)
class CoverageReport:
    """Aggregate output of ControlEvaluator.evaluate().

    evaluations:            One ControlEvaluation per enabled control, sorted
                            by control_id.
    excluded_fragments:     Excluded IR fragments, sorted by (reason, fragment_id).
    assessable_weight_total: Sum of weight_contribution over non-not_assessable
                            enabled controls.  Consumed by the scoring engine
                            as the denominator.  Never negative; never exceeds
                            catalogue_weight_total.
    catalogue_weight_total: Sum of weight_contribution over all enabled controls.
    banner:                 Present only when excluded_fragments is non-empty.
    coverage_stats:         Per-format assessment counts for metrics emission.
    """

    evaluations: tuple[ControlEvaluation, ...]
    excluded_fragments: tuple[ExcludedFragment, ...]
    assessable_weight_total: float
    catalogue_weight_total: float
    banner: BannerPayload | None
    coverage_stats: CoverageStats
