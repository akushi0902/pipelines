"""Control coverage state machine for PipelineShield (WO-018).

The ControlEvaluator consumes rule outcomes from the RuleEngine plus the
PipelineIR fragment resolution map, and produces for every enabled control
in the catalogue exactly one ControlEvaluation with state Present, Partial,
Missing or Not Assessable.

Exports the assessable_weight_total denominator for the scoring engine and
a CoverageReport listing every excluded fragment so the report view can render
the coverage-limitation banner.
"""
from .control_evaluator import ControlEvaluator
from .models import (
    BannerPayload,
    ControlEvaluation,
    ControlState,
    CoverageEvaluationError,
    CoverageReport,
    CoverageStats,
    ExcludedFragment,
    ExclusionReason,
)

__all__ = [
    "BannerPayload",
    "ControlEvaluation",
    "ControlEvaluator",
    "ControlState",
    "CoverageEvaluationError",
    "CoverageReport",
    "CoverageStats",
    "ExcludedFragment",
    "ExclusionReason",
]
