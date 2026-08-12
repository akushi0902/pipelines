"""Rule engine package — framework-free, pure-Python evaluation runtime.

No FastAPI, SQLAlchemy, HTTP client, or LLM client imports permitted here.
"""
from .engine import RuleEngine, AnalysisEvaluationError
from .protocol import (
    EvidenceAnchor,
    EvaluationContext,
    EvaluationResult,
    Rule,
    RuleError,
    RuleOutcome,
    RuleOutcomeVerdict,
    MetricsEmitter,
    NullMetricsEmitter,
)
from .registry import RuleRegistry

__all__ = [
    "AnalysisEvaluationError",
    "EvaluationContext",
    "EvaluationResult",
    "EvidenceAnchor",
    "MetricsEmitter",
    "NullMetricsEmitter",
    "Rule",
    "RuleEngine",
    "RuleError",
    "RuleOutcome",
    "RuleOutcomeVerdict",
    "RuleRegistry",
]
