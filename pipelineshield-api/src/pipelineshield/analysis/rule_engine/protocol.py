"""Rule engine protocol types.

All types here are pure Python — no framework or network imports.

Design:
  Rule         — Protocol that every security rule must satisfy.
  EvidenceAnchor — Source-location evidence attached to a violated finding.
  RuleOutcome  — Result of evaluating one Rule against one IR.
  RuleError    — Captures a rule that raised an exception (error isolation).
  EvaluationResult — Aggregate result from RuleEngine.evaluate().
  EvaluationContext — Caller-supplied observability metadata.
  MetricsEmitter — Protocol for emitting rule-engine telemetry.
"""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Protocol, runtime_checkable

from pipelineshield.analysis.ir.pipeline_ir import PipelineIR


# ---------------------------------------------------------------------------
# Verdict enum
# ---------------------------------------------------------------------------


class RuleOutcomeVerdict(str, enum.Enum):
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    NOT_ASSESSABLE = "not_assessable"


# ---------------------------------------------------------------------------
# Evidence anchor
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceAnchor:
    """Source-location anchor attached to a violated rule outcome.

    Maps back to the original pipeline definition using 1-based line/column.
    end_line is optional; omit for single-line anchors.
    """

    start_line: int
    start_column: int
    end_line: int | None = None
    label: str = ""

    def sort_key(self) -> tuple[int, int]:
        return (self.start_line, self.start_column)


# ---------------------------------------------------------------------------
# Rule outcome
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleOutcome:
    """Result of evaluating one predicate rule against a PipelineIR.

    Fields:
      control_id      — catalogue control identifier (e.g. "sh-001")
      rule_id         — stable rule identifier (e.g. "unpinned-action-ref")
      verdict         — satisfied / violated / not_assessable
      anchors         — non-empty for violated; empty otherwise
      evidence_kind   — short tag describing the evidence type (e.g. "action_ref")
      fingerprint     — deterministic SHA-256 hex of (rule_id, control_id, anchors)
    """

    control_id: str
    rule_id: str
    verdict: RuleOutcomeVerdict
    anchors: tuple[EvidenceAnchor, ...]
    evidence_kind: str
    fingerprint: str

    @staticmethod
    def compute_fingerprint(
        rule_id: str,
        control_id: str,
        anchors: tuple[EvidenceAnchor, ...],
    ) -> str:
        anchor_str = ",".join(
            f"{a.start_line}:{a.start_column}" for a in sorted(anchors, key=lambda a: a.sort_key())
        )
        raw = f"{rule_id}|{control_id}|{anchor_str}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def sort_key(self) -> tuple[str, str, int, int, str]:
        first = self.anchors[0] if self.anchors else None
        return (
            self.control_id,
            self.rule_id,
            first.start_line if first else 0,
            first.start_column if first else 0,
            self.fingerprint,
        )


# ---------------------------------------------------------------------------
# Rule error (exception isolation wrapper)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleError:
    """Records a rule that raised an exception during evaluation.

    The affected control is downgraded to not_assessable; the rest of the
    evaluation continues.
    """

    rule_id: str
    control_id: str
    exc_type: str
    message: str
    correlation_id: str = ""


# ---------------------------------------------------------------------------
# Per-rule telemetry
# ---------------------------------------------------------------------------


@dataclass
class RuleTelemetry:
    """Per-rule execution metadata emitted for observability."""

    rule_id: str
    control_id: str
    duration_ms: float
    verdict: RuleOutcomeVerdict | None = None
    outcome_count: int = 0
    errored: bool = False


# ---------------------------------------------------------------------------
# Evaluation context
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvaluationContext:
    """Caller-supplied observability metadata injected into engine logs.

    No security or evaluation logic depends on context values.
    """

    correlation_id: str = ""
    workspace_id: str = ""
    analysis_id: str = ""
    catalogue_version: str = ""
    source_format: str = ""


# ---------------------------------------------------------------------------
# Evaluation result
# ---------------------------------------------------------------------------


@dataclass
class EvaluationResult:
    """Aggregate result returned by RuleEngine.evaluate().

    outcomes         — deterministically sorted, deduped rule outcomes
    rule_telemetry   — per-rule duration and verdict counts
    rule_errors      — rules that raised exceptions (not_assessable)
    budget_exceeded  — True when a budget guard (node or wall-clock) fired
    budget_detail    — human-readable description of which budget fired
    total_rules_evaluated — total number of rules that ran (including errored)
    total_rules_skipped   — rules skipped due to format mismatch
    """

    outcomes: list[RuleOutcome] = field(default_factory=list)
    rule_telemetry: list[RuleTelemetry] = field(default_factory=list)
    rule_errors: list[RuleError] = field(default_factory=list)
    budget_exceeded: bool = False
    budget_detail: str = ""
    total_rules_evaluated: int = 0
    total_rules_skipped: int = 0


# ---------------------------------------------------------------------------
# Rule Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Rule(Protocol):
    """Protocol that every security rule must satisfy.

    Rules are registered in a RuleRegistry and evaluated by the RuleEngine.
    All attributes must be set at class/instance level (not computed at
    evaluation time) so the registry can validate them at registration.

    Attributes:
      rule_id          — stable, unique identifier (snake_case, max 128 chars)
      control_id       — catalogue control this rule evaluates
      category         — catalogue category id (e.g. "least_privilege")
      applicable_formats — set of source_format strings this rule targets
      severity_key     — key looked up in catalogue snapshot (never hardcoded)
      evidence_kind    — tag for the evidence type produced (e.g. "action_ref")
      anchor_extractor — callable: (ir, node) → Iterator[EvidenceAnchor]
                         must be set and callable; validated at registration

    evaluate(ir, catalogue_snapshot) must return an iterable of RuleOutcome.
    """

    rule_id: str
    control_id: str
    category: str
    applicable_formats: set[str]
    severity_key: str
    evidence_kind: str
    anchor_extractor: Callable[..., Iterator[EvidenceAnchor]]

    def evaluate(self, ir: PipelineIR, catalogue_snapshot: Any) -> Iterator[RuleOutcome]:
        ...


# ---------------------------------------------------------------------------
# MetricsEmitter Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class MetricsEmitter(Protocol):
    """Protocol for emitting rule-engine telemetry.

    All methods must be non-blocking.  The NullMetricsEmitter is the default.
    """

    def observe_duration(self, name: str, value_ms: float, labels: dict[str, str]) -> None:
        ...

    def increment(self, name: str, labels: dict[str, str]) -> None:
        ...


class NullMetricsEmitter:
    """No-op MetricsEmitter used in tests and when no exporter is configured."""

    def observe_duration(self, name: str, value_ms: float, labels: dict[str, str]) -> None:
        pass

    def increment(self, name: str, labels: dict[str, str]) -> None:
        pass
