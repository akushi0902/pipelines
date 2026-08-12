"""RuleEngine — deterministic, bounded, blast-radius-isolated evaluation runtime.

Design constraints enforced here:
  - No FastAPI, SQLAlchemy, httpx, requests, or LLM client imports.
  - Pure function over (IR, catalogue snapshot) with injected dependencies.
  - One rule raising an exception → that control becomes not_assessable;
    all other rules still run to completion.
  - Budget guards: node-count (checked before evaluation) and wall-clock
    (checked between rules).  Neither guard raises; both produce a
    budget_exceeded outcome recorded in telemetry.
  - Outcomes are deterministically sorted by (control_id, rule_id,
    first_anchor.start_line, first_anchor.start_column, fingerprint).
  - Identical fingerprints are deduplicated (first occurrence wins).
"""
from __future__ import annotations

import logging
import time
from typing import Any

from pipelineshield.analysis.ir.pipeline_ir import PipelineIR

from .accessors import count_ir_nodes, is_format_applicable
from .protocol import (
    EvaluationContext,
    EvaluationResult,
    EvidenceAnchor,
    MetricsEmitter,
    NullMetricsEmitter,
    RuleError,
    RuleOutcome,
    RuleOutcomeVerdict,
    RuleTelemetry,
)
from .registry import RuleRegistry

__all__ = ["RuleEngine", "AnalysisEvaluationError"]

_LOG = logging.getLogger(__name__)

# Default budget values (sized to the ~2.5 s deterministic slice of 30 s budget)
_DEFAULT_MAX_IR_NODES: int = 5_000
_DEFAULT_MAX_WALL_CLOCK_MS: float = 2_500.0


class AnalysisEvaluationError(Exception):
    """Raised for engine-level failures (invalid catalogue, IR schema mismatch).

    The orchestrator maps this to HTTP 422 with a structured body and no stack trace.
    """


class RuleEngine:
    """Evaluates all registered rules against a PipelineIR deterministically.

    Inject via constructor; no module-level singletons.
    """

    def __init__(
        self,
        registry: RuleRegistry,
        metrics: MetricsEmitter | None = None,
        max_ir_nodes: int = _DEFAULT_MAX_IR_NODES,
        max_wall_clock_ms: float = _DEFAULT_MAX_WALL_CLOCK_MS,
        clock: Any = None,
    ) -> None:
        self._registry = registry
        self._metrics = metrics or NullMetricsEmitter()
        self._max_ir_nodes = max_ir_nodes
        self._max_wall_clock_ms = max_wall_clock_ms
        # Injected clock callable (returns monotonic seconds); defaults to time.monotonic
        self._clock: Any = clock if clock is not None else time.monotonic

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        ir: PipelineIR,
        catalogue_snapshot: Any,
        context: EvaluationContext | None = None,
    ) -> EvaluationResult:
        """Evaluate all registered rules against *ir* and *catalogue_snapshot*.

        Returns an EvaluationResult with deterministically sorted outcomes,
        per-rule telemetry, and a list of rule_errors.

        Raises AnalysisEvaluationError only for engine-level failures
        (bad IR type, null catalogue).  Per-rule exceptions are isolated.
        """
        if not isinstance(ir, PipelineIR):
            raise AnalysisEvaluationError(
                f"Expected PipelineIR, got {type(ir).__name__}. "
                "The IR must be a validated PipelineIR instance."
            )
        if catalogue_snapshot is None:
            raise AnalysisEvaluationError(
                "catalogue_snapshot must not be None; "
                "resolve the active snapshot before calling evaluate()."
            )

        ctx = context or EvaluationContext()
        result = EvaluationResult()

        _LOG.info(
            "rule_engine.start correlation_id=%s format=%s rule_count=%d catalogue=%s",
            ctx.correlation_id,
            ir.source_format,
            len(self._registry),
            ctx.catalogue_version,
        )

        wall_start = self._clock()

        # ---- Node budget guard (checked once, before evaluation) --------
        node_count = count_ir_nodes(ir)
        if node_count > self._max_ir_nodes:
            detail = (
                f"IR node count {node_count} exceeds budget {self._max_ir_nodes}. "
                "Analysis downgraded to not_assessable for all controls."
            )
            _LOG.warning(
                "rule_engine.budget_exceeded.nodes count=%d max=%d correlation_id=%s",
                node_count,
                self._max_ir_nodes,
                ctx.correlation_id,
            )
            result.budget_exceeded = True
            result.budget_detail = detail
            self._metrics.increment(
                "rule_engine_budget_exceeded_total",
                {"reason": "node_count", "format": ir.source_format},
            )
            return result

        seen_fingerprints: set[str] = set()
        outcomes: list[RuleOutcome] = []
        telemetry: list[RuleTelemetry] = []
        errors: list[RuleError] = []

        for rule in self._registry.iter_rules():
            # ---- Wall-clock budget guard (checked between rules) --------
            elapsed_ms = (self._clock() - wall_start) * 1000.0
            if elapsed_ms > self._max_wall_clock_ms:
                detail = (
                    f"Wall-clock budget {self._max_wall_clock_ms:.0f} ms exceeded "
                    f"after {elapsed_ms:.1f} ms during rule {rule.rule_id!r}. "
                    "Remaining rules skipped."
                )
                _LOG.warning(
                    "rule_engine.budget_exceeded.wall_clock elapsed_ms=%.1f max_ms=%.1f "
                    "rule_id=%s correlation_id=%s",
                    elapsed_ms,
                    self._max_wall_clock_ms,
                    rule.rule_id,
                    ctx.correlation_id,
                )
                result.budget_exceeded = True
                result.budget_detail = detail
                self._metrics.increment(
                    "rule_engine_budget_exceeded_total",
                    {"reason": "wall_clock", "format": ir.source_format},
                )
                break

            # ---- Format applicability check ----------------------------
            if not is_format_applicable(ir, rule.applicable_formats):
                result.total_rules_skipped += 1
                continue

            rule_start = self._clock()
            t = RuleTelemetry(
                rule_id=rule.rule_id,
                control_id=rule.control_id,
                duration_ms=0.0,
            )

            try:
                raw_outcomes = list(rule.evaluate(ir, catalogue_snapshot))
            except Exception as exc:
                t.duration_ms = (self._clock() - rule_start) * 1000.0
                t.errored = True
                truncated_msg = str(exc)[:200]
                err = RuleError(
                    rule_id=rule.rule_id,
                    control_id=rule.control_id,
                    exc_type=type(exc).__name__,
                    message=truncated_msg,
                    correlation_id=ctx.correlation_id,
                )
                errors.append(err)
                _LOG.warning(
                    "rule_engine.rule_error rule_id=%s control_id=%s exc=%s "
                    "correlation_id=%s message=%s",
                    rule.rule_id,
                    rule.control_id,
                    type(exc).__name__,
                    ctx.correlation_id,
                    truncated_msg,
                )
                not_assessable = RuleOutcome(
                    control_id=rule.control_id,
                    rule_id=rule.rule_id,
                    verdict=RuleOutcomeVerdict.NOT_ASSESSABLE,
                    anchors=(),
                    evidence_kind=rule.evidence_kind,
                    fingerprint=RuleOutcome.compute_fingerprint(
                        rule.rule_id, rule.control_id, ()
                    ),
                )
                outcomes.append(not_assessable)
                telemetry.append(t)
                self._metrics.increment(
                    "rule_errors_total",
                    {"rule_id": rule.rule_id, "control_id": rule.control_id},
                )
                result.total_rules_evaluated += 1
                continue

            t.duration_ms = (self._clock() - rule_start) * 1000.0

            # ---- Validate and process outcomes -------------------------
            for outcome in raw_outcomes:
                if outcome.verdict == RuleOutcomeVerdict.VIOLATED and not outcome.anchors:
                    # Programming error: violated outcome without anchors
                    err = RuleError(
                        rule_id=rule.rule_id,
                        control_id=rule.control_id,
                        exc_type="MissingAnchorsError",
                        message=(
                            "Rule returned a violated outcome with empty anchors. "
                            "Violated outcomes must include at least one EvidenceAnchor."
                        ),
                        correlation_id=ctx.correlation_id,
                    )
                    errors.append(err)
                    _LOG.warning(
                        "rule_engine.missing_anchors rule_id=%s control_id=%s correlation_id=%s",
                        rule.rule_id,
                        rule.control_id,
                        ctx.correlation_id,
                    )
                    not_assessable = RuleOutcome(
                        control_id=rule.control_id,
                        rule_id=rule.rule_id,
                        verdict=RuleOutcomeVerdict.NOT_ASSESSABLE,
                        anchors=(),
                        evidence_kind=rule.evidence_kind,
                        fingerprint=RuleOutcome.compute_fingerprint(
                            rule.rule_id, rule.control_id, ()
                        ),
                    )
                    outcomes.append(not_assessable)
                    continue

                # Dedup by fingerprint (first occurrence wins)
                if outcome.fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(outcome.fingerprint)
                outcomes.append(outcome)
                t.outcome_count += 1

                self._metrics.increment(
                    "outcomes_total",
                    {"verdict": outcome.verdict.value, "control_id": outcome.control_id},
                )

            t.verdict = (
                max(
                    (o.verdict for o in raw_outcomes if o.rule_id == rule.rule_id),
                    key=lambda v: {"violated": 2, "not_assessable": 1, "satisfied": 0}[v.value],
                    default=None,
                )
            )
            telemetry.append(t)
            self._metrics.observe_duration(
                "rule_engine_duration_ms",
                t.duration_ms,
                {"rule_id": rule.rule_id, "control_id": rule.control_id},
            )
            self._metrics.increment(
                "rules_evaluated_total",
                {"control_id": rule.control_id},
            )
            result.total_rules_evaluated += 1

        # ---- Sort outcomes deterministically ---------------------------
        result.outcomes = sorted(outcomes, key=lambda o: o.sort_key())
        result.rule_telemetry = telemetry
        result.rule_errors = errors

        duration_ms = (self._clock() - wall_start) * 1000.0
        self._metrics.observe_duration(
            "rule_engine_duration_ms",
            duration_ms,
            {"format": ir.source_format, "phase": "total"},
        )

        _LOG.info(
            "rule_engine.finish correlation_id=%s format=%s rule_count=%d "
            "outcomes=%d errors=%d duration_ms=%.1f budget_exceeded=%s",
            ctx.correlation_id,
            ir.source_format,
            result.total_rules_evaluated,
            len(result.outcomes),
            len(result.rule_errors),
            duration_ms,
            result.budget_exceeded,
        )

        return result
