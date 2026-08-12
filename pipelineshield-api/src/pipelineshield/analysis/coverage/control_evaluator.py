"""ControlEvaluator — control coverage state machine (WO-018).

Consumes rule outcomes from the RuleEngine plus the PipelineIR fragment
resolution map and produces, for every enabled control in the pinned catalogue
snapshot, exactly one ControlEvaluation with state Present, Partial, Missing or
Not Assessable.

Explicitly computes assessable_weight_total for the scoring engine denominator
but deliberately does not compute a score, grade or percentage — that arithmetic
belongs to the scoring epic.

State derivation policy (in precedence order):
  1. No outcomes for this control → NOT_ASSESSABLE (reason: no_applicable_rule)
  2. All outcomes NOT_ASSESSABLE → NOT_ASSESSABLE (reason: evidence_unresolvable)
  3. Resolved SATISFIED only → PRESENT
  4. Resolved SATISFIED + VIOLATED mix → PARTIAL
  5. Resolved VIOLATED only, no NOT_ASSESSABLE → MISSING
  6. Resolved VIOLATED + NOT_ASSESSABLE mix → NOT_ASSESSABLE (presence uncertain)

Invariants:
  0 <= assessable_weight_total <= catalogue_weight_total
  len(evaluations) == number of enabled controls in catalogue
"""
from __future__ import annotations

import logging
from collections import defaultdict

from pipelineshield.analysis.ir.pipeline_ir import PipelineIR, UnresolvedFragment
from pipelineshield.analysis.rule_engine.protocol import (
    EvidenceAnchor,
    MetricsEmitter,
    NullMetricsEmitter,
    RuleOutcome,
    RuleOutcomeVerdict,
)
from pipelineshield.catalogue.schemas import CatalogueSnapshot

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

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fragment kind → ExclusionReason mapping
# ---------------------------------------------------------------------------

_KIND_TO_EXCLUSION_REASON: dict[str, ExclusionReason] = {
    "scripted_groovy": ExclusionReason.SCRIPTED_GROOVY,
    "script_block": ExclusionReason.SCRIPTED_GROOVY,
    "shared_library": ExclusionReason.SCRIPTED_GROOVY,
    "composite_action": ExclusionReason.UNRESOLVED_COMPOSITE_ACTION,
    "reusable_workflow": ExclusionReason.UNRESOLVED_REUSABLE_WORKFLOW,
    "reference_unresolvable": ExclusionReason.UNRESOLVED_REFERENCE,
    "include_local": ExclusionReason.UNRESOLVED_INCLUDE,
    "include_remote": ExclusionReason.UNRESOLVED_INCLUDE,
    "extends_missing": ExclusionReason.UNRESOLVED_EXTENDS,
    "extends_cycle": ExclusionReason.UNRESOLVED_EXTENDS,
    "matrix_dynamic": ExclusionReason.METADATA_MISSING,
    "dynamic_stage_name": ExclusionReason.METADATA_MISSING,
    "agent_kubernetes": ExclusionReason.METADATA_MISSING,
    "stages_inferred": ExclusionReason.METADATA_MISSING,
}


def _fragment_exclusion_reason(fragment: UnresolvedFragment) -> ExclusionReason:
    reason = _KIND_TO_EXCLUSION_REASON.get(fragment.kind)
    if reason is None:
        _LOG.warning(
            "Unknown fragment kind %r; treating as metadata_missing", fragment.kind
        )
        return ExclusionReason.METADATA_MISSING
    return reason


def _fragment_id(fragment: UnresolvedFragment) -> str:
    return f"{fragment.kind}:{fragment.locator}"


# ---------------------------------------------------------------------------
# State derivation helpers
# ---------------------------------------------------------------------------


def _derive_state(
    satisfied: list[RuleOutcome],
    violated: list[RuleOutcome],
    not_assessable: list[RuleOutcome],
) -> tuple[ControlState, str | None]:
    """Return (state, unassessable_reason) from outcome buckets.

    Precedence: resolved evidence (satisfied + violated) dominates not_assessable
    unless ALL evidence is not_assessable.
    """
    resolved = satisfied + violated

    if not resolved:
        if not_assessable:
            return ControlState.NOT_ASSESSABLE, "evidence_unresolvable"
        return ControlState.NOT_ASSESSABLE, "no_applicable_rule"

    # Resolved evidence exists — not_assessable only shadows when mixed with VIOLATED only
    if satisfied and not violated:
        return ControlState.PRESENT, None

    if satisfied and violated:
        return ControlState.PARTIAL, None

    # violated only
    if not_assessable:
        # Can't confirm absence when some evidence is unresolvable
        return ControlState.NOT_ASSESSABLE, "evidence_unresolvable"

    return ControlState.MISSING, None


def _collect_anchors(outcomes: list[RuleOutcome]) -> tuple[EvidenceAnchor, ...]:
    seen: set[tuple[int, int]] = set()
    result: list[EvidenceAnchor] = []
    for o in outcomes:
        for a in o.anchors:
            key = (a.start_line, a.start_column)
            if key not in seen:
                seen.add(key)
                result.append(a)
    return tuple(sorted(result, key=lambda a: a.sort_key()))


# ---------------------------------------------------------------------------
# Main evaluator
# ---------------------------------------------------------------------------


class ControlEvaluator:
    """Pure, stateless evaluator — inject MetricsEmitter for observability.

    No I/O; no network; no database.  Raises CoverageEvaluationError if
    outcomes reference a control absent from the catalogue snapshot.
    """

    def __init__(self, metrics: MetricsEmitter | None = None) -> None:
        self._metrics = metrics or NullMetricsEmitter()

    def evaluate(
        self,
        outcomes: list[RuleOutcome],
        ir: PipelineIR,
        catalogue_snapshot: CatalogueSnapshot,
    ) -> CoverageReport:
        """Return one ControlEvaluation per enabled catalogue control.

        Raises:
            CoverageEvaluationError: if any outcome references a control_id
                not present in catalogue_snapshot.
        """
        # 0. Build catalogue lookup structures
        enabled_controls: dict[str, tuple[str, float]] = {}  # id → (category_id, weight)
        catalogue_weight_total: float = 0.0
        for cat in catalogue_snapshot.categories:
            if not cat.enabled:
                continue
            for ctrl in cat.controls:
                if not ctrl.enabled:
                    continue
                enabled_controls[ctrl.id] = (cat.id, ctrl.weight_contribution)
                catalogue_weight_total += ctrl.weight_contribution

        # 1. Validate all outcome control_ids are known
        known_ids = set(enabled_controls.keys())
        for outcome in outcomes:
            if outcome.control_id not in known_ids:
                raise CoverageEvaluationError(
                    f"Outcome references unknown control_id {outcome.control_id!r}; "
                    "this analysis was run with a different catalogue version."
                )

        # 2. Group outcomes by control_id
        by_control: dict[str, list[RuleOutcome]] = defaultdict(list)
        for outcome in outcomes:
            by_control[outcome.control_id].append(outcome)

        # 3. Derive state for each enabled control
        evaluations: list[ControlEvaluation] = []
        for control_id in sorted(enabled_controls):
            category_id, weight = enabled_controls[control_id]
            ctrl_outcomes = by_control.get(control_id, [])

            satisfied = [o for o in ctrl_outcomes if o.verdict == RuleOutcomeVerdict.SATISFIED]
            violated = [o for o in ctrl_outcomes if o.verdict == RuleOutcomeVerdict.VIOLATED]
            na = [o for o in ctrl_outcomes if o.verdict == RuleOutcomeVerdict.NOT_ASSESSABLE]

            state, unassessable_reason = _derive_state(satisfied, violated, na)
            anchors = _collect_anchors(violated + satisfied)

            evaluations.append(
                ControlEvaluation(
                    control_id=control_id,
                    category_id=category_id,
                    state=state,
                    anchors=anchors,
                    unassessable_reason=unassessable_reason,
                    weight_contribution=weight,
                )
            )

        # 4. Compute assessable weight total
        assessable_weight_total: float = sum(
            e.weight_contribution
            for e in evaluations
            if e.state != ControlState.NOT_ASSESSABLE
        )
        assert 0 <= assessable_weight_total <= catalogue_weight_total + 1e-9, (
            f"Invariant violation: assessable_weight_total={assessable_weight_total} "
            f"outside [0, {catalogue_weight_total}]"
        )

        # 5. Build excluded fragments from IR
        na_control_ids = tuple(
            sorted(e.control_id for e in evaluations if e.state == ControlState.NOT_ASSESSABLE)
        )
        excluded_fragments = self._build_excluded_fragments(
            ir.coverage_report.unresolved, na_control_ids
        )

        # 6. Build banner (only when fragments excluded)
        banner: BannerPayload | None = None
        if excluded_fragments:
            affected_count = len(
                {cid for f in excluded_fragments for cid in f.affected_control_ids}
            )
            reasons_set = sorted({f.exclusion_reason.value for f in excluded_fragments})
            banner = BannerPayload(
                summary=(
                    f"{len(excluded_fragments)} fragment(s) could not be resolved; "
                    f"{affected_count} control(s) may be affected. "
                    f"Reasons: {', '.join(reasons_set)}."
                ),
                affected_control_count=affected_count,
                reasons=tuple(reasons_set),
            )

        # 7. Coverage stats
        na_count = sum(1 for e in evaluations if e.state == ControlState.NOT_ASSESSABLE)
        assessable_count = len(evaluations) - na_count
        stats = CoverageStats(
            source_format=ir.source_format,
            assessable_controls=assessable_count,
            unassessable_controls=na_count,
            excluded_fragment_count=len(excluded_fragments),
        )

        # 8. Emit metrics
        for e in evaluations:
            self._metrics.increment(
                "controls_by_state_total",
                {"state": e.state.value, "format": ir.source_format},
            )
        for frag in excluded_fragments:
            self._metrics.increment(
                "excluded_fragments_total",
                {"reason": frag.exclusion_reason.value, "format": ir.source_format},
            )
        ratio = (
            assessable_weight_total / catalogue_weight_total
            if catalogue_weight_total > 0
            else 1.0
        )
        self._metrics.observe_duration(
            "assessable_weight_ratio",
            ratio,
            {"format": ir.source_format},
        )

        # 9. Completeness invariant — every enabled control must have an evaluation
        result_ids = {e.control_id for e in evaluations}
        missing_evals = set(enabled_controls.keys()) - result_ids
        if missing_evals:
            raise CoverageEvaluationError(
                f"Completeness invariant failed — {len(missing_evals)} enabled "
                f"control(s) have no evaluation: {sorted(missing_evals)}"
            )

        return CoverageReport(
            evaluations=tuple(evaluations),
            excluded_fragments=tuple(excluded_fragments),
            assessable_weight_total=assessable_weight_total,
            catalogue_weight_total=catalogue_weight_total,
            banner=banner,
            coverage_stats=stats,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_excluded_fragments(
        self,
        unresolved: list[UnresolvedFragment],
        na_control_ids: tuple[str, ...],
    ) -> tuple[ExcludedFragment, ...]:
        """Map unresolved IR fragments to ExcludedFragment entries.

        Duplicates with the same fragment_id are collapsed to one entry.
        Every unresolved fragment is listed even if affected_control_ids
        is empty (for transparency).
        """
        # Group by fragment_id to deduplicate
        by_id: dict[str, list[UnresolvedFragment]] = defaultdict(list)
        for frag in unresolved:
            by_id[_fragment_id(frag)].append(frag)

        result: list[ExcludedFragment] = []
        for frag_id, frags in by_id.items():
            rep = frags[0]
            reason = _fragment_exclusion_reason(rep)
            result.append(
                ExcludedFragment(
                    fragment_id=frag_id,
                    exclusion_reason=reason,
                    affected_control_ids=na_control_ids,
                    detail=rep.reason,
                )
            )

        # Sort by (reason, fragment_id) for determinism
        result.sort(key=lambda f: (f.exclusion_reason.value, f.fragment_id))
        return tuple(result)
