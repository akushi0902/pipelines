"""ArchitectureRecommender — pure deterministic blueprint engine (WO-026).

No imports from FastAPI, SQLAlchemy, or any inference client.
The single public method recommend() is a pure function over its inputs:
calling it twice with identical inputs produces byte-identical output.

Determinism guarantees:
  - Stages ordered by StageDefinition.order (explicit integer, not dict order).
  - Controls within each stage ordered by (_SEVERITY_ORDER, control_id).
  - Coverage limitations ordered by (scope, reason).
  - All sorted() calls use stable sort keys from catalogue data, never
    insertion order.

BR-02 compliance:
  - No string produced by this module asserts the pipeline is secure,
    compliant, or certified.  Rationale strings are factual status descriptions.
  - LLM output never enters this module; advisory_narrative_present is always
    False here.  The service layer may set it True when persisted narrative
    exists, but only via constructing a replacement ControlEntry — this module's
    output is frozen.
"""
from __future__ import annotations

from pipelineshield.catalogue.schemas import CatalogueSnapshot, ControlDefinition, Severity

from .models import (
    ArchitectureBlueprint,
    ControlEntry,
    CoverageLimitationRef,
    GapSummary,
    ReferenceToolEntry,
    StageBlueprint,
)
from .stage_mapping import (
    STAGE_DEFINITIONS,
    fallback_tool_for_category,
    stage_for_control,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Ordered severity levels for deterministic sort (Critical first).
_SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}

_RATIONALE_TEMPLATES: dict[str, str] = {
    "satisfied": (
        "Evidence confirms this control is in place. "
        "Maintain current configuration and monitor for regressions."
    ),
    "partial": (
        "Partial evidence found — some aspects of this control are in place "
        "but at least one violation was also detected. Review and remediate "
        "the remaining gaps using the listed reference tool."
    ),
    "missing": (
        "At least one violation was detected and no satisfied evidence was found. "
        "Use the listed reference tool to implement this control."
    ),
    "not_assessable": (
        "This control could not be automatically assessed because the relevant "
        "pipeline fragment was unresolvable (for example a scripted Groovy block, "
        "unresolved include, or composite action). Manual review is required."
    ),
}

# Statuses that require at least one reference tool (enforced in recommend()).
_TOOL_REQUIRED_STATUSES: frozenset[str] = frozenset({"missing", "partial"})


# ---------------------------------------------------------------------------
# ArchitectureRecommender
# ---------------------------------------------------------------------------


class ArchitectureRecommender:
    """Pure deterministic recommender.  Instantiate once; call recommend() freely."""

    def recommend(
        self,
        catalogue_snapshot: CatalogueSnapshot,
        control_statuses: dict[str, str],
        coverage_limitations: list[tuple[str, str]],  # (scope, reason) pairs
        *,
        analysis_id: str,
        catalogue_version: int,
        advisory_disclaimer: str,
        generated_at: str,
    ) -> ArchitectureBlueprint:
        """Build an ArchitectureBlueprint from the given inputs.

        Parameters
        ----------
        catalogue_snapshot:
            The catalogue snapshot pinned to the analysis.  All enabled controls
            are iterated in deterministic sorted order.
        control_statuses:
            Mapping from control_id to status string: one of
            "satisfied", "partial", "missing", "not_assessable".
            Controls absent from this map default to "not_assessable".
        coverage_limitations:
            List of (scope, reason) tuples derived from excluded IR fragments.
        analysis_id:
            Analysis UUID as a string (no DB access in this module).
        catalogue_version:
            Integer catalogue version stamp for reproducibility.
        advisory_disclaimer:
            Non-dismissible disclaimer copied verbatim into the blueprint.
        generated_at:
            ISO-8601 UTC timestamp string, injected by the service layer.
        """
        # ----------------------------------------------------------------
        # 1. Bucket catalogue controls into stage groups.
        # ----------------------------------------------------------------
        stage_buckets: dict[str, list[ControlEntry]] = {
            s.stage_id: [] for s in STAGE_DEFINITIONS
        }

        missing_count = 0
        partial_count = 0
        not_assessable_count = 0

        # Iterate categories in stable order; controls in severity + id order.
        for category in sorted(catalogue_snapshot.categories, key=lambda c: c.id):
            for control in sorted(
                category.controls,
                key=lambda ctrl: (_SEVERITY_ORDER.get(ctrl.severity.value, 99), ctrl.id),
            ):
                if not control.enabled:
                    continue

                status = control_statuses.get(control.id, "not_assessable")

                if status == "missing":
                    missing_count += 1
                elif status == "partial":
                    partial_count += 1
                elif status == "not_assessable":
                    not_assessable_count += 1

                tools = self._build_tools(control, category.id, status)
                rationale = _RATIONALE_TEMPLATES.get(status, _RATIONALE_TEMPLATES["not_assessable"])

                entry = ControlEntry(
                    control_id=control.id,
                    category=category.id,
                    severity=control.severity.value,
                    status=status,
                    reference_tools=tools,
                    rationale=rationale,
                    advisory_narrative_present=False,
                )

                stage_id = stage_for_control(control.id)
                # stage_for_control may return a stage_id not in STAGE_DEFINITIONS
                # if new catalogue controls arrive before stage_mapping is updated.
                # Default to "build" in that case.
                if stage_id not in stage_buckets:
                    stage_id = "build"
                stage_buckets[stage_id].append(entry)

        # ----------------------------------------------------------------
        # 2. Assemble StageBlueprint objects in explicit order.
        # ----------------------------------------------------------------
        stage_blueprints: list[StageBlueprint] = []
        for stage_def in sorted(STAGE_DEFINITIONS, key=lambda s: s.order):
            controls = stage_buckets[stage_def.stage_id]
            # Re-sort within stage: severity order, then control_id.
            sorted_controls = tuple(
                sorted(controls, key=lambda c: (_SEVERITY_ORDER.get(c.severity, 99), c.control_id))
            )
            stage_blueprints.append(
                StageBlueprint(
                    stage_id=stage_def.stage_id,
                    display_name=stage_def.display_name,
                    order=stage_def.order,
                    controls=sorted_controls,
                )
            )

        # ----------------------------------------------------------------
        # 3. Build coverage limitation refs in deterministic order.
        # ----------------------------------------------------------------
        cov_limits = tuple(
            CoverageLimitationRef(scope=scope, reason=reason)
            for scope, reason in sorted(coverage_limitations, key=lambda t: (t[0], t[1]))
        )

        return ArchitectureBlueprint(
            analysis_id=analysis_id,
            catalogue_version=catalogue_version,
            generated_at=generated_at,
            advisory_disclaimer=advisory_disclaimer,
            stages=tuple(stage_blueprints),
            coverage_limitations=cov_limits,
            gap_summary=GapSummary(
                missing_count=missing_count,
                partial_count=partial_count,
                not_assessable_count=not_assessable_count,
            ),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_tools(
        control: ControlDefinition,
        category_id: str,
        status: str,
    ) -> tuple[ReferenceToolEntry, ...]:
        """Return the reference tool entries for *control* given its *status*.

        For missing/partial controls: use catalogue tools when present, else
        the per-category fallback.  This structurally guarantees at least one
        tool for every missing/partial control (AC-2).

        For not_assessable: return empty (no tool recommendation without verdict).
        For satisfied: include catalogue tools as informational guidance.
        """
        if status == "not_assessable":
            return ()

        raw_tools = list(control.reference_tools)

        if status in _TOOL_REQUIRED_STATUSES and not raw_tools:
            raw_tools = [fallback_tool_for_category(category_id)]

        return tuple(
            ReferenceToolEntry(name=name, purpose="")
            for name in raw_tools
        )
