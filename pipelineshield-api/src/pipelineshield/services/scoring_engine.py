"""ScoringEngine — pure, deterministic catalogue-pinned security posture scorer.

Usage::

    from pipelineshield.services.scoring_engine import ScoringEngine, ControlOutcome

    engine = ScoringEngine(snapshot)
    result = engine.score({
        "sh-001": ControlOutcome.present,
        "sh-002": ControlOutcome.missing,
        "as-001": ControlOutcome.not_assessable,
    })
    print(result.score, result.grade)  # e.g. 67 "D"

Design constraints (WO-013):
- Pure: no database access, no HTTP, no wall-clock, no global state.
- Deterministic: identical evaluations + snapshot → identical output on every call.
- Stable iteration: categories and controls are always processed in sorted(id) order
  so the score never depends on dict-insertion order.
- Grade mapping reads grade_bands from the pinned snapshot, never from constants.
- Denominator: sum of weights of enabled categories that have at least one assessable
  control.  A fully Not Assessable category removes its weight from the denominator
  and records a coverage limitation.  Disabled categories are excluded entirely.
- Zero denominator: returns an unscorable result with a coverage-limitation notice
  rather than raising or returning 0.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Mapping

from pipelineshield.catalogue.schemas import CatalogueSnapshot

__all__ = [
    "ControlOutcome",
    "CategoryScore",
    "ScoreResult",
    "ScoringEngine",
]


class ControlOutcome(str, enum.Enum):
    """Evaluation result for a single security control."""

    present = "present"
    partial = "partial"
    missing = "missing"
    not_assessable = "not_assessable"


@dataclass(frozen=True)
class CategoryScore:
    """Per-category breakdown of the scoring calculation."""

    category_id: str
    category_name: str
    category_weight: int
    earned_weight: float
    assessable_count: int
    not_assessable_count: int
    present_count: int
    partial_count: int
    missing_count: int
    in_denominator: bool


@dataclass(frozen=True)
class ScoreResult:
    """Complete result of one scoring call.

    ``is_unscorable`` is True when every enabled category is fully Not Assessable
    and the denominator is zero.  In that case ``score`` and ``grade`` are both
    ``None`` and ``coverage_limitations`` explains why.
    """

    score: int | None
    grade: str | None
    denominator: int
    assessed_control_count: int
    excluded_control_count: int
    categories: tuple[CategoryScore, ...]
    coverage_limitations: tuple[str, ...]
    catalogue_version_id: uuid.UUID
    is_unscorable: bool


class ScoringEngine:
    """Pure, injected-snapshot scoring engine.

    Constructed with an immutable ``CatalogueSnapshot`` so the same engine
    instance can be called multiple times without any global state changes.
    Dependency-injected into services to make unit testing trivial.
    """

    # Weight multipliers for each outcome
    _OUTCOME_MULTIPLIERS: dict[ControlOutcome, float] = {
        ControlOutcome.present: 1.0,
        ControlOutcome.partial: 0.5,
        ControlOutcome.missing: 0.0,
        ControlOutcome.not_assessable: 0.0,  # excluded from denominator separately
    }

    def __init__(self, snapshot: CatalogueSnapshot, catalogue_version_id: uuid.UUID) -> None:
        self._snapshot = snapshot
        self._catalogue_version_id = catalogue_version_id

    def score(
        self,
        evaluations: Mapping[str, ControlOutcome | str],
    ) -> ScoreResult:
        """Compute the security posture score from control evaluation outcomes.

        ``evaluations`` maps control_id → ControlOutcome (or its string value).
        Controls absent from the map are treated as ``missing``.

        Returns a ``ScoreResult`` with score, grade, per-category breakdown, and
        coverage limitations.  Always deterministic for identical inputs.
        """
        # Normalise string values to enum
        normalised: dict[str, ControlOutcome] = {}
        for ctrl_id, outcome in evaluations.items():
            if isinstance(outcome, ControlOutcome):
                normalised[ctrl_id] = outcome
            else:
                normalised[ctrl_id] = ControlOutcome(outcome)

        categories: list[CategoryScore] = []
        coverage_limitations: list[str] = []
        total_earned: float = 0.0
        denominator: int = 0
        assessed_total: int = 0
        excluded_total: int = 0

        # Stable sort: always iterate categories by id
        sorted_categories = sorted(
            (c for c in self._snapshot.categories if c.enabled),
            key=lambda c: c.id,
        )

        for cat in sorted_categories:
            # Only consider enabled controls, stable-sorted by id
            enabled_controls = sorted(
                (ctrl for ctrl in cat.controls if ctrl.enabled),
                key=lambda ctrl: ctrl.id,
            )

            present_count = 0
            partial_count = 0
            missing_count = 0
            not_assessable_count = 0

            for ctrl in enabled_controls:
                outcome = normalised.get(ctrl.id, ControlOutcome.missing)
                if outcome is ControlOutcome.not_assessable:
                    not_assessable_count += 1
                elif outcome is ControlOutcome.present:
                    present_count += 1
                elif outcome is ControlOutcome.partial:
                    partial_count += 1
                else:
                    missing_count += 1

            assessable_count = len(enabled_controls) - not_assessable_count
            fully_not_assessable = assessable_count == 0 and len(enabled_controls) > 0

            if fully_not_assessable or len(enabled_controls) == 0:
                # Category excluded from denominator
                in_denominator = False
                cat_earned = 0.0
                if len(enabled_controls) > 0:
                    coverage_limitations.append(
                        f"Category '{cat.id}' ({cat.name}) excluded from denominator: "
                        f"all {not_assessable_count} enabled control(s) are Not Assessable."
                    )
                    excluded_total += not_assessable_count
            else:
                in_denominator = True
                denominator += cat.weight
                assessed_total += assessable_count
                excluded_total += not_assessable_count

                # Earned weight: present + 0.5*partial out of assessable
                earned_fraction = (
                    present_count + 0.5 * partial_count
                ) / assessable_count
                cat_earned = cat.weight * earned_fraction
                total_earned += cat_earned

            categories.append(CategoryScore(
                category_id=cat.id,
                category_name=cat.name,
                category_weight=cat.weight,
                earned_weight=cat_earned,
                assessable_count=assessable_count,
                not_assessable_count=not_assessable_count,
                present_count=present_count,
                partial_count=partial_count,
                missing_count=missing_count,
                in_denominator=in_denominator,
            ))

        if denominator == 0:
            return ScoreResult(
                score=None,
                grade=None,
                denominator=0,
                assessed_control_count=0,
                excluded_control_count=excluded_total,
                categories=tuple(categories),
                coverage_limitations=tuple(coverage_limitations + [
                    "Score cannot be computed: no assessable controls found across "
                    "all enabled categories."
                ]),
                catalogue_version_id=self._catalogue_version_id,
                is_unscorable=True,
            )

        raw_score = total_earned / denominator * 100
        score_int = min(100, max(0, round(raw_score)))
        grade = self._map_grade(score_int)

        return ScoreResult(
            score=score_int,
            grade=grade,
            denominator=denominator,
            assessed_control_count=assessed_total,
            excluded_control_count=excluded_total,
            categories=tuple(categories),
            coverage_limitations=tuple(coverage_limitations),
            catalogue_version_id=self._catalogue_version_id,
            is_unscorable=False,
        )

    def _map_grade(self, score: int) -> str:
        """Map an integer score to a letter grade using the pinned snapshot's bands.

        The snapshot's grade_bands are guaranteed to cover 0-100 contiguously
        (validated at snapshot creation time).  Binary search is not needed for
        the small number of bands (typically 5).
        """
        for band in sorted(self._snapshot.grade_bands, key=lambda b: b.min_score):
            if band.min_score <= score <= band.max_score:
                return band.grade
        # Should never reach here given validated snapshot; fail explicitly
        raise ValueError(
            f"Score {score} falls outside all grade bands in the snapshot. "
            "This indicates a corrupted snapshot that bypassed validation."
        )
