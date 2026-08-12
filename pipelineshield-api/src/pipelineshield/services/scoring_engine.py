"""ScoringEngine — pure, deterministic catalogue-pinned security posture scorer.

No database access, HTTP, wall-clock, or global mutable state.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass
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
    """Complete result of one scoring call."""

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
    """Pure, deterministic scoring engine using one pinned catalogue snapshot."""

    _OUTCOME_MULTIPLIERS: dict[ControlOutcome, float] = {
        ControlOutcome.present: 1.0,
        ControlOutcome.partial: 0.5,
        ControlOutcome.missing: 0.0,
        ControlOutcome.not_assessable: 0.0,
    }

    def __init__(
        self,
        snapshot: CatalogueSnapshot,
        catalogue_version_id: uuid.UUID,
    ) -> None:
        self._snapshot = snapshot
        self._catalogue_version_id = catalogue_version_id

    def score(
        self,
        evaluations: Mapping[str, ControlOutcome | str],
    ) -> ScoreResult:
        """Compute a deterministic score from control evaluation outcomes.

        Controls absent from ``evaluations`` are treated as ``missing``.
        """

        normalised: dict[str, ControlOutcome] = {}

        for ctrl_id, outcome in evaluations.items():
            try:
                normalised[ctrl_id] = (
                    outcome
                    if isinstance(outcome, ControlOutcome)
                    else ControlOutcome(outcome)
                )
            except ValueError as exc:
                raise ValueError(
                    f"Unknown control outcome for {ctrl_id!r}: {outcome!r}"
                ) from exc

        categories: list[CategoryScore] = []
        coverage_limitations: list[str] = []

        total_earned = 0.0
        denominator = 0
        assessed_total = 0
        excluded_total = 0

        sorted_categories = sorted(
            (category for category in self._snapshot.categories if category.enabled),
            key=lambda category: category.id,
        )

        for category in sorted_categories:
            enabled_controls = sorted(
                (
                    control
                    for control in category.controls
                    if control.enabled
                ),
                key=lambda control: control.id,
            )

            present_count = 0
            partial_count = 0
            missing_count = 0
            not_assessable_count = 0

            for control in enabled_controls:
                outcome = normalised.get(
                    control.id,
                    ControlOutcome.missing,
                )

                if outcome is ControlOutcome.not_assessable:
                    not_assessable_count += 1
                elif outcome is ControlOutcome.present:
                    present_count += 1
                elif outcome is ControlOutcome.partial:
                    partial_count += 1
                else:
                    missing_count += 1

            assessable_count = (
                len(enabled_controls) - not_assessable_count
            )

            fully_not_assessable = (
                len(enabled_controls) > 0
                and assessable_count == 0
            )

            if not enabled_controls or fully_not_assessable:
                in_denominator = False
                cat_earned = 0.0

                if enabled_controls:
                    coverage_limitations.append(
                        f"Category '{category.id}' ({category.name}) "
                        f"excluded from denominator: all "
                        f"{not_assessable_count} enabled control(s) "
                        "are Not Assessable."
                    )
                    excluded_total += not_assessable_count
            else:
                in_denominator = True
                denominator += category.weight
                assessed_total += assessable_count
                excluded_total += not_assessable_count

                earned_fraction = (
                    present_count + 0.5 * partial_count
                ) / assessable_count

                cat_earned = category.weight * earned_fraction
                total_earned += cat_earned

            categories.append(
                CategoryScore(
                    category_id=category.id,
                    category_name=category.name,
                    category_weight=category.weight,
                    earned_weight=cat_earned,
                    assessable_count=assessable_count,
                    not_assessable_count=not_assessable_count,
                    present_count=present_count,
                    partial_count=partial_count,
                    missing_count=missing_count,
                    in_denominator=in_denominator,
                )
            )

        if denominator == 0:
            limitations = list(coverage_limitations)
            limitations.append(
                "Score cannot be computed: no assessable controls found "
                "across all enabled categories."
            )

            return ScoreResult(
                score=None,
                grade=None,
                denominator=0,
                assessed_control_count=0,
                excluded_control_count=excluded_total,
                categories=tuple(categories),
                coverage_limitations=tuple(limitations),
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
        """Map a score to a grade using the pinned catalogue snapshot."""

        for band in sorted(
            self._snapshot.grade_bands,
            key=lambda band: band.min_score,
        ):
            if band.min_score <= score <= band.max_score:
                return band.grade

        raise ValueError(
            f"Score {score} falls outside all grade bands in the snapshot. "
            "This indicates a corrupted snapshot that bypassed validation."
        )
