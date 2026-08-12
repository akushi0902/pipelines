"""Deterministic weighted scoring engine for PipelineShield.

Public API: ScoringEngine.score()

Design constraints:
- Zero stochastic or LLM-derived input — pure deterministic function over
  control verdicts and a CatalogueSnapshot.
- Decimal arithmetic (decimal.Decimal, ROUND_HALF_UP) for cross-platform
  reproducibility.
- NOT_ASSESSABLE controls excluded from BOTH numerator AND denominator
  (honest-coverage principle P2).
- No FastAPI, SQLAlchemy, or HTTP client imports — this module must be
  testable with a hand-built CatalogueSnapshot and no test client.
"""
from __future__ import annotations

import logging
import uuid
from decimal import ROUND_HALF_UP, Decimal
from typing import Optional, Sequence

from pipelineshield.catalogue.schemas import CatalogueSnapshot

from .models import (
    CategoryScore,
    ControlVerdict,
    ScoreResult,
    ScoringError,
    VerdictEnum,
)

_LOG = logging.getLogger(__name__)

_DEFAULT_PARTIAL_CREDIT = Decimal("0.5")
_SCORE_PLACES = Decimal("0.1")


class ScoringEngine:
    """Pure, stateless scoring engine.

    Inject no external dependencies — all data flows through score() arguments.
    The engine is safe to share across threads and may be module-level singleton.
    """

    def score(
        self,
        verdicts: Sequence[ControlVerdict],
        catalogue: CatalogueSnapshot,
        catalogue_version: int,
        *,
        partial_credit_ratio: Decimal = _DEFAULT_PARTIAL_CREDIT,
        analysis_id: Optional[uuid.UUID] = None,
    ) -> ScoreResult:
        """Compute a weighted 0-100 score from control verdicts.

        Parameters
        ----------
        verdicts:
            One ControlVerdict per assessed control.  Controls absent from
            this list are treated as NOT_ASSESSABLE (unknown coverage).
        catalogue:
            Validated CatalogueSnapshot — weights must sum to 100 (enforced
            by the schema; this engine re-verifies for defence-in-depth).
        catalogue_version:
            Integer version label of *catalogue*, stamped on the result.
        partial_credit_ratio:
            Weight fraction awarded for PARTIAL verdicts.  Default 0.5.
            Must be in [0, 1].
        analysis_id:
            Optional UUID of the analysis row; threaded into the result for
            the persistence layer.

        Raises
        ------
        ScoringError
            - Unknown control_id in a verdict.
            - Duplicate control_id in verdicts.
            - partial_credit_ratio outside [0, 1].
            - Catalogue weight sum != 100 (defence-in-depth check).
        """
        if not (Decimal("0") <= partial_credit_ratio <= Decimal("1")):
            raise ScoringError(
                f"partial_credit_ratio must be in [0, 1]; got {partial_credit_ratio}",
                code="invalid_partial_credit_ratio",
            )

        # Build catalogue lookup structures
        cat_weights: dict[str, Decimal] = {}
        cat_controls: dict[str, list[str]] = {}
        enabled_control_cats: dict[str, str] = {}

        enabled_weight_total = Decimal("0")
        for cat in catalogue.categories:
            if not cat.enabled:
                continue
            cat_weights[cat.id] = Decimal(str(cat.weight))
            enabled_weight_total += cat_weights[cat.id]
            cat_controls[cat.id] = [
                ctrl.id for ctrl in cat.controls if ctrl.enabled
            ]
            for ctrl in cat.controls:
                if ctrl.enabled:
                    enabled_control_cats[ctrl.id] = cat.id

        if enabled_weight_total != Decimal("100"):
            raise ScoringError(
                f"Catalogue enabled-category weights sum to {enabled_weight_total}, "
                "expected exactly 100.",
                code="catalogue_weight_mismatch",
            )

        # Validate input verdicts
        all_verdict_ids = [v.control_id for v in verdicts]
        seen: set[str] = set()
        for cid in all_verdict_ids:
            if cid in seen:
                raise ScoringError(
                    f"Duplicate verdict for control_id {cid!r}.",
                    code="duplicate_verdict",
                )
            seen.add(cid)
        unknown = seen - set(enabled_control_cats.keys())
        if unknown:
            raise ScoringError(
                f"Verdict references unknown control_id(s): {sorted(unknown)}",
                code="unknown_control_id",
            )

        verdict_map: dict[str, VerdictEnum] = {v.control_id: v.verdict for v in verdicts}

        # Compute per-category scores
        category_scores: list[CategoryScore] = []
        total_earned = Decimal("0")
        total_possible = Decimal("0")

        for cat in sorted(catalogue.categories, key=lambda c: c.id):
            if not cat.enabled:
                continue

            cat_id = cat.id
            cat_weight = cat_weights[cat_id]
            controls = [ctrl for ctrl in cat.controls if ctrl.enabled]
            n_controls = len(controls)

            if n_controls == 0:
                category_scores.append(
                    CategoryScore(
                        category_id=cat_id,
                        earned=Decimal("0"),
                        possible=Decimal("0"),
                        excluded_count=0,
                    )
                )
                continue

            # Determine per-control weight.
            # If any control has non-zero weight_contribution, use those values;
            # otherwise distribute category weight equally across enabled controls.
            contributions = [ctrl.weight_contribution for ctrl in controls]
            if any(w > 0 for w in contributions):
                per_ctrl_weights = [Decimal(str(w)) for w in contributions]
            else:
                # Equal distribution of category weight
                base = cat_weight / Decimal(str(n_controls))
                per_ctrl_weights = [base] * n_controls

            earned = Decimal("0")
            possible = Decimal("0")
            excluded = 0

            for ctrl, ctrl_weight in zip(controls, per_ctrl_weights):
                verdict = verdict_map.get(ctrl.id, VerdictEnum.NOT_ASSESSABLE)
                if verdict == VerdictEnum.NOT_ASSESSABLE:
                    excluded += 1
                    continue
                possible += ctrl_weight
                if verdict == VerdictEnum.PRESENT:
                    earned += ctrl_weight
                elif verdict == VerdictEnum.PARTIAL:
                    earned += ctrl_weight * partial_credit_ratio
                # MISSING → earned += 0

            category_scores.append(
                CategoryScore(
                    category_id=cat_id,
                    earned=earned,
                    possible=possible,
                    excluded_count=excluded,
                )
            )
            total_earned += earned
            total_possible += possible

        # Zero-denominator → unscorable
        if total_possible == Decimal("0"):
            _LOG.info(
                "scoring.unscorable analysis_id=%s catalogue_version=%s "
                "reason=all_not_assessable",
                analysis_id,
                catalogue_version,
            )
            return ScoreResult(
                total_score=None,
                letter_grade=None,
                unscorable=True,
                unscorable_reason="all_not_assessable",
                category_scores=tuple(category_scores),
                catalogue_version=catalogue_version,
                analysis_id=analysis_id,
            )

        # Compute total score: (earned / possible) * 100, ROUND_HALF_UP to 1dp
        raw_score = (total_earned / total_possible) * Decimal("100")
        total_score = raw_score.quantize(_SCORE_PLACES, rounding=ROUND_HALF_UP)

        # Find letter grade
        letter_grade = _find_grade(total_score, catalogue)

        _LOG.info(
            "scoring.complete analysis_id=%s catalogue_version=%s "
            "total_score=%s letter_grade=%s",
            analysis_id,
            catalogue_version,
            total_score,
            letter_grade,
        )

        return ScoreResult(
            total_score=total_score,
            letter_grade=letter_grade,
            unscorable=False,
            unscorable_reason=None,
            category_scores=tuple(category_scores),
            catalogue_version=catalogue_version,
            analysis_id=analysis_id,
        )


def _find_grade(score: Decimal, catalogue: CatalogueSnapshot) -> Optional[str]:
    """Map *score* to a letter grade using the catalogue grade_bands.

    Grade bands use inclusive integer comparisons after rounding score to the
    nearest integer with ROUND_HALF_UP.  Returns None if no band matches
    (should never happen with a valid catalogue, but avoids silent failure).
    """
    # Integer comparison: score 89.5 rounds to 90 (ROUND_HALF_UP)
    int_score = int(score.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    for band in catalogue.grade_bands:
        if band.min_score <= int_score <= band.max_score:
            return band.grade
    _LOG.warning("No grade band found for score=%s (int=%s)", score, int_score)
    return None
