"""Unit tests for ScoringEngine (WO-013 AC-2, AC-4, AC-5, AC-9).

All tests construct ScoringEngine with hand-built CatalogueSnapshot fixtures —
no database, no HTTP, no global state.

Coverage:
- Weighted scoring with all controls present
- All controls missing → score 0
- Mixed present/partial/missing scoring
- Disabled categories excluded from denominator
- Not Assessable controls reduce assessable count
- Fully Not Assessable category removes weight from denominator
- Every-category Not Assessable → unscorable result (no zero-division)
- Grade band mapping at every boundary (59/60, 69/70, 79/80, 89/90, 100)
- Stable sorted iteration determinism
- Injection of alternative snapshot
- Determinism: 20 iterations produce identical results
"""
from __future__ import annotations

import json
import uuid
from copy import deepcopy

import pytest

from pipelineshield.catalogue.schemas import (
    CatalogueSnapshot,
    ControlCategory,
    ControlDefinition,
    GradeBand,
    Severity,
)
from pipelineshield.services.scoring_engine import ControlOutcome, ScoringEngine


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_STANDARD_GRADE_BANDS = [
    GradeBand(grade="F", min_score=0, max_score=59),
    GradeBand(grade="D", min_score=60, max_score=69),
    GradeBand(grade="C", min_score=70, max_score=79),
    GradeBand(grade="B", min_score=80, max_score=89),
    GradeBand(grade="A", min_score=90, max_score=100),
]

CAT_VERSION_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


def _make_snapshot(categories: list[ControlCategory]) -> CatalogueSnapshot:
    return CatalogueSnapshot(categories=categories, grade_bands=_STANDARD_GRADE_BANDS)


def _ctrl(ctrl_id: str, cat_id: str, enabled: bool = True) -> ControlDefinition:
    return ControlDefinition(
        id=ctrl_id,
        category_id=cat_id,
        severity=Severity.HIGH,
        enabled=enabled,
        reference_tools=["test-tool"],
    )


def _cat(
    cat_id: str,
    weight: int,
    controls: list[ControlDefinition],
    enabled: bool = True,
) -> ControlCategory:
    return ControlCategory(
        id=cat_id, name=cat_id.replace("_", " ").title(),
        weight=weight, enabled=enabled, controls=controls,
    )


def _engine(categories: list[ControlCategory]) -> ScoringEngine:
    return ScoringEngine(_make_snapshot(categories), CAT_VERSION_ID)


# ---------------------------------------------------------------------------
# Basic scoring
# ---------------------------------------------------------------------------

class TestScoringBasics:
    def test_all_present_yields_max_score(self) -> None:
        eng = _engine([
            _cat("cat_a", 60, [_ctrl("c1", "cat_a"), _ctrl("c2", "cat_a")]),
            _cat("cat_b", 40, [_ctrl("c3", "cat_b")]),
        ])
        result = eng.score({
            "c1": ControlOutcome.present,
            "c2": ControlOutcome.present,
            "c3": ControlOutcome.present,
        })
        assert result.score == 100
        assert result.grade == "A"
        assert not result.is_unscorable

    def test_all_missing_yields_zero(self) -> None:
        eng = _engine([
            _cat("cat_a", 60, [_ctrl("c1", "cat_a")]),
            _cat("cat_b", 40, [_ctrl("c2", "cat_b")]),
        ])
        result = eng.score({
            "c1": ControlOutcome.missing,
            "c2": ControlOutcome.missing,
        })
        assert result.score == 0
        assert result.grade == "F"

    def test_absent_controls_treated_as_missing(self) -> None:
        eng = _engine([
            _cat("cat_a", 100, [_ctrl("c1", "cat_a")]),
        ])
        result = eng.score({})  # no evaluations provided
        assert result.score == 0

    def test_partial_outcome_scores_half_weight(self) -> None:
        eng = _engine([
            _cat("cat_a", 100, [_ctrl("c1", "cat_a")]),
        ])
        result = eng.score({"c1": ControlOutcome.partial})
        # 0.5 * 100 / 100 * 100 = 50
        assert result.score == 50

    def test_mixed_outcomes(self) -> None:
        eng = _engine([
            _cat("cat_a", 100, [
                _ctrl("c1", "cat_a"),
                _ctrl("c2", "cat_a"),
                _ctrl("c3", "cat_a"),
                _ctrl("c4", "cat_a"),
            ]),
        ])
        result = eng.score({
            "c1": ControlOutcome.present,   # 1.0
            "c2": ControlOutcome.partial,   # 0.5
            "c3": ControlOutcome.missing,   # 0.0
            "c4": ControlOutcome.missing,   # 0.0
        })
        # earned = (1.0 + 0.5) / 4 = 0.375 → 37.5 → round → 38
        assert result.score == 38
        assert result.grade == "F"


# ---------------------------------------------------------------------------
# Disabled categories
# ---------------------------------------------------------------------------

class TestDisabledCategories:
    def test_disabled_category_excluded_from_denominator(self) -> None:
        # cat_a enabled weight=100 (enabled weights must sum to 100)
        # cat_b disabled weight=30 (not counted in the 100 sum check)
        cats = [
            _cat("cat_a", 100, [_ctrl("c1", "cat_a")]),
            _cat("cat_b", 30, [_ctrl("c2", "cat_b")], enabled=False),
        ]
        eng = ScoringEngine(
            CatalogueSnapshot(categories=cats, grade_bands=_STANDARD_GRADE_BANDS),
            CAT_VERSION_ID,
        )
        result = eng.score({"c1": ControlOutcome.present})
        # Only cat_a in denominator (enabled weight=100)
        assert result.score == 100
        assert result.denominator == 100

    def test_disabled_controls_not_scored(self) -> None:
        cats = [
            _cat("cat_a", 100, [
                _ctrl("c_enabled", "cat_a", enabled=True),
                _ctrl("c_disabled", "cat_a", enabled=False),
            ])
        ]
        eng = ScoringEngine(
            CatalogueSnapshot(categories=cats, grade_bands=_STANDARD_GRADE_BANDS),
            CAT_VERSION_ID,
        )
        # Only c_enabled counts; c_disabled is not counted
        result = eng.score({"c_enabled": ControlOutcome.present})
        assert result.score == 100

    def test_disabled_category_not_in_breakdown(self) -> None:
        cats = [
            _cat("cat_a", 100, [_ctrl("c1", "cat_a")]),
            _cat("cat_b", 30, [_ctrl("c2", "cat_b")], enabled=False),
        ]
        eng = ScoringEngine(
            CatalogueSnapshot(categories=cats, grade_bands=_STANDARD_GRADE_BANDS),
            CAT_VERSION_ID,
        )
        result = eng.score({"c1": ControlOutcome.present})
        cat_ids_in_result = {c.category_id for c in result.categories}
        assert "cat_b" not in cat_ids_in_result, (
            "Disabled category must not appear in scoring breakdown"
        )


# ---------------------------------------------------------------------------
# Not Assessable controls and denominator exclusion
# ---------------------------------------------------------------------------

class TestNotAssessable:
    def test_not_assessable_reduces_assessable_count(self) -> None:
        eng = _engine([
            _cat("cat_a", 100, [
                _ctrl("c1", "cat_a"),
                _ctrl("c2", "cat_a"),
            ]),
        ])
        result = eng.score({
            "c1": ControlOutcome.present,
            "c2": ControlOutcome.not_assessable,
        })
        # Assessable = 1 (only c1), c1 is present → 1/1 = 100%
        assert result.score == 100
        cat = result.categories[0]
        assert cat.assessable_count == 1
        assert cat.not_assessable_count == 1

    def test_fully_not_assessable_category_removed_from_denominator(self) -> None:
        # Weights must sum to 100 for enabled categories
        cats = [
            _cat("cat_a", 60, [_ctrl("c1", "cat_a")]),
            _cat("cat_na", 40, [_ctrl("c_na", "cat_na")]),
        ]
        eng = ScoringEngine(
            CatalogueSnapshot(categories=cats, grade_bands=_STANDARD_GRADE_BANDS),
            CAT_VERSION_ID,
        )
        result = eng.score({
            "c1": ControlOutcome.present,
            "c_na": ControlOutcome.not_assessable,
        })
        # cat_na is fully not assessable → excluded from denominator
        assert result.denominator == 60
        assert not result.is_unscorable
        # cat_a fully present → score = 60/60*100 = 100
        assert result.score == 100

    def test_fully_not_assessable_records_coverage_limitation(self) -> None:
        cats = [
            _cat("cat_a", 60, [_ctrl("c1", "cat_a")]),
            _cat("cat_na", 40, [_ctrl("c_na", "cat_na")]),
        ]
        eng = ScoringEngine(
            CatalogueSnapshot(categories=cats, grade_bands=_STANDARD_GRADE_BANDS),
            CAT_VERSION_ID,
        )
        result = eng.score({
            "c1": ControlOutcome.present,
            "c_na": ControlOutcome.not_assessable,
        })
        assert result.coverage_limitations
        assert any("cat_na" in lim for lim in result.coverage_limitations)

    def test_all_categories_fully_not_assessable_is_unscorable(self) -> None:
        cats = [
            _cat("cat_a", 60, [_ctrl("c1", "cat_a")]),
            _cat("cat_b", 40, [_ctrl("c2", "cat_b")]),
        ]
        eng = ScoringEngine(
            CatalogueSnapshot(categories=cats, grade_bands=_STANDARD_GRADE_BANDS),
            CAT_VERSION_ID,
        )
        result = eng.score({
            "c1": ControlOutcome.not_assessable,
            "c2": ControlOutcome.not_assessable,
        })
        assert result.is_unscorable
        assert result.score is None
        assert result.grade is None
        assert result.denominator == 0
        assert result.coverage_limitations

    def test_unscorable_does_not_raise_zero_division(self) -> None:
        eng = _engine([
            _cat("cat_a", 100, [_ctrl("c1", "cat_a")]),
        ])
        # Should return unscorable result, not raise ZeroDivisionError
        result = eng.score({"c1": ControlOutcome.not_assessable})
        assert result.is_unscorable


# ---------------------------------------------------------------------------
# Grade band mapping
# ---------------------------------------------------------------------------

class TestGradeBandMapping:
    def _score_at(self, score_int: int) -> str:
        """Produce an exact integer score using a synthetic single-control setup."""
        # Use a single category with weight=100 and a single control
        # We'll directly call _map_grade
        cats = [_cat("cat_a", 100, [_ctrl("c1", "cat_a")])]
        eng = ScoringEngine(
            CatalogueSnapshot(categories=cats, grade_bands=_STANDARD_GRADE_BANDS),
            CAT_VERSION_ID,
        )
        return eng._map_grade(score_int)

    def test_score_59_is_F(self) -> None:
        assert self._score_at(59) == "F"

    def test_score_60_is_D(self) -> None:
        assert self._score_at(60) == "D"

    def test_score_69_is_D(self) -> None:
        assert self._score_at(69) == "D"

    def test_score_70_is_C(self) -> None:
        assert self._score_at(70) == "C"

    def test_score_79_is_C(self) -> None:
        assert self._score_at(79) == "C"

    def test_score_80_is_B(self) -> None:
        assert self._score_at(80) == "B"

    def test_score_89_is_B(self) -> None:
        assert self._score_at(89) == "B"

    def test_score_90_is_A(self) -> None:
        assert self._score_at(90) == "A"

    def test_score_100_is_A(self) -> None:
        assert self._score_at(100) == "A"

    def test_score_0_is_F(self) -> None:
        assert self._score_at(0) == "F"

    def test_alternative_snapshot_grade_bands_respected(self) -> None:
        """ScoringEngine reads grade bands from the injected snapshot, not constants."""
        alt_bands = [
            GradeBand(grade="X", min_score=0, max_score=49),
            GradeBand(grade="Y", min_score=50, max_score=100),
        ]
        cats = [_cat("cat_a", 100, [_ctrl("c1", "cat_a")])]
        snap = CatalogueSnapshot(categories=cats, grade_bands=alt_bands)
        eng = ScoringEngine(snap, CAT_VERSION_ID)

        result_x = eng.score({"c1": ControlOutcome.missing})
        result_y = eng.score({"c1": ControlOutcome.present})

        assert result_x.grade == "X"
        assert result_y.grade == "Y"


# ---------------------------------------------------------------------------
# Determinism: 20-iteration check
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_20_iterations_produce_identical_results(self) -> None:
        cats = [
            _cat("cat_a", 60, [_ctrl("c1", "cat_a"), _ctrl("c2", "cat_a")]),
            _cat("cat_b", 40, [_ctrl("c3", "cat_b"), _ctrl("c4", "cat_b")]),
        ]
        eng = ScoringEngine(
            CatalogueSnapshot(categories=cats, grade_bands=_STANDARD_GRADE_BANDS),
            CAT_VERSION_ID,
        )
        evaluations = {
            "c1": ControlOutcome.present,
            "c2": ControlOutcome.partial,
            "c3": ControlOutcome.missing,
            "c4": ControlOutcome.not_assessable,
        }

        results = [eng.score(evaluations) for _ in range(20)]
        # All results must be identical
        scores = [r.score for r in results]
        grades = [r.grade for r in results]
        denominators = [r.denominator for r in results]

        assert len(set(scores)) == 1, f"Non-deterministic scores: {set(scores)}"
        assert len(set(grades)) == 1, f"Non-deterministic grades: {set(grades)}"
        assert len(set(denominators)) == 1, f"Non-deterministic denominators: {set(denominators)}"

    def test_category_iteration_order_is_stable(self) -> None:
        """Categories processed in sorted(id) order — not dict-insertion dependent."""
        # Use cat IDs that would sort differently from insertion order
        cats_order1 = [
            _cat("zzz_last", 50, [_ctrl("z1", "zzz_last")]),
            _cat("aaa_first", 50, [_ctrl("a1", "aaa_first")]),
        ]
        cats_order2 = [
            _cat("aaa_first", 50, [_ctrl("a1", "aaa_first")]),
            _cat("zzz_last", 50, [_ctrl("z1", "zzz_last")]),
        ]
        snap1 = CatalogueSnapshot(categories=cats_order1, grade_bands=_STANDARD_GRADE_BANDS)
        snap2 = CatalogueSnapshot(categories=cats_order2, grade_bands=_STANDARD_GRADE_BANDS)

        eng1 = ScoringEngine(snap1, CAT_VERSION_ID)
        eng2 = ScoringEngine(snap2, CAT_VERSION_ID)

        evaluations = {"z1": ControlOutcome.present, "a1": ControlOutcome.missing}
        r1 = eng1.score(evaluations)
        r2 = eng2.score(evaluations)

        assert r1.score == r2.score, "Score must not depend on category insertion order"
        # Category order in result should be sorted by id
        assert [c.category_id for c in r1.categories] == sorted(
            c.category_id for c in r1.categories
        )


# ---------------------------------------------------------------------------
# Snapshot injection
# ---------------------------------------------------------------------------

class TestSnapshotInjection:
    def test_alternative_snapshot_different_weights_changes_score(self) -> None:
        cats_v1 = [
            _cat("cat_a", 90, [_ctrl("c1", "cat_a")]),
            _cat("cat_b", 10, [_ctrl("c2", "cat_b")]),
        ]
        cats_v2 = [
            _cat("cat_a", 10, [_ctrl("c1", "cat_a")]),
            _cat("cat_b", 90, [_ctrl("c2", "cat_b")]),
        ]
        eng1 = ScoringEngine(
            CatalogueSnapshot(categories=cats_v1, grade_bands=_STANDARD_GRADE_BANDS),
            uuid.UUID("00000000-0000-0000-0000-000000000001"),
        )
        eng2 = ScoringEngine(
            CatalogueSnapshot(categories=cats_v2, grade_bands=_STANDARD_GRADE_BANDS),
            uuid.UUID("00000000-0000-0000-0000-000000000002"),
        )
        evaluations = {"c1": ControlOutcome.present, "c2": ControlOutcome.missing}

        r1 = eng1.score(evaluations)
        r2 = eng2.score(evaluations)

        # v1: cat_a(weight=90) present → score near 90; cat_b(weight=10) missing → 90
        # v2: cat_a(weight=10) present → 10; cat_b(weight=90) missing → 10
        assert r1.score != r2.score, "Different snapshot weights must produce different scores"
        assert r1.catalogue_version_id != r2.catalogue_version_id

    def test_no_global_state_between_engine_instances(self) -> None:
        cats = [_cat("cat_a", 100, [_ctrl("c1", "cat_a")])]
        snap = CatalogueSnapshot(categories=cats, grade_bands=_STANDARD_GRADE_BANDS)

        eng_a = ScoringEngine(snap, uuid.UUID("00000000-0000-0000-0000-000000000001"))
        eng_b = ScoringEngine(snap, uuid.UUID("00000000-0000-0000-0000-000000000002"))

        r_a = eng_a.score({"c1": ControlOutcome.present})
        r_b = eng_b.score({"c1": ControlOutcome.missing})

        assert r_a.score == 100
        assert r_b.score == 0
        assert r_a.catalogue_version_id != r_b.catalogue_version_id


# ---------------------------------------------------------------------------
# Catalogue v1 fixture integration (AC-9: real catalogue)
# ---------------------------------------------------------------------------

class TestCatalogueV1Fixture:
    def _v1_engine(self) -> ScoringEngine:
        import json
        from pathlib import Path
        fixture_path = Path(__file__).parent.parent / "fixtures" / "catalogue_v1.json"
        data = json.loads(fixture_path.read_text())
        snap = CatalogueSnapshot.model_validate(data)
        return ScoringEngine(snap, uuid.UUID("00000000-0000-0000-0000-000000000099"))

    def test_all_present_against_v1(self) -> None:
        eng = self._v1_engine()
        # All controls present
        evaluations = {
            "sh-001": ControlOutcome.present, "sh-002": ControlOutcome.present,
            "as-001": ControlOutcome.present, "as-002": ControlOutcome.present,
            "sa-001": ControlOutcome.present,
            "ds-001": ControlOutcome.present, "ds-002": ControlOutcome.present,
            "lp-001": ControlOutcome.present, "lp-002": ControlOutcome.present,
            "iac-001": ControlOutcome.present,
            "sci-001": ControlOutcome.present, "sci-002": ControlOutcome.present,
            "sbom-001": ControlOutcome.present,
            "ag-001": ControlOutcome.present,
        }
        result = eng.score(evaluations)
        assert result.score == 100
        assert result.grade == "A"

    def test_all_missing_against_v1(self) -> None:
        eng = self._v1_engine()
        result = eng.score({})
        assert result.score == 0
        assert result.grade == "F"

    def test_v1_deterministic_over_20_runs(self) -> None:
        eng = self._v1_engine()
        evaluations = {
            "sh-001": ControlOutcome.present,
            "sh-002": ControlOutcome.missing,
            "as-001": ControlOutcome.partial,
            "as-002": ControlOutcome.present,
            "sa-001": ControlOutcome.not_assessable,
            "ds-001": ControlOutcome.present,
            "ds-002": ControlOutcome.partial,
            "lp-001": ControlOutcome.missing,
            "lp-002": ControlOutcome.present,
            "iac-001": ControlOutcome.present,
            "sci-001": ControlOutcome.missing,
            "sci-002": ControlOutcome.not_assessable,
            "sbom-001": ControlOutcome.present,
            "ag-001": ControlOutcome.partial,
        }
        results = [eng.score(evaluations) for _ in range(20)]
        scores = {r.score for r in results}
        grades = {r.grade for r in results}
        # Serialise per-category breakdown to assert byte-identical
        breakdowns = [
            json.dumps(
                [(c.category_id, c.earned_weight, c.assessable_count) for c in r.categories],
                sort_keys=True,
            )
            for r in results
        ]
        assert len(scores) == 1, f"Non-deterministic: {scores}"
        assert len(grades) == 1
        assert len(set(breakdowns)) == 1, "Per-category breakdown is non-deterministic"
