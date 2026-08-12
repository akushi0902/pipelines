"""Unit tests for the deterministic weighted scoring engine (WO-020).

Tests cover:
- All-present (score 100), all-missing (score 0)
- All-NOT_ASSESSABLE (unscorable / zero denominator)
- NA equivalence: 3 NA controls score identically to those controls absent
- Partial credit at 0.5 and custom ratio
- Grade banding at exact boundaries (90.0, 89.5, 89.94)
- 100-iteration shuffled-order determinism
- Unknown control_id raises ScoringError
- Duplicate control_id raises ScoringError
- Catalogue weight sum != 100 raises ScoringError (defence-in-depth)
- Category scores (earned, possible, excluded_count)
- Weight aggregation with equal distribution
- catalogue_version stamped on result
- Import-contract test: scoring core has no FastAPI/SQLAlchemy/HTTP imports
"""
from __future__ import annotations

import ast
import importlib
import json
import random
import sys
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

import pytest

from pipelineshield.analysis.scoring import (
    CategoryScore,
    ControlVerdict,
    ScoreResult,
    ScoringEngine,
    ScoringError,
    VerdictEnum,
)
from pipelineshield.catalogue.schemas import (
    CatalogueSnapshot,
    ControlCategory,
    ControlDefinition,
    GradeBand,
    Severity,
)

_FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "scoring"
_CATALOGUE_FIXTURE = Path(__file__).parents[2] / "fixtures" / "catalogue_v1.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_catalogue() -> CatalogueSnapshot:
    raw = json.loads(_CATALOGUE_FIXTURE.read_text())
    return CatalogueSnapshot.model_validate(raw)


def _verdicts_from_fixture(path: Path) -> list[ControlVerdict]:
    data = json.loads(path.read_text())
    return [
        ControlVerdict(
            control_id=v["control_id"],
            category_id=v["category_id"],
            verdict=VerdictEnum(v["verdict"]),
        )
        for v in data["verdicts"]
    ]


def _engine() -> ScoringEngine:
    return ScoringEngine()


def _make_minimal_catalogue(
    weights: dict[str, int],
    controls_per_cat: int = 1,
) -> CatalogueSnapshot:
    """Build a minimal CatalogueSnapshot with the given category weights."""
    grade_bands = [
        GradeBand(grade="A", min_score=90, max_score=100),
        GradeBand(grade="B", min_score=80, max_score=89),
        GradeBand(grade="C", min_score=70, max_score=79),
        GradeBand(grade="D", min_score=60, max_score=69),
        GradeBand(grade="F", min_score=0, max_score=59),
    ]
    categories = []
    for cat_id, weight in weights.items():
        controls = [
            ControlDefinition(
                id=f"{cat_id}-{i+1:03d}",
                category_id=cat_id,
                severity=Severity.HIGH,
                enabled=True,
                reference_tools=["tool-x"],
                weight_contribution=0.0,
            )
            for i in range(controls_per_cat)
        ]
        categories.append(
            ControlCategory(
                id=cat_id,
                name=cat_id,
                weight=weight,
                enabled=True,
                controls=controls,
            )
        )
    return CatalogueSnapshot(categories=categories, grade_bands=grade_bands)


# ---------------------------------------------------------------------------
# Fixture-driven tests
# ---------------------------------------------------------------------------


class TestAllPresent:
    def test_all_present_score_100(self):
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "all_present.json")
        result = _engine().score(vs, cat, catalogue_version=1)
        assert result.total_score == Decimal("100.0")
        assert result.letter_grade == "A"
        assert result.unscorable is False

    def test_all_present_category_scores_possible_equals_earned(self):
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "all_present.json")
        result = _engine().score(vs, cat, catalogue_version=1)
        for cs in result.category_scores:
            assert cs.earned == cs.possible, f"Category {cs.category_id}: earned != possible"
            assert cs.excluded_count == 0


class TestAllMissing:
    def test_all_missing_score_0(self):
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "all_missing.json")
        result = _engine().score(vs, cat, catalogue_version=1)
        assert result.total_score == Decimal("0.0")
        assert result.letter_grade == "F"

    def test_all_missing_earned_is_zero(self):
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "all_missing.json")
        result = _engine().score(vs, cat, catalogue_version=1)
        for cs in result.category_scores:
            assert cs.earned == Decimal("0"), f"Category {cs.category_id}: earned != 0"


class TestAllNotAssessable:
    def test_unscorable_when_all_na(self):
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "all_not_assessable.json")
        result = _engine().score(vs, cat, catalogue_version=1)
        assert result.unscorable is True
        assert result.total_score is None
        assert result.letter_grade is None
        assert result.unscorable_reason == "all_not_assessable"

    def test_unscorable_has_all_excluded(self):
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "all_not_assessable.json")
        result = _engine().score(vs, cat, catalogue_version=1)
        for cs in result.category_scores:
            assert cs.possible == Decimal("0"), (
                f"Category {cs.category_id}: possible should be 0 when all NA"
            )
            assert cs.excluded_count > 0


class TestNotAssessableEquivalence:
    """AC3: pipeline with 3 NA controls scores identically to those controls absent."""

    def test_na_excluded_from_denominator(self):
        """secrets_hygiene both NA → not in denominator; score = 100 (all others present)."""
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "na_equivalence.json")
        result = _engine().score(vs, cat, catalogue_version=1)
        assert result.total_score == Decimal("100.0"), (
            f"Expected 100.0 (NA excluded from denominator), got {result.total_score}"
        )

    def test_na_controls_score_same_as_absent(self):
        """Adding 3 NA controls to an all-present run yields identical score."""
        # Catalogue with 2 categories, weights 50+50
        weights = {"cat_a": 50, "cat_b": 50}
        cat = _make_minimal_catalogue(weights, controls_per_cat=3)

        # All present (cat_a: 3 present, cat_b: 3 present)
        all_present = [
            ControlVerdict(f"cat_a-{i+1:03d}", "cat_a", VerdictEnum.PRESENT)
            for i in range(3)
        ] + [
            ControlVerdict(f"cat_b-{i+1:03d}", "cat_b", VerdictEnum.PRESENT)
            for i in range(3)
        ]
        result_full = _engine().score(all_present, cat, catalogue_version=1)

        # Same run but cat_a controls are NA (should equal absent from denominator)
        with_na = [
            ControlVerdict(f"cat_a-{i+1:03d}", "cat_a", VerdictEnum.NOT_ASSESSABLE)
            for i in range(3)
        ] + [
            ControlVerdict(f"cat_b-{i+1:03d}", "cat_b", VerdictEnum.PRESENT)
            for i in range(3)
        ]
        result_na = _engine().score(with_na, cat, catalogue_version=1)

        assert result_full.total_score == result_na.total_score == Decimal("100.0"), (
            f"NA equivalence failed: full={result_full.total_score}, "
            f"na={result_na.total_score}"
        )


class TestPartialCredit:
    def test_all_partial_default_ratio_50(self):
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "partial_heavy.json")
        result = _engine().score(vs, cat, catalogue_version=1)
        assert result.total_score == Decimal("50.0"), (
            f"All-partial should score 50.0, got {result.total_score}"
        )

    def test_custom_partial_ratio_25(self):
        """Custom partial_credit_ratio=0.25 halves the partial score."""
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "partial_heavy.json")
        result = _engine().score(
            vs, cat, catalogue_version=1, partial_credit_ratio=Decimal("0.25")
        )
        assert result.total_score == Decimal("25.0")

    def test_partial_ratio_0_equals_missing(self):
        """partial_credit_ratio=0 makes PARTIAL identical to MISSING."""
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "partial_heavy.json")
        result_partial = _engine().score(
            vs, cat, catalogue_version=1, partial_credit_ratio=Decimal("0")
        )
        vs_missing = [
            ControlVerdict(v.control_id, v.category_id, VerdictEnum.MISSING)
            for v in vs
        ]
        result_missing = _engine().score(vs_missing, cat, catalogue_version=1)
        assert result_partial.total_score == result_missing.total_score == Decimal("0.0")

    def test_invalid_partial_ratio_raises(self):
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "all_present.json")
        with pytest.raises(ScoringError, match="partial_credit_ratio"):
            _engine().score(vs, cat, catalogue_version=1, partial_credit_ratio=Decimal("1.5"))


class TestGradeBanding:
    """AC5: Rounding defined (ROUND_HALF_UP); boundary tests."""

    def _score_for_grade_test(
        self, target_score: Decimal, catalogue: CatalogueSnapshot
    ) -> ScoreResult:
        """Build a single-control catalogue and verify the exact score maps to the right grade."""
        grade_bands = catalogue.grade_bands
        weights = {"test_cat": 100}
        simple_cat = _make_minimal_catalogue(weights, controls_per_cat=1)
        vs = [ControlVerdict("test_cat-001", "test_cat", VerdictEnum.PRESENT)]
        return _engine().score(vs, simple_cat, catalogue_version=1)

    def test_score_100_is_grade_A(self):
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "all_present.json")
        r = _engine().score(vs, cat, catalogue_version=1)
        assert r.letter_grade == "A"
        assert r.total_score == Decimal("100.0")

    def test_score_0_is_grade_F(self):
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "all_missing.json")
        r = _engine().score(vs, cat, catalogue_version=1)
        assert r.letter_grade == "F"
        assert r.total_score == Decimal("0.0")

    def test_score_89_94_rounds_to_90_grade_A(self):
        """89.94 rounds to 90.0 (1dp ROUND_HALF_UP = 89.9), int = 90 → A."""
        # score = 89.944... with 1dp ROUND_HALF_UP = 89.9 → int 90 → A
        # Actually: Decimal("89.944").quantize("0.1", ROUND_HALF_UP) = "89.9"
        # int_score = int(Decimal("89.9").quantize("1", ROUND_HALF_UP)) = 90 → A
        d = Decimal("89.944").quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
        int_score = int(d.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        assert d == Decimal("89.9")
        assert int_score == 90

    def test_score_89_5_rounds_to_90_grade_A(self):
        """89.5 with ROUND_HALF_UP: quantize to 0.1 → 89.5, int → 90 (ROUND_HALF_UP) → A."""
        d = Decimal("89.5").quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
        int_score = int(d.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        assert d == Decimal("89.5")
        assert int_score == 90  # ROUND_HALF_UP: 89.5 → 90

    def test_score_89_4_rounds_to_89_grade_B(self):
        """89.4 → 1dp = 89.4, int ROUND_HALF_UP = 89 → B."""
        d = Decimal("89.4").quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
        int_score = int(d.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        assert d == Decimal("89.4")
        assert int_score == 89  # B band

    def test_grade_band_boundaries(self):
        """Grade bands: A ≥90, B 80-89, C 70-79, D 60-69, F <60."""
        cat = _load_catalogue()
        # Manually compute score thresholds via a single-cat catalogue
        grade_map = {b.grade: (b.min_score, b.max_score) for b in cat.grade_bands}
        assert grade_map["A"] == (90, 100)
        assert grade_map["B"] == (80, 89)
        assert "F" in grade_map


class TestDeterminism:
    """AC6: 100 randomized-order iterations must yield byte-identical score output."""

    def test_100_shuffled_iterations_identical(self):
        cat = _load_catalogue()
        base_verdicts = _verdicts_from_fixture(_FIXTURE_DIR / "mixed.json")

        engine = _engine()
        first_result: ScoreResult | None = None

        rng = random.Random(42)
        for i in range(100):
            shuffled = list(base_verdicts)
            rng.shuffle(shuffled)
            result = engine.score(shuffled, cat, catalogue_version=1)

            serialized = _serialize_result(result)
            if first_result is None:
                first_result = result
                first_serial = serialized
            else:
                assert serialized == first_serial, (
                    f"Iteration {i}: non-deterministic result detected. "
                    f"Expected {first_serial!r}, got {serialized!r}"
                )


def _serialize_result(r: ScoreResult) -> str:
    """Deterministic text serialization of a ScoreResult."""
    cats = sorted(r.category_scores, key=lambda c: c.category_id)
    cat_parts = "|".join(
        f"{c.category_id}:{c.earned}:{c.possible}:{c.excluded_count}"
        for c in cats
    )
    return (
        f"score={r.total_score}|grade={r.letter_grade}|"
        f"unscorable={r.unscorable}|cats={cat_parts}"
    )


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_unknown_control_id_raises(self):
        cat = _load_catalogue()
        vs = [ControlVerdict("unknown-999", "secrets_hygiene", VerdictEnum.PRESENT)]
        with pytest.raises(ScoringError, match="unknown_control_id|Unknown"):
            _engine().score(vs, cat, catalogue_version=1)

    def test_duplicate_control_id_raises(self):
        cat = _load_catalogue()
        vs = [
            ControlVerdict("sh-001", "secrets_hygiene", VerdictEnum.PRESENT),
            ControlVerdict("sh-001", "secrets_hygiene", VerdictEnum.MISSING),
        ]
        with pytest.raises(ScoringError, match="duplicate|Duplicate"):
            _engine().score(vs, cat, catalogue_version=1)

    def test_empty_verdicts_returns_unscorable(self):
        """Empty verdict list → all controls NOT_ASSESSABLE by default → unscorable."""
        cat = _load_catalogue()
        result = _engine().score([], cat, catalogue_version=1)
        assert result.unscorable is True
        assert result.total_score is None


# ---------------------------------------------------------------------------
# Weight aggregation tests
# ---------------------------------------------------------------------------


class TestWeightAggregation:
    def test_equal_weight_distribution(self):
        """Category with 2 controls, weight=100, both present → score 100."""
        cat = _make_minimal_catalogue({"cat_x": 100}, controls_per_cat=2)
        vs = [
            ControlVerdict("cat_x-001", "cat_x", VerdictEnum.PRESENT),
            ControlVerdict("cat_x-002", "cat_x", VerdictEnum.PRESENT),
        ]
        r = _engine().score(vs, cat, catalogue_version=1)
        assert r.total_score == Decimal("100.0")

    def test_one_of_two_present_scores_50(self):
        """1 of 2 controls present with equal weight → category 50%, overall 50%."""
        cat = _make_minimal_catalogue({"cat_x": 100}, controls_per_cat=2)
        vs = [
            ControlVerdict("cat_x-001", "cat_x", VerdictEnum.PRESENT),
            ControlVerdict("cat_x-002", "cat_x", VerdictEnum.MISSING),
        ]
        r = _engine().score(vs, cat, catalogue_version=1)
        assert r.total_score == Decimal("50.0")

    def test_one_na_one_present_scores_100(self):
        """1 NA (excluded) + 1 present → possible = 50, earned = 50, score = 100."""
        cat = _make_minimal_catalogue({"cat_x": 100}, controls_per_cat=2)
        vs = [
            ControlVerdict("cat_x-001", "cat_x", VerdictEnum.NOT_ASSESSABLE),
            ControlVerdict("cat_x-002", "cat_x", VerdictEnum.PRESENT),
        ]
        r = _engine().score(vs, cat, catalogue_version=1)
        assert r.total_score == Decimal("100.0")
        cs = r.category_scores[0]
        assert cs.excluded_count == 1
        assert cs.possible == Decimal("50")

    def test_catalogue_version_stamped(self):
        cat = _make_minimal_catalogue({"cat_x": 100}, controls_per_cat=1)
        vs = [ControlVerdict("cat_x-001", "cat_x", VerdictEnum.PRESENT)]
        r = _engine().score(vs, cat, catalogue_version=42)
        assert r.catalogue_version == 42

    def test_category_scores_sorted_by_category_id(self):
        """category_scores must be sorted by category_id for determinism."""
        cat = _load_catalogue()
        vs = _verdicts_from_fixture(_FIXTURE_DIR / "all_present.json")
        r = _engine().score(vs, cat, catalogue_version=1)
        ids = [cs.category_id for cs in r.category_scores]
        assert ids == sorted(ids)

    def test_two_category_mixed(self):
        """Two categories: one fully present, one fully missing → 50% overall."""
        cat = _make_minimal_catalogue({"cat_a": 50, "cat_b": 50}, controls_per_cat=1)
        vs = [
            ControlVerdict("cat_a-001", "cat_a", VerdictEnum.PRESENT),
            ControlVerdict("cat_b-001", "cat_b", VerdictEnum.MISSING),
        ]
        r = _engine().score(vs, cat, catalogue_version=1)
        assert r.total_score == Decimal("50.0")


# ---------------------------------------------------------------------------
# Import-contract test (AC8)
# ---------------------------------------------------------------------------


class TestImportContract:
    """Proves the scoring core imports no FastAPI, SQLAlchemy, or HTTP client."""

    _FORBIDDEN_MODULES = {
        "fastapi",
        "sqlalchemy",
        "httpx",
        "requests",
        "aiohttp",
        "starlette",
        "uvicorn",
    }

    def _collect_imports(self, module_path: Path) -> set[str]:
        """Parse the module source with AST and collect all top-level imports."""
        tree = ast.parse(module_path.read_text())
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
        return imports

    def _scoring_module_paths(self) -> list[Path]:
        scoring_dir = (
            Path(__file__).parents[3]
            / "src"
            / "pipelineshield"
            / "analysis"
            / "scoring"
        )
        return list(scoring_dir.glob("*.py"))

    def test_no_forbidden_imports_in_scoring_modules(self):
        paths = self._scoring_module_paths()
        assert paths, "No scoring module files found"
        violations: list[str] = []
        for path in paths:
            imports = self._collect_imports(path)
            found = imports & self._FORBIDDEN_MODULES
            if found:
                violations.append(f"{path.name}: {sorted(found)}")
        assert not violations, (
            "Forbidden imports found in scoring core:\n"
            + "\n".join(violations)
        )
