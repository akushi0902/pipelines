"""Unit tests for ControlEvaluator — WO-018.

Coverage:
  1. State derivation: present, partial, missing, not_assessable
  2. No outcomes → not_assessable (no_applicable_rule)
  3. All NOT_ASSESSABLE outcomes → not_assessable (evidence_unresolvable)
  4. Disabled controls omitted from evaluations and denominator
  5. assessable_weight_total boundaries (all unassessable → 0)
  6. ExcludedFragment from unresolved IR fragments, reason codes
  7. Banner payload produced when fragments excluded; absent when none
  8. CoverageEvaluationError for unknown control_id in outcomes
  9. Determinism — same input → identical output ordering
  10. Per-format coverage stats
  11. Grep test: no grade/score/percentage arithmetic in coverage module
  12. Mixed violated + not_assessable → not_assessable (presence uncertain)
"""
from __future__ import annotations

import pathlib
import re
import uuid

import pytest

from pipelineshield.analysis.coverage import (
    ControlEvaluator,
    ControlState,
    CoverageEvaluationError,
    ExclusionReason,
)
from pipelineshield.analysis.ir.pipeline_ir import (
    Anchor,
    CoverageReport as IRCoverageReport,
    PipelineIR,
    UnresolvedFragment,
)
from pipelineshield.analysis.rule_engine.protocol import (
    EvidenceAnchor,
    RuleOutcome,
    RuleOutcomeVerdict,
)
from pipelineshield.catalogue.schemas import (
    CatalogueSnapshot,
    ControlCategory,
    ControlDefinition,
    GradeBand,
    Severity,
)

# ---------------------------------------------------------------------------
# Minimal catalogue snapshot builder
# ---------------------------------------------------------------------------


def _make_catalogue(
    controls: list[tuple[str, str, float, bool]],  # (ctrl_id, cat_id, weight, enabled)
) -> CatalogueSnapshot:
    """Build a minimal CatalogueSnapshot from (control_id, category_id, weight, enabled) tuples."""
    # Group by category
    by_cat: dict[str, list[tuple[str, float, bool]]] = {}
    cat_order: list[str] = []
    for ctrl_id, cat_id, w, enabled in controls:
        if cat_id not in by_cat:
            by_cat[cat_id] = []
            cat_order.append(cat_id)
        by_cat[cat_id].append((ctrl_id, w, enabled))

    categories: list[ControlCategory] = []
    total_weight = 0
    for cat_id in cat_order:
        ctrl_defs = [
            ControlDefinition(
                id=cid,
                category_id=cat_id,
                severity=Severity.HIGH,
                enabled=en,
                reference_tools=["tool-a"],
                weight_contribution=w,
            )
            for (cid, w, en) in by_cat[cat_id]
        ]
        # Assign a category weight so totals are valid; use 100 for single cat
        cat_weight = 100 if len(cat_order) == 1 else (100 // len(cat_order))
        total_weight += cat_weight
        categories.append(
            ControlCategory(
                id=cat_id,
                name=cat_id.title(),
                weight=cat_weight,
                enabled=True,
                controls=ctrl_defs,
            )
        )

    # Adjust last category to ensure sum == 100
    if categories and total_weight != 100:
        diff = 100 - total_weight
        last = categories[-1]
        categories[-1] = ControlCategory(
            id=last.id,
            name=last.name,
            weight=last.weight + diff,
            enabled=last.enabled,
            controls=last.controls,
        )

    return CatalogueSnapshot(
        categories=categories,
        grade_bands=[
            GradeBand(grade="A", min_score=90, max_score=100),
            GradeBand(grade="B", min_score=70, max_score=89),
            GradeBand(grade="C", min_score=50, max_score=69),
            GradeBand(grade="D", min_score=30, max_score=49),
            GradeBand(grade="F", min_score=0, max_score=29),
        ],
    )


def _single_control_catalogue(
    ctrl_id: str = "sh-001",
    cat_id: str = "secrets",
    weight: float = 5.0,
    enabled: bool = True,
) -> CatalogueSnapshot:
    return _make_catalogue([(ctrl_id, cat_id, weight, enabled)])


def _make_ir(
    source_format: str = "github_actions",
    unresolved: list[UnresolvedFragment] | None = None,
) -> PipelineIR:
    return PipelineIR(
        source_format=source_format,
        coverage_report=IRCoverageReport(unresolved=unresolved or []),
    )


def _outcome(
    control_id: str,
    verdict: RuleOutcomeVerdict,
    anchors: tuple[EvidenceAnchor, ...] = (),
    rule_id: str = "test-rule",
) -> RuleOutcome:
    return RuleOutcome(
        control_id=control_id,
        rule_id=rule_id,
        verdict=verdict,
        anchors=anchors,
        evidence_kind="test",
        fingerprint=RuleOutcome.compute_fingerprint(rule_id, control_id, anchors),
    )


_SATISFIED = RuleOutcomeVerdict.SATISFIED
_VIOLATED = RuleOutcomeVerdict.VIOLATED
_NA = RuleOutcomeVerdict.NOT_ASSESSABLE

# ---------------------------------------------------------------------------
# 1. State derivation — present
# ---------------------------------------------------------------------------


class TestStatePresent:
    def test_satisfied_outcome_yields_present(self):
        cat = _single_control_catalogue("sh-001")
        ir = _make_ir()
        outcomes = [_outcome("sh-001", _SATISFIED)]
        ev = ControlEvaluator()

        report = ev.evaluate(outcomes, ir, cat)

        assert len(report.evaluations) == 1
        assert report.evaluations[0].state == ControlState.PRESENT

    def test_multiple_satisfied_still_present(self):
        cat = _single_control_catalogue("sh-001")
        ir = _make_ir()
        outcomes = [
            _outcome("sh-001", _SATISFIED, rule_id="rule-a"),
            _outcome("sh-001", _SATISFIED, rule_id="rule-b"),
        ]
        report = ControlEvaluator().evaluate(outcomes, ir, cat)
        assert report.evaluations[0].state == ControlState.PRESENT


# ---------------------------------------------------------------------------
# 2. State derivation — missing
# ---------------------------------------------------------------------------


class TestStateMissing:
    def test_violated_only_yields_missing(self):
        cat = _single_control_catalogue("sh-001")
        ir = _make_ir()
        anchor = EvidenceAnchor(start_line=5, start_column=1)
        outcomes = [_outcome("sh-001", _VIOLATED, anchors=(anchor,))]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        eval_ = report.evaluations[0]
        assert eval_.state == ControlState.MISSING
        assert len(eval_.anchors) == 1
        assert eval_.anchors[0].start_line == 5


# ---------------------------------------------------------------------------
# 3. State derivation — partial
# ---------------------------------------------------------------------------


class TestStatePartial:
    def test_mixed_satisfied_violated_yields_partial(self):
        cat = _single_control_catalogue("sh-001")
        ir = _make_ir()
        anchor = EvidenceAnchor(start_line=3, start_column=1)
        outcomes = [
            _outcome("sh-001", _SATISFIED, rule_id="rule-a"),
            _outcome("sh-001", _VIOLATED, anchors=(anchor,), rule_id="rule-b"),
        ]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert report.evaluations[0].state == ControlState.PARTIAL


# ---------------------------------------------------------------------------
# 4. State derivation — not_assessable
# ---------------------------------------------------------------------------


class TestStateNotAssessable:
    def test_no_outcomes_yields_not_assessable(self):
        cat = _single_control_catalogue("sh-001")
        ir = _make_ir()

        report = ControlEvaluator().evaluate([], ir, cat)

        eval_ = report.evaluations[0]
        assert eval_.state == ControlState.NOT_ASSESSABLE
        assert eval_.unassessable_reason == "no_applicable_rule"

    def test_all_na_outcomes_yields_not_assessable(self):
        cat = _single_control_catalogue("sh-001")
        ir = _make_ir()
        outcomes = [_outcome("sh-001", _NA)]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        eval_ = report.evaluations[0]
        assert eval_.state == ControlState.NOT_ASSESSABLE
        assert eval_.unassessable_reason == "evidence_unresolvable"

    def test_violated_plus_na_yields_not_assessable(self):
        """When presence cannot be confirmed, violated + NA → not_assessable."""
        cat = _single_control_catalogue("sh-001")
        ir = _make_ir()
        anchor = EvidenceAnchor(start_line=1, start_column=1)
        outcomes = [
            _outcome("sh-001", _VIOLATED, anchors=(anchor,), rule_id="rule-a"),
            _outcome("sh-001", _NA, rule_id="rule-b"),
        ]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert report.evaluations[0].state == ControlState.NOT_ASSESSABLE

    def test_format_with_no_applicable_rules_is_not_assessable(self):
        """ag-001 has no applicable rules for github_actions → not_assessable."""
        cat = _single_control_catalogue("ag-001")
        ir = _make_ir(source_format="github_actions")
        # No outcomes for ag-001

        report = ControlEvaluator().evaluate([], ir, cat)

        assert report.evaluations[0].state == ControlState.NOT_ASSESSABLE
        assert report.evaluations[0].unassessable_reason == "no_applicable_rule"


# ---------------------------------------------------------------------------
# 5. Disabled controls
# ---------------------------------------------------------------------------


class TestDisabledControls:
    def test_disabled_control_omitted_from_evaluations(self):
        cat = _make_catalogue([
            ("sh-001", "secrets", 5.0, True),
            ("sh-002", "secrets", 3.0, False),  # disabled
        ])
        ir = _make_ir()
        outcomes = [_outcome("sh-001", _SATISFIED)]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        control_ids = {e.control_id for e in report.evaluations}
        assert "sh-001" in control_ids
        assert "sh-002" not in control_ids

    def test_disabled_control_not_in_denominator(self):
        cat = _make_catalogue([
            ("sh-001", "secrets", 5.0, True),
            ("sh-002", "secrets", 10.0, False),  # disabled — excluded from weight
        ])
        ir = _make_ir()
        outcomes = [_outcome("sh-001", _SATISFIED)]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert report.catalogue_weight_total == 5.0
        assert report.assessable_weight_total == 5.0


# ---------------------------------------------------------------------------
# 6. assessable_weight_total
# ---------------------------------------------------------------------------


class TestAssessableWeightTotal:
    def test_all_unassessable_yields_zero_denominator(self):
        cat = _single_control_catalogue("sh-001", weight=7.5)
        ir = _make_ir()

        report = ControlEvaluator().evaluate([], ir, cat)  # no outcomes → all NA

        assert report.assessable_weight_total == 0.0
        assert report.catalogue_weight_total == 7.5

    def test_present_control_included_in_denominator(self):
        cat = _single_control_catalogue("sh-001", weight=8.0)
        ir = _make_ir()
        outcomes = [_outcome("sh-001", _SATISFIED)]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert report.assessable_weight_total == 8.0

    def test_missing_control_included_in_denominator(self):
        """MISSING controls ARE assessed (we know they're absent) → included."""
        cat = _single_control_catalogue("sh-001", weight=6.0)
        ir = _make_ir()
        anchor = EvidenceAnchor(start_line=1, start_column=1)
        outcomes = [_outcome("sh-001", _VIOLATED, anchors=(anchor,))]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert report.assessable_weight_total == 6.0

    def test_assessable_weight_never_exceeds_catalogue_total(self):
        cat = _make_catalogue([
            ("sh-001", "secrets", 5.0, True),
            ("sh-002", "secrets", 3.0, True),
        ])
        ir = _make_ir()
        outcomes = [
            _outcome("sh-001", _SATISFIED, rule_id="r1"),
            _outcome("sh-002", _SATISFIED, rule_id="r2"),
        ]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert report.assessable_weight_total <= report.catalogue_weight_total


# ---------------------------------------------------------------------------
# 7. Excluded fragments and ExclusionReason codes
# ---------------------------------------------------------------------------


class TestExcludedFragments:
    def _eval_with_fragment(self, kind: str, locator: str = "test-loc") -> tuple:
        cat = _single_control_catalogue("sh-001")
        fragment = UnresolvedFragment(
            kind=kind,
            locator=locator,
            reason=f"{kind} fragment",
        )
        ir = _make_ir(unresolved=[fragment])
        outcomes = [_outcome("sh-001", _NA)]
        report = ControlEvaluator().evaluate(outcomes, ir, cat)
        return report.excluded_fragments

    def test_scripted_groovy_exclusion_reason(self):
        frags = self._eval_with_fragment("scripted_groovy")
        assert frags[0].exclusion_reason == ExclusionReason.SCRIPTED_GROOVY

    def test_composite_action_exclusion_reason(self):
        frags = self._eval_with_fragment("composite_action")
        assert frags[0].exclusion_reason == ExclusionReason.UNRESOLVED_COMPOSITE_ACTION

    def test_reusable_workflow_exclusion_reason(self):
        frags = self._eval_with_fragment("reusable_workflow")
        assert frags[0].exclusion_reason == ExclusionReason.UNRESOLVED_REUSABLE_WORKFLOW

    def test_reference_unresolvable_exclusion_reason(self):
        frags = self._eval_with_fragment("reference_unresolvable")
        assert frags[0].exclusion_reason == ExclusionReason.UNRESOLVED_REFERENCE

    def test_include_local_exclusion_reason(self):
        frags = self._eval_with_fragment("include_local")
        assert frags[0].exclusion_reason == ExclusionReason.UNRESOLVED_INCLUDE

    def test_extends_missing_exclusion_reason(self):
        frags = self._eval_with_fragment("extends_missing")
        assert frags[0].exclusion_reason == ExclusionReason.UNRESOLVED_EXTENDS

    def test_duplicate_fragments_collapsed(self):
        """Two fragments with same kind+locator → one ExcludedFragment entry."""
        cat = _single_control_catalogue("sh-001")
        frags = [
            UnresolvedFragment(kind="composite_action", locator="owner/repo", reason="a"),
            UnresolvedFragment(kind="composite_action", locator="owner/repo", reason="b"),
        ]
        ir = _make_ir(unresolved=frags)
        outcomes = [_outcome("sh-001", _NA)]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert len(report.excluded_fragments) == 1

    def test_fragment_with_no_na_controls_has_affected_empty_or_na(self):
        """Fragment present, but control is PRESENT — fragment still listed."""
        cat = _single_control_catalogue("sh-001")
        fragment = UnresolvedFragment(
            kind="composite_action", locator="x/y", reason="r"
        )
        ir = _make_ir(unresolved=[fragment])
        # Control is PRESENT — not NA
        outcomes = [_outcome("sh-001", _SATISFIED)]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert len(report.excluded_fragments) == 1
        assert report.excluded_fragments[0].affected_control_ids == ()

    def test_excluded_fragments_sorted_by_reason_then_id(self):
        cat = _make_catalogue([
            ("sh-001", "secrets", 0.0, True),
            ("sh-002", "secrets", 0.0, True),
        ])
        frags = [
            UnresolvedFragment(kind="reusable_workflow", locator="z/z", reason="r"),
            UnresolvedFragment(kind="composite_action", locator="a/a", reason="r"),
        ]
        ir = _make_ir(unresolved=frags)
        outcomes = []

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        keys = [(f.exclusion_reason.value, f.fragment_id) for f in report.excluded_fragments]
        assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# 8. Banner payload
# ---------------------------------------------------------------------------


class TestBannerPayload:
    def test_banner_present_when_fragments_excluded(self):
        cat = _single_control_catalogue("sh-001")
        frag = UnresolvedFragment(kind="scripted_groovy", locator="Jenkinsfile", reason="r")
        ir = _make_ir(unresolved=[frag])
        outcomes = [_outcome("sh-001", _NA)]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert report.banner is not None
        assert report.banner.affected_control_count >= 0
        assert "scripted_groovy" in report.banner.reasons

    def test_banner_absent_when_no_fragments(self):
        cat = _single_control_catalogue("sh-001")
        ir = _make_ir()
        outcomes = [_outcome("sh-001", _SATISFIED)]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert report.banner is None


# ---------------------------------------------------------------------------
# 9. CoverageEvaluationError for unknown control_id
# ---------------------------------------------------------------------------


class TestCoverageEvaluationError:
    def test_unknown_control_id_raises(self):
        cat = _single_control_catalogue("sh-001")
        ir = _make_ir()
        bad_outcome = _outcome("xx-999", _SATISFIED)

        with pytest.raises(CoverageEvaluationError, match="xx-999"):
            ControlEvaluator().evaluate([bad_outcome], ir, cat)


# ---------------------------------------------------------------------------
# 10. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_input_produces_identical_ordering(self):
        cat = _make_catalogue([
            ("sh-001", "secrets", 3.0, True),
            ("sh-002", "secrets", 2.0, True),
            ("sa-001", "sast", 5.0, True),
        ])
        # Different cat needs adjusted weights — use 100 total via category weight
        cat2 = _make_catalogue([
            ("sh-001", "s1", 3.0, True),
            ("sh-002", "s1", 2.0, True),
            ("sa-001", "s2", 5.0, True),
        ])
        ir = _make_ir()
        outcomes = [
            _outcome("sh-001", _SATISFIED, rule_id="r1"),
            _outcome("sh-002", _NA, rule_id="r2"),
        ]

        r1 = ControlEvaluator().evaluate(outcomes, ir, cat2)
        r2 = ControlEvaluator().evaluate(outcomes, ir, cat2)

        ctrl_ids_1 = [e.control_id for e in r1.evaluations]
        ctrl_ids_2 = [e.control_id for e in r2.evaluations]
        assert ctrl_ids_1 == ctrl_ids_2
        assert ctrl_ids_1 == sorted(ctrl_ids_1)


# ---------------------------------------------------------------------------
# 11. Per-format coverage stats
# ---------------------------------------------------------------------------


class TestCoverageStats:
    def test_stats_reflect_format(self):
        cat = _make_catalogue([
            ("sh-001", "s1", 0.0, True),
            ("sh-002", "s1", 0.0, True),
        ])
        ir = _make_ir(source_format="gitlab_ci")
        outcomes = [_outcome("sh-001", _SATISFIED, rule_id="r1")]

        report = ControlEvaluator().evaluate(outcomes, ir, cat)

        assert report.coverage_stats.source_format == "gitlab_ci"
        assert report.coverage_stats.assessable_controls == 1
        assert report.coverage_stats.unassessable_controls == 1


# ---------------------------------------------------------------------------
# 12. Grep test — no grade/score/percentage arithmetic in coverage module
# ---------------------------------------------------------------------------


class TestNoGradeLogic:
    _COVERAGE_SRC = (
        pathlib.Path(__file__).parents[3]
        / "src"
        / "pipelineshield"
        / "analysis"
        / "coverage"
    )
    # Match assignment/comparison patterns indicating grade/score computation:
    # e.g. "grade =", "score >=", "letter_grade =", "pct =", "percentage ="
    # Excludes bare mentions in docstrings/comments by requiring an operator.
    _GRADE_RE = re.compile(
        r"\b(grade_band|letter_grade|pct\s*=|percentage\s*[=>]|score\s*[=>+\-*/])",
        re.IGNORECASE,
    )

    def test_no_grade_band_logic_in_coverage_module(self):
        violations: list[str] = []
        for pyfile in self._COVERAGE_SRC.rglob("*.py"):
            src = pyfile.read_text(encoding="utf-8")
            for lineno, line in enumerate(src.splitlines(), start=1):
                stripped = line.lstrip()
                if stripped.startswith("#") or stripped.startswith(('"""', "'''")):
                    continue
                if self._GRADE_RE.search(line):
                    violations.append(f"{pyfile.name}:{lineno}: {line.strip()!r}")
        assert not violations, (
            "Grade/score arithmetic found in coverage module:\n"
            + "\n".join(violations[:10])
        )
