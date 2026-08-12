"""Integration tests — ControlEvaluator end-to-end (WO-018).

Tests drive the ControlEvaluator directly against hand-constructed IRs that
simulate the output of real normalizers, asserting the expected ControlEvaluation
and CoverageReport contents.

These tests do NOT invoke normalizers or the rule engine (those have their own
test suites) — they start from a known set of rule outcomes and IR to focus on
the coverage evaluation logic itself.
"""
from __future__ import annotations

import pathlib
import uuid

import pytest

from pipelineshield.analysis.coverage import (
    ControlEvaluator,
    ControlState,
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
# Fixtures
# ---------------------------------------------------------------------------

_FIXTURE_DIR = pathlib.Path(__file__).parents[1] / "fixtures" / "pipelines"


def _grade_bands() -> list[GradeBand]:
    return [
        GradeBand(grade="A", min_score=90, max_score=100),
        GradeBand(grade="B", min_score=70, max_score=89),
        GradeBand(grade="C", min_score=50, max_score=69),
        GradeBand(grade="D", min_score=30, max_score=49),
        GradeBand(grade="F", min_score=0, max_score=29),
    ]


def _make_snapshot(*control_ids: str) -> CatalogueSnapshot:
    """Build a single-category catalogue with one control per id."""
    controls = [
        ControlDefinition(
            id=cid,
            category_id="security",
            severity=Severity.HIGH,
            enabled=True,
            reference_tools=["tool-x"],
            weight_contribution=1.0,
        )
        for cid in control_ids
    ]
    return CatalogueSnapshot(
        categories=[
            ControlCategory(
                id="security",
                name="Security",
                weight=100,
                enabled=True,
                controls=controls,
            )
        ],
        grade_bands=_grade_bands(),
    )


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
    rule_id: str = "r",
) -> RuleOutcome:
    return RuleOutcome(
        control_id=control_id,
        rule_id=rule_id,
        verdict=verdict,
        anchors=anchors,
        evidence_kind="test",
        fingerprint=RuleOutcome.compute_fingerprint(rule_id, control_id, anchors),
    )


_S = RuleOutcomeVerdict.SATISFIED
_V = RuleOutcomeVerdict.VIOLATED
_NA = RuleOutcomeVerdict.NOT_ASSESSABLE


# ---------------------------------------------------------------------------
# Jenkins scripted body — all controls not_assessable, banner present
# ---------------------------------------------------------------------------


class TestJenkinsScriptedBody:
    def test_scripted_groovy_produces_all_not_assessable(self):
        """Fully scripted Jenkins Jenkinsfile → all controls NOT_ASSESSABLE, banner present."""
        snapshot = _make_snapshot("sh-001", "sa-001", "ds-001")

        scripted_fragment = UnresolvedFragment(
            kind="scripted_groovy",
            locator="Jenkinsfile",
            reason="Entire file is scripted Groovy",
        )
        ir = _make_ir(source_format="jenkins", unresolved=[scripted_fragment])

        # Rule engine produces NOT_ASSESSABLE for all controls
        outcomes = [
            _outcome("sh-001", _NA, rule_id="r1"),
            _outcome("sa-001", _NA, rule_id="r2"),
            _outcome("ds-001", _NA, rule_id="r3"),
        ]

        report = ControlEvaluator().evaluate(outcomes, ir, snapshot)

        for eval_ in report.evaluations:
            assert eval_.state == ControlState.NOT_ASSESSABLE, (
                f"{eval_.control_id} should be NOT_ASSESSABLE"
            )

        assert report.assessable_weight_total == 0.0
        assert report.banner is not None
        assert report.banner.affected_control_count >= 0
        assert ExclusionReason.SCRIPTED_GROOVY.value in report.banner.reasons
        assert len(report.excluded_fragments) == 1
        assert report.excluded_fragments[0].exclusion_reason == ExclusionReason.SCRIPTED_GROOVY

    def test_scripted_groovy_fixture_file_exists(self):
        fixture = _FIXTURE_DIR / "jenkins" / "scripted_body.jenkinsfile"
        assert fixture.exists(), f"Fixture not found: {fixture}"

    def test_empty_missing_set_for_scripted_jenkins(self):
        """No MISSING controls — they are all NOT_ASSESSABLE, not missing."""
        snapshot = _make_snapshot("sh-001", "sa-001")
        scripted = UnresolvedFragment(
            kind="scripted_groovy", locator="Jenkinsfile", reason="scripted"
        )
        ir = _make_ir(source_format="jenkins", unresolved=[scripted])
        outcomes = [
            _outcome("sh-001", _NA, rule_id="r1"),
            _outcome("sa-001", _NA, rule_id="r2"),
        ]

        report = ControlEvaluator().evaluate(outcomes, ir, snapshot)

        missing = [e for e in report.evaluations if e.state == ControlState.MISSING]
        assert missing == [], f"Expected no MISSING, got: {[e.control_id for e in missing]}"


# ---------------------------------------------------------------------------
# GitLab CI with unresolved include — referencing fragment anchored
# ---------------------------------------------------------------------------


class TestGitLabUnresolvedInclude:
    def test_unresolved_include_produces_banner(self):
        snapshot = _make_snapshot("sh-001", "sa-001")

        include_fragment = UnresolvedFragment(
            kind="include_local",
            locator=".gitlab/templates/build.yml",
            reason="local include not resolved",
        )
        ir = _make_ir(source_format="gitlab_ci", unresolved=[include_fragment])
        outcomes = [
            _outcome("sh-001", _SATISFIED, rule_id="r1"),
            _outcome("sa-001", _NA, rule_id="r2"),
        ]

        report = ControlEvaluator().evaluate(outcomes, ir, snapshot)

        assert report.banner is not None
        assert report.excluded_fragments[0].exclusion_reason == ExclusionReason.UNRESOLVED_INCLUDE

    def test_unresolved_include_fixture_file_exists(self):
        fixture = _FIXTURE_DIR / "gitlab_ci" / "unresolved_include.yml"
        assert fixture.exists(), f"Fixture not found: {fixture}"

    def test_partial_resolution_mixed_outcomes(self):
        """Some controls resolved (PRESENT), others not (NOT_ASSESSABLE)."""
        snapshot = _make_snapshot("sh-001", "sa-001", "ds-001")
        frag = UnresolvedFragment(
            kind="include_local", locator=".gitlab/sec.yml", reason="unresolved"
        )
        ir = _make_ir(source_format="gitlab_ci", unresolved=[frag])
        outcomes = [
            _outcome("sh-001", _SATISFIED, rule_id="r1"),
            _outcome("sa-001", _NA, rule_id="r2"),
            # ds-001 has no outcomes → no_applicable_rule
        ]

        report = ControlEvaluator().evaluate(outcomes, ir, snapshot)

        by_id = {e.control_id: e.state for e in report.evaluations}
        assert by_id["sh-001"] == ControlState.PRESENT
        assert by_id["sa-001"] == ControlState.NOT_ASSESSABLE
        assert by_id["ds-001"] == ControlState.NOT_ASSESSABLE


# ---------------------------------------------------------------------------
# Full determinism snapshot comparison
# ---------------------------------------------------------------------------


class TestDeterminismSnapshot:
    def test_same_inputs_identical_serializable_output(self):
        """Two identical evaluate() calls produce the same control_id ordering."""
        snapshot = _make_snapshot("sh-001", "sa-001")
        ir = _make_ir()
        outcomes = [
            _outcome("sh-001", _S, rule_id="r1"),
            _outcome("sa-001", _V, anchors=(EvidenceAnchor(start_line=5, start_column=1),), rule_id="r2"),
        ]

        r1 = ControlEvaluator().evaluate(outcomes, ir, snapshot)
        r2 = ControlEvaluator().evaluate(outcomes, ir, snapshot)

        ids_1 = [e.control_id for e in r1.evaluations]
        ids_2 = [e.control_id for e in r2.evaluations]
        assert ids_1 == ids_2
        assert ids_1 == sorted(ids_1)

        states_1 = [e.state.value for e in r1.evaluations]
        states_2 = [e.state.value for e in r2.evaluations]
        assert states_1 == states_2
