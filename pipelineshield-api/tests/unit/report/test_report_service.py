"""Unit tests for ReportService (WO-021).

Covers:
- Payload assembly from fixture-like objects (no DB needed).
- Severity distribution aggregation (deterministic only; AI excluded).
- Coverage-limitation mapping.
- Disclaimer presence invariant (AC3).
- Forbidden-phrase guard (AC6): no field asserts security completeness.
- requires_human_review is always present (AC5).
- AnalysisReport shape matches API contract (AC2).
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from pipelineshield.api.v1.schemas.analysis import ADVISORY_DISCLAIMER
from pipelineshield.api.v1.schemas.report import (
    AnalysisReport,
    AnchorDetail,
    CategoryScoreItem,
    CoverageLimitationItem,
    FindingSummary,
    HumanReviewItem,
    SeverityDistribution,
)
from pipelineshield.services.report_service import (
    MissingScoringResultError,
    ReportService,
)

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "reports"

# ---------------------------------------------------------------------------
# Forbidden phrases (BR-02 / AC6)
# ---------------------------------------------------------------------------

_FORBIDDEN = re.compile(
    r"\b(fully compliant|is secure|certified secure|guaranteed|security guarantee)\b",
    re.IGNORECASE,
)


def _scan_for_forbidden(report: AnalysisReport) -> list[str]:
    """Return every field value that contains a forbidden phrase."""
    hits: list[str] = []
    for field_name, value in report.model_dump().items():
        text = json.dumps(value, default=str)
        for m in _FORBIDDEN.finditer(text):
            hits.append(f"{field_name}: {m.group(0)!r}")
    return hits


# ---------------------------------------------------------------------------
# Helpers for building in-memory objects
# ---------------------------------------------------------------------------


def _make_analysis(
    *,
    score: int | None = 88,
    grade: str = "B",
    unscorable_reason: str | None = None,
    pipeline_format: str = "github_actions",
    format_confidence: float = 0.99,
    catalogue_version_id: uuid.UUID | None = None,
) -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        workspace_id=uuid.uuid4(),
        pipeline_format=pipeline_format,
        format_confidence=format_confidence,
        score=score,
        grade=grade,
        unscorable_reason=unscorable_reason,
        catalogue_version_id=catalogue_version_id or uuid.uuid4(),
        created_at=datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_finding(
    *,
    source: str = "deterministic",
    severity: str = "high",
    control_id: str = "ih-001",
    category: str = "infrastructure_hardening",
    requires_human_review: bool = False,
    anchor_line: int = 14,
    evidence: dict | None = None,
) -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        source=source,
        severity=severity,
        control_id=control_id,
        control_category=category,
        title="Test finding",
        requires_human_review=requires_human_review,
        anchor_line=anchor_line,
        anchor_column=1,
        evidence=evidence or {"snippet": "  runs-on: ubuntu-latest"},
    )


def _make_category_score(
    category_id: str = "secrets_hygiene",
    earned: float = 11.11,
    possible: float = 11.11,
    excluded_count: int = 0,
) -> Any:
    return SimpleNamespace(
        category_id=category_id,
        earned=earned,
        possible=possible,
        excluded_count=excluded_count,
    )


def _make_cov_limit(
    kind: str = "unresolved_include",
    location: str = ".gitlab/ci/base.yml",
    reason: str = "File not found.",
    affected: list | None = None,
) -> Any:
    return SimpleNamespace(
        kind=kind,
        location=location,
        reason=reason,
        affected_control_ids=affected or ["sh-001"],
        created_at=datetime(2026, 1, 15, 12, 0, 1, tzinfo=timezone.utc),
    )


def _make_service_with_data(
    *,
    analysis: Any,
    cat_scores: list | None = None,
    findings: list | None = None,
    cov_limits: list | None = None,
    catalogue_version: int = 1,
) -> ReportService:
    """Return a ReportService with session mocked to return test data."""
    svc = ReportService.__new__(ReportService)

    def _load_cat_scores(aid): return cat_scores or []  # noqa: E704
    def _load_findings(aid, wid): return findings or []  # noqa: E704
    def _load_cov_limits(aid): return cov_limits or []  # noqa: E704
    def _resolve_cat_ver(cvid): return catalogue_version  # noqa: E704

    svc._load_category_scores = _load_cat_scores
    svc._load_findings = _load_findings
    svc._load_coverage_limitations = _load_cov_limits
    svc._resolve_catalogue_version = _resolve_cat_ver
    return svc


# ---------------------------------------------------------------------------
# Tests: AnalysisReport shape (AC2)
# ---------------------------------------------------------------------------


class TestAnalysisReportShape:
    def test_all_required_fields_present(self):
        analysis = _make_analysis()
        svc = _make_service_with_data(analysis=analysis)
        report = svc.build_report(analysis)

        assert isinstance(report.analysis_id, uuid.UUID)
        assert isinstance(report.workspace_id, uuid.UUID)
        assert isinstance(report.format, str)
        assert isinstance(report.format_confidence, float)
        assert isinstance(report.catalogue_version, int)
        assert isinstance(report.severity_distribution, SeverityDistribution)
        assert isinstance(report.findings, list)
        assert isinstance(report.coverage_limitations, list)
        assert isinstance(report.requires_human_review, list)
        assert isinstance(report.advisory_disclaimer, str)
        assert isinstance(report.created_at, datetime)

    def test_category_scores_is_list(self):
        analysis = _make_analysis()
        cat_scores = [_make_category_score("sh", 5.0, 11.11)]
        svc = _make_service_with_data(analysis=analysis, cat_scores=cat_scores)
        report = svc.build_report(analysis)
        assert len(report.category_scores) == 1
        item = report.category_scores[0]
        assert isinstance(item, CategoryScoreItem)
        assert item.category == "sh"

    def test_null_score_when_unscorable(self):
        analysis = _make_analysis(
            score=None, grade="", unscorable_reason="all_not_assessable"
        )
        svc = _make_service_with_data(analysis=analysis)
        report = svc.build_report(analysis)
        assert report.total_score is None
        assert report.letter_grade is None
        assert report.unscorable_reason == "all_not_assessable"

    def test_score_populated_when_scorable(self):
        analysis = _make_analysis(score=88, grade="B")
        svc = _make_service_with_data(analysis=analysis)
        report = svc.build_report(analysis)
        assert report.total_score == 88.0
        assert report.letter_grade == "B"
        assert report.unscorable_reason is None


# ---------------------------------------------------------------------------
# Tests: Disclaimer invariant (AC3)
# ---------------------------------------------------------------------------


class TestDisclaimerInvariant:
    def test_disclaimer_always_populated(self):
        analysis = _make_analysis()
        svc = _make_service_with_data(analysis=analysis)
        report = svc.build_report(analysis)
        assert report.advisory_disclaimer == ADVISORY_DISCLAIMER
        assert len(report.advisory_disclaimer.strip()) > 0

    def test_disclaimer_populated_on_unscorable(self):
        analysis = _make_analysis(
            score=None, grade="", unscorable_reason="all_not_assessable"
        )
        svc = _make_service_with_data(analysis=analysis)
        report = svc.build_report(analysis)
        assert report.advisory_disclaimer == ADVISORY_DISCLAIMER

    @pytest.mark.parametrize(
        "pipeline_format",
        ["github_actions", "gitlab_ci", "jenkins"],
    )
    def test_disclaimer_present_for_every_format(self, pipeline_format):
        analysis = _make_analysis(pipeline_format=pipeline_format)
        svc = _make_service_with_data(analysis=analysis)
        report = svc.build_report(analysis)
        assert report.advisory_disclaimer, "disclaimer must not be blank"

    def test_blank_disclaimer_rejected_by_model(self):
        with pytest.raises(Exception):
            AnalysisReport(
                analysis_id=uuid.uuid4(),
                workspace_id=uuid.uuid4(),
                format="github_actions",
                format_confidence=0.99,
                catalogue_version=1,
                severity_distribution=SeverityDistribution(),
                advisory_disclaimer="",
                created_at=datetime.now(timezone.utc),
            )

    def test_whitespace_only_disclaimer_rejected(self):
        with pytest.raises(Exception):
            AnalysisReport(
                analysis_id=uuid.uuid4(),
                workspace_id=uuid.uuid4(),
                format="github_actions",
                format_confidence=0.99,
                catalogue_version=1,
                severity_distribution=SeverityDistribution(),
                advisory_disclaimer="   \t  ",
                created_at=datetime.now(timezone.utc),
            )


# ---------------------------------------------------------------------------
# Tests: Forbidden-phrase guard (AC6)
# ---------------------------------------------------------------------------


class TestForbiddenPhraseGuard:
    def test_no_forbidden_phrases_in_scored_report(self):
        analysis = _make_analysis()
        findings = [_make_finding(source="deterministic", severity="high")]
        svc = _make_service_with_data(analysis=analysis, findings=findings)
        report = svc.build_report(analysis)
        hits = _scan_for_forbidden(report)
        assert not hits, f"Forbidden phrases found: {hits}"

    def test_no_forbidden_phrases_in_unscorable_report(self):
        analysis = _make_analysis(
            score=None, grade="", unscorable_reason="all_not_assessable"
        )
        svc = _make_service_with_data(analysis=analysis)
        report = svc.build_report(analysis)
        hits = _scan_for_forbidden(report)
        assert not hits, f"Forbidden phrases found: {hits}"

    @pytest.mark.parametrize(
        "pipeline_format",
        ["github_actions", "gitlab_ci", "jenkins"],
    )
    def test_no_forbidden_phrases_for_any_format(self, pipeline_format):
        analysis = _make_analysis(pipeline_format=pipeline_format)
        svc = _make_service_with_data(analysis=analysis)
        report = svc.build_report(analysis)
        hits = _scan_for_forbidden(report)
        assert not hits, f"Forbidden phrases in {pipeline_format}: {hits}"

    def test_forbidden_phrases_in_fixtures(self):
        """Report fixtures must not contain forbidden phrases in assembled reports."""
        for fixture_path in (_FIXTURES / "github_actions_high_score.json",
                             _FIXTURES / "gitlab_ci_low_score.json",
                             _FIXTURES / "jenkins_na_heavy.json"):
            raw = fixture_path.read_text()
            for phrase in ("fully compliant", "is secure", "certified secure",
                           "guaranteed", "security guarantee"):
                assert phrase.lower() not in raw.lower(), (
                    f"Fixture {fixture_path.name} contains forbidden phrase: {phrase!r}"
                )


# ---------------------------------------------------------------------------
# Tests: Severity distribution (AC2)
# ---------------------------------------------------------------------------


class TestSeverityDistribution:
    def test_counts_deterministic_findings_only(self):
        findings = [
            _make_finding(source="deterministic", severity="critical"),
            _make_finding(source="deterministic", severity="high"),
            _make_finding(source="deterministic", severity="high"),
            _make_finding(source="deterministic", severity="medium"),
            _make_finding(source="ai", severity="critical"),  # excluded from counts
        ]
        dist = ReportService._build_severity_distribution(findings)
        assert dist.critical == 1
        assert dist.high == 2
        assert dist.medium == 1
        assert dist.low == 0
        assert dist.informational == 0

    def test_info_mapped_to_informational(self):
        findings = [
            _make_finding(source="deterministic", severity="info"),
            _make_finding(source="deterministic", severity="informational"),
        ]
        dist = ReportService._build_severity_distribution(findings)
        assert dist.informational == 2

    def test_zero_findings_produces_all_zeros(self):
        dist = ReportService._build_severity_distribution([])
        assert dist.critical == dist.high == dist.medium == dist.low == dist.informational == 0

    def test_ai_findings_not_counted_in_severity(self):
        findings = [_make_finding(source="ai", severity="critical")]
        dist = ReportService._build_severity_distribution(findings)
        assert dist.critical == 0


# ---------------------------------------------------------------------------
# Tests: Coverage limitation mapping (AC4)
# ---------------------------------------------------------------------------


class TestCoverageLimitationMapping:
    def test_single_limitation_mapped(self):
        cl = _make_cov_limit(
            kind="unresolved_include",
            location=".gitlab/ci/base.yml",
            reason="Not found.",
            affected=["sh-001", "rc-001"],
        )
        result = ReportService._build_coverage_limitations([cl])
        assert len(result) == 1
        item = result[0]
        assert item.kind == "unresolved_include"
        assert item.location == ".gitlab/ci/base.yml"
        assert item.reason == "Not found."
        assert "sh-001" in item.affected_control_ids
        assert "rc-001" in item.affected_control_ids

    def test_empty_limitations_returns_empty_list(self):
        result = ReportService._build_coverage_limitations([])
        assert result == []

    def test_scripted_groovy_limitation(self):
        cl = _make_cov_limit(
            kind="scripted_groovy",
            location="Jenkinsfile:stage('Build'):script",
            reason="Dynamic Groovy execution.",
            affected=["sh-001", "sh-002"],
        )
        result = ReportService._build_coverage_limitations([cl])
        assert result[0].kind == "scripted_groovy"


# ---------------------------------------------------------------------------
# Tests: requires_human_review always present (AC5)
# ---------------------------------------------------------------------------


class TestRequiresHumanReview:
    def test_always_present_even_when_empty(self):
        analysis = _make_analysis()
        svc = _make_service_with_data(analysis=analysis)
        report = svc.build_report(analysis)
        assert isinstance(report.requires_human_review, list)

    def test_ai_findings_included(self):
        findings = [
            _make_finding(source="ai", control_id="sh-001", requires_human_review=True),
            _make_finding(source="deterministic", control_id="ih-001"),
        ]
        items = ReportService._build_human_review_items(findings, [])
        assert len(items) == 1
        assert items[0].reason == "ai_advisory"
        assert items[0].control_id == "sh-001"

    def test_coverage_limitation_controls_included(self):
        cl = _make_cov_limit(affected=["na-ctrl-1", "na-ctrl-2"])
        items = ReportService._build_human_review_items([], [cl])
        reasons = {i.reason for i in items}
        assert reasons == {"not_assessable"}
        ctrl_ids = {i.control_id for i in items}
        assert "na-ctrl-1" in ctrl_ids
        assert "na-ctrl-2" in ctrl_ids

    def test_no_duplicate_not_assessable_controls(self):
        cl1 = _make_cov_limit(affected=["na-001"])
        cl2 = _make_cov_limit(affected=["na-001", "na-002"])  # na-001 seen twice
        items = ReportService._build_human_review_items([], [cl1, cl2])
        na_ctrl_ids = [i.control_id for i in items if i.reason == "not_assessable"]
        assert na_ctrl_ids.count("na-001") == 1  # deduped

    def test_ai_finding_has_finding_id(self):
        finding = _make_finding(source="ai", control_id="sh-001")
        items = ReportService._build_human_review_items([finding], [])
        assert items[0].finding_id == finding.id


# ---------------------------------------------------------------------------
# Tests: MissingScoringResultError (error handling)
# ---------------------------------------------------------------------------


class TestMissingScoringResultError:
    def test_raises_when_score_is_none_without_unscorable_reason(self):
        analysis = _make_analysis(score=None, grade="", unscorable_reason=None)
        svc = _make_service_with_data(analysis=analysis)
        with pytest.raises(MissingScoringResultError):
            svc.build_report(analysis)

    def test_does_not_raise_when_unscorable_reason_set(self):
        analysis = _make_analysis(
            score=None, grade="", unscorable_reason="all_not_assessable"
        )
        svc = _make_service_with_data(analysis=analysis)
        report = svc.build_report(analysis)
        assert report.unscorable_reason == "all_not_assessable"


# ---------------------------------------------------------------------------
# Tests: FindingSummary construction
# ---------------------------------------------------------------------------


class TestFindingSummaryConstruction:
    def test_anchor_populated_from_anchor_line(self):
        finding = _make_finding(anchor_line=14, evidence={"snippet": "  test"})
        summaries = ReportService._build_finding_summaries([finding])
        assert summaries[0].anchor is not None
        assert summaries[0].anchor.start_line == 14
        assert summaries[0].anchor.excerpt == "  test"

    def test_control_id_fallback_empty_string_when_none(self):
        finding = _make_finding(control_id=None)
        finding.control_id = None
        summaries = ReportService._build_finding_summaries([finding])
        assert summaries[0].control_id == ""

    def test_source_passes_through(self):
        finding = _make_finding(source="deterministic")
        summaries = ReportService._build_finding_summaries([finding])
        assert summaries[0].source == "deterministic"


# ---------------------------------------------------------------------------
# Tests: Fixture files loaded and format correct
# ---------------------------------------------------------------------------


class TestReportFixtures:
    @pytest.mark.parametrize(
        "fixture_name",
        [
            "github_actions_high_score.json",
            "gitlab_ci_low_score.json",
            "jenkins_na_heavy.json",
        ],
    )
    def test_fixture_is_valid_json(self, fixture_name):
        path = _FIXTURES / fixture_name
        data = json.loads(path.read_text())
        assert "description" in data
        assert "analysis" in data
        assert "category_scores" in data
        assert "findings" in data
        assert "coverage_limitations" in data

    def test_github_actions_fixture_has_high_score(self):
        data = json.loads((_FIXTURES / "github_actions_high_score.json").read_text())
        assert data["analysis"]["pipeline_format"] == "github_actions"
        assert data["analysis"]["score"] is not None
        assert data["analysis"]["score"] >= 70

    def test_gitlab_ci_fixture_has_low_score(self):
        data = json.loads((_FIXTURES / "gitlab_ci_low_score.json").read_text())
        assert data["analysis"]["pipeline_format"] == "gitlab_ci"
        assert data["analysis"]["score"] is not None
        assert data["analysis"]["score"] < 40

    def test_jenkins_fixture_is_unscorable(self):
        data = json.loads((_FIXTURES / "jenkins_na_heavy.json").read_text())
        assert data["analysis"]["pipeline_format"] == "jenkins"
        assert data["analysis"]["unscorable_reason"] == "all_not_assessable"
        assert data["analysis"]["score"] is None
        assert len(data["coverage_limitations"]) >= 1

    def test_jenkins_fixture_has_scripted_groovy_limitation(self):
        data = json.loads((_FIXTURES / "jenkins_na_heavy.json").read_text())
        kinds = {cl["kind"] for cl in data["coverage_limitations"]}
        assert "scripted_groovy" in kinds

    def test_gitlab_fixture_has_ai_finding(self):
        data = json.loads((_FIXTURES / "gitlab_ci_low_score.json").read_text())
        ai_findings = [f for f in data["findings"] if f["source"] == "ai"]
        assert len(ai_findings) >= 1
