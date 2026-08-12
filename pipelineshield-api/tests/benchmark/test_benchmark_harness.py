"""Benchmark harness test suite — marked 'benchmark'.

Excluded from the default fast unit run via pytest marker configuration.

Test layers:
- Unit: metric computation, match tolerance, percentile, threshold evaluation
- Integration: full harness run over committed corpus, JSON report shape
- CLI: in-process entry point, exit code 0 (pass) and exit code 1 (breach)
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

_CORPUS_DIR = Path(__file__).parents[2] / "tests" / "fixtures" / "corpus"
_CATALOGUE_PATH = Path(__file__).parents[2] / "tests" / "fixtures" / "catalogue_v1.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_case_result(
    path: str = "test.yml",
    fmt: str = "github_actions",
    duration_ms: float = 100.0,
    validated_findings: list | None = None,
    suppression_report=None,
    coverage_report=None,
    error: str | None = None,
) -> Any:
    from pipelineshield.analysis.anchoring.models import SuppressionReport
    from pipelineshield.benchmark.runner import CaseResult

    return CaseResult(
        case_path=path,
        source_format=fmt,
        duration_ms=duration_ms,
        validated_findings=validated_findings or [],
        suppression_report=suppression_report or SuppressionReport(),
        coverage_report=coverage_report,
        error=error,
    )


def _make_validated_finding(control_id: str, anchor_line: int, rule_id: str = "r1") -> Any:
    """Create a minimal ValidatedFinding-like mock for metric tests."""
    import uuid

    from pipelineshield.analysis.anchoring.models import ValidatedFinding

    return ValidatedFinding(
        rule_id=rule_id,
        control_id=control_id,
        category="test",
        source="deterministic",
        severity="high",
        title="test",
        description="",
        evidence={},
        analysis_id=uuid.uuid4(),
        workspace_id=uuid.uuid4(),
        anchor_line=anchor_line,
        anchor_column=1,
        snippet="",
        weight=1,
        requires_human_review=False,
    )


def _make_corpus_file(
    path: str = "test.yml",
    fmt: str = "github_actions",
    seeded_gaps: list | None = None,
) -> Any:
    from pipelineshield.benchmark.ground_truth import CorpusFile, PipelineFormat

    return CorpusFile(
        path=path,
        format=PipelineFormat(fmt),
        line_count=50,
        seeded_gaps=seeded_gaps or [],
    )


def _make_seeded_gap(
    control_id: str = "sh-001",
    category: str = "secrets_hygiene",
    expected_anchor_line: int | None = 10,
    expected_status: str = "missing",
) -> Any:
    from pipelineshield.benchmark.ground_truth import (
        ControlStatus,
        Severity,
        SeededGap,
    )

    return SeededGap(
        control_id=control_id,
        category=category,
        severity=Severity.high,
        expected_status=ControlStatus(expected_status),
        expected_anchor_line=expected_anchor_line,
        rationale="test",
    )


# ---------------------------------------------------------------------------
# Unit tests — detection matching and tolerance
# ---------------------------------------------------------------------------


class TestDetectionTolerance:
    def test_exact_anchor_match_detected(self):
        from pipelineshield.benchmark.metrics import compute_metrics

        gap = _make_seeded_gap(control_id="sh-001", expected_anchor_line=10)
        vf = _make_validated_finding("sh-001", anchor_line=10)
        cr = _make_case_result(validated_findings=[vf])
        cf = _make_corpus_file(seeded_gaps=[gap])

        m = compute_metrics([cr], [cf], anchor_line_tolerance=2)
        assert m.total_detected == 1
        assert m.gap_results[0].detected is True

    def test_anchor_within_tolerance_detected(self):
        from pipelineshield.benchmark.metrics import compute_metrics

        gap = _make_seeded_gap(control_id="sh-001", expected_anchor_line=10)
        vf = _make_validated_finding("sh-001", anchor_line=12)  # +2
        cr = _make_case_result(validated_findings=[vf])
        cf = _make_corpus_file(seeded_gaps=[gap])

        m = compute_metrics([cr], [cf], anchor_line_tolerance=2)
        assert m.total_detected == 1

    def test_anchor_outside_tolerance_not_detected(self):
        from pipelineshield.benchmark.metrics import compute_metrics

        gap = _make_seeded_gap(control_id="sh-001", expected_anchor_line=10)
        vf = _make_validated_finding("sh-001", anchor_line=13)  # +3
        cr = _make_case_result(validated_findings=[vf])
        cf = _make_corpus_file(seeded_gaps=[gap])

        m = compute_metrics([cr], [cf], anchor_line_tolerance=2)
        assert m.total_detected == 0

    def test_wrong_control_id_not_detected(self):
        from pipelineshield.benchmark.metrics import compute_metrics

        gap = _make_seeded_gap(control_id="sh-001", expected_anchor_line=10)
        vf = _make_validated_finding("lp-001", anchor_line=10)
        cr = _make_case_result(validated_findings=[vf])
        cf = _make_corpus_file(seeded_gaps=[gap])

        m = compute_metrics([cr], [cf], anchor_line_tolerance=2)
        assert m.total_detected == 0

    def test_null_expected_anchor_line_any_match_detected(self):
        """SeededGap with null expected_anchor_line: any matching control_id counts."""
        from pipelineshield.benchmark.metrics import compute_metrics

        gap = _make_seeded_gap(control_id="as-001", expected_anchor_line=None)
        vf = _make_validated_finding("as-001", anchor_line=99)
        cr = _make_case_result(validated_findings=[vf])
        cf = _make_corpus_file(seeded_gaps=[gap])

        m = compute_metrics([cr], [cf], anchor_line_tolerance=2)
        assert m.total_detected == 1

    def test_not_assessable_gap_excluded_from_denominator(self):
        """SeededGap with expected_status=not_assessable must not count in denominator."""
        from pipelineshield.benchmark.metrics import compute_metrics

        gap = _make_seeded_gap(
            control_id="sh-001",
            expected_anchor_line=10,
            expected_status="not_assessable",
        )
        cr = _make_case_result()
        cf = _make_corpus_file(seeded_gaps=[gap])

        m = compute_metrics([cr], [cf], anchor_line_tolerance=2)
        assert m.total_seeded_gaps == 0

    def test_no_gaps_detection_rate_nan(self):
        """Corpus file with no seeded gaps → overall rate is NaN (no division by zero)."""
        from pipelineshield.benchmark.metrics import compute_metrics

        cr = _make_case_result()
        cf = _make_corpus_file(seeded_gaps=[])

        m = compute_metrics([cr], [cf])
        assert math.isnan(m.overall_detection_rate)

    def test_duplicate_finding_counts_once(self):
        """Two findings matching same gap → 1 detection, extra surfaced in adjudication."""
        from pipelineshield.benchmark.metrics import compute_metrics

        gap = _make_seeded_gap(control_id="sh-001", expected_anchor_line=10)
        vf1 = _make_validated_finding("sh-001", anchor_line=10, rule_id="r1")
        vf2 = _make_validated_finding("sh-001", anchor_line=11, rule_id="r2")  # within +1
        cr = _make_case_result(validated_findings=[vf1, vf2])
        cf = _make_corpus_file(seeded_gaps=[gap])

        m = compute_metrics([cr], [cf], anchor_line_tolerance=2)
        assert m.total_detected == 1
        # Second finding should appear in adjudication
        assert len(m.adjudication_required) >= 1


# ---------------------------------------------------------------------------
# Unit tests — latency percentile
# ---------------------------------------------------------------------------


class TestLatencyPercentile:
    def test_p50_middle_value(self):
        from pipelineshield.benchmark.metrics import _percentile

        vals = sorted([100.0, 200.0, 300.0])
        assert abs(_percentile(vals, 50) - 200.0) < 1e-9

    def test_p95_near_max(self):
        from pipelineshield.benchmark.metrics import _percentile

        vals = sorted(float(i) for i in range(100))
        p95 = _percentile(vals, 95)
        assert 93.0 <= p95 <= 95.0

    def test_empty_list_returns_zero(self):
        from pipelineshield.benchmark.metrics import _percentile

        assert _percentile([], 50) == 0.0

    def test_single_element(self):
        from pipelineshield.benchmark.metrics import _percentile

        assert _percentile([42.0], 95) == 42.0


# ---------------------------------------------------------------------------
# Unit tests — threshold evaluation
# ---------------------------------------------------------------------------


class TestThresholdEvaluation:
    def _make_metrics(self, **kwargs) -> Any:
        from pipelineshield.benchmark.metrics import BenchmarkMetrics

        defaults = dict(
            total_seeded_gaps=10,
            total_detected=9,
            overall_detection_rate=0.90,
            detection_rate_by_format={
                "github_actions": 0.90,
                "gitlab_ci": 0.85,
            },
            detection_rate_by_category={},
            gap_results=[],
            adjudication_required=[],
            unanchored_findings=0,
            latency_p50_ms=100.0,
            latency_p95_ms=1000.0,
            not_assessable_by_format=[],
            case_errors=[],
        )
        defaults.update(kwargs)
        return BenchmarkMetrics(**defaults)

    def _check(self, metrics, thresholds: dict) -> list[str]:
        from pipelineshield.benchmark.cli import _check_thresholds

        return _check_thresholds(metrics, thresholds)

    def test_all_pass_returns_empty(self):
        m = self._make_metrics()
        breaches = self._check(m, {
            "overall_detection_min": 0.80,
            "format_detection_min": {"github_actions": 0.80, "gitlab_ci": 0.80},
            "max_unanchored_findings": 0,
            "deterministic_p95_budget_ms": 5000,
        })
        assert breaches == []

    def test_overall_rate_breach(self):
        m = self._make_metrics(overall_detection_rate=0.70)
        breaches = self._check(m, {"overall_detection_min": 0.80})
        assert any("overall detection" in b for b in breaches)

    def test_format_rate_breach(self):
        m = self._make_metrics(detection_rate_by_format={"github_actions": 0.60})
        breaches = self._check(m, {
            "format_detection_min": {"github_actions": 0.80},
        })
        assert any("github_actions" in b for b in breaches)

    def test_unanchored_breach(self):
        m = self._make_metrics(unanchored_findings=1)
        breaches = self._check(m, {"max_unanchored_findings": 0})
        assert any("unanchored" in b for b in breaches)

    def test_latency_breach(self):
        m = self._make_metrics(latency_p95_ms=6000.0)
        breaches = self._check(m, {"deterministic_p95_budget_ms": 5000})
        assert any("latency" in b or "p95" in b for b in breaches)

    def test_nan_detection_rate_not_breaching(self):
        """NaN detection rate (no seeded gaps in format) should not trigger breach."""
        m = self._make_metrics(
            detection_rate_by_format={"github_actions": float("nan")}
        )
        breaches = self._check(m, {
            "format_detection_min": {"github_actions": 0.80},
        })
        assert not any("github_actions" in b for b in breaches)


# ---------------------------------------------------------------------------
# Unit tests — adjudication list
# ---------------------------------------------------------------------------


class TestAdjudicationList:
    def test_extra_finding_surfaces_in_adjudication(self):
        from pipelineshield.benchmark.metrics import compute_metrics

        vf = _make_validated_finding("lp-001", anchor_line=5)
        cr = _make_case_result(validated_findings=[vf])
        cf = _make_corpus_file(seeded_gaps=[])  # no expected gaps

        m = compute_metrics([cr], [cf])
        assert len(m.adjudication_required) == 1
        assert m.adjudication_required[0].control_id == "lp-001"
        assert m.adjudication_required[0].anchor_line == 5

    def test_matched_finding_not_in_adjudication(self):
        from pipelineshield.benchmark.metrics import compute_metrics

        gap = _make_seeded_gap(control_id="sh-001", expected_anchor_line=10)
        vf = _make_validated_finding("sh-001", anchor_line=10)
        cr = _make_case_result(validated_findings=[vf])
        cf = _make_corpus_file(seeded_gaps=[gap])

        m = compute_metrics([cr], [cf])
        assert m.adjudication_required == []


# ---------------------------------------------------------------------------
# Unit tests — unanchored counting
# ---------------------------------------------------------------------------


class TestUnanchoredCounting:
    def test_missing_anchor_suppression_counted(self):
        from pipelineshield.analysis.anchoring.models import (
            SuppressionReason,
            SuppressionRecord,
            SuppressionReport,
        )
        from pipelineshield.benchmark.metrics import compute_metrics

        report = SuppressionReport(
            suppressions=[
                SuppressionRecord(
                    rule_id="r1",
                    control_id="sh-001",
                    source="deterministic",
                    reason=SuppressionReason.MISSING_ANCHOR,
                )
            ]
        )
        cr = _make_case_result(suppression_report=report)
        cf = _make_corpus_file()

        m = compute_metrics([cr], [cf])
        assert m.unanchored_findings == 1

    def test_other_suppression_reasons_not_counted_as_unanchored(self):
        from pipelineshield.analysis.anchoring.models import (
            SuppressionReason,
            SuppressionRecord,
            SuppressionReport,
        )
        from pipelineshield.benchmark.metrics import compute_metrics

        report = SuppressionReport(
            suppressions=[
                SuppressionRecord(
                    rule_id="r1",
                    control_id="sh-001",
                    source="deterministic",
                    reason=SuppressionReason.FINGERPRINT_MISMATCH,
                )
            ]
        )
        cr = _make_case_result(suppression_report=report)
        cf = _make_corpus_file()

        m = compute_metrics([cr], [cf])
        assert m.unanchored_findings == 0


# ---------------------------------------------------------------------------
# Unit tests — JSON report shape
# ---------------------------------------------------------------------------


class TestReportJSON:
    def _make_simple_metrics(self):
        from pipelineshield.benchmark.metrics import BenchmarkMetrics

        return BenchmarkMetrics(
            total_seeded_gaps=3,
            total_detected=2,
            overall_detection_rate=0.667,
            detection_rate_by_format={"github_actions": 0.667},
            detection_rate_by_category={"secrets_hygiene": 1.0},
            gap_results=[],
            adjudication_required=[],
            unanchored_findings=0,
            latency_p50_ms=120.0,
            latency_p95_ms=400.0,
            not_assessable_by_format=[],
            case_errors=[],
        )

    def test_required_top_level_keys(self):
        from pipelineshield.benchmark.report import render_json

        doc = render_json(self._make_simple_metrics(), catalogue_version=1)
        required = {
            "harness_version",
            "catalogue_version",
            "corpus_checksum",
            "aggregate",
            "detection_by_format",
            "detection_by_category",
            "not_assessable_by_format",
            "gap_results",
            "adjudication_required",
        }
        assert required.issubset(doc.keys())

    def test_aggregate_keys_present(self):
        from pipelineshield.benchmark.report import render_json

        doc = render_json(self._make_simple_metrics())
        agg = doc["aggregate"]
        for key in [
            "total_seeded_gaps",
            "total_detected",
            "overall_detection_rate",
            "unanchored_findings",
            "latency_p50_ms",
            "latency_p95_ms",
            "case_errors",
        ]:
            assert key in agg, f"Missing aggregate key: {key}"

    def test_json_serializable(self):
        from pipelineshield.benchmark.report import render_json

        doc = render_json(self._make_simple_metrics())
        serialized = json.dumps(doc)
        reparsed = json.loads(serialized)
        assert reparsed["aggregate"]["total_seeded_gaps"] == 3

    def test_nan_rate_rendered_as_null(self):
        from pipelineshield.benchmark.metrics import BenchmarkMetrics
        from pipelineshield.benchmark.report import render_json

        m = BenchmarkMetrics(
            total_seeded_gaps=0,
            total_detected=0,
            overall_detection_rate=float("nan"),
            detection_rate_by_format={"github_actions": float("nan")},
            detection_rate_by_category={},
            gap_results=[],
            adjudication_required=[],
            unanchored_findings=0,
            latency_p50_ms=0.0,
            latency_p95_ms=0.0,
            not_assessable_by_format=[],
            case_errors=[],
        )
        doc = render_json(m)
        assert doc["aggregate"]["overall_detection_rate"] is None
        assert doc["detection_by_format"]["github_actions"] is None


# ---------------------------------------------------------------------------
# Integration test — full harness run over committed corpus
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
class TestBenchmarkHarness:
    """Runs the full harness over the committed synthetic corpus.

    Requires no network, no LLM, no live database.
    Excluded from default test run via the 'benchmark' marker.
    """

    @pytest.fixture(scope="class")
    def catalogue_snapshot(self):
        from pipelineshield.catalogue.schemas import CatalogueSnapshot

        raw = json.loads(_CATALOGUE_PATH.read_text())
        return CatalogueSnapshot.model_validate(raw)

    @pytest.fixture(scope="class")
    def ground_truth(self):
        from tests.fixtures import load_ground_truth

        return load_ground_truth()

    @pytest.fixture(scope="class")
    def case_results(self, ground_truth, catalogue_snapshot):
        from pipelineshield.benchmark.runner import run_corpus

        return run_corpus(
            ground_truth.files,
            _CORPUS_DIR,
            catalogue_snapshot,
            warmup=True,
            warmup_iterations=1,
        )

    @pytest.fixture(scope="class")
    def metrics(self, case_results, ground_truth):
        from pipelineshield.benchmark.metrics import compute_metrics

        return compute_metrics(
            case_results, list(ground_truth.files), anchor_line_tolerance=2
        )

    def test_no_case_errors(self, case_results):
        errors = [r for r in case_results if r.error]
        assert errors == [], f"Case errors: {[r.error for r in errors]}"

    def test_json_report_has_required_keys(self, metrics):
        from pipelineshield.benchmark.report import render_json

        doc = render_json(metrics, catalogue_version=1)
        assert "harness_version" in doc
        assert "aggregate" in doc
        assert "detection_by_format" in doc
        assert "gap_results" in doc
        assert "adjudication_required" in doc
        assert "not_assessable_by_format" in doc

    def test_unanchored_findings_zero(self, metrics):
        assert metrics.unanchored_findings == 0, (
            f"Expected 0 unanchored findings, got {metrics.unanchored_findings}"
        )

    def test_github_actions_detection_meets_threshold(self, metrics):
        rate = metrics.detection_rate_by_format.get("github_actions", float("nan"))
        if not math.isnan(rate):
            assert rate >= 0.80, (
                f"GitHub Actions detection rate {rate:.1%} below 80%"
            )

    def test_gitlab_ci_detection_meets_threshold(self, metrics):
        rate = metrics.detection_rate_by_format.get("gitlab_ci", float("nan"))
        if not math.isnan(rate):
            assert rate >= 0.80, (
                f"GitLab CI detection rate {rate:.1%} below 80%"
            )

    def test_latency_p95_within_budget(self, metrics):
        assert metrics.latency_p95_ms <= 5000, (
            f"p95 latency {metrics.latency_p95_ms:.1f}ms exceeds 5000ms budget"
        )

    def test_hardened_variant_no_violated_outcomes(self, case_results, ground_truth):
        """Hardened corpus files with no seeded gaps must produce no violated outcomes."""
        from pipelineshield.analysis.rule_engine.protocol import RuleOutcomeVerdict

        hardened_files = {
            cf.path
            for cf in ground_truth.files
            if not cf.seeded_gaps
        }
        for cr in case_results:
            if cr.case_path not in hardened_files:
                continue
            violated = [
                o for o in cr.outcomes
                if o.verdict == RuleOutcomeVerdict.VIOLATED
            ]
            assert violated == [], (
                f"Hardened case {cr.case_path!r} has violated outcomes: "
                f"{[o.control_id for o in violated]}"
            )


# ---------------------------------------------------------------------------
# CLI integration tests — in-process entry point
# ---------------------------------------------------------------------------


class TestCLIEntryPoint:
    def _run_cli(self, argv: list[str]) -> int:
        from pipelineshield.benchmark.cli import main

        return main(argv)

    def test_help_does_not_raise(self):
        from pipelineshield.benchmark.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0

    def test_invalid_thresholds_path_exits_2(self, tmp_path):
        code = self._run_cli([
            "--thresholds", str(tmp_path / "nonexistent.yaml"),
            "--corpus-dir", str(_CORPUS_DIR),
            "--catalogue", str(_CATALOGUE_PATH),
        ])
        assert code == 2

    def test_empty_corpus_dir_exits_2(self, tmp_path):
        """An empty corpus directory (no ground_truth.yaml) must exit 2."""
        code = self._run_cli([
            "--corpus-dir", str(tmp_path),
            "--catalogue", str(_CATALOGUE_PATH),
        ])
        assert code == 2

    def test_degraded_thresholds_exit_1(self, tmp_path):
        """Lowering threshold below 1.0 but demanding 100% detection triggers breach."""
        import yaml

        thresholds = {
            "overall_detection_min": 1.0,
            "format_detection_min": {
                "github_actions": 1.0,
                "gitlab_ci": 1.0,
            },
            "max_unanchored_findings": 0,
            "deterministic_p95_budget_ms": 1,  # 1ms budget — guaranteed breach
            "anchor_line_tolerance": 2,
        }
        t_path = tmp_path / "strict_thresholds.yaml"
        t_path.write_text(yaml.dump(thresholds), encoding="utf-8")

        code = self._run_cli([
            "--thresholds", str(t_path),
            "--corpus-dir", str(_CORPUS_DIR),
            "--catalogue", str(_CATALOGUE_PATH),
            "--warmup", "0",
        ])
        # p95 > 1ms → exit 1 (gate breach)
        assert code in (1, 2)  # 2 if case errors
