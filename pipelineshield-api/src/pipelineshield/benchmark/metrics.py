"""Benchmark metrics computation — detection rates, latency, adjudication list.

All functions are pure (no I/O) and work on CaseResult lists produced by runner.py.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

from pipelineshield.analysis.anchoring.models import SuppressionReason
from pipelineshield.benchmark.ground_truth import CorpusFile, SeededGap
from pipelineshield.benchmark.runner import CaseResult


@dataclass
class AdjudicationEntry:
    """A validated finding that does not match any seeded gap."""

    case_path: str
    control_id: str
    rule_id: str
    anchor_line: int
    category: str = ""       # WO-046: for FP-by-category aggregation
    source_format: str = ""  # WO-046: for FP-by-format aggregation


@dataclass
class GapMatchResult:
    """Outcome for a single seeded gap after attempting match."""

    case_path: str
    control_id: str
    expected_anchor_line: Optional[int]
    detected: bool
    expected_status: str


@dataclass
class NotAssessableStats:
    """Per-format not-assessable accounting."""

    source_format: str
    assessable_controls: int
    unassessable_controls: int
    excluded_fragment_count: int
    assessable_weight_total: float
    catalogue_weight_total: float

    @property
    def assessable_weight_ratio(self) -> float:
        if self.catalogue_weight_total <= 0:
            return 0.0
        return self.assessable_weight_total / self.catalogue_weight_total


@dataclass
class BenchmarkMetrics:
    """Aggregate metrics across the entire corpus run."""

    total_seeded_gaps: int
    total_detected: int
    overall_detection_rate: float
    detection_rate_by_format: dict[str, float]
    detection_rate_by_category: dict[str, float]
    gap_results: list[GapMatchResult]
    adjudication_required: list[AdjudicationEntry]
    unanchored_findings: int
    latency_p50_ms: float
    latency_p95_ms: float
    not_assessable_by_format: list[NotAssessableStats]
    case_errors: list[str]

    # WO-046: raw gap counts per format/category (for TP/FN calculation in reports)
    gaps_by_format: dict[str, int] = field(default_factory=dict)
    detected_by_format: dict[str, int] = field(default_factory=dict)
    gaps_by_category: dict[str, int] = field(default_factory=dict)
    detected_by_category: dict[str, int] = field(default_factory=dict)

    # WO-046: false positive metrics (first-class, not derived from adjudication length)
    false_positive_count: int = 0
    false_positive_by_format: dict[str, int] = field(default_factory=dict)
    false_positive_by_category: dict[str, int] = field(default_factory=dict)

    # WO-046: precision per format/category  (TP / (TP + FP))
    precision_by_format: dict[str, float] = field(default_factory=dict)
    precision_by_category: dict[str, float] = field(default_factory=dict)

    # WO-046: stable sha256 digest over sorted gap detection outcomes
    reproducibility_digest: str = ""


def _percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    n = len(sorted_values)
    idx = (p / 100.0) * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    frac = idx - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def _compute_reproducibility_digest(gap_results: list[GapMatchResult]) -> str:
    """Stable sha256 over sorted gap outcomes — identical inputs produce identical digest."""
    import hashlib

    lines = sorted(
        f"{r.case_path}|{r.control_id}|{r.expected_status}|{r.expected_anchor_line!r}|{r.detected}"
        for r in gap_results
    )
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _gap_is_detected(
    gap: SeededGap,
    case_result: CaseResult,
    tolerance: int,
) -> bool:
    """Return True when any validated finding matches this gap within tolerance."""
    for vf in case_result.validated_findings:
        if vf.control_id != gap.control_id:
            continue
        if gap.expected_anchor_line is None:
            return True
        if abs(vf.anchor_line - gap.expected_anchor_line) <= tolerance:
            return True
    return False


def _build_adjudication_list(
    case_result: CaseResult,
    corpus_file: CorpusFile,
    tolerance: int,
) -> list[AdjudicationEntry]:
    """Return findings that do not match any seeded gap, or are duplicates of a matched gap.

    Each gap may consume at most one finding.  If two findings both match the same
    gap, the first (in list order) is considered the detection; subsequent ones are
    surfaced as adjudication_required.
    """
    # Track which gaps have been consumed (by index in corpus_file.seeded_gaps).
    consumed: set[int] = set()
    extra: list[AdjudicationEntry] = []

    for vf in case_result.validated_findings:
        matched_gap_idx: int | None = None
        for idx, gap in enumerate(corpus_file.seeded_gaps):
            if gap.control_id != vf.control_id:
                continue
            if idx in consumed:
                continue
            if gap.expected_anchor_line is None:
                matched_gap_idx = idx
                break
            if abs(vf.anchor_line - gap.expected_anchor_line) <= tolerance:
                matched_gap_idx = idx
                break

        if matched_gap_idx is not None:
            consumed.add(matched_gap_idx)
        else:
            extra.append(
                AdjudicationEntry(
                    case_path=case_result.case_path,
                    control_id=vf.control_id,
                    rule_id=vf.rule_id,
                    anchor_line=vf.anchor_line,
                    category=vf.category,
                    source_format=case_result.source_format,
                )
            )
    return extra


def compute_metrics(
    case_results: list[CaseResult],
    corpus_files: list[CorpusFile],
    *,
    anchor_line_tolerance: int = 2,
) -> BenchmarkMetrics:
    """Compute detection rate, latency percentiles, and adjudication list.

    *case_results* and *corpus_files* must be in the same order (one result
    per corpus file).  Cases with *error* set are counted as errors and skip
    detection accounting.
    """
    assert len(case_results) == len(corpus_files), (
        "case_results and corpus_files must have the same length"
    )

    gap_results: list[GapMatchResult] = []
    adjudication: list[AdjudicationEntry] = []
    unanchored = 0
    latencies: list[float] = []
    case_errors: list[str] = []

    # Per-format and per-category bookkeeping
    fmt_gaps: dict[str, int] = {}
    fmt_detected: dict[str, int] = {}
    cat_gaps: dict[str, int] = {}
    cat_detected: dict[str, int] = {}

    # Not-assessable stats per format
    na_by_fmt: dict[str, dict[str, float | int]] = {}

    for cr, cf in zip(case_results, corpus_files):
        if cr.error:
            case_errors.append(f"{cr.case_path}: {cr.error}")
            continue

        latencies.append(cr.duration_ms)

        # Count unanchored (MISSING_ANCHOR suppressions from anchor gate)
        for sup in cr.suppression_report.suppressions:
            if sup.reason == SuppressionReason.MISSING_ANCHOR:
                unanchored += 1

        # Detection matching (exclude not_assessable expected gaps)
        fmt = cr.source_format
        fmt_gaps.setdefault(fmt, 0)
        fmt_detected.setdefault(fmt, 0)

        assessable_gaps = [
            g for g in cf.seeded_gaps if g.expected_status.value != "not_assessable"
        ]

        for gap in assessable_gaps:
            detected = _gap_is_detected(gap, cr, anchor_line_tolerance)
            gap_results.append(
                GapMatchResult(
                    case_path=cr.case_path,
                    control_id=gap.control_id,
                    expected_anchor_line=gap.expected_anchor_line,
                    detected=detected,
                    expected_status=gap.expected_status.value,
                )
            )
            fmt_gaps[fmt] = fmt_gaps.get(fmt, 0) + 1
            cat_gaps.setdefault(gap.category, 0)
            cat_gaps[gap.category] += 1
            if detected:
                fmt_detected[fmt] = fmt_detected.get(fmt, 0) + 1
                cat_detected.setdefault(gap.category, 0)
                cat_detected[gap.category] += 1

        adj_list = _build_adjudication_list(cr, cf, anchor_line_tolerance)
        adjudication.extend(adj_list)

        # Not-assessable accounting (aggregate per format)
        if cr.coverage_report is not None:
            stats = cr.coverage_report.coverage_stats
            if fmt not in na_by_fmt:
                na_by_fmt[fmt] = {
                    "assessable_controls": 0,
                    "unassessable_controls": 0,
                    "excluded_fragment_count": 0,
                    "assessable_weight_total": 0.0,
                    "catalogue_weight_total": 0.0,
                }
            na_by_fmt[fmt]["assessable_controls"] += stats.assessable_controls
            na_by_fmt[fmt]["unassessable_controls"] += stats.unassessable_controls
            na_by_fmt[fmt]["excluded_fragment_count"] += stats.excluded_fragment_count
            na_by_fmt[fmt]["assessable_weight_total"] += cr.coverage_report.assessable_weight_total
            na_by_fmt[fmt]["catalogue_weight_total"] += cr.coverage_report.catalogue_weight_total

    total_gaps = len(gap_results)
    total_detected = sum(1 for r in gap_results if r.detected)
    overall_rate = (total_detected / total_gaps) if total_gaps > 0 else float("nan")

    detection_by_format = {
        fmt: (fmt_detected.get(fmt, 0) / fmt_gaps[fmt]) if fmt_gaps.get(fmt, 0) > 0 else float("nan")
        for fmt in fmt_gaps
    }
    detection_by_category = {
        cat: (cat_detected.get(cat, 0) / cat_gaps[cat]) if cat_gaps.get(cat, 0) > 0 else float("nan")
        for cat in cat_gaps
    }

    latencies.sort()
    p50 = _percentile(latencies, 50)
    p95 = _percentile(latencies, 95)

    na_stats_list = [
        NotAssessableStats(
            source_format=fmt,
            assessable_controls=int(v["assessable_controls"]),
            unassessable_controls=int(v["unassessable_controls"]),
            excluded_fragment_count=int(v["excluded_fragment_count"]),
            assessable_weight_total=float(v["assessable_weight_total"]),
            catalogue_weight_total=float(v["catalogue_weight_total"]),
        )
        for fmt, v in sorted(na_by_fmt.items())
    ]

    # WO-046: collect FP counts per format/category from enriched adjudication entries
    fp_by_fmt: dict[str, int] = {}
    fp_by_cat: dict[str, int] = {}
    for entry in adjudication:
        if entry.source_format:
            fp_by_fmt[entry.source_format] = fp_by_fmt.get(entry.source_format, 0) + 1
        if entry.category:
            fp_by_cat[entry.category] = fp_by_cat.get(entry.category, 0) + 1

    # WO-046: precision = TP / (TP + FP) per format
    all_fmts = set(list(fmt_gaps.keys()) + list(fp_by_fmt.keys()))
    precision_by_fmt: dict[str, float] = {
        fmt: (
            (fmt_detected.get(fmt, 0) / (fmt_detected.get(fmt, 0) + fp_by_fmt.get(fmt, 0)))
            if (fmt_detected.get(fmt, 0) + fp_by_fmt.get(fmt, 0)) > 0
            else float("nan")
        )
        for fmt in all_fmts
    }

    # WO-046: precision = TP / (TP + FP) per category
    all_cats = set(list(cat_gaps.keys()) + list(fp_by_cat.keys()))
    precision_by_cat: dict[str, float] = {
        cat: (
            (cat_detected.get(cat, 0) / (cat_detected.get(cat, 0) + fp_by_cat.get(cat, 0)))
            if (cat_detected.get(cat, 0) + fp_by_cat.get(cat, 0)) > 0
            else float("nan")
        )
        for cat in all_cats
    }

    digest = _compute_reproducibility_digest(gap_results)

    return BenchmarkMetrics(
        total_seeded_gaps=total_gaps,
        total_detected=total_detected,
        overall_detection_rate=overall_rate,
        detection_rate_by_format=detection_by_format,
        detection_rate_by_category=detection_by_category,
        gap_results=gap_results,
        adjudication_required=adjudication,
        unanchored_findings=unanchored,
        latency_p50_ms=p50,
        latency_p95_ms=p95,
        not_assessable_by_format=na_stats_list,
        case_errors=case_errors,
        gaps_by_format=dict(fmt_gaps),
        detected_by_format=dict(fmt_detected),
        gaps_by_category=dict(cat_gaps),
        detected_by_category=dict(cat_detected),
        false_positive_count=len(adjudication),
        false_positive_by_format=fp_by_fmt,
        false_positive_by_category=fp_by_cat,
        precision_by_format=precision_by_fmt,
        precision_by_category=precision_by_cat,
        reproducibility_digest=digest,
    )
