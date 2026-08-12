"""Benchmark report renderers — JSON and human-readable text.

Usage:
    metrics = compute_metrics(case_results, corpus_files)
    manifest = load_ground_truth()
    text_out = render_text(metrics)
    json_doc = render_json(metrics, manifest, harness_version="1.0.0", corpus_checksum="...")
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

from pipelineshield.benchmark.metrics import BenchmarkMetrics

_HARNESS_VERSION = "1.0.0"


def corpus_checksum(corpus_dir: Path) -> str:
    """Stable sha256 of sorted file contents in corpus_dir (recursive)."""
    h = hashlib.sha256()
    for path in sorted(corpus_dir.rglob("*")):
        if path.is_file():
            h.update(path.read_bytes())
    return h.hexdigest()[:16]


def render_json(
    metrics: BenchmarkMetrics,
    *,
    harness_version: str = _HARNESS_VERSION,
    catalogue_version: int | str = "unknown",
    corpus_checksum_value: str = "",
) -> dict[str, Any]:
    """Return a machine-readable JSON-serializable result document."""

    def _rate(v: float) -> float | None:
        if math.isnan(v):
            return None
        return round(v, 4)

    return {
        "harness_version": harness_version,
        "catalogue_version": str(catalogue_version),
        "corpus_checksum": corpus_checksum_value,
        "aggregate": {
            "total_seeded_gaps": metrics.total_seeded_gaps,
            "total_detected": metrics.total_detected,
            "overall_detection_rate": _rate(metrics.overall_detection_rate),
            "unanchored_findings": metrics.unanchored_findings,
            "latency_p50_ms": round(metrics.latency_p50_ms, 2),
            "latency_p95_ms": round(metrics.latency_p95_ms, 2),
            "case_errors": metrics.case_errors,
        },
        "detection_by_format": {
            fmt: _rate(rate)
            for fmt, rate in metrics.detection_rate_by_format.items()
        },
        "detection_by_category": {
            cat: _rate(rate)
            for cat, rate in metrics.detection_rate_by_category.items()
        },
        "not_assessable_by_format": [
            {
                "format": s.source_format,
                "assessable_controls": s.assessable_controls,
                "unassessable_controls": s.unassessable_controls,
                "excluded_fragment_count": s.excluded_fragment_count,
                "assessable_weight_total": round(s.assessable_weight_total, 4),
                "catalogue_weight_total": round(s.catalogue_weight_total, 4),
                "assessable_weight_ratio": round(s.assessable_weight_ratio, 4),
            }
            for s in metrics.not_assessable_by_format
        ],
        "gap_results": [
            {
                "case_path": r.case_path,
                "control_id": r.control_id,
                "expected_anchor_line": r.expected_anchor_line,
                "expected_status": r.expected_status,
                "detected": r.detected,
            }
            for r in metrics.gap_results
        ],
        "adjudication_required": [
            {
                "case_path": e.case_path,
                "control_id": e.control_id,
                "rule_id": e.rule_id,
                "anchor_line": e.anchor_line,
            }
            for e in metrics.adjudication_required
        ],
    }


def render_text(
    metrics: BenchmarkMetrics,
    *,
    harness_version: str = _HARNESS_VERSION,
    catalogue_version: int | str = "unknown",
) -> str:
    """Return a human-readable benchmark summary."""

    def _pct(v: float) -> str:
        if math.isnan(v):
            return "n/a"
        return f"{v:.1%}"

    lines: list[str] = [
        f"PipelineShield Benchmark — harness v{harness_version}  catalogue v{catalogue_version}",
        "=" * 70,
        "",
        "Overall",
        f"  Seeded gaps      : {metrics.total_seeded_gaps}",
        f"  Detected         : {metrics.total_detected}",
        f"  Detection rate   : {_pct(metrics.overall_detection_rate)}",
        f"  Unanchored       : {metrics.unanchored_findings}",
        f"  Adjudication req : {len(metrics.adjudication_required)}",
        "",
        "Latency (deterministic path)",
        f"  p50  : {metrics.latency_p50_ms:.1f} ms",
        f"  p95  : {metrics.latency_p95_ms:.1f} ms",
        "",
        "Detection by format",
    ]

    for fmt, rate in sorted(metrics.detection_rate_by_format.items()):
        lines.append(f"  {fmt:<20} {_pct(rate)}")

    lines += ["", "Detection by category"]
    for cat, rate in sorted(metrics.detection_rate_by_category.items()):
        lines.append(f"  {cat:<30} {_pct(rate)}")

    if metrics.not_assessable_by_format:
        lines += ["", "Not-assessable accounting"]
        for s in metrics.not_assessable_by_format:
            lines.append(
                f"  {s.source_format:<20} "
                f"assessable={s.assessable_controls} "
                f"unassessable={s.unassessable_controls} "
                f"excluded_fragments={s.excluded_fragment_count} "
                f"weight_ratio={s.assessable_weight_ratio:.1%}"
            )

    if metrics.adjudication_required:
        lines += ["", "Adjudication required (extra findings)"]
        for e in metrics.adjudication_required[:20]:
            lines.append(f"  {e.case_path}  {e.control_id}@L{e.anchor_line}")
        if len(metrics.adjudication_required) > 20:
            lines.append(f"  ... and {len(metrics.adjudication_required) - 20} more")

    if metrics.case_errors:
        lines += ["", "Case errors"]
        for err in metrics.case_errors:
            lines.append(f"  ERROR: {err}")

    lines.append("")
    return "\n".join(lines)
