"""Latency SLO benchmark — replay corpus, compute percentiles, evaluate gates.

Usage (CLI)::

    python -m pipelineshield.benchmark.latency [options]

Exit codes:
    0  all SLO gates passed
    1  one or more SLO gates breached
    2  harness fault (corpus empty, catalogue load failure, etc.)

The benchmark:
  1. Loads the ground-truth corpus via the existing benchmark infrastructure.
  2. Runs each corpus case *repeat* times (default 5), discarding the first
     *warmup* runs (default 1) to remove cold-start inflation.
  3. Collects per-case wall-clock durations from ``CaseResult.duration_ms``.
  4. Computes p50 and p95 overall, per format, and per stage.
  5. Evaluates the configured SLO budgets and exits non-zero on any breach.

Stage budgets (milliseconds) — sourced from the WO-048 architecture latency
table and kept in ``latency_budgets.yaml`` so tightening is a config change:

    redact:     200 ms   (regex + entropy scan, linear in input size)
    detect:      50 ms   (regex heuristics)
    normalize:  500 ms   (YAML parse + IR construction)
    evaluate:  2000 ms   (rule engine over full catalogue)
    score:      200 ms   (pure arithmetic)
    infer:    12000 ms   (model pass; may degrade; bounded by timeout)
    validate:   200 ms   (anchor gating)
    persist:    500 ms   (single transaction)
    overall p95: 30000 ms

The benchmark reuses CaseResult.duration_ms as the end-to-end wall clock.
Per-stage times are collected from the ``stage_timings_ms`` dict if
CaseResult carries one (added by the instrumented orchestrator); otherwise
only end-to-end latency is evaluated.
"""
from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Default per-stage budgets (milliseconds). Lower = tighter gate.
DEFAULT_STAGE_BUDGETS_MS: dict[str, float] = {
    "redact":    200.0,
    "detect":     50.0,
    "normalize": 500.0,
    "evaluate": 2000.0,
    "score":     200.0,
    "infer":   12000.0,
    "validate":  200.0,
    "persist":   500.0,
}

DEFAULT_OVERALL_P95_BUDGET_MS: float = 30_000.0
DEFAULT_MIN_SAMPLES: int = 3  # require at least this many samples for p95


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class LatencySample:
    """One measured duration for a corpus case."""

    case_path: str
    source_format: str
    duration_ms: float
    stage_timings_ms: dict[str, float] = field(default_factory=dict)


@dataclass
class PercentileResult:
    """Computed p50/p95 for a slice (overall or per-format / per-stage)."""

    label: str
    p50_ms: float
    p95_ms: float
    sample_count: int


@dataclass
class GateBreach:
    """Describes one SLO gate that was breached."""

    gate: str
    label: str
    budget_ms: float
    p95_ms: float

    def message(self) -> str:
        return (
            f"SLO BREACH [{self.gate}] {self.label}: "
            f"p95={self.p95_ms:.1f}ms > budget={self.budget_ms:.0f}ms"
        )


@dataclass
class LatencyReport:
    """Collected latency measurements and gate evaluation results."""

    overall: PercentileResult
    per_format: list[PercentileResult]
    per_stage: list[PercentileResult]
    breaches: list[GateBreach]
    sample_count: int
    warmup_discarded: int
    repeat_count: int
    corpus_version: str = ""
    git_commit_sha: str = ""

    @property
    def passed(self) -> bool:
        return not self.breaches


# ---------------------------------------------------------------------------
# Percentile computation
# ---------------------------------------------------------------------------


def _percentile(sorted_values: list[float], p: float) -> float:
    """Compute the p-th percentile of a pre-sorted list (0 ≤ p ≤ 100)."""
    if not sorted_values:
        return 0.0
    n = len(sorted_values)
    idx = (p / 100.0) * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    frac = idx - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def compute_percentiles(samples: list[LatencySample]) -> PercentileResult:
    """Compute overall p50/p95 for the given samples."""
    durations = sorted(s.duration_ms for s in samples)
    p50 = _percentile(durations, 50)
    p95 = _percentile(durations, 95)
    return PercentileResult(
        label="overall",
        p50_ms=p50,
        p95_ms=p95,
        sample_count=len(durations),
    )


def compute_per_format_percentiles(
    samples: list[LatencySample],
) -> list[PercentileResult]:
    """Compute p50/p95 broken out by source_format."""
    by_format: dict[str, list[float]] = {}
    for s in samples:
        by_format.setdefault(s.source_format, []).append(s.duration_ms)

    results: list[PercentileResult] = []
    for fmt, durations in sorted(by_format.items()):
        durations_sorted = sorted(durations)
        results.append(
            PercentileResult(
                label=fmt,
                p50_ms=_percentile(durations_sorted, 50),
                p95_ms=_percentile(durations_sorted, 95),
                sample_count=len(durations_sorted),
            )
        )
    return results


def compute_per_stage_percentiles(
    samples: list[LatencySample],
) -> list[PercentileResult]:
    """Compute p50/p95 broken out by stage, using stage_timings_ms if available."""
    by_stage: dict[str, list[float]] = {}
    for s in samples:
        for stage, duration_ms in s.stage_timings_ms.items():
            by_stage.setdefault(stage, []).append(duration_ms)

    results: list[PercentileResult] = []
    for stage, durations in sorted(by_stage.items()):
        durations_sorted = sorted(durations)
        results.append(
            PercentileResult(
                label=stage,
                p50_ms=_percentile(durations_sorted, 50),
                p95_ms=_percentile(durations_sorted, 95),
                sample_count=len(durations_sorted),
            )
        )
    return results


# ---------------------------------------------------------------------------
# Gate evaluation
# ---------------------------------------------------------------------------


def evaluate_latency_gates(
    overall: PercentileResult,
    per_format: list[PercentileResult],
    per_stage: list[PercentileResult],
    *,
    overall_p95_budget_ms: float = DEFAULT_OVERALL_P95_BUDGET_MS,
    stage_budgets_ms: dict[str, float] | None = None,
    min_samples: int = DEFAULT_MIN_SAMPLES,
) -> list[GateBreach]:
    """Evaluate all latency gates and return any breaches.

    A gate is only evaluated when ``sample_count >= min_samples``.
    """
    stage_budgets = stage_budgets_ms or DEFAULT_STAGE_BUDGETS_MS
    breaches: list[GateBreach] = []

    # Overall p95
    if overall.sample_count >= min_samples:
        if overall.p95_ms > overall_p95_budget_ms:
            breaches.append(
                GateBreach(
                    gate="overall_p95",
                    label="Overall end-to-end",
                    budget_ms=overall_p95_budget_ms,
                    p95_ms=overall.p95_ms,
                )
            )

    # Per-format — each format is evaluated against the overall budget
    for fmt_result in per_format:
        if fmt_result.sample_count >= min_samples:
            if fmt_result.p95_ms > overall_p95_budget_ms:
                breaches.append(
                    GateBreach(
                        gate=f"format_p95_{fmt_result.label}",
                        label=f"Format {fmt_result.label}",
                        budget_ms=overall_p95_budget_ms,
                        p95_ms=fmt_result.p95_ms,
                    )
                )

    # Per-stage
    for stage_result in per_stage:
        budget = stage_budgets.get(stage_result.label)
        if budget is None:
            # Unknown stage — fail fast; no unbounded allowance
            breaches.append(
                GateBreach(
                    gate=f"stage_unconfigured_{stage_result.label}",
                    label=f"Stage {stage_result.label} (no budget configured)",
                    budget_ms=0.0,
                    p95_ms=stage_result.p95_ms,
                )
            )
            continue
        if stage_result.sample_count >= min_samples:
            if stage_result.p95_ms > budget:
                breaches.append(
                    GateBreach(
                        gate=f"stage_p95_{stage_result.label}",
                        label=f"Stage {stage_result.label}",
                        budget_ms=budget,
                        p95_ms=stage_result.p95_ms,
                    )
                )

    return breaches


# ---------------------------------------------------------------------------
# Corpus replay
# ---------------------------------------------------------------------------


def run_latency_benchmark(
    manifest_files: list[Any],
    corpus_dir: Path,
    catalogue_snapshot: Any,
    *,
    repeat: int = 5,
    warmup: int = 1,
) -> list[LatencySample]:
    """Replay the corpus *repeat* times and collect LatencySamples.

    The first *warmup* runs per case are discarded to remove cold-start
    inflation.  A minimum of 1 warm-up run is always performed.

    Parameters
    ----------
    manifest_files:
        List of ``CorpusFile`` objects from the ground-truth manifest.
    corpus_dir:
        Root directory of the corpus files on disk.
    catalogue_snapshot:
        Active ``CatalogueSnapshot`` instance.
    repeat:
        Number of measurement runs (after warm-up).  Minimum 1.
    warmup:
        Number of warm-up runs to discard per case.  Minimum 1.
    """
    from pipelineshield.benchmark.runner import run_case

    repeat = max(1, repeat)
    warmup = max(1, warmup)
    samples: list[LatencySample] = []

    for corpus_file in manifest_files:
        # Warm-up — discard these runs
        for _ in range(warmup):
            run_case(corpus_file, corpus_dir, catalogue_snapshot)

        # Measurement runs
        for _ in range(repeat):
            result = run_case(corpus_file, corpus_dir, catalogue_snapshot)
            if result.error:
                # Skip errored cases from latency data; they are reported separately
                continue
            stage_timings = getattr(result, "stage_timings_ms", {}) or {}
            samples.append(
                LatencySample(
                    case_path=result.case_path,
                    source_format=result.source_format,
                    duration_ms=result.duration_ms,
                    stage_timings_ms=dict(stage_timings),
                )
            )

    return samples


def build_latency_report(
    samples: list[LatencySample],
    *,
    overall_p95_budget_ms: float = DEFAULT_OVERALL_P95_BUDGET_MS,
    stage_budgets_ms: dict[str, float] | None = None,
    repeat: int = 5,
    warmup: int = 1,
    corpus_version: str = "",
    git_commit_sha: str = "",
) -> LatencyReport:
    """Compute percentiles and evaluate gates from collected samples."""
    overall = compute_percentiles(samples)
    per_format = compute_per_format_percentiles(samples)
    per_stage = compute_per_stage_percentiles(samples)
    breaches = evaluate_latency_gates(
        overall,
        per_format,
        per_stage,
        overall_p95_budget_ms=overall_p95_budget_ms,
        stage_budgets_ms=stage_budgets_ms,
    )
    return LatencyReport(
        overall=overall,
        per_format=per_format,
        per_stage=per_stage,
        breaches=breaches,
        sample_count=len(samples),
        warmup_discarded=warmup,
        repeat_count=repeat,
        corpus_version=corpus_version,
        git_commit_sha=git_commit_sha,
    )


def render_latency_json(report: LatencyReport) -> dict[str, Any]:
    """Serialise the latency report to a JSON-compatible dict."""

    def _pct(p: PercentileResult) -> dict[str, Any]:
        return {
            "label": p.label,
            "p50_ms": round(p.p50_ms, 2),
            "p95_ms": round(p.p95_ms, 2),
            "sample_count": p.sample_count,
        }

    return {
        "corpus_version": report.corpus_version,
        "git_commit_sha": report.git_commit_sha,
        "repeat_count": report.repeat_count,
        "warmup_discarded": report.warmup_discarded,
        "sample_count": report.sample_count,
        "overall": _pct(report.overall),
        "per_format": [_pct(r) for r in report.per_format],
        "per_stage": [_pct(r) for r in report.per_stage],
        "passed": report.passed,
        "breaches": [
            {
                "gate": b.gate,
                "label": b.label,
                "budget_ms": b.budget_ms,
                "p95_ms": round(b.p95_ms, 2),
                "message": b.message(),
            }
            for b in report.breaches
        ],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="PipelineShield latency SLO benchmark"
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=Path(__file__).parents[4] / "tests" / "fixtures" / "corpus",
    )
    parser.add_argument(
        "--catalogue",
        type=Path,
        default=Path(__file__).parents[4] / "tests" / "fixtures" / "catalogue_v1.json",
    )
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--output", "-o", type=Path, default=None)
    parser.add_argument(
        "--overall-budget-ms",
        type=float,
        default=DEFAULT_OVERALL_P95_BUDGET_MS,
    )
    args = parser.parse_args(argv)

    import yaml  # type: ignore[import]

    from pipelineshield.benchmark.ground_truth import GroundTruthManifest
    from pipelineshield.catalogue.schemas import CatalogueSnapshot

    try:
        with args.catalogue.open() as fh:
            import json as _json
            raw_cat = _json.load(fh)
        catalogue_snapshot = CatalogueSnapshot.model_validate(raw_cat)
    except Exception as exc:
        print(f"HARNESS FAULT: Cannot load catalogue: {exc}", file=sys.stderr)
        return 2

    manifest_path = args.corpus_dir / "ground_truth.yaml"
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        manifest = GroundTruthManifest.model_validate(raw)
    except Exception as exc:
        print(f"HARNESS FAULT: Cannot load manifest: {exc}", file=sys.stderr)
        return 2

    if not manifest.files:
        print("HARNESS FAULT: Empty corpus.", file=sys.stderr)
        return 2

    samples = run_latency_benchmark(
        manifest.files,
        args.corpus_dir,
        catalogue_snapshot,
        repeat=args.repeat,
        warmup=args.warmup,
    )

    if not samples:
        print("HARNESS FAULT: No successful samples collected.", file=sys.stderr)
        return 2

    report = build_latency_report(
        samples,
        overall_p95_budget_ms=args.overall_budget_ms,
        repeat=args.repeat,
        warmup=args.warmup,
        corpus_version=manifest.corpus_version,
    )

    doc = render_latency_json(report)
    output_str = json.dumps(doc, indent=2)
    print(output_str)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output_str, encoding="utf-8")
        print(f"Latency report written to {args.output}", file=sys.stderr)

    if report.breaches:
        print("\nLATENCY SLO GATE FAILED:", file=sys.stderr)
        for breach in report.breaches:
            print(f"  {breach.message()}", file=sys.stderr)
        return 1

    print("Latency SLO gate: PASSED")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
