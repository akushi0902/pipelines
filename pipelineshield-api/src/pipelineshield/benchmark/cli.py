"""Benchmark CLI entry point.

Usage:
    python -m pipelineshield.benchmark.cli [options]

Exit codes:
    0  all thresholds passed
    1  one or more quality-gate thresholds breached
    2  harness fault (manifest invalid, corpus empty, catalogue load failure, etc.)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_thresholds(path: Path) -> dict:
    import yaml  # type: ignore[import]

    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _default_thresholds_path() -> Path:
    return Path(__file__).parent / "thresholds.yaml"


def _load_catalogue(catalogue_path: Path):
    import json as _json

    from pipelineshield.catalogue.schemas import CatalogueSnapshot

    with catalogue_path.open(encoding="utf-8") as fh:
        raw = _json.load(fh)
    return CatalogueSnapshot.model_validate(raw)


def _check_thresholds(metrics, thresholds: dict) -> list[str]:
    """Return a list of threshold breach messages (empty → all pass)."""
    breaches: list[str] = []
    overall_min = float(thresholds.get("overall_detection_min", 0.80))
    max_unanchored = int(thresholds.get("max_unanchored_findings", 0))
    p95_budget = float(thresholds.get("deterministic_p95_budget_ms", 5000))
    fmt_mins: dict[str, float] = {
        k: float(v)
        for k, v in thresholds.get("format_detection_min", {}).items()
    }

    import math

    if not math.isnan(metrics.overall_detection_rate):
        if metrics.overall_detection_rate < overall_min:
            breaches.append(
                f"overall detection rate {metrics.overall_detection_rate:.1%} "
                f"< required {overall_min:.0%}"
            )

    for fmt, min_rate in fmt_mins.items():
        rate = metrics.detection_rate_by_format.get(fmt)
        if rate is None or math.isnan(rate):
            continue
        if rate < min_rate:
            breaches.append(
                f"{fmt} detection rate {rate:.1%} < required {min_rate:.0%}"
            )

    if metrics.unanchored_findings > max_unanchored:
        breaches.append(
            f"unanchored_findings={metrics.unanchored_findings} > limit {max_unanchored}"
        )

    if metrics.latency_p95_ms > p95_budget:
        breaches.append(
            f"latency p95={metrics.latency_p95_ms:.1f}ms > budget {p95_budget:.0f}ms"
        )

    return breaches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PipelineShield benchmark harness — seeded corpus detection gate"
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=Path(__file__).parents[4] / "tests" / "fixtures" / "corpus",
        help="Path to the corpus root directory (default: tests/fixtures/corpus/)",
    )
    parser.add_argument(
        "--catalogue",
        type=Path,
        default=Path(__file__).parents[4] / "tests" / "fixtures" / "catalogue_v1.json",
        help="Path to catalogue_v1.json (default: tests/fixtures/catalogue_v1.json)",
    )
    parser.add_argument(
        "--thresholds",
        type=Path,
        default=_default_thresholds_path(),
        help="Path to thresholds.yaml",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Write JSON report to this path (default: stdout only)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=3,
        metavar="N",
        help="Number of warm-up iterations (default: 3)",
    )

    args = parser.parse_args(argv)

    # --- harness fault paths (exit 2) ---
    try:
        thresholds = _load_thresholds(args.thresholds)
    except Exception as exc:
        print(f"HARNESS FAULT: Cannot load thresholds {args.thresholds}: {exc}", file=sys.stderr)
        return 2

    try:
        catalogue_snapshot = _load_catalogue(args.catalogue)
    except Exception as exc:
        print(f"HARNESS FAULT: Cannot load catalogue {args.catalogue}: {exc}", file=sys.stderr)
        return 2

    try:
        import yaml  # type: ignore[import]
        from pipelineshield.benchmark.ground_truth import GroundTruthManifest

        manifest_path = args.corpus_dir / "ground_truth.yaml"
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        manifest = GroundTruthManifest.model_validate(raw)
    except Exception as exc:
        print(
            f"HARNESS FAULT: Cannot load ground-truth manifest from {args.corpus_dir}: {exc}",
            file=sys.stderr,
        )
        return 2

    if not manifest.files:
        print("HARNESS FAULT: Empty corpus — no files to run.", file=sys.stderr)
        return 2

    corpus_dir = args.corpus_dir

    # --- Run corpus ---
    from pipelineshield.benchmark.metrics import compute_metrics
    from pipelineshield.benchmark.report import (
        corpus_checksum,
        render_json,
        render_text,
    )
    from pipelineshield.benchmark.runner import run_corpus

    try:
        warmup_iters = max(0, args.warmup)
        case_results = run_corpus(
            manifest.files,
            corpus_dir,
            catalogue_snapshot,
            warmup=warmup_iters > 0,
            warmup_iterations=warmup_iters,
        )
    except Exception as exc:
        print(f"HARNESS FAULT: Run failed: {exc}", file=sys.stderr)
        return 2

    tolerance = int(thresholds.get("anchor_line_tolerance", 2))
    metrics = compute_metrics(case_results, list(manifest.files), anchor_line_tolerance=tolerance)

    # Any case errors → harness fault
    if metrics.case_errors:
        for err in metrics.case_errors:
            print(f"HARNESS FAULT: case error — {err}", file=sys.stderr)
        return 2

    # --- Render outputs ---
    checksum = corpus_checksum(corpus_dir)
    json_doc = render_json(
        metrics,
        catalogue_version=manifest.catalogue_version,
        corpus_checksum_value=checksum,
    )
    text_summary = render_text(
        metrics,
        catalogue_version=manifest.catalogue_version,
    )

    print(text_summary)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(json_doc, indent=2), encoding="utf-8")
        print(f"JSON report written to {args.output}")

    # --- Threshold check (exit 1) ---
    breaches = _check_thresholds(metrics, thresholds)
    if breaches:
        print("\nQUALITY GATE FAILED:", file=sys.stderr)
        for b in breaches:
            print(f"  - {b}", file=sys.stderr)
        return 1

    print("Quality gate: PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
