"""Benchmark harness — seeded corpus detection gate.

Entry point: pipelineshield.benchmark.cli.main() or
             python -m pipelineshield.benchmark.cli
"""
from .ground_truth import CorpusFile, GroundTruthManifest, SeededGap
from .metrics import BenchmarkMetrics, compute_metrics
from .runner import CaseResult, run_case, run_corpus

__all__ = [
    "BenchmarkMetrics",
    "CaseResult",
    "CorpusFile",
    "GroundTruthManifest",
    "SeededGap",
    "compute_metrics",
    "run_case",
    "run_corpus",
]
