"""Pydantic v2 schemas for benchmark run results.

BenchmarkRun is the canonical serializable representation written to
benchmark-results/<run_id>.json and latest.json, and returned by
GET /api/v1/benchmark/latest.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


class GapResultItem(BaseModel):
    """Outcome of a single seeded gap after matching."""

    model_config = ConfigDict(frozen=True)

    case_path: str
    control_id: str
    expected_anchor_line: Optional[int]
    expected_status: str
    detected: bool


class FormatResult(BaseModel):
    """Detection metrics for one pipeline format (GitHub Actions, GitLab CI, Jenkins…)."""

    model_config = ConfigDict(frozen=True)

    format: str
    seeded_gaps: int
    true_positives: int
    false_negatives: int
    false_positives: int
    recall: Optional[float] = None     # None when seeded_gaps == 0
    precision: Optional[float] = None  # None when TP + FP == 0


class CategoryResult(BaseModel):
    """Detection metrics for one control category (secrets_hygiene, access_secrets…)."""

    model_config = ConfigDict(frozen=True)

    category: str
    seeded_gaps: int
    true_positives: int
    false_negatives: int
    false_positives: int
    recall: Optional[float] = None
    precision: Optional[float] = None


class BenchmarkRun(BaseModel):
    """Full machine-readable benchmark run result.

    Written to a versioned artefact and to latest.json by the CLI.
    Consumed by GET /api/v1/benchmark/latest for the dashboard Trust panel.
    """

    model_config = ConfigDict(frozen=True)

    run_id: str
    timestamp: str                     # ISO 8601, UTC
    git_commit_sha: Optional[str] = None
    corpus_version: str
    catalogue_version: int
    corpus_checksum: str
    harness_version: str
    overall_seeded_gaps: int
    overall_true_positives: int
    overall_false_negatives: int
    overall_false_positives: int
    overall_detection_rate: Optional[float] = None  # None when seeded_gaps == 0
    overall_precision: Optional[float] = None       # None when TP + FP == 0
    reproducibility_digest: str
    format_results: list[FormatResult]              # Jenkins always a separate entry
    category_results: list[CategoryResult]
    unanchored_findings: int
    latency_p50_ms: float
    latency_p95_ms: float
    case_errors: list[str] = []
    gap_results: list[GapResultItem] = []
