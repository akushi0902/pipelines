"""Benchmark comparison utilities.

Provides:
  DeterminismCheckResult — result of running a sample twice and comparing outputs
  check_determinism      — run each corpus case twice and return mismatches
  StubMode               — inference stub behavior modes (success/timeout/malformed/unavailable)
  BenchmarkStubClient    — multi-mode inference stub for harness testing
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from pipelineshield.analysis.explanation.inference_client import (
    InferenceClient,
    InferenceResult,
)
from pipelineshield.benchmark.ground_truth import CorpusFile
from pipelineshield.benchmark.runner import CaseResult, run_case


class StubMode(str, Enum):
    """Controls what BenchmarkStubClient returns from complete()."""

    SUCCESS = "success"
    """Returns a minimal valid response string (no real content)."""

    TIMEOUT = "timeout"
    """Returns a degraded result with degraded=True simulating a timeout."""

    MALFORMED = "malformed"
    """Returns content that is not valid JSON, simulating a schema-invalid response."""

    UNAVAILABLE = "unavailable"
    """Returns a degraded result simulating an unavailable endpoint."""


class BenchmarkStubClient:
    """Multi-mode inference stub for benchmark harness testing.

    Satisfies the InferenceClient protocol.  The *mode* controls the behavior
    so harness tests can assert that the deterministic path is unaffected by
    inference failures of any kind.

    All modes return InferenceResult rather than raising so callers follow the
    normal degraded-path without requiring exception handling.
    """

    def __init__(self, mode: StubMode = StubMode.SUCCESS) -> None:
        self.mode = mode

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        timeout_s: float = 12.0,
    ) -> InferenceResult:
        if self.mode == StubMode.SUCCESS:
            return InferenceResult(
                content='{"explanation": "stub success", "remediations": []}',
                degraded=False,
                latency_ms=1.0,
            )
        if self.mode == StubMode.TIMEOUT:
            return InferenceResult(
                content="",
                degraded=True,
                error="BenchmarkStubClient: simulated timeout",
                latency_ms=timeout_s * 1000,
            )
        if self.mode == StubMode.MALFORMED:
            return InferenceResult(
                content="NOT_VALID_JSON{{{",
                degraded=False,
                latency_ms=1.0,
            )
        # UNAVAILABLE
        return InferenceResult(
            content="",
            degraded=True,
            error="BenchmarkStubClient: simulated endpoint unavailable",
            latency_ms=0.0,
        )


@dataclass
class DeterminismCheckResult:
    """Outcome for a single corpus case's determinism check."""

    case_path: str
    passed: bool
    mismatches: list[str] = field(default_factory=list)


def _digest_case_result(cr: CaseResult) -> str:
    """Stable sha256 of the score-visible outputs of a CaseResult.

    Captures: sorted finding ids (control_id+rule_id), sorted anchor lines.
    Excludes wall-clock timing and error details.
    """
    finding_ids = sorted(
        f"{vf.control_id}:{vf.rule_id}:{vf.anchor_line}"
        for vf in cr.validated_findings
    )
    outcome_fingerprints = sorted(
        o.fingerprint for o in cr.outcomes
    )
    lines = finding_ids + outcome_fingerprints
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def check_determinism(
    corpus_files: list[CorpusFile],
    corpus_dir: Path,
    catalogue_snapshot: Any,
) -> list[DeterminismCheckResult]:
    """Run each corpus case twice and return one DeterminismCheckResult per file.

    A case passes when both runs produce identical finding ids and anchors.
    Cases that error on either run fail with a descriptive mismatch message.
    """
    results: list[DeterminismCheckResult] = []

    for corpus_file in corpus_files:
        run_a = run_case(corpus_file, corpus_dir, catalogue_snapshot)
        run_b = run_case(corpus_file, corpus_dir, catalogue_snapshot)

        mismatches: list[str] = []

        if run_a.error or run_b.error:
            err_a = run_a.error or ""
            err_b = run_b.error or ""
            if err_a != err_b:
                mismatches.append(
                    f"run A error={err_a!r} vs run B error={err_b!r}"
                )
            elif err_a:
                mismatches.append(f"both runs errored: {err_a!r}")
            results.append(
                DeterminismCheckResult(
                    case_path=corpus_file.path,
                    passed=not mismatches,
                    mismatches=mismatches,
                )
            )
            continue

        digest_a = _digest_case_result(run_a)
        digest_b = _digest_case_result(run_b)

        if digest_a != digest_b:
            # Surface which findings differ for actionable reporting
            ids_a = sorted(
                f"{vf.control_id}:{vf.rule_id}:{vf.anchor_line}"
                for vf in run_a.validated_findings
            )
            ids_b = sorted(
                f"{vf.control_id}:{vf.rule_id}:{vf.anchor_line}"
                for vf in run_b.validated_findings
            )
            if ids_a != ids_b:
                only_in_a = set(ids_a) - set(ids_b)
                only_in_b = set(ids_b) - set(ids_a)
                if only_in_a:
                    mismatches.append(f"findings only in run A: {sorted(only_in_a)}")
                if only_in_b:
                    mismatches.append(f"findings only in run B: {sorted(only_in_b)}")
            else:
                mismatches.append(
                    f"outcome fingerprints differ (digest_a={digest_a[:8]} "
                    f"digest_b={digest_b[:8]})"
                )

        results.append(
            DeterminismCheckResult(
                case_path=corpus_file.path,
                passed=not mismatches,
                mismatches=mismatches,
            )
        )

    return results
