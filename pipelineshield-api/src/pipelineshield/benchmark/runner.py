"""Benchmark runner — executes the full deterministic pipeline path per corpus case.

Pipeline per case:
  1. redact(content) → RedactedDoc
  2. build_redacted_document(doc) → RedactedDocument
  3. normalizer.normalize(content) → PipelineIR
  4. rule_engine.evaluate(ir, catalogue) → EvaluationResult
  5. anchor_validator.validate(candidates, rdoc) → (ValidatedFinding[], SuppressionReport)
  6. control_evaluator.evaluate(outcomes, ir, catalogue) → CoverageReport

No LLM, no network, no database.  Wall-clock timing measured with time.monotonic().
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pipelineshield.analysis.anchoring import (
    AnchorValidator,
    CandidateFinding,
    SuppressionReport,
    ValidatedFinding,
    build_redacted_document,
)
from pipelineshield.analysis.coverage import ControlEvaluator
from pipelineshield.analysis.coverage.models import CoverageReport
from pipelineshield.analysis.redactor import redact
from pipelineshield.analysis.rule_engine import (
    EvaluationContext,
    RuleEngine,
    RuleOutcome,
    RuleOutcomeVerdict,
)
from pipelineshield.analysis.rule_engine.protocol import EvidenceAnchor
from pipelineshield.analysis.rules import build_default_registry
from pipelineshield.api.v1.schemas.analysis import PipelineFormat
from pipelineshield.benchmark.ground_truth import CorpusFile
from pipelineshield.services.normalizer_registry import (
    NormalizerRegistry,
    create_default_registry,
)

_LOG = logging.getLogger(__name__)

_ENGINE: RuleEngine | None = None
_NORMALIZER_REGISTRY: NormalizerRegistry | None = None


def _get_engine() -> RuleEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = RuleEngine(registry=build_default_registry())
    return _ENGINE


def _get_normalizer_registry() -> NormalizerRegistry:
    global _NORMALIZER_REGISTRY
    if _NORMALIZER_REGISTRY is None:
        _NORMALIZER_REGISTRY = create_default_registry()
    return _NORMALIZER_REGISTRY


@dataclass
class CaseResult:
    """Result from running the full deterministic pipeline on one corpus case."""

    case_path: str
    source_format: str
    duration_ms: float
    outcomes: list[RuleOutcome] = field(default_factory=list)
    validated_findings: list[ValidatedFinding] = field(default_factory=list)
    suppression_report: SuppressionReport = field(default_factory=SuppressionReport)
    coverage_report: CoverageReport | None = None
    error: str | None = None


def run_case(
    corpus_file: CorpusFile,
    corpus_dir: Path,
    catalogue_snapshot: Any,
    *,
    analysis_id: str | None = None,
) -> CaseResult:
    """Run the full deterministic path for one corpus file.

    Returns CaseResult with error set (and other fields empty/zero) on failure.
    Never raises — per-case exceptions are captured as case_error.
    """
    aid = analysis_id or str(uuid.uuid4())
    fmt = PipelineFormat(corpus_file.format.value)
    file_path = corpus_dir / corpus_file.path

    t0 = time.monotonic()
    try:
        content = file_path.read_text(encoding="utf-8")

        # Step 1–2: redact and build line-indexed document
        redacted_doc = redact(content)
        rdoc = build_redacted_document(redacted_doc)

        # Step 3: normalize → PipelineIR
        norm_result = _get_normalizer_registry().normalize(content, fmt)
        if norm_result.pipeline_ir is None:
            raise ValueError(f"Normalizer returned no IR for {corpus_file.path!r}")
        ir = norm_result.pipeline_ir

        # Step 4: rule engine
        eval_result = _get_engine().evaluate(
            ir,
            catalogue_snapshot,
            context=EvaluationContext(
                analysis_id=aid,
                source_format=ir.source_format,
            ),
        )
        outcomes = eval_result.outcomes

        # Step 5: convert violated/satisfied outcomes to candidates and gate them
        candidates: list[CandidateFinding] = []
        for outcome in outcomes:
            if outcome.verdict == RuleOutcomeVerdict.VIOLATED:
                anchor = outcome.anchors[0] if outcome.anchors else EvidenceAnchor(
                    start_line=1, start_column=1
                )
                candidates.append(
                    CandidateFinding(
                        rule_id=outcome.rule_id,
                        control_id=outcome.control_id,
                        category=outcome.evidence_kind,
                        source="deterministic",
                        severity="high",
                        title=f"Violated: {outcome.control_id}",
                        description="",
                        evidence={"fingerprint": outcome.fingerprint},
                        analysis_id=uuid.UUID(aid) if _is_uuid(aid) else uuid.uuid4(),
                        workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
                        anchor=anchor,
                    )
                )

        validator = AnchorValidator(analysis_id=aid)
        accepted, suppression = validator.validate(candidates, rdoc)

        # Step 6: control evaluator
        evaluator = ControlEvaluator()
        coverage = evaluator.evaluate(outcomes, ir, catalogue_snapshot)

    except Exception as exc:
        duration_ms = (time.monotonic() - t0) * 1000
        _LOG.error("Case %r failed: %s", corpus_file.path, exc, exc_info=True)
        return CaseResult(
            case_path=corpus_file.path,
            source_format=corpus_file.format.value,
            duration_ms=duration_ms,
            error=f"{type(exc).__name__}: {exc}",
        )

    duration_ms = (time.monotonic() - t0) * 1000
    return CaseResult(
        case_path=corpus_file.path,
        source_format=corpus_file.format.value,
        duration_ms=duration_ms,
        outcomes=list(outcomes),
        validated_findings=accepted,
        suppression_report=suppression,
        coverage_report=coverage,
    )


def run_corpus(
    manifest_files: list[CorpusFile],
    corpus_dir: Path,
    catalogue_snapshot: Any,
    *,
    warmup: bool = True,
    warmup_iterations: int = 1,
) -> list[CaseResult]:
    """Run all corpus files and return one CaseResult per file.

    If *warmup* is True, run the first case warmup_iterations times
    extra before recording, to amortize import-time cost.
    """
    if not manifest_files:
        raise ValueError("Empty corpus: no files to run.")

    if warmup and manifest_files and warmup_iterations > 0:
        for _ in range(warmup_iterations):
            run_case(manifest_files[0], corpus_dir, catalogue_snapshot)

    return [
        run_case(f, corpus_dir, catalogue_snapshot)
        for f in manifest_files
    ]


def _is_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except ValueError:
        return False
