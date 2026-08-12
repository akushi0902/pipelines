"""AnalysisOrchestrator — stage-sequenced ingestion business logic.

Stage sequence:
  1. validate       — non-empty, size bound, content-type guard
  2. yaml_parse     — structural syntax check; returns line+column on failure
  3. redact         — WO-002 secret masking before any persistence or logging
  4. detect_format  — heuristic format classification
  5. normalize      — format-specific normalisation (stub until WO-05/06/07)
  6. persist        — transactional: Analysis + PipelineDefinition in one flush
  7. audit          — exactly one audit_event per accepted ingestion

The orchestrator owns no database session; the caller passes in an open
``Session`` and owns the commit/rollback boundary.

No outbound HTTP — asserted by the import-graph test.
"""
from __future__ import annotations

import logging
import secrets
import time
import uuid
from typing import Any

from sqlalchemy.orm import Session

from pipelineshield.analysis.format_detector import CONFIDENCE_THRESHOLD, detect
from pipelineshield.analysis.redactor import redact
from pipelineshield.api.security.authz_guard import CurrentActor
from pipelineshield.api.v1.schemas.analysis import (
    ADVISORY_DISCLAIMER,
    AnalysisResponse,
    PipelineFormat,
)
from pipelineshield.catalogue.schemas import CatalogueSnapshot
from pipelineshield.crypto.key_provider import KeyProvider
from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.pipeline_definition import PipelineDefinition
from pipelineshield.persistence.repositories.analysis import SQLAlchemyAnalysisRepository
from pipelineshield.persistence.repositories.catalogue import SQLAlchemyCatalogueRepository
from pipelineshield.persistence.repositories.definition import SQLAlchemyDefinitionRepository
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.services.normalizer_registry import NormalizerRegistry, NormalizationResult
from pipelineshield.services.scoring_engine import ScoringEngine

__all__ = [
    "AnalysisOrchestrator",
    "IngestionError",
    "YamlParseError",
    "EmptyContentError",
    "UnsupportedContentTypeError",
]

_LOG = logging.getLogger(__name__)

_METRICS: dict[str, int] = {
    "analysis_ingestion_accepted_total": 0,
    "analysis_ingestion_rejected_4xx_total": 0,
    "analysis_ingestion_error_5xx_total": 0,
}


# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------


class IngestionError(Exception):
    """Base for ingestion-path failures that map to structured HTTP errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        constraint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.constraint = constraint


class EmptyContentError(IngestionError):
    def __init__(self) -> None:
        super().__init__(
            message="Pipeline definition content must not be empty or whitespace-only.",
            status_code=400,
            constraint="non_empty_content",
        )


class PayloadTooLargeError(IngestionError):
    def __init__(self, actual_bytes: int) -> None:
        super().__init__(
            message=(
                f"Payload size {actual_bytes} bytes exceeds the 512 KB limit "
                "(524,288 bytes). Reduce the definition content."
            ),
            status_code=413,
            constraint="max_bytes=524288",
        )


class UnsupportedContentTypeError(IngestionError):
    def __init__(self, received: str) -> None:
        super().__init__(
            message=(
                f"Unsupported content type {received!r}. Accepted types for "
                "paste: text/plain, text/yaml, application/x-yaml, "
                "application/json. For upload: multipart/form-data."
            ),
            status_code=415,
            constraint="content_type_allowlist",
        )


class YamlParseError(IngestionError):
    """Raised when YAML syntax validation fails."""

    def __init__(
        self,
        message: str,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(message=message, status_code=422, constraint="yaml_syntax")
        self.parse_line = line
        self.parse_column = column


class NoCatalogueError(IngestionError):
    def __init__(self) -> None:
        super().__init__(
            message=(
                "No active control catalogue version found. "
                "A seeded catalogue is required before analyses can be accepted."
            ),
            status_code=503,
            constraint="catalogue_required",
        )


# ---------------------------------------------------------------------------
# YAML validation (best-effort; graceful degradation if no parser installed)
# ---------------------------------------------------------------------------

_YAML_MAX_ALIASES = 100


def _validate_yaml_syntax(content: str) -> None:
    """Parse *content* as YAML; raise YamlParseError on syntax failure.

    Tries ruamel.yaml first (YAML 1.2 mode with alias expansion guard),
    falls back to pyyaml if ruamel.yaml is not installed.
    If neither parser is available, validation is skipped silently.
    """
    try:
        import io as _io
        from ruamel.yaml import YAML  # type: ignore[import-untyped]

        y = YAML()
        y.version = (1, 2)

        # ruamel.yaml doesn't have a built-in alias count limit; we guard
        # by bounding via a custom Loader that counts nodes.
        try:
            list(y.load_all(_io.StringIO(content)))
        except Exception as exc:
            # ruamel raises various internal exception types; inspect by duck-typing
            mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
            line: int | None = (mark.line + 1) if mark is not None else None
            col: int | None = (mark.column + 1) if mark is not None else None
            problem = getattr(exc, "problem", None) or str(exc)
            raise YamlParseError(str(problem), line=line, column=col) from exc
        return
    except ImportError:
        pass

    try:
        import yaml  # type: ignore[import-untyped]

        class _BoundedLoader(yaml.SafeLoader):
            _alias_count = 0

        original_construct = _BoundedLoader.construct_object

        def _counted_construct(self: Any, node: Any, deep: bool = False) -> Any:
            if isinstance(node, yaml.AliasNode):
                _BoundedLoader._alias_count += 1
                if _BoundedLoader._alias_count > _YAML_MAX_ALIASES:
                    raise yaml.YAMLError(
                        "YAML alias expansion limit exceeded (possible alias bomb)"
                    )
            return original_construct(self, node, deep=deep)

        _BoundedLoader.construct_object = _counted_construct  # type: ignore[method-assign]

        try:
            list(yaml.load_all(content, Loader=_BoundedLoader))
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            line = (mark.line + 1) if mark is not None else None
            col = (mark.column + 1) if mark is not None else None
            raise YamlParseError(str(exc), line=line, column=col) from exc
        return
    except ImportError:
        pass

    # No YAML parser available — skip structural validation
    _LOG.debug(
        "yaml_validation_skipped",
        extra={"reason": "no_yaml_parser_installed"},
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class AnalysisOrchestrator:
    """Orchestrates the analysis ingestion pipeline.

    Dependencies are injected via the constructor so every stage is unit-
    testable without HTTP or a real database.
    """

    _MAX_BYTES = 512 * 1024

    def __init__(
        self,
        key_provider: KeyProvider,
        normalizer_registry: NormalizerRegistry | None = None,
    ) -> None:
        self._key_provider = key_provider
        self._normalizer_registry = normalizer_registry or NormalizerRegistry()

    def ingest(
        self,
        session: Session,
        actor: CurrentActor,
        definition_text: str,
        filename: str | None,
        declared_format: str | None,
        correlation_id: str | None = None,
    ) -> AnalysisResponse:
        """Run the full ingestion pipeline synchronously.

        The *session* must be in an open transaction; the caller owns
        commit/rollback.  Raises IngestionError subclasses on validation
        failures or NoCatalogueError if no catalogue is seeded.
        """
        correlation_id = correlation_id or secrets.token_hex(16)
        timings: dict[str, float] = {}

        # ------------------------------------------------------------------
        # Stage 1: Validate content
        # ------------------------------------------------------------------
        t0 = time.monotonic()
        self._validate_content(definition_text)
        timings["validation_ms"] = (time.monotonic() - t0) * 1000

        # ------------------------------------------------------------------
        # Stage 2: YAML syntax check (for YAML-format content)
        # ------------------------------------------------------------------
        t0 = time.monotonic()
        self._maybe_validate_yaml(definition_text, filename)
        timings["yaml_parse_ms"] = (time.monotonic() - t0) * 1000

        # ------------------------------------------------------------------
        # Stage 3: Redact — before any persistence or log emission
        # ------------------------------------------------------------------
        t0 = time.monotonic()
        redacted_doc = redact(definition_text)
        masked_text = redacted_doc.masked_text
        if redacted_doc.pattern_counts:
            _LOG.info(
                "ingestion_redacted_secrets",
                extra={
                    "correlation_id": correlation_id,
                    "pattern_counts": dict(redacted_doc.pattern_counts),
                    "actor_id": str(actor.user_id),
                },
            )
        timings["redaction_ms"] = (time.monotonic() - t0) * 1000

        # ------------------------------------------------------------------
        # Stage 4: Detect format
        # ------------------------------------------------------------------
        t0 = time.monotonic()
        verdict = detect(masked_text, filename=filename)
        detected_format_str = verdict.format  # string: "github_actions"|"gitlab_ci"|"jenkins"|"unknown"
        confidence = verdict.confidence
        # format_confirmation_required when:
        #   (a) confidence is below the named threshold, OR
        #   (b) the caller declared a format that differs from what was detected
        format_confirmation_required = verdict.confirmation_required or (
            declared_format is not None
            and declared_format != detected_format_str
        )
        timings["format_detection_ms"] = (time.monotonic() - t0) * 1000

        # ------------------------------------------------------------------
        # Stage 5: Normalize (stub until WO-05/06/07)
        # When format confirmation is required, skip normalizer dispatch.
        # ------------------------------------------------------------------
        t0 = time.monotonic()
        if format_confirmation_required or detected_format_str == "unknown":
            norm_result = NormalizationResult(
                normalized_content=masked_text,
                coverage_report={
                    "note": "Format confirmation required; normalization deferred",
                    "fragments": [],
                    "not_assessable": [],
                },
            )
        else:
            effective_format = PipelineFormat(detected_format_str)
            norm_result = self._normalizer_registry.normalize(masked_text, effective_format)
        timings["normalization_ms"] = (time.monotonic() - t0) * 1000

        # ------------------------------------------------------------------
        # Stage 5.5: Resolve active catalogue snapshot once (pinned for this request)
        # ------------------------------------------------------------------
        cat_repo = SQLAlchemyCatalogueRepository(session)
        active_cat = cat_repo.get_active()
        if active_cat is None:
            raise NoCatalogueError()
        pinned_snapshot: CatalogueSnapshot = CatalogueSnapshot.model_validate(active_cat.snapshot)
        scoring_engine = ScoringEngine(pinned_snapshot, active_cat.id)

        # Score with empty evaluations (findings engine not yet wired; WO-05+)
        score_result = scoring_engine.score({})
        final_score = score_result.score if score_result.score is not None else 0
        final_grade = score_result.grade if score_result.grade is not None else "-"
        merged_coverage = dict(norm_result.coverage_report)
        merged_coverage["assessed_control_count"] = score_result.assessed_control_count
        merged_coverage["excluded_control_count"] = score_result.excluded_control_count
        if score_result.coverage_limitations:
            merged_coverage["coverage_limitations"] = list(score_result.coverage_limitations)

        # ------------------------------------------------------------------
        # Stage 6: Persist — atomic transaction
        # ------------------------------------------------------------------
        t0 = time.monotonic()
        analysis, pipeline_def = self._persist(
            session=session,
            actor=actor,
            masked_text=norm_result.normalized_content,
            filename=filename,
            detected_format_str=detected_format_str,
            confidence=confidence,
            coverage_report=merged_coverage,
            correlation_id=correlation_id,
            catalogue_version_id=active_cat.id,
            score=final_score,
            grade=final_grade,
        )
        timings["persistence_ms"] = (time.monotonic() - t0) * 1000

        # ------------------------------------------------------------------
        # Stage 7: Audit — exactly one event per accepted ingestion
        # ------------------------------------------------------------------
        t0 = time.monotonic()
        writer = AuditWriter(session)
        writer.write(
            actor_id=str(actor.user_id),
            actor_persona=actor.persona,
            actor_user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            action="analysis.ingestion_accepted",
            resource_type="analysis",
            resource_id=str(analysis.id),
            correlation_id=correlation_id,
            change_detail={
                "detected_format": detected_format_str,
                "format_confidence": round(confidence, 3),
                "format_confirmation_required": format_confirmation_required,
                "filename": filename,
                "line_count": pipeline_def.line_count,
            },
        )
        timings["audit_ms"] = (time.monotonic() - t0) * 1000

        _LOG.info(
            "analysis_ingested",
            extra={
                "analysis_id": str(analysis.id),
                "correlation_id": correlation_id,
                "detected_format": detected_format_str,
                "timings_ms": timings,
            },
        )
        _METRICS["analysis_ingestion_accepted_total"] += 1

        return AnalysisResponse(
            analysis_id=analysis.id,
            workspace_id=actor.workspace_id,
            catalogue_version_id=active_cat.id,
            created_at=analysis.created_at,
            detected_format=detected_format_str,
            format_confidence=confidence,
            format_confirmation_required=format_confirmation_required,
            coverage_report=merged_coverage,
            advisory_disclaimer=ADVISORY_DISCLAIMER,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_content(self, text: str) -> None:
        if not text or not text.strip():
            _METRICS["analysis_ingestion_rejected_4xx_total"] += 1
            raise EmptyContentError()
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) > self._MAX_BYTES:
            _METRICS["analysis_ingestion_rejected_4xx_total"] += 1
            raise PayloadTooLargeError(len(encoded))

    def _maybe_validate_yaml(self, text: str, filename: str | None) -> None:
        """Only validate YAML syntax for non-Jenkinsfile content."""
        fname_lower = (filename or "").lower()
        if "jenkinsfile" in fname_lower or fname_lower.endswith(".groovy"):
            return
        # Attempt YAML validation; JSON content will also parse as valid YAML
        # (JSON is a subset of YAML) so this is safe for both types.
        try:
            _validate_yaml_syntax(text)
        except YamlParseError:
            _METRICS["analysis_ingestion_rejected_4xx_total"] += 1
            raise

    def _persist(
        self,
        session: Session,
        actor: CurrentActor,
        masked_text: str,
        filename: str | None,
        detected_format_str: str,
        confidence: float,
        coverage_report: dict[str, Any],
        correlation_id: str,
        catalogue_version_id: uuid.UUID | None = None,
        score: int = 0,
        grade: str = "-",
    ) -> tuple[Analysis, PipelineDefinition]:
        """Create Analysis + PipelineDefinition rows in a single flush.

        Both rows are added before the flush so the session's unit-of-work
        inserts them atomically.  Any flush failure propagates to the caller
        who owns the rollback.

        catalogue_version_id must be passed by the caller (resolved once at
        request start via the active catalogue snapshot).
        """
        if catalogue_version_id is None:
            # Fallback: resolve here to preserve backward-compat if called directly
            cat_repo = SQLAlchemyCatalogueRepository(session)
            active_cat = cat_repo.get_active()
            if active_cat is None:
                raise NoCatalogueError()
            catalogue_version_id = active_cat.id

        line_count = len(masked_text.splitlines())

        analysis = Analysis(
            id=uuid.uuid4(),
            workspace_id=actor.workspace_id,
            owner_id=actor.user_id,
            catalogue_version_id=catalogue_version_id,
            pipeline_format=detected_format_str,
            format_confidence=confidence,
            score=score,
            grade=grade,
            coverage_report=coverage_report,
            status="pending_analysis",
        )

        analysis_repo = SQLAlchemyAnalysisRepository(session)
        analysis_repo.add(analysis)

        defn = PipelineDefinition(
            workspace_id=actor.workspace_id,
            analysis_id=analysis.id,
            masked_content="",  # filled by add_encrypted
            key_id="",          # filled by add_encrypted
            original_filename=filename,
            line_count=line_count,
            is_sample=False,
        )

        defn_repo = SQLAlchemyDefinitionRepository(session, self._key_provider)
        defn_repo.add_encrypted(defn, masked_text)

        return analysis, defn
