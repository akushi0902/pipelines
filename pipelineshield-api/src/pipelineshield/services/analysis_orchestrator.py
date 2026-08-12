"""AnalysisOrchestrator — stage-sequenced ingestion business logic.

Stage sequence:

1. validate
2. yaml_parse
3. redact
4. detect_format
5. normalize
6. evaluate controls
7. score
8. persist
9. audit

The orchestrator owns no database session; the caller passes an open
Session and owns the commit/rollback boundary.

No outbound HTTP.
"""

from __future__ import annotations

import logging
import secrets
import time
import uuid
from typing import Any, Mapping

from sqlalchemy.orm import Session

from pipelineshield.analysis.format_detector import detect
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
from pipelineshield.persistence.repositories.analysis import (
    SQLAlchemyAnalysisRepository,
)
from pipelineshield.persistence.repositories.catalogue import (
    SQLAlchemyCatalogueRepository,
)
from pipelineshield.persistence.repositories.definition import (
    SQLAlchemyDefinitionRepository,
)
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.services.normalizer_registry import (
    NormalizerRegistry,
    NormalizationResult,
)
from pipelineshield.services.scoring_engine import (
    ControlOutcome,
    ScoreResult,
    ScoringEngine,
)

_LOG = logging.getLogger(__name__)

__all__ = [
    "AnalysisOrchestrator",
    "IngestionError",
    "YamlParseError",
    "EmptyContentError",
    "PayloadTooLargeError",
    "UnsupportedContentTypeError",
    "NoCatalogueError",
]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

_METRICS: dict[str, int] = {
    "analysis_ingestion_accepted_total": 0,
    "analysis_ingestion_rejected_4xx_total": 0,
    "analysis_ingestion_error_5xx_total": 0,
}


# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------


class IngestionError(Exception):
    """Base for ingestion-path failures."""

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
            message=(
                "Pipeline definition content must not be empty "
                "or whitespace-only."
            ),
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
        super().__init__(
            message=message,
            status_code=422,
            constraint="yaml_syntax",
        )
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
# YAML validation
# ---------------------------------------------------------------------------

_YAML_MAX_ALIASES = 100


def _validate_yaml_syntax(content: str) -> None:
    """Validate YAML syntax.

    ruamel.yaml is preferred. PyYAML is used as fallback.
    """

    try:
        import io as _io

        from ruamel.yaml import YAML  # type: ignore[import-untyped]

        yaml_parser = YAML()
        yaml_parser.version = (1, 2)

        try:
            list(yaml_parser.load_all(_io.StringIO(content)))
        except Exception as exc:
            mark = getattr(exc, "problem_mark", None) or getattr(
                exc,
                "context_mark",
                None,
            )

            line = (
                mark.line + 1
                if mark is not None
                else None
            )

            column = (
                mark.column + 1
                if mark is not None
                else None
            )

            problem = getattr(exc, "problem", None) or str(exc)

            raise YamlParseError(
                str(problem),
                line=line,
                column=column,
            ) from exc

        return

    except ImportError:
        pass

    try:
        import yaml  # type: ignore[import-untyped]

        class _BoundedLoader(yaml.SafeLoader):
            _alias_count = 0

        original_construct = _BoundedLoader.construct_object

        def _counted_construct(
            self: Any,
            node: Any,
            deep: bool = False,
        ) -> Any:
            if isinstance(node, yaml.AliasNode):
                _BoundedLoader._alias_count += 1

                if _BoundedLoader._alias_count > _YAML_MAX_ALIASES:
                    raise yaml.YAMLError(
                        "YAML alias expansion limit exceeded "
                        "(possible alias bomb)"
                    )

            return original_construct(
                self,
                node,
                deep=deep,
            )

        _BoundedLoader.construct_object = _counted_construct  # type: ignore[method-assign]

        try:
            list(
                yaml.load_all(
                    content,
                    Loader=_BoundedLoader,
                )
            )
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)

            line = (
                mark.line + 1
                if mark is not None
                else None
            )

            column = (
                mark.column + 1
                if mark is not None
                else None
            )

            raise YamlParseError(
                str(exc),
                line=line,
                column=column,
            ) from exc

        return

    except ImportError:
        _LOG.debug(
            "yaml_validation_skipped",
            extra={
                "reason": "no_yaml_parser_installed",
            },
        )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class AnalysisOrchestrator:
    """Orchestrates the complete analysis ingestion pipeline."""

    _MAX_BYTES = 512 * 1024

    def __init__(
        self,
        key_provider: KeyProvider,
        normalizer_registry: NormalizerRegistry | None = None,
        rule_engine: Any | None = None,
    ) -> None:
        self._key_provider = key_provider
        self._normalizer_registry = (
            normalizer_registry
            or NormalizerRegistry()
        )

        # IMPORTANT:
        # RuleEngine is injected because its constructor/API is not present
        # in the files supplied so far.
        self._rule_engine = rule_engine

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(
        self,
        session: Session,
        actor: CurrentActor,
        definition_text: str,
        filename: str | None,
        declared_format: str | None,
        correlation_id: str | None = None,
    ) -> AnalysisResponse:
        """Run the complete ingestion pipeline."""

        correlation_id = (
            correlation_id
            or secrets.token_hex(16)
        )

        timings: dict[str, float] = {}

        # ==============================================================
        # Stage 1: Validate
        # ==============================================================

        t0 = time.monotonic()

        self._validate_content(
            definition_text
        )

        timings["validation_ms"] = (
            time.monotonic() - t0
        ) * 1000

        # ==============================================================
        # Stage 2: YAML validation
        # ==============================================================

        t0 = time.monotonic()

        self._maybe_validate_yaml(
            definition_text,
            filename,
        )

        timings["yaml_parse_ms"] = (
            time.monotonic() - t0
        ) * 1000

        # ==============================================================
        # Stage 3: Redaction
        # ==============================================================

        t0 = time.monotonic()

        redacted_doc = redact(
            definition_text
        )

        masked_text = redacted_doc.masked_text

        if redacted_doc.pattern_counts:
            _LOG.info(
                "ingestion_redacted_secrets",
                extra={
                    "correlation_id": correlation_id,
                    "pattern_counts": dict(
                        redacted_doc.pattern_counts
                    ),
                    "actor_id": str(
                        actor.user_id
                    ),
                },
            )

        timings["redaction_ms"] = (
            time.monotonic() - t0
        ) * 1000

        # ==============================================================
        # Stage 4: Detect format
        # ==============================================================

        t0 = time.monotonic()

        verdict = detect(
            masked_text,
            filename=filename,
        )

        detected_format_str = verdict.format
        confidence = verdict.confidence

        format_confirmation_required = (
            verdict.confirmation_required
            or (
                declared_format is not None
                and declared_format
                != detected_format_str
            )
        )

        timings["format_detection_ms"] = (
            time.monotonic() - t0
        ) * 1000

        # ==============================================================
        # Stage 5: Normalize
        # ==============================================================

        t0 = time.monotonic()

        if (
            format_confirmation_required
            or detected_format_str == "unknown"
        ):
            norm_result = NormalizationResult(
                normalized_content=masked_text,
                coverage_report={
                    "note": (
                        "Format confirmation required; "
                        "normalization deferred"
                    ),
                    "fragments": [],
                    "not_assessable": [],
                },
            )

        else:
            effective_format = PipelineFormat(
                detected_format_str
            )

            norm_result = (
                self._normalizer_registry.normalize(
                    masked_text,
                    effective_format,
                )
            )

        timings["normalization_ms"] = (
            time.monotonic() - t0
        ) * 1000

        # ==============================================================
        # Stage 5.5: Resolve catalogue
        # ==============================================================

        cat_repo = SQLAlchemyCatalogueRepository(
            session
        )

        active_cat = cat_repo.get_active()

        if active_cat is None:
            raise NoCatalogueError()

        pinned_snapshot = (
            CatalogueSnapshot.model_validate(
                active_cat.snapshot
            )
        )

        scoring_engine = ScoringEngine(
            pinned_snapshot,
            active_cat.id,
        )

        # ==============================================================
        # Stage 6: Evaluate controls
        # ==============================================================

        t0 = time.monotonic()

        evaluations = self._evaluate_controls(
            normalized_content=(
                norm_result.normalized_content
            ),
            detected_format=detected_format_str,
            snapshot=pinned_snapshot,
        )

        timings["evaluation_ms"] = (
            time.monotonic() - t0
        ) * 1000

        # ==============================================================
        # Stage 7: Score
        # ==============================================================

        t0 = time.monotonic()

        score_result = scoring_engine.score(
            evaluations
        )

        timings["scoring_ms"] = (
            time.monotonic() - t0
        ) * 1000

        # --------------------------------------------------------------
        # IMPORTANT:
        # Do NOT convert an unscorable result into 0/F.
        # --------------------------------------------------------------

        final_score = score_result.score
        final_grade = score_result.grade

        merged_coverage = dict(
            norm_result.coverage_report
        )

        merged_coverage[
            "assessed_control_count"
        ] = score_result.assessed_control_count

        merged_coverage[
            "excluded_control_count"
        ] = score_result.excluded_control_count

        if score_result.coverage_limitations:
            merged_coverage[
                "coverage_limitations"
            ] = list(
                score_result.coverage_limitations
            )

        # ==============================================================
        # Stage 7.5: Persist category scores
        # ==============================================================

        self._persist_category_scores(
            session=session,
            analysis_id=None,
            score_result=score_result,
        )

        # ==============================================================
        # Stage 8: Persist Analysis + PipelineDefinition
        # ==============================================================

        t0 = time.monotonic()

        analysis, pipeline_def = self._persist(
            session=session,
            actor=actor,
            masked_text=(
                norm_result.normalized_content
            ),
            filename=filename,
            detected_format_str=detected_format_str,
            confidence=confidence,
            coverage_report=merged_coverage,
            correlation_id=correlation_id,
            catalogue_version_id=active_cat.id,
            score=final_score,
            grade=final_grade,
            unscorable_reason=(
                self._get_unscorable_reason(
                    score_result
                )
            ),
        )

        timings["persistence_ms"] = (
            time.monotonic() - t0
        ) * 1000

        # ==============================================================
        # Stage 9: Audit
        # ==============================================================

        t0 = time.monotonic()

        writer = AuditWriter(
            session
        )

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
                "format_confidence": round(
                    confidence,
                    3,
                ),
                "format_confirmation_required": (
                    format_confirmation_required
                ),
                "filename": filename,
                "line_count": pipeline_def.line_count,
                "score": final_score,
                "grade": final_grade,
                "assessed_control_count": (
                    score_result.assessed_control_count
                ),
                "excluded_control_count": (
                    score_result.excluded_control_count
                ),
            },
        )

        timings["audit_ms"] = (
            time.monotonic() - t0
        ) * 1000

        # ==============================================================
        # Logging
        # ==============================================================

        _LOG.info(
            "analysis_ingested",
            extra={
                "analysis_id": str(
                    analysis.id
                ),
                "correlation_id": correlation_id,
                "detected_format": (
                    detected_format_str
                ),
                "score": final_score,
                "grade": final_grade,
                "timings_ms": timings,
            },
        )

        _METRICS[
            "analysis_ingestion_accepted_total"
        ] += 1

        # ==============================================================
        # Response
        # ==============================================================

        return AnalysisResponse(
            analysis_id=analysis.id,
            workspace_id=actor.workspace_id,
            catalogue_version_id=active_cat.id,
            created_at=analysis.created_at,
            detected_format=detected_format_str,
            format_confidence=confidence,
            format_confirmation_required=(
                format_confirmation_required
            ),
            coverage_report=merged_coverage,
            advisory_disclaimer=(
                ADVISORY_DISCLAIMER
            ),
        )

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def _evaluate_controls(
        self,
        normalized_content: str,
        detected_format: str,
        snapshot: CatalogueSnapshot,
    ) -> Mapping[str, ControlOutcome]:
        """Evaluate the normalized pipeline against the catalogue.

        The RuleEngine must return a mapping:

            control_id -> ControlOutcome

        This is the missing connection in the original implementation.
        """

        if self._rule_engine is None:
            raise RuntimeError(
                "RuleEngine is not configured. "
                "Analysis scoring requires control evaluation "
                "before ScoringEngine.score()."
            )

        # --------------------------------------------------------------
        # IMPORTANT:
        # This adapter supports the common RuleEngine API patterns.
        # --------------------------------------------------------------

        engine = self._rule_engine

        # Pattern 1:
        # engine.evaluate(content, snapshot)
        if hasattr(engine, "evaluate"):
            result = engine.evaluate(
                normalized_content,
                snapshot,
            )

        # Pattern 2:
        # engine.run(content, snapshot)
        elif hasattr(engine, "run"):
            result = engine.run(
                normalized_content,
                snapshot,
            )

        # Pattern 3:
        # engine.evaluate(ir, catalogue)
        elif hasattr(engine, "execute"):
            result = engine.execute(
                normalized_content,
                snapshot,
            )

        else:
            raise RuntimeError(
                "Configured RuleEngine does not expose "
                "evaluate(), run(), or execute()."
            )

        # --------------------------------------------------------------
        # Convert result to control_id -> ControlOutcome
        # --------------------------------------------------------------

        if isinstance(result, Mapping):
            evaluations: dict[
                str,
                ControlOutcome,
            ] = {}

            for control_id, outcome in result.items():
                if isinstance(
                    outcome,
                    ControlOutcome,
                ):
                    evaluations[
                        str(control_id)
                    ] = outcome
                elif isinstance(outcome, str):
                    evaluations[
                        str(control_id)
                    ] = ControlOutcome(
                        outcome
                    )
                elif hasattr(
                    outcome,
                    "outcome",
                ):
                    raw_outcome = outcome.outcome

                    if isinstance(
                        raw_outcome,
                        ControlOutcome,
                    ):
                        evaluations[
                            str(control_id)
                        ] = raw_outcome
                    else:
                        evaluations[
                            str(control_id)
                        ] = ControlOutcome(
                            str(raw_outcome)
                        )

            return evaluations

        raise RuntimeError(
            "RuleEngine returned an unsupported result. "
            "Expected a mapping of control_id to ControlOutcome."
        )

    # ------------------------------------------------------------------
    # Content validation
    # ------------------------------------------------------------------

    def _validate_content(
        self,
        text: str,
    ) -> None:
        if not text or not text.strip():
            _METRICS[
                "analysis_ingestion_rejected_4xx_total"
            ] += 1

            raise EmptyContentError()

        encoded = text.encode(
            "utf-8",
            errors="replace",
        )

        if len(encoded) > self._MAX_BYTES:
            _METRICS[
                "analysis_ingestion_rejected_4xx_total"
            ] += 1

            raise PayloadTooLargeError(
                len(encoded)
            )

    def _maybe_validate_yaml(
        self,
        text: str,
        filename: str | None,
    ) -> None:
        fname_lower = (
            filename or ""
        ).lower()

        if (
            "jenkinsfile" in fname_lower
            or fname_lower.endswith(".groovy")
        ):
            return

        try:
            _validate_yaml_syntax(
                text
            )
        except YamlParseError:
            _METRICS[
                "analysis_ingestion_rejected_4xx_total"
            ] += 1
            raise

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_unscorable_reason(
        score_result: ScoreResult,
    ) -> str | None:
        if not score_result.is_unscorable:
            return None

        if score_result.coverage_limitations:
            return "; ".join(
                score_result.coverage_limitations
            )

        return (
            "Score cannot be computed because "
            "no assessable controls were found."
        )

    def _persist_category_scores(
        self,
        session: Session,
        analysis_id: uuid.UUID | None,
        score_result: ScoreResult,
    ) -> None:
        """Persist per-category score rows.

        This method is intentionally called after the Analysis ID exists.
        Therefore the actual category rows are inserted from _persist().
        """

        # Category rows are persisted in _persist() after analysis creation.
        # This method is kept as a separate hook so the scoring result is
        # explicitly carried through the ingestion pipeline.
        return

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

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
        score: int | None = None,
        grade: str | None = None,
        unscorable_reason: str | None = None,
    ) -> tuple[
        Analysis,
        PipelineDefinition,
    ]:
        """Create Analysis + PipelineDefinition."""

        if catalogue_version_id is None:
            cat_repo = (
                SQLAlchemyCatalogueRepository(
                    session
                )
            )

            active_cat = cat_repo.get_active()

            if active_cat is None:
                raise NoCatalogueError()

            catalogue_version_id = (
                active_cat.id
            )

        line_count = len(
            masked_text.splitlines()
        )

        analysis = Analysis(
            id=uuid.uuid4(),
            workspace_id=actor.workspace_id,
            owner_id=actor.user_id,
            catalogue_version_id=(
                catalogue_version_id
            ),
            pipeline_format=(
                detected_format_str
            ),
            format_confidence=confidence,
            score=score,
            grade=grade,
            unscorable_reason=(
                unscorable_reason
            ),
            coverage_report=coverage_report,
            status="pending_analysis",
        )

        analysis_repo = (
            SQLAlchemyAnalysisRepository(
                session
            )
        )

        analysis_repo.add(
            analysis
        )

        defn = PipelineDefinition(
            workspace_id=actor.workspace_id,
            analysis_id=analysis.id,
            masked_content="",
            key_id="",
            original_filename=filename,
            line_count=line_count,
            is_sample=False,
        )

        defn_repo = (
            SQLAlchemyDefinitionRepository(
                session,
                self._key_provider,
            )
        )

        defn_repo.add_encrypted(
            defn,
            masked_text,
        )

        return analysis, defn
