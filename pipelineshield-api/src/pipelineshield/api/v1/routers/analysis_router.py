"""Analysis ingestion router — POST /api/v1/analyses.

Accepts both application/json (paste) and multipart/form-data (upload).
Content-type dispatch is done via the incoming Content-Type header.

The router is thin — no SQL and no role branching. All business logic
lives in AnalysisOrchestrator. Errors are mapped to RFC 7807 bodies.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from pipelineshield.analysis.format_detector import CONFIDENCE_THRESHOLD
from pipelineshield.analysis.rule_engine.engine import RuleEngine
from pipelineshield.analysis.rules import build_default_registry
from pipelineshield.api.security.authz_guard import (
    CurrentActor,
    PERSONA_CAPABILITIES,
    require_capability,
)
from pipelineshield.api.security.scope import ResourceNotVisibleError
from pipelineshield.api.v1.schemas.analysis import (
    AnalysisResponse,
    FormatConfirmationRequest,
    FormatConfirmationResponse,
    IngestionErrorResponse,
    PAYLOAD_MAX_BYTES,
    PasteAnalysisRequest,
)
from pipelineshield.api.v1.schemas.report import AnalysisReport
from pipelineshield.crypto.key_provider import EnvKeyProvider
from pipelineshield.persistence.repositories.analysis import (
    SQLAlchemyAnalysisRepository,
)
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.services.analysis_orchestrator import (
    AnalysisOrchestrator,
    EmptyContentError,
    IngestionError,
    NoCatalogueError,
    PayloadTooLargeError,
    UnsupportedContentTypeError,
    YamlParseError,
)
from pipelineshield.services.report_service import (
    MissingScoringResultError,
    ReportService,
)

_LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/analyses", tags=["analyses"])

_ALLOWED_PASTE_TYPES = frozenset(
    {
        "application/json",
        "text/plain",
        "text/yaml",
        "application/x-yaml",
    }
)


# ---------------------------------------------------------------------------
# Dependency: database session
# ---------------------------------------------------------------------------


def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError(
        "get_db must be overridden before use"
    )


# ---------------------------------------------------------------------------
# Dependency: orchestrator
# ---------------------------------------------------------------------------


def get_orchestrator() -> AnalysisOrchestrator:  # pragma: no cover
    """Build an AnalysisOrchestrator with the default rule engine."""

    registry = build_default_registry()
    rule_engine = RuleEngine(
        registry=registry,
    )

    return AnalysisOrchestrator(
        key_provider=EnvKeyProvider(),
        rule_engine=rule_engine,
    )


# ---------------------------------------------------------------------------
# RFC 7807 error builder
# ---------------------------------------------------------------------------


def _error_body(
    correlation_id: str,
    status_code: int,
    title: str,
    detail: str,
    constraint: str | None = None,
    parse_line: int | None = None,
    parse_column: int | None = None,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:

    error_type = (
        "https://pipelineshield.internal/errors/"
        f"{title.lower().replace(' ', '-')}"
    )

    body: dict[str, Any] = {
        "type": error_type,
        "title": title,
        "status": status_code,
        "detail": detail,
        "correlation_id": correlation_id,
        "errors": errors or [],
    }

    if constraint is not None:
        body["constraint"] = constraint

    if parse_line is not None:
        body["parse_line"] = parse_line

    if parse_column is not None:
        body["parse_column"] = parse_column

    return body


def _raise_http_error(
    correlation_id: str,
    status_code: int,
    title: str,
    detail: str,
    *,
    constraint: str | None = None,
    parse_line: int | None = None,
    parse_column: int | None = None,
    errors: list[dict[str, Any]] | None = None,
) -> None:

    body = _error_body(
        correlation_id=correlation_id,
        status_code=status_code,
        title=title,
        detail=detail,
        constraint=constraint,
        parse_line=parse_line,
        parse_column=parse_column,
        errors=errors,
    )

    raise HTTPException(
        status_code=status_code,
        detail=body,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/analyses
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=AnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a pipeline definition for security analysis",
    responses={
        400: {"model": IngestionErrorResponse},
        401: {"model": IngestionErrorResponse},
        403: {"model": IngestionErrorResponse},
        413: {"model": IngestionErrorResponse},
        415: {"model": IngestionErrorResponse},
        422: {"model": IngestionErrorResponse},
        503: {"model": IngestionErrorResponse},
    },
)
async def create_analysis(
    request: Request,
    actor: Annotated[
        CurrentActor,
        Depends(require_capability("analysis:create")),
    ],
    session: Session = Depends(get_db),
    orchestrator: AnalysisOrchestrator = Depends(
        get_orchestrator
    ),
) -> AnalysisResponse:
    """Accept a pipeline definition and return the created analysis."""

    correlation_id = secrets.token_hex(16)

    content_type = (
        request.headers.get("content-type", "")
        .split(";", 1)[0]
        .strip()
        .lower()
    )

    try:

        if content_type == "multipart/form-data":

            (
                definition_text,
                filename,
                declared_format_str,
            ) = await _parse_upload(
                request,
                correlation_id,
            )

        elif (
            content_type in _ALLOWED_PASTE_TYPES
            or content_type == ""
        ):

            (
                definition_text,
                filename,
                declared_format_str,
            ) = await _parse_paste(
                request,
                correlation_id,
            )

        else:
            raise UnsupportedContentTypeError(
                content_type
            )

        return orchestrator.ingest(
            session=session,
            actor=actor,
            definition_text=definition_text,
            filename=filename,
            declared_format=declared_format_str,
            correlation_id=correlation_id,
        )

    except PayloadTooLargeError as exc:

        _raise_http_error(
            correlation_id,
            413,
            "Payload Too Large",
            str(exc),
            constraint=exc.constraint,
        )

    except EmptyContentError as exc:

        _raise_http_error(
            correlation_id,
            400,
            "Empty Content",
            str(exc),
            constraint=exc.constraint,
        )

    except UnsupportedContentTypeError as exc:

        _raise_http_error(
            correlation_id,
            415,
            "Unsupported Media Type",
            str(exc),
            constraint=exc.constraint,
        )

    except YamlParseError as exc:

        _raise_http_error(
            correlation_id,
            422,
            "Unprocessable Definition",
            str(exc),
            constraint=exc.constraint,
            parse_line=exc.parse_line,
            parse_column=exc.parse_column,
        )

    except NoCatalogueError as exc:

        _raise_http_error(
            correlation_id,
            503,
            "Service Unavailable",
            str(exc),
            constraint=exc.constraint,
        )

    except IngestionError as exc:

        _raise_http_error(
            correlation_id,
            exc.status_code,
            "Ingestion Error",
            str(exc),
            constraint=exc.constraint,
        )

    except HTTPException:
        raise

    except Exception as exc:

        # Keep the full traceback in backend logs.
        _LOG.exception(
            "analysis_ingestion_unhandled_error",
            extra={
                "correlation_id": correlation_id,
                "actor_id": str(actor.user_id),
                "error_type": type(exc).__name__,
            },
        )

        _raise_http_error(
            correlation_id,
            500,
            "Internal Server Error",
            (
                "An unexpected error occurred. "
                "Please retry with the correlation id."
            ),
        )

    raise AssertionError("Unreachable")


# ---------------------------------------------------------------------------
# POST /api/v1/analyses/{analysis_id}/format-confirmation
# ---------------------------------------------------------------------------


@router.post(
    "/{analysis_id}/format-confirmation",
    response_model=FormatConfirmationResponse,
    status_code=status.HTTP_200_OK,
    summary="Confirm the pipeline format for a low-confidence analysis",
    responses={
        400: {"model": IngestionErrorResponse},
        401: {"model": IngestionErrorResponse},
        404: {"model": IngestionErrorResponse},
        409: {"model": IngestionErrorResponse},
        422: {"model": IngestionErrorResponse},
    },
)
async def confirm_format(
    analysis_id: uuid.UUID,
    body: FormatConfirmationRequest,
    actor: Annotated[
        CurrentActor,
        Depends(require_capability("analysis:create")),
    ],
    session: Session = Depends(get_db),
) -> FormatConfirmationResponse:

    """Confirm the pipeline format for an analysis."""

    correlation_id = secrets.token_hex(16)

    analysis_repo = SQLAlchemyAnalysisRepository(
        session
    )

    analysis = (
        analysis_repo.get_by_id_owner_scoped(
            analysis_id=analysis_id,
            owner_id=actor.user_id,
            workspace_id=actor.workspace_id,
        )
    )

    if analysis is None:
        raise ResourceNotVisibleError(
            resource_type="analysis"
        )

    if analysis.format_confirmed_by_user:

        _raise_http_error(
            correlation_id,
            409,
            "Conflict",
            (
                "This analysis has already been "
                "format-confirmed. Re-confirmation "
                "is not permitted."
            ),
            constraint="already_confirmed",
        )

    if (
        analysis.format_confidence
        >= CONFIDENCE_THRESHOLD
    ):

        _raise_http_error(
            correlation_id,
            422,
            "Unprocessable",
            (
                "Format confirmation is not required "
                "for this analysis "
                f"(confidence="
                f"{analysis.format_confidence:.3f} "
                f">= {CONFIDENCE_THRESHOLD}). "
                "The detected format has already "
                "been applied."
            ),
            constraint="confirmation_not_required",
        )

    previous_format = analysis.pipeline_format
    confirmed_str = body.confirmed_format.value

    analysis.confirmed_format = confirmed_str
    analysis.format_confirmed_by_user = True

    session.flush()

    writer = AuditWriter(session)

    writer.write(
        actor_id=str(actor.user_id),
        actor_persona=actor.persona,
        actor_user_id=actor.user_id,
        workspace_id=actor.workspace_id,
        action="format_confirmed",
        resource_type="analysis",
        resource_id=str(analysis.id),
        correlation_id=correlation_id,
        change_detail={
            "detected_format": previous_format,
            "confirmed_format": confirmed_str,
        },
    )

    _LOG.info(
        "format_confirmed",
        extra={
            "analysis_id": str(analysis.id),
            "correlation_id": correlation_id,
            "detected_format": previous_format,
            "confirmed_format": confirmed_str,
            "actor_id": str(actor.user_id),
        },
    )

    return FormatConfirmationResponse(
        analysis_id=analysis.id,
        confirmed_format=confirmed_str,
        format_confirmed_by_user=True,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/analyses/{analysis_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{analysis_id}",
    response_model=AnalysisReport,
    status_code=status.HTTP_200_OK,
    summary="Retrieve the risk assessment report for an analysis",
    responses={
        401: {"model": IngestionErrorResponse},
        404: {"model": IngestionErrorResponse},
        500: {"model": IngestionErrorResponse},
    },
)
async def get_analysis_report(
    analysis_id: uuid.UUID,
    actor: Annotated[
        CurrentActor,
        Depends(require_capability("analysis:read:own")),
    ],
    session: Session = Depends(get_db),
) -> AnalysisReport:

    """Return the full risk assessment report for an analysis."""

    correlation_id = secrets.token_hex(16)

    analysis_repo = SQLAlchemyAnalysisRepository(
        session
    )

    actor_caps = PERSONA_CAPABILITIES.get(
        actor.persona,
        frozenset(),
    )

    if "analysis:read:all" in actor_caps:

        analysis = analysis_repo.get_by_id(
            analysis_id=analysis_id,
            workspace_id=actor.workspace_id,
        )

    else:

        analysis = (
            analysis_repo.get_by_id_owner_scoped(
                analysis_id=analysis_id,
                owner_id=actor.user_id,
                workspace_id=actor.workspace_id,
            )
        )

    if analysis is None:

        _raise_http_error(
            correlation_id,
            404,
            "Not Found",
            "The requested analysis was not found.",
            constraint="analysis_not_found",
        )

    try:

        report_service = ReportService(session)

        report = report_service.build_report(
            analysis
        )

    except MissingScoringResultError as exc:

        _LOG.error(
            "analysis_report_scoring_missing",
            extra={
                "correlation_id": correlation_id,
                "analysis_id": str(analysis_id),
                "actor_id": str(actor.user_id),
                "error": str(exc),
            },
            exc_info=False,
        )

        _raise_http_error(
            correlation_id,
            500,
            "Internal Server Error",
            (
                "Scoring result is unavailable for "
                "this analysis. Please retry with "
                "the correlation id."
            ),
        )

    writer = AuditWriter(session)

    writer.write(
        actor_id=str(actor.user_id),
        actor_persona=actor.persona,
        actor_user_id=actor.user_id,
        workspace_id=actor.workspace_id,
        action="analysis.report_read",
        resource_type="analysis",
        resource_id=str(analysis.id),
        correlation_id=correlation_id,
        change_detail={
            "catalogue_version": report.catalogue_version,
            "format": report.format,
        },
    )

    _LOG.info(
        "analysis_report_read",
        extra={
            "analysis_id": str(analysis_id),
            "correlation_id": correlation_id,
            "actor_id": str(actor.user_id),
            "persona": actor.persona,
            "format": report.format,
            "catalogue_version": report.catalogue_version,
        },
    )

    return report


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


async def _parse_paste(
    request: Request,
    correlation_id: str,
) -> tuple[str, str | None, str | None]:

    """Parse a JSON paste request body."""

    try:

        raw = await request.json()

    except Exception as exc:

        _raise_http_error(
            correlation_id,
            400,
            "Malformed Request",
            "Request body is not valid JSON.",
        )

        raise AssertionError(
            "Unreachable"
        ) from exc

    try:

        parsed = PasteAnalysisRequest.model_validate(
            raw
        )

    except Exception as exc:

        _raise_http_error(
            correlation_id,
            422,
            "Validation Error",
            f"Request body failed validation: {exc}",
        )

        raise AssertionError(
            "Unreachable"
        ) from exc

    declared = (
        parsed.declared_format.value
        if parsed.declared_format
        else None
    )

    return (
        parsed.definition_text,
        parsed.filename,
        declared,
    )


async def _parse_upload(
    request: Request,
    correlation_id: str,
) -> tuple[str, str | None, str | None]:

    """Parse a multipart upload request."""

    try:

        form = await request.form()

    except Exception as exc:

        _raise_http_error(
            correlation_id,
            400,
            "Malformed Request",
            "Could not parse multipart form data.",
        )

        raise AssertionError(
            "Unreachable"
        ) from exc

    file_fields = [
        value
        for _, value in form.multi_items()
        if isinstance(value, UploadFile)
    ]

    if len(file_fields) != 1:

        _raise_http_error(
            correlation_id,
            400,
            "Missing File",
            (
                "Multipart request must contain exactly "
                "one file part."
            ),
            constraint="multipart_file_required",
        )

    file_field = file_fields[0]

    raw_bytes = await file_field.read()

    if len(raw_bytes) > PAYLOAD_MAX_BYTES:
        raise PayloadTooLargeError(
            len(raw_bytes)
        )

    if not raw_bytes:

        raise HTTPException(
            status_code=400,
            detail=_error_body(
                correlation_id,
                400,
                "Empty Content",
                "Uploaded file must not be empty.",
                constraint="non_empty_content",
            ),
        )

    try:

        definition_text = raw_bytes.decode(
            "utf-8-sig"
        )

    except UnicodeDecodeError:

        definition_text = raw_bytes.decode(
            "latin-1"
        )

    if not definition_text.strip():

        raise HTTPException(
            status_code=400,
            detail=_error_body(
                correlation_id,
                400,
                "Empty Content",
                (
                    "Uploaded file must not contain "
                    "only whitespace."
                ),
                constraint="non_empty_content",
            ),
        )

    filename = file_field.filename or None

    declared_str = form.get(
        "declared_format"
    )

    if isinstance(
        declared_str,
        UploadFile,
    ):
        declared_str = None

    declared_format_str = (
        str(declared_str)
        if declared_str
        else None
    )

    return (
        definition_text,
        filename,
        declared_format_str,
    )
