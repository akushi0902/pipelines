"""Governance router — subject data export and erasure.

POST /api/v1/governance/subjects/{user_id}/export
    Returns a masked JSON bundle of all data stored about the subject.
    Requires governance:data capability.

POST /api/v1/governance/subjects/{user_id}/erasure
    Immediately hard-deletes the subject's Confidential material using the
    shared purge primitive.  Requires governance:data capability and an
    explicit confirm=true in the request body.

Out of scope (PRD Assumption A7, pending ratification):
    - DSAR case management
    - Data rectification
    - Portability formats beyond JSON

Status codes:
  200  success (export or erasure)
  400  missing/false confirm field
  403  non-governance persona (app_developer, devops_engineer, engineering_manager)
  404  unknown or cross-workspace subject (existence not disclosed)
  500  partial erasure failure (receipt written, correlation_id only in response)
"""
from __future__ import annotations

import secrets
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from pipelineshield.api.security.authz_guard import CurrentActor, require_capability
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.services.subject_rights_service import (
    ConfirmationRequiredError,
    ErasureReceipt,
    SubjectBundle,
    SubjectNotFoundError,
    SubjectRightsService,
)

router = APIRouter(prefix="/governance", tags=["governance"])

_service = SubjectRightsService()


def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError("get_db must be overridden before use")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SubjectBundleResponse(BaseModel):
    bundle_version: str
    generated_at: str
    subject: dict[str, Any]
    role_bindings: list[dict[str, Any]]
    definitions: list[dict[str, Any]]
    analyses: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    remediations: list[dict[str, Any]]
    generated_drafts: list[dict[str, Any]]
    audit_trail: list[dict[str, Any]]


class ErasureRequest(BaseModel):
    confirm: bool
    reason: str = ""

    @field_validator("confirm")
    @classmethod
    def confirm_must_be_true(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "confirm must be true to proceed with erasure. "
                "This operation is irreversible."
            )
        return v


class ErasureResponse(BaseModel):
    batch_id: str
    executed_at: str
    entity_counts: dict[str, int]
    verification_digest: str
    status: str
    subject_user_id: str


class ErrorResponse(BaseModel):
    type: str
    title: str
    status: int
    detail: str
    correlation_id: str | None = None
    errors: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# POST /api/v1/governance/subjects/{user_id}/export
# ---------------------------------------------------------------------------


@router.post(
    "/subjects/{user_id}/export",
    response_model=SubjectBundleResponse,
    summary="Export all data stored about a data subject (governance only)",
    responses={
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
)
async def export_subject(
    user_id: uuid.UUID,
    actor: Annotated[CurrentActor, Depends(require_capability("governance:data"))],
    request: Request,
    session: Session = Depends(get_db),
) -> SubjectBundleResponse:
    corr = request.headers.get("x-correlation-id") or secrets.token_hex(8)
    audit = AuditWriter(session)
    try:
        bundle = _service.export_subject_data(
            session,
            user_id=user_id,
            workspace_id=actor.workspace_id,
            actor_id=str(actor.user_id),
            audit_writer=audit,
            correlation_id=corr,
        )
    except SubjectNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "type": "https://pipelineshield.internal/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": "The requested subject was not found.",
                "correlation_id": corr,
                "errors": [],
            },
        ) from exc

    return SubjectBundleResponse(
        bundle_version=bundle.bundle_version,
        generated_at=bundle.generated_at,
        subject=bundle.subject,
        role_bindings=bundle.role_bindings,
        definitions=bundle.definitions,
        analyses=bundle.analyses,
        findings=bundle.findings,
        remediations=bundle.remediations,
        generated_drafts=bundle.generated_drafts,
        audit_trail=bundle.audit_trail,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/governance/subjects/{user_id}/erasure
# ---------------------------------------------------------------------------


@router.post(
    "/subjects/{user_id}/erasure",
    response_model=ErasureResponse,
    summary="Erase a data subject's Confidential material (governance only)",
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def erase_subject(
    user_id: uuid.UUID,
    body: ErasureRequest,
    actor: Annotated[CurrentActor, Depends(require_capability("governance:data"))],
    request: Request,
    session: Session = Depends(get_db),
) -> ErasureResponse:
    corr = request.headers.get("x-correlation-id") or secrets.token_hex(8)
    audit = AuditWriter(session)
    try:
        receipt = _service.erase_subject_data(
            session,
            user_id=user_id,
            workspace_id=actor.workspace_id,
            actor_id=str(actor.user_id),
            confirm=body.confirm,
            reason=body.reason,
            audit_writer=audit,
            correlation_id=corr,
        )
    except ConfirmationRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "type": "https://pipelineshield.internal/errors/validation",
                "title": "Confirmation Required",
                "status": 400,
                "detail": str(exc),
                "correlation_id": corr,
                "errors": [{"field": "confirm", "message": str(exc)}],
            },
        ) from exc
    except SubjectNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "type": "https://pipelineshield.internal/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": "The requested subject was not found.",
                "correlation_id": corr,
                "errors": [],
            },
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "type": "https://pipelineshield.internal/errors/erasure-failed",
                "title": "Erasure Failed",
                "status": 500,
                "detail": "Erasure completed with verification failure. See audit log.",
                "correlation_id": corr,
                "errors": [],
            },
        ) from exc

    return ErasureResponse(
        batch_id=str(receipt.batch_id),
        executed_at=receipt.executed_at,
        entity_counts=receipt.entity_counts,
        verification_digest=receipt.verification_digest,
        status=receipt.status,
        subject_user_id=receipt.subject_user_id,
    )


# =============================================================================
# Governance Console endpoints (WO-042)
#
# GET  /governance/classification-inventory
# GET  /governance/audit-events
# GET  /governance/retention-policy
# PUT  /governance/retention-policy
# GET  /governance/purge-receipts
# GET  /governance/export-history
#
# All require governance:data capability (devsecops_engineer, appsec_lead).
# =============================================================================

import logging as _logging
from datetime import datetime as _datetime

from pipelineshield.api.v1.schemas.governance import (
    ClassificationEntityItem,
    ClassificationInventoryResponse,
    ExportHistoryItem,
    ExportHistoryResponse,
    GovernanceAuditEventItem,
    GovernanceAuditEventsResponse,
    GovernanceErrorResponse,
    PurgeReceiptItem,
    PurgeReceiptsResponse,
    RetentionPolicyResponse,
    RetentionPolicyUpdate,
)
from pipelineshield.services.governance_service import GovernanceService
from fastapi import Query

_GLOG = _logging.getLogger(__name__)
_gov_service = GovernanceService()

_INVALID_CURSOR_RESPONSE = {
    "type": "https://pipelineshield.internal/errors/invalid-cursor",
    "title": "Bad Request",
    "status": 400,
    "detail": "The pagination cursor is invalid or expired.",
    "errors": [],
}


# ---------------------------------------------------------------------------
# GET /api/v1/governance/classification-inventory
# ---------------------------------------------------------------------------


@router.get(
    "/classification-inventory",
    response_model=ClassificationInventoryResponse,
    summary="Entity classification inventory (governance only)",
    responses={403: {"model": GovernanceErrorResponse}},
)
def get_classification_inventory(
    actor: Annotated[CurrentActor, Depends(require_capability("governance:data"))],
) -> ClassificationInventoryResponse:
    entities = _gov_service.get_classification_inventory()
    return ClassificationInventoryResponse(
        entities=[ClassificationEntityItem(**e) for e in entities]
    )


# ---------------------------------------------------------------------------
# GET /api/v1/governance/audit-events
# ---------------------------------------------------------------------------


@router.get(
    "/audit-events",
    response_model=GovernanceAuditEventsResponse,
    summary="Cursor-paginated governance audit log (governance only)",
    responses={
        400: {"model": GovernanceErrorResponse},
        403: {"model": GovernanceErrorResponse},
    },
)
def get_governance_audit_events(
    actor: Annotated[CurrentActor, Depends(require_capability("governance:data"))],
    session: Session = Depends(get_db),
    cursor: str | None = Query(default=None, description="Opaque pagination cursor"),
    limit: int = Query(default=50, ge=1, le=200),
    actor_id: str | None = Query(default=None),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    from_dt: _datetime | None = Query(default=None, alias="from"),
    to_dt: _datetime | None = Query(default=None, alias="to"),
) -> GovernanceAuditEventsResponse:
    page = _gov_service.get_audit_events(
        session,
        workspace_id=actor.workspace_id,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        from_dt=from_dt,
        to_dt=to_dt,
        cursor=cursor,
        limit=limit,
    )
    items = [
        GovernanceAuditEventItem(
            id=evt.id,
            occurred_at=evt.occurred_at,
            actor_id=evt.actor_id,
            actor_display=evt.actor_reference,
            actor_persona=evt.actor_persona,
            workspace_id=evt.workspace_id,
            action=evt.action,
            resource_type=evt.resource_type,
            resource_id=evt.resource_id,
            change_detail=evt.change_detail or {},
        )
        for evt in page.items
    ]
    return GovernanceAuditEventsResponse(
        items=items,
        next_cursor=page.next_cursor,
        has_more=page.next_cursor is not None,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/governance/retention-policy
# ---------------------------------------------------------------------------


@router.get(
    "/retention-policy",
    response_model=RetentionPolicyResponse,
    summary="Current retention policy (governance only)",
    responses={403: {"model": GovernanceErrorResponse}},
)
def get_retention_policy(
    actor: Annotated[CurrentActor, Depends(require_capability("governance:data"))],
    session: Session = Depends(get_db),
) -> RetentionPolicyResponse:
    info = _gov_service.get_retention_policy(session)
    return RetentionPolicyResponse(
        retention_days=info.retention_days,
        next_run_at=info.next_run_at,
        last_run_at=info.last_run_at,
        last_run_status=info.last_run_status,
        purge_sla_breaches=info.purge_sla_breaches,
        updated_by=info.updated_by,
        updated_at=info.updated_at,
    )


# ---------------------------------------------------------------------------
# PUT /api/v1/governance/retention-policy
# ---------------------------------------------------------------------------


@router.put(
    "/retention-policy",
    response_model=RetentionPolicyResponse,
    summary="Update retention policy (governance only, max 90 days)",
    responses={
        400: {"model": GovernanceErrorResponse},
        403: {"model": GovernanceErrorResponse},
    },
)
def update_retention_policy(
    body: RetentionPolicyUpdate,
    actor: Annotated[CurrentActor, Depends(require_capability("governance:data"))],
    request: Request,
    session: Session = Depends(get_db),
) -> RetentionPolicyResponse:
    from pipelineshield.platform.audit_writer import AuditWriter
    corr = request.headers.get("x-correlation-id") or secrets.token_hex(8)
    audit = AuditWriter(session)
    try:
        info = _gov_service.update_retention_policy(
            session,
            retention_days=body.retention_days,
            actor_id=actor.user_id,
            audit_writer=audit,
            workspace_id=actor.workspace_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "type": "https://pipelineshield.internal/errors/validation",
                "title": "Bad Request",
                "status": 400,
                "detail": str(exc),
                "correlation_id": corr,
                "errors": [{"field": "retention_days", "message": str(exc)}],
            },
        ) from exc

    return RetentionPolicyResponse(
        retention_days=info.retention_days,
        next_run_at=info.next_run_at,
        last_run_at=info.last_run_at,
        last_run_status=info.last_run_status,
        purge_sla_breaches=info.purge_sla_breaches,
        updated_by=info.updated_by,
        updated_at=info.updated_at,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/governance/purge-receipts
# ---------------------------------------------------------------------------


@router.get(
    "/purge-receipts",
    response_model=PurgeReceiptsResponse,
    summary="Paginated purge receipt list (governance only)",
    responses={
        400: {"model": GovernanceErrorResponse},
        403: {"model": GovernanceErrorResponse},
    },
)
def get_purge_receipts(
    actor: Annotated[CurrentActor, Depends(require_capability("governance:data"))],
    session: Session = Depends(get_db),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> PurgeReceiptsResponse:
    try:
        page = _gov_service.get_purge_receipts(session, cursor=cursor, limit=limit)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_INVALID_CURSOR_RESPONSE,
        )
    items = [
        PurgeReceiptItem(
            batch_id=r.batch_id,
            executed_at=r.executed_at,
            entity_counts=r.deleted_counts or {},
            verification_digest=r.verification_digest,
            status=r.status,
            error_detail=r.error_detail,
            trigger=r.trigger if hasattr(r, "trigger") else "scheduled",
            subject_user_id=r.subject_user_id if hasattr(r, "subject_user_id") else None,
        )
        for r in page.items
    ]
    return PurgeReceiptsResponse(
        items=items,
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/governance/export-history
# ---------------------------------------------------------------------------


@router.get(
    "/export-history",
    response_model=ExportHistoryResponse,
    summary="Export history (governance only)",
    responses={403: {"model": GovernanceErrorResponse}},
)
def get_export_history(
    actor: Annotated[CurrentActor, Depends(require_capability("governance:data"))],
    session: Session = Depends(get_db),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> ExportHistoryResponse:
    page = _gov_service.get_export_history(
        session,
        workspace_id=actor.workspace_id,
        cursor=cursor,
        limit=limit,
    )
    items = [
        ExportHistoryItem(
            id=evt.id,
            occurred_at=evt.occurred_at,
            actor_id=evt.actor_id,
            resource_type=evt.resource_type,
            resource_id=evt.resource_id,
            format=evt.change_detail.get("format") if evt.change_detail else None,
        )
        for evt in page.items
    ]
    return ExportHistoryResponse(
        items=items,
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )
