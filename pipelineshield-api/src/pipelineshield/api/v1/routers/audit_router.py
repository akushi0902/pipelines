"""Audit events router — read-only, cursor-paginated.

GET /api/v1/audit-events
  Requires audit:read capability (devsecops_engineer, appsec_lead).
  Returns events scoped to the actor's workspace.
  Cursor pagination via opaque next_cursor token.

No POST/PATCH/DELETE endpoints exist — absence is intentional and
machine-verifiable from the OpenAPI document.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from pipelineshield.api.security.authz_guard import CurrentActor, require_capability
from pipelineshield.api.v1.schemas.audit import AuditErrorResponse, AuditEventItem, AuditEventsResponse
from pipelineshield.persistence.repositories.audit import SQLAlchemyAuditRepository

_LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/audit-events", tags=["audit"])


# ---------------------------------------------------------------------------
# Database session dependency (overridden in tests via app.dependency_overrides)
# ---------------------------------------------------------------------------


def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError("get_db must be overridden before use")


# ---------------------------------------------------------------------------
# GET /api/v1/audit-events
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=AuditEventsResponse,
    summary="List audit events (security personas only)",
    responses={
        401: {"model": AuditErrorResponse},
        403: {"model": AuditErrorResponse},
    },
)
def list_audit_events(
    actor: Annotated[CurrentActor, Depends(require_capability("audit:read"))],
    session: Session = Depends(get_db),
    cursor: str | None = Query(default=None, description="Opaque pagination cursor"),
    limit: int = Query(default=50, ge=1, le=200),
    action: str | None = Query(default=None),
    actor_id: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    from_dt: datetime | None = Query(default=None, alias="from"),
    to_dt: datetime | None = Query(default=None, alias="to"),
) -> AuditEventsResponse:
    repo = SQLAlchemyAuditRepository(session)
    page = repo.list_scoped(
        workspace_id=actor.workspace_id,
        action=action,
        actor_id=actor_id,
        resource_type=resource_type,
        from_dt=from_dt,
        to_dt=to_dt,
        cursor=cursor,
        limit=limit,
    )

    items = [
        AuditEventItem(
            id=evt.id,
            occurred_at=evt.occurred_at,
            actor_id=evt.actor_id,
            actor_reference=evt.actor_reference,
            actor_persona=evt.actor_persona,
            workspace_id=evt.workspace_id,
            action=evt.action,
            resource_type=evt.resource_type,
            resource_id=evt.resource_id,
            change_detail=evt.change_detail or {},
            correlation_id=evt.correlation_id,
        )
        for evt in page.items
    ]

    return AuditEventsResponse(
        items=items,
        next_cursor=page.next_cursor,
        total_returned=len(items),
    )
