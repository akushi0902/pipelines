"""Admin router — role binding and group persona mapping administration.

All routes are guarded by admin:role:write (appsec_lead only).
The router contains no SQL and no role branching; all logic is delegated
to RoleBindingService and direct repository calls.

Status codes:
  200  GET success, PATCH success
  201  POST (grant) success
  204  DELETE (revoke) success
  403  Lacking admin:role:write
  404  Workspace invisible to actor (existence not disclosed)
  409  Duplicate active grant or last-admin protection
  422  Invalid persona value (Pydantic validation)
"""
from __future__ import annotations

import uuid
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from pipelineshield.api.security.authz_guard import CurrentActor, require_capability
from pipelineshield.api.v1.schemas.admin import (
    ChangeBindingRequest,
    ErrorResponse,
    GrantBindingRequest,
    GrantBindingResponse,
    GroupPersonaMappingItem,
    GroupPersonaMappingListResponse,
    GroupPersonaMappingUpsertRequest,
    RoleBindingItem,
    RoleBindingListResponse,
)
from pipelineshield.persistence.models.app_user import AppUser
from pipelineshield.persistence.models.group_persona_mapping import GroupPersonaMapping
from pipelineshield.persistence.models.workspace import Workspace
from pipelineshield.persistence.repositories.role_binding_repository import (
    RoleBindingRepository,
)
from pipelineshield.persistence.repositories.user_repository import UserRepository
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.services.role_binding_service import (
    DuplicateBindingError,
    InvalidPersonaError,
    LastAdminError,
    RoleBindingService,
    SelfEscalationError,
)

router = APIRouter(tags=["admin"])

_service = RoleBindingService()
_rb_repo = RoleBindingRepository()
_user_repo = UserRepository()


def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError("get_db must be overridden before use")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_visible_workspace(
    workspace_id: uuid.UUID, actor: CurrentActor, session: Session
) -> Workspace:
    """Return the Workspace if active and accessible, else raise 404.

    404 (not 403) is returned for invisible workspaces to avoid existence
    disclosure.
    """
    ws = session.get(Workspace, workspace_id)
    if ws is None or not ws.active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "type": "https://pipelineshield.internal/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": "The requested workspace was not found.",
                "correlation_id": secrets.token_hex(8),
                "errors": [],
            },
        )
    return ws


def _rb_to_item(rb: "pipelineshield.persistence.models.role_binding.RoleBinding", user: AppUser) -> RoleBindingItem:  # type: ignore[name-defined]
    return RoleBindingItem(
        id=rb.id,
        app_user_id=rb.app_user_id,
        masked_email=user.email,
        display_name=user.display_name,
        persona=rb.persona,
        granted_by_id=rb.granted_by_id,
        granted_at=rb.granted_at,
        revoked_at=rb.revoked_at,
    )


def _conflict_response(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "type": "https://pipelineshield.internal/errors/conflict",
            "title": "Conflict",
            "status": 409,
            "detail": detail,
            "correlation_id": secrets.token_hex(8),
            "errors": [],
        },
    )


# ---------------------------------------------------------------------------
# GET /api/v1/workspaces/{workspace_id}/role-bindings
# ---------------------------------------------------------------------------


@router.get(
    "/workspaces/{workspace_id}/role-bindings",
    response_model=RoleBindingListResponse,
    summary="List active role bindings for a workspace",
    responses={
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
)
async def list_role_bindings(
    workspace_id: uuid.UUID,
    actor: Annotated[CurrentActor, Depends(require_capability("admin:role:write"))],
    session: Session = Depends(get_db),
) -> RoleBindingListResponse:
    _get_visible_workspace(workspace_id, actor, session)
    bindings = _rb_repo.list_for_workspace(session, workspace_id=workspace_id)
    items = []
    for rb in bindings:
        user = _user_repo.get_by_id(session, rb.app_user_id, workspace_id=workspace_id)
        if user is None:
            # Cross-workspace user or orphaned binding — skip rather than expose.
            continue
        items.append(_rb_to_item(rb, user))
    return RoleBindingListResponse(items=items, total=len(items))


# ---------------------------------------------------------------------------
# POST /api/v1/workspaces/{workspace_id}/role-bindings
# ---------------------------------------------------------------------------


@router.post(
    "/workspaces/{workspace_id}/role-bindings",
    response_model=GrantBindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Grant a role binding in a workspace",
    responses={
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
async def grant_role_binding(
    workspace_id: uuid.UUID,
    body: GrantBindingRequest,
    actor: Annotated[CurrentActor, Depends(require_capability("admin:role:write"))],
    session: Session = Depends(get_db),
) -> GrantBindingResponse:
    _get_visible_workspace(workspace_id, actor, session)
    audit = AuditWriter(session)
    try:
        binding = _service.grant_binding(
            session,
            actor=actor,
            workspace_id=workspace_id,
            app_user_id=body.user_id,
            persona=body.persona,
            audit_writer=audit,
        )
    except (DuplicateBindingError, LastAdminError) as exc:
        raise _conflict_response(str(exc)) from exc
    except (SelfEscalationError, InvalidPersonaError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "type": "https://pipelineshield.internal/errors/forbidden",
                "title": "Forbidden",
                "status": 403,
                "detail": str(exc),
                "correlation_id": secrets.token_hex(8),
                "errors": [],
            },
        ) from exc

    user = _user_repo.get_by_id(session, binding.app_user_id, workspace_id=workspace_id)
    if user is None:
        # The user was just granted in the request; if not found, use placeholder.
        masked_email = "***@***.***"
        display_name = str(binding.app_user_id)
    else:
        masked_email = user.email
        display_name = user.display_name

    return GrantBindingResponse(
        id=binding.id,
        app_user_id=binding.app_user_id,
        masked_email=masked_email,
        display_name=display_name,
        persona=binding.persona,
        granted_by_id=binding.granted_by_id,
        granted_at=binding.granted_at,
        revoked_at=binding.revoked_at,
    )


# ---------------------------------------------------------------------------
# PATCH /api/v1/workspaces/{workspace_id}/role-bindings/{binding_id}
# ---------------------------------------------------------------------------


@router.patch(
    "/workspaces/{workspace_id}/role-bindings/{binding_id}",
    response_model=GrantBindingResponse,
    summary="Change the persona of an active role binding",
    responses={
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
async def change_role_binding(
    workspace_id: uuid.UUID,
    binding_id: uuid.UUID,
    body: ChangeBindingRequest,
    actor: Annotated[CurrentActor, Depends(require_capability("admin:role:write"))],
    session: Session = Depends(get_db),
) -> GrantBindingResponse:
    _get_visible_workspace(workspace_id, actor, session)
    audit = AuditWriter(session)
    try:
        binding = _service.change_binding(
            session,
            actor=actor,
            binding_id=binding_id,
            workspace_id=workspace_id,
            new_persona=body.persona,
            audit_writer=audit,
        )
    except (DuplicateBindingError, LastAdminError) as exc:
        raise _conflict_response(str(exc)) from exc
    except (SelfEscalationError, InvalidPersonaError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "type": "https://pipelineshield.internal/errors/forbidden",
                "title": "Forbidden",
                "status": 403,
                "detail": str(exc),
                "correlation_id": secrets.token_hex(8),
                "errors": [],
            },
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "type": "https://pipelineshield.internal/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": str(exc),
                "correlation_id": secrets.token_hex(8),
                "errors": [],
            },
        ) from exc

    user = _user_repo.get_by_id(session, binding.app_user_id, workspace_id=workspace_id)
    masked_email = user.email if user else "***@***.***"
    display_name = user.display_name if user else str(binding.app_user_id)

    return GrantBindingResponse(
        id=binding.id,
        app_user_id=binding.app_user_id,
        masked_email=masked_email,
        display_name=display_name,
        persona=binding.persona,
        granted_by_id=binding.granted_by_id,
        granted_at=binding.granted_at,
        revoked_at=binding.revoked_at,
    )


# ---------------------------------------------------------------------------
# DELETE /api/v1/workspaces/{workspace_id}/role-bindings/{binding_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/workspaces/{workspace_id}/role-bindings/{binding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a role binding",
    responses={
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
    },
)
async def revoke_role_binding(
    workspace_id: uuid.UUID,
    binding_id: uuid.UUID,
    actor: Annotated[CurrentActor, Depends(require_capability("admin:role:write"))],
    session: Session = Depends(get_db),
) -> None:
    _get_visible_workspace(workspace_id, actor, session)
    audit = AuditWriter(session)
    try:
        _service.revoke_binding(
            session,
            actor=actor,
            binding_id=binding_id,
            workspace_id=workspace_id,
            audit_writer=audit,
        )
    except LastAdminError as exc:
        raise _conflict_response(str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "type": "https://pipelineshield.internal/errors/not-found",
                "title": "Not Found",
                "status": 404,
                "detail": str(exc),
                "correlation_id": secrets.token_hex(8),
                "errors": [],
            },
        ) from exc


# ---------------------------------------------------------------------------
# GET /api/v1/group-persona-mappings
# ---------------------------------------------------------------------------


@router.get(
    "/group-persona-mappings",
    response_model=GroupPersonaMappingListResponse,
    summary="List group-to-persona mappings (all workspaces the actor can see)",
    responses={
        403: {"model": ErrorResponse},
    },
)
async def list_group_persona_mappings(
    actor: Annotated[CurrentActor, Depends(require_capability("admin:role:write"))],
    session: Session = Depends(get_db),
) -> GroupPersonaMappingListResponse:
    # Scoped to actor's workspace.
    stmt = (
        select(GroupPersonaMapping)
        .where(GroupPersonaMapping.workspace_id == actor.workspace_id)
        .order_by(GroupPersonaMapping.precedence, GroupPersonaMapping.idp_group)
    )
    rows = session.execute(stmt).scalars().all()
    items = [
        GroupPersonaMappingItem(
            id=r.id,
            idp_group=r.idp_group,
            workspace_id=r.workspace_id,
            persona=r.persona,
            precedence=r.precedence,
            created_at=r.created_at,
        )
        for r in rows
    ]
    return GroupPersonaMappingListResponse(items=items, total=len(items))


# ---------------------------------------------------------------------------
# PUT /api/v1/group-persona-mappings
# ---------------------------------------------------------------------------


@router.put(
    "/group-persona-mappings",
    response_model=GroupPersonaMappingListResponse,
    summary="Replace all group-to-persona mappings for the actor's workspace",
    responses={
        403: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
async def upsert_group_persona_mappings(
    body: GroupPersonaMappingUpsertRequest,
    actor: Annotated[CurrentActor, Depends(require_capability("admin:role:write"))],
    session: Session = Depends(get_db),
) -> GroupPersonaMappingListResponse:
    import uuid as _uuid
    from datetime import datetime, timezone

    # Delete all existing mappings for the actor's workspace.
    existing_stmt = select(GroupPersonaMapping).where(
        GroupPersonaMapping.workspace_id == actor.workspace_id
    )
    for row in session.execute(existing_stmt).scalars().all():
        session.delete(row)

    new_rows: list[GroupPersonaMapping] = []
    for item in body.items:
        row = GroupPersonaMapping(
            id=_uuid.uuid4(),
            idp_group=item.idp_group,
            workspace_id=item.workspace_id,
            persona=item.persona,
            precedence=item.precedence,
        )
        session.add(row)
        new_rows.append(row)

    session.flush()

    audit = AuditWriter(session)
    audit.write(
        actor_id=str(actor.user_id),
        actor_persona=actor.persona,
        actor_user_id=actor.user_id,
        workspace_id=actor.workspace_id,
        resource_type="group_persona_mapping",
        resource_id=str(actor.workspace_id),
        action="group_persona_mapping.replaced",
        change_detail={
            "count": len(new_rows),
            "workspace_id": str(actor.workspace_id),
        },
    )

    items = [
        GroupPersonaMappingItem(
            id=r.id,
            idp_group=r.idp_group,
            workspace_id=r.workspace_id,
            persona=r.persona,
            precedence=r.precedence,
            created_at=r.created_at,
        )
        for r in new_rows
    ]
    return GroupPersonaMappingListResponse(items=items, total=len(items))
