"""RoleBindingRepository — scoped CRUD for persona bindings.

Revocation is modelled as setting ``revoked_at``; rows are never deleted so
history remains reconstructable alongside the audit trail.  All query methods
are parameterized and return only bindings that belong to the specified
workspace.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pipelineshield.persistence.models.role_binding import RoleBinding


class RoleBindingRepository:
    """Row-level scoped persistence for RoleBinding entities."""

    def list_active_for_user(
        self,
        session: Session,
        *,
        user_id: uuid.UUID,
    ) -> Sequence[RoleBinding]:
        """Return all active (non-revoked) bindings for *user_id* across all workspaces."""
        stmt = select(RoleBinding).where(
            RoleBinding.app_user_id == user_id,
            RoleBinding.revoked_at.is_(None),
        )
        return session.execute(stmt).scalars().all()

    def list_for_workspace(
        self,
        session: Session,
        *,
        workspace_id: uuid.UUID,
        include_revoked: bool = False,
    ) -> Sequence[RoleBinding]:
        """Return bindings scoped to *workspace_id*.

        This method cannot return bindings outside *workspace_id*.
        """
        stmt = select(RoleBinding).where(
            RoleBinding.workspace_id == workspace_id,
        )
        if not include_revoked:
            stmt = stmt.where(RoleBinding.revoked_at.is_(None))
        stmt = stmt.order_by(RoleBinding.granted_at.desc())
        return session.execute(stmt).scalars().all()

    def get_active(
        self,
        session: Session,
        *,
        binding_id: uuid.UUID,
        workspace_id: uuid.UUID,
    ) -> RoleBinding | None:
        """Return the active binding by id scoped to *workspace_id*, or None."""
        stmt = select(RoleBinding).where(
            RoleBinding.id == binding_id,
            RoleBinding.workspace_id == workspace_id,
            RoleBinding.revoked_at.is_(None),
        )
        return session.execute(stmt).scalar_one_or_none()

    def find_active_binding(
        self,
        session: Session,
        *,
        app_user_id: uuid.UUID,
        workspace_id: uuid.UUID,
        persona: str,
    ) -> RoleBinding | None:
        """Return the active binding for the given (user, workspace, persona), or None."""
        stmt = select(RoleBinding).where(
            RoleBinding.app_user_id == app_user_id,
            RoleBinding.workspace_id == workspace_id,
            RoleBinding.persona == persona,
            RoleBinding.revoked_at.is_(None),
        )
        return session.execute(stmt).scalar_one_or_none()

    def grant(
        self,
        session: Session,
        *,
        workspace_id: uuid.UUID,
        app_user_id: uuid.UUID,
        persona: str,
        granted_by_id: uuid.UUID | None,
    ) -> RoleBinding:
        """Create and flush a new active binding row.

        Does NOT check for duplicates — callers must call
        ``find_active_binding`` first (the service layer owns that invariant).
        """
        binding = RoleBinding(
            id=uuid.uuid4(),
            workspace_id=workspace_id,
            app_user_id=app_user_id,
            persona=persona,
            granted_by_id=granted_by_id,
        )
        session.add(binding)
        session.flush()
        return binding

    def revoke(
        self,
        session: Session,
        *,
        binding_id: uuid.UUID,
        workspace_id: uuid.UUID,
    ) -> RoleBinding:
        """Set revoked_at on the binding identified by *binding_id* + *workspace_id*.

        Raises ValueError if no active binding is found (already revoked or
        wrong workspace — do not disclose which).
        """
        binding = self.get_active(
            session, binding_id=binding_id, workspace_id=workspace_id
        )
        if binding is None:
            raise ValueError(
                f"Active binding {binding_id!r} not found in workspace {workspace_id!r}."
            )
        binding.revoked_at = datetime.now(tz=timezone.utc)
        session.flush()
        return binding

    def count_active_admins(
        self,
        session: Session,
        *,
        workspace_id: uuid.UUID,
    ) -> int:
        """Return the number of active appsec_lead bindings in *workspace_id*."""
        stmt = select(func.count()).where(
            RoleBinding.workspace_id == workspace_id,
            RoleBinding.persona == "appsec_lead",
            RoleBinding.revoked_at.is_(None),
        )
        result = session.execute(stmt).scalar_one()
        return int(result)
