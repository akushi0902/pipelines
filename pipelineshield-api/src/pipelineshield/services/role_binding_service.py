"""RoleBindingService — invariant-owning service for role binding administration.

This service owns three invariants:
1. Duplicate grant: one active binding per (user, workspace, persona).
2. Self-escalation: an actor cannot grant a persona above their own capability.
3. Last-administrator protection: cannot revoke or demote the final admin binding
   in a workspace, leaving it unmanageable.

The AuditWriter is invoked exactly once per privilege change inside the service.
An AuditWriteError propagates to the caller, rolling back the entire transaction
so no unaudited privilege change can occur (fail-closed).
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from pipelineshield.api.security.authz_guard import CurrentActor, PERSONA_CAPABILITIES
from pipelineshield.persistence.models.role_binding import RoleBinding, VALID_PERSONAS
from pipelineshield.persistence.repositories.role_binding_repository import (
    RoleBindingRepository,
)
from pipelineshield.platform.audit_writer import AuditWriter


class DuplicateBindingError(Exception):
    """Raised when an active binding already exists for (user, workspace, persona)."""


class SelfEscalationError(Exception):
    """Raised when the actor attempts to grant a persona they cannot hold."""


class LastAdminError(Exception):
    """Raised when an operation would remove the last admin in a workspace."""


class InvalidPersonaError(Exception):
    """Raised when the requested persona is not a recognised value."""


class RoleBindingService:
    """Orchestrates grant, change, and revoke operations with full invariant checks."""

    def __init__(self) -> None:
        self._repo = RoleBindingRepository()

    def grant_binding(
        self,
        session: Session,
        *,
        actor: CurrentActor,
        workspace_id: uuid.UUID,
        app_user_id: uuid.UUID,
        persona: str,
        audit_writer: AuditWriter,
    ) -> RoleBinding:
        """Grant *persona* to *app_user_id* in *workspace_id*.

        Raises:
        - InvalidPersonaError: *persona* is not a recognised value.
        - SelfEscalationError: actor cannot grant a persona above their own.
        - DuplicateBindingError: an active binding already exists.
        """
        self._validate_persona(persona)
        self._check_self_escalation(actor, persona)

        existing = self._repo.find_active_binding(
            session,
            app_user_id=app_user_id,
            workspace_id=workspace_id,
            persona=persona,
        )
        if existing is not None:
            raise DuplicateBindingError(
                f"User {app_user_id!r} already holds an active {persona!r} binding "
                f"in workspace {workspace_id!r}."
            )

        binding = self._repo.grant(
            session,
            workspace_id=workspace_id,
            app_user_id=app_user_id,
            persona=persona,
            granted_by_id=actor.user_id,
        )

        audit_writer.write(
            actor_id=str(actor.user_id),
            actor_persona=actor.persona,
            actor_user_id=actor.user_id,
            workspace_id=workspace_id,
            resource_type="role_binding",
            resource_id=str(binding.id),
            action="role_binding.granted",
            change_detail={
                "target_user_id": str(app_user_id),
                "previous_persona": None,
                "new_persona": persona,
                "workspace_id": str(workspace_id),
            },
        )
        return binding

    def change_binding(
        self,
        session: Session,
        *,
        actor: CurrentActor,
        binding_id: uuid.UUID,
        workspace_id: uuid.UUID,
        new_persona: str,
        audit_writer: AuditWriter,
    ) -> RoleBinding:
        """Change the persona of an active binding.

        Implemented as revoke + grant in the same transaction to preserve
        history.  The last-admin check uses the count *before* revocation.

        Raises:
        - InvalidPersonaError, SelfEscalationError, DuplicateBindingError,
          LastAdminError.
        """
        self._validate_persona(new_persona)
        self._check_self_escalation(actor, new_persona)

        old_binding = self._repo.get_active(
            session, binding_id=binding_id, workspace_id=workspace_id
        )
        if old_binding is None:
            raise ValueError(
                f"Active binding {binding_id!r} not found in workspace {workspace_id!r}."
            )

        old_persona = old_binding.persona
        target_user_id = old_binding.app_user_id

        # Last-admin guard: would this demote the last admin?
        if old_persona == "appsec_lead" and new_persona != "appsec_lead":
            count = self._repo.count_active_admins(session, workspace_id=workspace_id)
            if count <= 1:
                raise LastAdminError(
                    "Cannot demote the last appsec_lead in workspace "
                    f"{workspace_id!r}. Grant a replacement admin first."
                )

        # Duplicate guard for the new persona.
        existing = self._repo.find_active_binding(
            session,
            app_user_id=target_user_id,
            workspace_id=workspace_id,
            persona=new_persona,
        )
        if existing is not None and existing.id != binding_id:
            raise DuplicateBindingError(
                f"User {target_user_id!r} already holds an active {new_persona!r} "
                f"binding in workspace {workspace_id!r}."
            )

        # Revoke old binding then grant new one.
        revoked = self._repo.revoke(
            session, binding_id=binding_id, workspace_id=workspace_id
        )
        new_binding = self._repo.grant(
            session,
            workspace_id=workspace_id,
            app_user_id=target_user_id,
            persona=new_persona,
            granted_by_id=actor.user_id,
        )

        audit_writer.write(
            actor_id=str(actor.user_id),
            actor_persona=actor.persona,
            actor_user_id=actor.user_id,
            workspace_id=workspace_id,
            resource_type="role_binding",
            resource_id=str(new_binding.id),
            action="role_binding.changed",
            change_detail={
                "target_user_id": str(target_user_id),
                "previous_persona": old_persona,
                "new_persona": new_persona,
                "previous_binding_id": str(revoked.id),
                "workspace_id": str(workspace_id),
            },
        )
        return new_binding

    def revoke_binding(
        self,
        session: Session,
        *,
        actor: CurrentActor,
        binding_id: uuid.UUID,
        workspace_id: uuid.UUID,
        audit_writer: AuditWriter,
    ) -> None:
        """Revoke an active binding by setting revoked_at.

        Raises LastAdminError if this would remove the last admin.
        """
        binding = self._repo.get_active(
            session, binding_id=binding_id, workspace_id=workspace_id
        )
        if binding is None:
            raise ValueError(
                f"Active binding {binding_id!r} not found in workspace {workspace_id!r}."
            )

        if binding.persona == "appsec_lead":
            count = self._repo.count_active_admins(session, workspace_id=workspace_id)
            if count <= 1:
                raise LastAdminError(
                    "Cannot revoke the last appsec_lead binding in workspace "
                    f"{workspace_id!r}. Grant a replacement admin first."
                )

        target_user_id = binding.app_user_id
        old_persona = binding.persona

        self._repo.revoke(
            session, binding_id=binding_id, workspace_id=workspace_id
        )

        audit_writer.write(
            actor_id=str(actor.user_id),
            actor_persona=actor.persona,
            actor_user_id=actor.user_id,
            workspace_id=workspace_id,
            resource_type="role_binding",
            resource_id=str(binding_id),
            action="role_binding.revoked",
            change_detail={
                "target_user_id": str(target_user_id),
                "previous_persona": old_persona,
                "new_persona": None,
                "workspace_id": str(workspace_id),
            },
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_persona(persona: str) -> None:
        if persona not in VALID_PERSONAS:
            raise InvalidPersonaError(
                f"{persona!r} is not a recognised persona. "
                f"Valid values: {VALID_PERSONAS!r}."
            )

    @staticmethod
    def _check_self_escalation(actor: CurrentActor, requested_persona: str) -> None:
        """Block granting a persona whose capability set is strictly above the actor's.

        An actor with ``admin:role:write`` (appsec_lead) can grant any persona
        in the system.  Other personas cannot grant any persona because they
        lack ``admin:role:write`` — the authz guard prevents them from reaching
        this method, but we defend-in-depth here.

        The check compares the requested persona's capability set against the
        actor's capability set.  If the requested set is not a subset of the
        actor's set, escalation is blocked.
        """
        actor_caps = PERSONA_CAPABILITIES.get(actor.persona, frozenset())
        requested_caps = PERSONA_CAPABILITIES.get(requested_persona, frozenset())
        # If the requested persona has capabilities the actor does not, block it.
        if not requested_caps.issubset(actor_caps):
            raise SelfEscalationError(
                f"Actor with persona {actor.persona!r} cannot grant "
                f"{requested_persona!r}: that persona has capabilities "
                f"beyond the actor's own set."
            )
