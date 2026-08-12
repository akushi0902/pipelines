"""AuditWriter — the single path through which audit_event rows are written.

Every audit write must go through this module.  Direct imports of
AuditRepository.append or the AuditEvent model in other modules are
prohibited (enforced by static test in tests/unit/test_audit_repository.py).

Usage::

    from pipelineshield.platform.audit_writer import AuditWriter

    writer = AuditWriter(session)
    writer.write(
        actor_id="00000000-...",
        actor_persona="devsecops_engineer",
        resource_type="catalogue",
        resource_id=str(version_id),
        action="catalogue.version_created",
        change_detail={"version": 2, "diff_count": 3},
        correlation_id=request_id,
    )

The writer runs the content guard before every append.  A
``AuditContentViolation`` propagates to the caller so the calling
operation fails rather than persisting Confidential material.
"""
from __future__ import annotations

import secrets
import uuid
from typing import Any

from sqlalchemy.orm import Session

from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.repositories.audit import SQLAlchemyAuditRepository
from pipelineshield.platform.content_guard import AuditContentViolation, guard_change_detail

import collections as _collections

__all__ = ["AuditWriter", "AuditWriteError", "AuditContentViolation", "AUDIT_EVENTS_WRITTEN_TOTAL"]

#: Per-action counter for audit events written (process-local; best-effort).
#: Increment is per-commit, not per-flush — the row is flushed but not yet durable.
AUDIT_EVENTS_WRITTEN_TOTAL: dict[str, int] = _collections.defaultdict(int)


class AuditWriteError(Exception):
    """Raised when AuditWriter cannot write a record due to invalid input.

    Callers must treat this as fatal and roll back the enclosing transaction
    rather than completing an unaudited mutation (fail-closed).
    """


class AuditWriter:
    """Validates and appends audit events to the append-only audit trail.

    This is the ONLY permitted writer to the audit_event table.
    """

    def __init__(self, session: Session) -> None:
        self._repo = SQLAlchemyAuditRepository(session)

    def write(
        self,
        *,
        actor_id: str,
        action: str,
        resource_type: str,
        change_detail: dict[str, Any] | None = None,
        actor_persona: str | None = None,
        actor_user_id: uuid.UUID | None = None,
        actor_reference: str | None = None,
        workspace_id: uuid.UUID | None = None,
        resource_id: str | None = None,
        correlation_id: str | None = None,
        source_ip_masked: str | None = None,
        user_agent_hash: str | None = None,
    ) -> AuditEvent:
        """Build, validate, and append one audit event row.

        Returns the persisted AuditEvent instance.
        Raises AuditWriteError if actor_id is missing or empty.
        Raises AuditContentViolation if change_detail contains secret-shaped content.
        """
        if not actor_id:
            raise AuditWriteError(
                "actor_id must be provided for every audit event; "
                "use actor_reference for pre-authentication events."
            )
        detail = change_detail or {}
        guarded_detail = guard_change_detail(detail)

        event = AuditEvent(
            actor_id=actor_id,
            actor_persona=actor_persona,
            actor_user_id=actor_user_id,
            actor_reference=actor_reference,
            workspace_id=workspace_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            change_detail=guarded_detail,
            correlation_id=correlation_id or secrets.token_hex(8),
            source_ip_masked=source_ip_masked,
            user_agent_hash=user_agent_hash,
        )
        persisted = self._repo.append(event)
        AUDIT_EVENTS_WRITTEN_TOTAL[action] += 1
        return persisted
