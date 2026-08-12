"""AuditEvent model — append-only audit log.

Data classification: Restricted
Retention: 1 year

IMMUTABILITY INVARIANT:
The pipelineshield_app database role holds INSERT and SELECT on this table
but NOT UPDATE or DELETE.  This is enforced at the database level by the
Alembic baseline migration so that no application code path can silently
bypass the audit trail.

change_detail MUST NEVER contain definition content or secret values.
This invariant is documented here and enforced by code review.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from pipelineshield.persistence.models.types import DialectJSON

from .base import Base


class AuditEvent(Base):
    """Append-only audit log entry.

    One record is written for every mutating operation in the system.
    The table is append-only at the database-role level: pipelineshield_app
    can INSERT and SELECT but cannot UPDATE or DELETE.  A BEFORE UPDATE OR
    DELETE trigger provides defence against future grant drift.

    change_detail MUST NEVER contain definition content or secret values.

    Deletion semantics: NOT permitted (append-only).
    """

    __tablename__ = "audit_event"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — audit event identifier.",
    )
    actor_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Identifier of the user or service account performing the action.",
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="FK to app_user.id — null for unauthenticated events.",
    )
    actor_reference: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Masked actor reference for unauthenticated events.",
    )
    actor_persona: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Persona label at the time of the action (null for system events).",
    )
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="Workspace context of the event.",
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
        comment="Wall-clock timestamp of the event (UTC).  Immutable once written.",
    )
    resource_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Type of resource affected (e.g. 'analysis', 'workspace', 'auth').",
    )
    resource_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="UUID or other identifier of the affected resource.",
    )
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Action label (e.g. 'create', 'delete', 'auth_login_success').",
    )
    change_detail: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        DialectJSON,
        nullable=False,
        default=dict,
        comment=(
            "Structured event detail (JSONB on PostgreSQL, JSON on SQLite).  "
            "INVARIANT: MUST NOT contain definition content or secret values."
        ),
    )
    correlation_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        comment="Optional request correlation ID for distributed tracing.",
    )
    source_ip_masked: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Source IP address, masked (last octet zeroed for IPv4).",
    )
    user_agent_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="SHA-256 hex digest of the User-Agent header.",
    )

    def __repr__(self) -> str:
        return (
            f"<AuditEvent id={self.id!r} "
            f"action={self.action!r} actor={self.actor_id!r}>"
        )
