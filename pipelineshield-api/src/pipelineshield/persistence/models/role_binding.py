"""RoleBinding model — persona assignments within a workspace.

Data classification: Internal
Retention: indefinite (revocation sets revoked_at; rows are never deleted)
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

# Valid persona values — kept in sync with the authorisation layer.
VALID_PERSONAS = (
    "app_developer",
    "devops_engineer",
    "devsecops_engineer",
    "appsec_lead",
    "engineering_manager",
)


class RoleBinding(Base):
    """Maps an AppUser to a persona within a workspace.

    A user may hold at most one *active* binding per workspace per persona.
    Active is defined as revoked_at IS NULL.  The partial unique index
    ``uq_rb_active_user_workspace_persona`` enforces this on PostgreSQL;
    the service layer enforces it on SQLite test databases.

    Revocation semantics: set revoked_at — never delete rows — so history
    remains reconstructable from the audit trail.
    """

    __tablename__ = "role_binding"
    __table_args__ = (
        # Partial unique index: at most one active binding per (user, workspace, persona).
        # The postgresql_where is ignored on SQLite (duplicate guard is in the service).
        Index(
            "uq_rb_active_user_workspace_persona",
            "app_user_id",
            "workspace_id",
            "persona",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
        # Fast per-request lookup: active bindings for a given user.
        Index(
            "ix_role_binding_user_revoked_at",
            "app_user_id",
            "revoked_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — role binding identifier.",
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Workspace this binding belongs to.",
    )
    app_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_user.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="User being granted the persona.",
    )
    persona: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment=(
            "Persona label — one of: app_developer, devops_engineer, "
            "devsecops_engineer, appsec_lead, engineering_manager."
        ),
    )
    granted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_user.id", ondelete="SET NULL"),
        nullable=True,
        comment="Actor who granted this binding; nullable for legacy / seed rows.",
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Timestamp when the binding was created (UTC).",
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Revocation timestamp; NULL means the binding is currently active.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship(  # type: ignore[name-defined]
        back_populates="role_bindings",
        lazy="raise",
    )
    app_user: Mapped["AppUser"] = relationship(  # type: ignore[name-defined]
        foreign_keys=[app_user_id],
        back_populates="role_bindings",
        lazy="raise",
    )
    granted_by: Mapped["AppUser | None"] = relationship(  # type: ignore[name-defined]
        foreign_keys=[granted_by_id],
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<RoleBinding id={self.id!r} "
            f"user={self.app_user_id!r} persona={self.persona!r} "
            f"revoked={self.revoked_at is not None}>"
        )
