"""GroupPersonaMapping model — IdP group claim → persona configuration.

Data classification: Internal
Retention: indefinite
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class GroupPersonaMapping(Base):
    """Configuration row mapping an IdP group claim to a persona within a workspace.

    When a user logs in, PersonaResolver queries this table using the user's
    IdP group claims.  If multiple rows match, the one with the lowest
    ``precedence`` value wins.  Ties are broken alphabetically by persona.

    Group-to-persona mapping is configuration data, not code, so pilot
    workspaces can be onboarded without a code deploy.
    """

    __tablename__ = "group_persona_mapping"
    __table_args__ = (
        UniqueConstraint(
            "idp_group",
            "workspace_id",
            name="uq_gpm_group_workspace",
        ),
        Index("ix_gpm_workspace_id", "workspace_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key.",
    )
    idp_group: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="IdP group claim string as returned by the identity provider.",
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="CASCADE"),
        nullable=False,
        comment="Workspace context for this mapping.",
    )
    persona: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Persona assigned to members of idp_group in this workspace.",
    )
    precedence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default="100",
        comment=(
            "Lower value wins when a user belongs to multiple mapped groups. "
            "Ties broken by persona name alphabetically."
        ),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    workspace: Mapped["Workspace"] = relationship(  # type: ignore[name-defined]
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<GroupPersonaMapping idp_group={self.idp_group!r} "
            f"workspace={self.workspace_id!r} persona={self.persona!r}>"
        )
