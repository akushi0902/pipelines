"""Workspace model — top-level tenant container.

Data classification: Internal
Retention: indefinite
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func, true
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class Workspace(Base):
    """Top-level tenant container.

    Every workspace represents an isolated organisational unit.  All
    tenant-scoped tables reference workspace_id as a foreign key so that
    row-level scoping can be expressed as a simple SQL predicate.

    Deletion semantics: hard delete only.  Because analyses and pipeline
    definitions are Confidential, they must be purged explicitly (with a
    purge_receipt) before the workspace can be removed.  Foreign keys on
    tenant-scoped tables are therefore RESTRICT, not CASCADE.
    """

    __tablename__ = "workspace"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — workspace identifier.",
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable workspace name.",
    )
    slug: Mapped[str] = mapped_column(
        String(63),
        nullable=False,
        unique=True,
        comment="URL-safe slug; unique across the platform.",
    )
    classification: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        server_default="internal",
        comment="Data classification label (e.g. internal, confidential).",
    )
    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=true(),
        comment="False when workspace is deactivated; bindings yield no access.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships — not loaded by default; used for typing only.
    app_users: Mapped[list["AppUser"]] = relationship(  # type: ignore[name-defined]
        back_populates="workspace",
        lazy="raise",
    )
    role_bindings: Mapped[list["RoleBinding"]] = relationship(  # type: ignore[name-defined]
        back_populates="workspace",
        lazy="raise",
    )
    analyses: Mapped[list["Analysis"]] = relationship(  # type: ignore[name-defined]
        back_populates="workspace",
        lazy="raise",
    )
    pipeline_definitions: Mapped[list["PipelineDefinition"]] = relationship(  # type: ignore[name-defined]
        back_populates="workspace",
        lazy="raise",
    )
    sample_pipelines: Mapped[list["SamplePipeline"]] = relationship(  # type: ignore[name-defined]
        back_populates="workspace",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return f"<Workspace id={self.id!r} slug={self.slug!r}>"
