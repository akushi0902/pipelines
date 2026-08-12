"""ControlCatalogueVersion model — versioned security control catalogue.

Data classification: Internal
Retention: indefinite

Each row is an immutable snapshot: no application code path may issue
UPDATE or DELETE against this table.  New catalogue versions are created
by INSERT; the prior active version is marked superseded by the transition
guard added in WO-10.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .types import DialectJSON


class ControlCatalogueVersion(Base):
    """Versioned, checksummed snapshot of the security control catalogue.

    Every analysis records the catalogue_version it was scored against.
    Versioning ensures that historical results remain valid as the
    catalogue evolves.

    Deletion semantics: hard delete only (Internal classification).
    """

    __tablename__ = "control_catalogue_version"

    __table_args__ = (
        sa.CheckConstraint(
            "status IN ('active', 'superseded')",
            name="status_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — catalogue version identifier.",
    )
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        unique=True,
        comment="Monotonically increasing version counter.  Globally unique.",
    )
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        server_default=sa.text("'active'"),
        comment="Lifecycle status: active or superseded.",
    )
    snapshot: Mapped[Any] = mapped_column(
        DialectJSON(),
        nullable=False,
        comment="Full catalogue snapshot (JSONB on PostgreSQL, JSON on SQLite).",
    )
    grade_bands: Mapped[Any] = mapped_column(
        DialectJSON(),
        nullable=False,
        comment="Grade-band configuration snapshot (JSONB on PostgreSQL, JSON on SQLite).",
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_user.id", ondelete="RESTRICT"),
        nullable=False,
        comment="Actor who created this version; never null.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )
    change_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable description of what changed in this version.",
    )
    content_checksum: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA-256 hex digest of the canonical JSON serialisation of snapshot.",
    )

    # Relationships
    analyses: Mapped[list["Analysis"]] = relationship(  # type: ignore[name-defined]
        back_populates="catalogue_version",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<ControlCatalogueVersion id={self.id!r} "
            f"version={self.version!r} status={self.status!r}>"
        )
