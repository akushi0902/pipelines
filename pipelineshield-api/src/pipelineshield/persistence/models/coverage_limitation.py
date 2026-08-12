"""CoverageLimitation model — unresolved fragments limiting assessment coverage.

Data classification: Confidential
Retention: 90 days (matches analysis lifecycle)

Each row describes one fragment (unresolved include, scripted Groovy block,
etc.) that caused one or more controls to be evaluated as NOT_ASSESSABLE.

Rows are written during analysis ingestion alongside the analysis row and
are read-only thereafter.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .types import DialectJSON


class CoverageLimitation(Base):
    """One unresolved fragment that caused controls to be NOT_ASSESSABLE.

    Deletion semantics: hard delete only (Confidential).
    """

    __tablename__ = "coverage_limitation"

    __table_args__ = (
        sa.CheckConstraint(
            "json_array_length(affected_control_ids) >= 0",
            name="affected_control_ids_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key.",
    )

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        ForeignKey("analysis.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Owning analysis row.",
    )

    kind: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment=(
            "Fragment kind: scripted_groovy, unresolved_include, "
            "unresolved_extends, unresolved_reference, "
            "unresolved_composite_action, unresolved_reusable_workflow."
        ),
    )

    location: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        comment="File path, line reference, or block identifier.",
    )

    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment=(
            "Human-readable explanation of why this fragment was unresolved."
        ),
    )

    affected_control_ids: Mapped[list] = mapped_column(  # type: ignore[type-arg]
        DialectJSON(),
        nullable=False,
        default=list,
        comment=(
            "Catalogue control IDs rendered NOT_ASSESSABLE "
            "by this limitation."
        ),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships
    analysis: Mapped["Analysis"] = relationship(  # type: ignore[name-defined]
        back_populates="coverage_limitations",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<CoverageLimitation id={self.id!r} "
            f"kind={self.kind!r} "
            f"analysis_id={self.analysis_id!r}>"
        )
