"""GeneratedDraft model — AI-generated hardened pipeline configuration draft.

Data classification: Confidential
Retention: 90 days
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class GeneratedDraft(Base):
    """AI-generated hardened pipeline configuration draft.

    Contains the model-proposed secure configuration for the analysed
    pipeline.  Always requires human review before any operational use.
    The content is stored encrypted (same KeyProvider pattern as
    pipeline_definition).

    Deletion semantics: hard delete only (Confidential).  No deleted_at or
    is_deleted columns are permitted on this table.
    """

    __tablename__ = "generated_draft"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — generated draft identifier.",
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Owning workspace — tenant scope.",
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Parent analysis that produced this draft.",
    )
    draft_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment=(
            "Type of draft: secure_pipeline_architecture or "
            "hardened_configuration."
        ),
    )
    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment=(
            "Draft content.  Always advisory — never applied automatically.  "
            "Classification: Confidential."
        ),
    )
    model_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Identifier of the model that produced this draft.",
    )
    requires_human_review: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Always True — AI-generated drafts require human review.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships
    analysis: Mapped["Analysis"] = relationship(  # type: ignore[name-defined]
        back_populates="generated_drafts",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<GeneratedDraft id={self.id!r} "
            f"type={self.draft_type!r} analysis={self.analysis_id!r}>"
        )
