"""CategoryGapRollup model — pre-aggregated weekly per-category missing counts.

Data classification: Internal
Retention: indefinite

Tracks how often each control category is flagged as missing, partial, or
not-assessable across completed analyses in a workspace bucket.  Sample
pipelines are excluded from these counts.

Row-level scoping:
  - Developer persona: filter WHERE owner_id = :actor
  - Workspace personas: filter WHERE workspace_id = :ws
"""
from __future__ import annotations

import uuid
from datetime import date, datetime

import sqlalchemy as sa
from sqlalchemy import Date, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class CategoryGapRollup(Base):
    """Pre-aggregated weekly category-gap counts per owner."""

    __tablename__ = "category_gap_rollup"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "owner_id",
            "bucket_date",
            "control_category_id",
            name="uq_cgr_workspace_owner_bucket_category",
        ),
        sa.Index("ix_cgr_workspace_bucket", "workspace_id", "bucket_date"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key.",
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="RESTRICT"),
        nullable=False,
        comment="Owning workspace.",
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_user.id", ondelete="RESTRICT"),
        nullable=False,
        comment="Owner of the analyses in this bucket.",
    )
    bucket_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
        comment="ISO week-start date (Monday) for this rollup bucket.",
    )
    control_category_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Control category identifier matching the catalogue.",
    )
    missing_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=sa.text("0"),
        comment="Analyses where this category was completely missing.",
    )
    partial_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=sa.text("0"),
        comment="Analyses where this category was partially covered.",
    )
    not_assessable_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=sa.text("0"),
        comment="Analyses where this category could not be assessed.",
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        comment="Last update timestamp.",
    )

    def __repr__(self) -> str:
        return (
            f"<CategoryGapRollup workspace={self.workspace_id!r} "
            f"bucket={self.bucket_date!r} category={self.control_category_id!r}>"
        )
