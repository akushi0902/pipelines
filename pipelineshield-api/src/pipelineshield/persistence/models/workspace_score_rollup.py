"""WorkspaceScoreRollup model — pre-aggregated per-owner per-week score buckets.

Data classification: Internal
Retention: indefinite

Each row summarises all completed non-sample analyses for one
(workspace, owner, bucket_week, catalogue_version) combination.
The rollup is written incrementally inside the same transaction that
persists a completed Analysis so dashboard queries never scan findings.

Row-level scoping:
  - Developer persona: filter WHERE owner_id = :actor
  - DevOps / DevSecOps / Manager personas: filter WHERE workspace_id = :ws
    (aggregate across all owner_ids)
"""
from __future__ import annotations

import uuid
from datetime import date, datetime

import sqlalchemy as sa
from sqlalchemy import Date, DateTime, ForeignKey, Integer, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class WorkspaceScoreRollup(Base):
    """Pre-aggregated weekly score rollup per workspace owner and catalogue version.

    Unique key: (workspace_id, owner_id, bucket_date, catalogue_version).
    All counts default to 0 so a fresh bucket row is valid before any upsert.
    """

    __tablename__ = "workspace_score_rollup"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id",
            "owner_id",
            "bucket_date",
            "catalogue_version",
            name="uq_wsr_workspace_owner_bucket_catalogue",
        ),
        sa.Index("ix_wsr_workspace_bucket", "workspace_id", "bucket_date"),
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
    catalogue_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Catalogue version integer used for the analyses in this bucket.",
    )
    analysis_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=sa.text("0"),
        comment="Number of non-sample analyses in this bucket.",
    )
    score_sum: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=sa.text("0"),
        comment="Sum of scores (use score_sum/analysis_count for mean trend).",
    )
    # Grade counts
    grade_a: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    grade_b: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    grade_c: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    grade_d: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    grade_f: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    # Severity finding counts
    sev_critical: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    sev_high: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    sev_medium: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    sev_low: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))
    sev_info: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sa.text("0"))

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        comment="Last update timestamp.",
    )

    def __repr__(self) -> str:
        return (
            f"<WorkspaceScoreRollup workspace={self.workspace_id!r} "
            f"bucket={self.bucket_date!r} count={self.analysis_count!r}>"
        )
