"""AnalysisCategoryScore model — per-category scoring breakdown.

Data classification: Internal
Retention: same as owning analysis (90 days)

One row per (analysis_id, category_id) pair, storing the earned / possible
weight and the count of NOT_ASSESSABLE controls excluded from scoring.
Rows are written once (INSERT) and never mutated; the analysis row is the
authoritative source of the catalogue_version used for scoring.
"""
from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import DateTime, ForeignKey, Numeric, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class AnalysisCategoryScore(Base):
    """Per-category score breakdown for one analysis run.

    Unique key: (analysis_id, category_id) — one row per category per analysis.
    """

    __tablename__ = "analysis_category_score"

    __table_args__ = (
        sa.UniqueConstraint(
            "analysis_id",
            "category_id",
            name="uq_analysis_category_score_analysis_id_category_id",
        ),
        sa.CheckConstraint(
            "excluded_count >= 0",
            name="excluded_count_non_negative",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key.",
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Owning analysis row.",
    )
    category_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Catalogue category identifier (e.g. 'secrets_hygiene').",
    )
    earned: Mapped[float] = mapped_column(
        Numeric(8, 4),
        nullable=False,
        comment="Weighted credit earned for this category (0 – category weight).",
    )
    possible: Mapped[float] = mapped_column(
        Numeric(8, 4),
        nullable=False,
        comment=(
            "Maximum possible credit for this category "
            "(excludes NOT_ASSESSABLE controls)."
        ),
    )
    excluded_count: Mapped[int] = mapped_column(
        sa.Integer,
        nullable=False,
        server_default=sa.text("0"),
        comment="Number of NOT_ASSESSABLE controls excluded from denominator.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationship
    analysis: Mapped["Analysis"] = relationship(  # type: ignore[name-defined]
        back_populates="category_scores",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<AnalysisCategoryScore analysis_id={self.analysis_id!r} "
            f"category={self.category_id!r} "
            f"earned={self.earned!r} possible={self.possible!r}>"
        )
