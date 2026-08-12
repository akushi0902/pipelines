"""Finding model — security finding from deterministic rule engine or AI pass.

Data classification: Confidential
Retention: 90 days

KEY CONSTRAINTS:

- source must be 'deterministic' or 'ai'.
- When source = 'ai', weight MUST be 0.
- requires_human_review is always True for AI-sourced findings.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class Finding(Base):
    """Security finding from a pipeline analysis.

    Two sources are valid:

    - 'deterministic': emitted by the rule engine; scored and authoritative.
    - 'ai': advisory candidate from the model pass; never scored (weight = 0)
      and always requires human review.

    Database constraints enforce the source and AI zero-weight invariants.

    Deletion semantics: hard delete only (Confidential). No deleted_at or
    is_deleted columns are permitted on this table.
    """

    __tablename__ = "finding"

    __table_args__ = (
        CheckConstraint(
            "source IN ('deterministic', 'ai')",
            name="finding_source_valid",
        ),
        CheckConstraint(
            "NOT (source = 'ai' AND weight != 0)",
            name="ai_source_zero_weight",
        ),
        CheckConstraint(
            "weight >= 0",
            name="finding_weight_non_negative",
        ),
        CheckConstraint(
            "anchor_line IS NULL OR anchor_line >= 1",
            name="anchor_line_positive",
        ),
        CheckConstraint(
            "anchor_column IS NULL OR anchor_column >= 1",
            name="anchor_column_positive",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — finding identifier.",
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
        comment="Parent analysis this finding belongs to.",
    )

    source: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment=(
            "Origin of this finding: 'deterministic' (rule engine, "
            "authoritative) or 'ai' (model pass, advisory only)."
        ),
    )

    requires_human_review: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        comment=(
            "True when a human must review this finding before acting on "
            "it. Always True for AI-sourced findings."
        ),
    )

    control_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment=(
            "Catalogue control identifier that produced this finding. "
            "NULL for findings created before migration 0015."
        ),
    )

    control_category: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment=(
            "One of the nine control categories "
            "(e.g. secrets, signing)."
        ),
    )

    rule_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Stable rule identifier for deduplication and tracking.",
    )

    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="Severity level: critical, high, medium, low, info.",
    )

    weight: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment=(
            "Score contribution of this finding. MUST be 0 when "
            "source = 'ai' (enforced by CHECK constraint "
            "ai_source_zero_weight)."
        ),
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Short, human-readable finding title.",
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
        server_default="",
        comment="Full finding description. Never contains secret values.",
    )

    anchor_line: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="1-indexed source line where the issue was detected.",
    )

    anchor_column: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="1-indexed source column where the issue was detected.",
    )

    evidence: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
        comment="Structured evidence supporting the finding. No secret values.",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships
    analysis: Mapped["Analysis"] = relationship(  # type: ignore[name-defined]
        back_populates="findings",
        lazy="raise",
    )

    remediations: Mapped[list["Remediation"]] = relationship(  # type: ignore[name-defined]
        back_populates="finding",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<Finding id={self.id!r} "
            f"source={self.source!r} "
            f"severity={self.severity!r} "
            f"rule_id={self.rule_id!r}>"
        )
