"""RetentionPolicy model — single-row workspace retention configuration.

Data classification: Internal
Retention: indefinite (governance record)
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer, SmallInteger, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class RetentionPolicy(Base):
    """Single-row retention policy table.

    Stores the current retention period for Confidential pipeline definitions.
    A single row with id=1 is enforced by the ck_retention_policy_single_row
    constraint.  Updates must be written through AuditWriter so the change
    appears in the append-only audit log.

    Deletion semantics: NOT permitted — this is a governance configuration
    record.  UPDATE is the only permitted write after initial INSERT.
    """

    __tablename__ = "retention_policy"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_retention_policy_single_row"),
        CheckConstraint(
            "retention_days >= 1 AND retention_days <= 90",
            name="ck_retention_policy_days",
        ),
    )

    id: Mapped[int] = mapped_column(
        SmallInteger(),
        primary_key=True,
        comment="Single-row PK — always 1.",
    )
    retention_days: Mapped[int] = mapped_column(
        Integer(),
        nullable=False,
        default=90,
        comment="Number of days Confidential pipeline definitions are retained.",
    )
    updated_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        comment="FK to app_user.id — last actor to modify retention policy.",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Timestamp of the last policy update (UTC).",
    )

    def __repr__(self) -> str:
        return (
            f"<RetentionPolicy retention_days={self.retention_days!r} "
            f"updated_by={self.updated_by!r}>"
        )
