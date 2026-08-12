"""PurgeReceipt model — record of a completed data purge batch.

Data classification: Internal
Retention: indefinite
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
import uuid as _uuid_module

from .base import Base


class PurgeReceipt(Base):
    """Record of a completed hard-delete purge batch.

    Written by the purge worker at the conclusion of each purge run.
    Provides a reconciliation record that can be audited to confirm
    Confidential data was removed at the required retention boundary.

    Deletion semantics: hard delete is NOT performed on purge receipts
    themselves — they are retained indefinitely as evidence records.
    """

    __tablename__ = "purge_receipt"
    __table_args__ = (
        CheckConstraint(
            "status IN ('succeeded', 'failed', 'partial')",
            name="ck_purge_receipt_status",
        ),
        CheckConstraint(
            "trigger IN ('scheduled', 'on_demand')",
            name="ck_purge_receipt_trigger",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — purge receipt identifier.",
    )
    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        comment=(
            "Unique batch identifier for this purge run.  "
            "Stable across retries of the same purge job."
        ),
    )
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Timestamp when the purge batch completed (UTC).",
    )
    deleted_counts: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        comment=(
            "JSONB map of table name → row count deleted "
            "(e.g. {\"analysis\": 42, \"finding\": 310})."
        ),
    )
    verification_digest: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment=(
            "Cryptographic digest of the batch manifest used to verify "
            "the purge was complete (e.g. SHA-256 hex)."
        ),
    )
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        server_default="succeeded",
        comment=(
            "Purge batch outcome: 'succeeded', 'failed', or 'partial'. "
            "Checked at the database level via ck_purge_receipt_status."
        ),
    )
    error_detail: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment=(
            "Non-sensitive error description when status != succeeded. "
            "Must not contain row content or secret values."
        ),
    )
    trigger: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default="scheduled",
        comment=(
            "Source of the purge: 'scheduled' (RetentionWorker) or "
            "'on_demand' (SubjectRightsService governance endpoint)."
        ),
    )
    subject_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment=(
            "Data subject whose Confidential material was erased. "
            "NULL for scheduled purge batches."
        ),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    def __repr__(self) -> str:
        return (
            f"<PurgeReceipt id={self.id!r} "
            f"batch_id={self.batch_id!r} executed_at={self.executed_at!r}>"
        )
