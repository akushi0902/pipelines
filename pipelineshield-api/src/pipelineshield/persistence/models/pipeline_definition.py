"""PipelineDefinition model — encrypted pipeline definition content.

Data classification: Confidential
Retention: 90 days

IMPORTANT: masked_content is stored as application-level envelope-encrypted
ciphertext.  The column contains the output of KeyProvider.encrypt(); the
key source is never stored alongside the ciphertext and is injected at
runtime via the KeyProvider interface.
"""
from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class PipelineDefinition(Base):
    """Encrypted pipeline definition content.

    The raw definition is masked (secrets redacted) before storage and then
    envelope-encrypted at the application layer.  No plaintext definition
    column and no object-storage reference exists; the entire content is in
    the encrypted masked_content column.

    Column notes:
    - masked_content: application-level encrypted ciphertext (base-64 encoded
      envelope).  Maximum 512 KB source → ≈ 700 KB ciphertext.
    - key_id: identifies the encryption key version so the application knows
      which KeyProvider key to use for decryption without storing the key value.

    Deletion semantics: hard delete only (Confidential).  No deleted_at or
    is_deleted columns are permitted on this table.
    """

    __tablename__ = "pipeline_definition"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — pipeline definition identifier.",
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
        unique=True,
        comment="One-to-one link to the parent analysis.",
    )
    masked_content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment=(
            "Application-level envelope-encrypted ciphertext of the masked "
            "pipeline definition.  Contains no plaintext secrets or "
            "definition text.  Classification: Confidential."
        ),
    )
    key_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment=(
            "Identifier of the encryption key version used to produce "
            "masked_content.  Never stores the key value itself."
        ),
    )
    original_filename: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Original filename supplied by the user (optional).",
    )
    line_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Number of lines in the original masked definition.",
    )
    is_sample: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=sa.text("false"),
        comment=(
            "True for bundled demo/sample pipelines that must be excluded "
            "from all posture aggregate and rollup calculations."
        ),
    )
    purge_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment=(
            "Timestamp when this definition becomes eligible for hard deletion.  "
            "Null until set by the application layer.  "
            "Defaults to created_at + 90 days when the record is committed."
        ),
    )
    retention_class: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        server_default="confidential_90d",
        comment=(
            "Retention class governing the purge schedule.  "
            "'confidential_90d': hard-delete 90 days after upload.  "
            "'sample': excluded from purge (is_sample=True rows)."
        ),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships
    workspace: Mapped["Workspace"] = relationship(  # type: ignore[name-defined]
        back_populates="pipeline_definitions",
        lazy="raise",
    )
    analysis: Mapped["Analysis"] = relationship(  # type: ignore[name-defined]
        back_populates="pipeline_definition",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<PipelineDefinition id={self.id!r} "
            f"analysis_id={self.analysis_id!r}>"
        )
