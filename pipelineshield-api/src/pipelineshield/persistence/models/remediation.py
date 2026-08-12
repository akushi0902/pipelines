"""Remediation model — recommended remediation action for a finding.

Data classification: Confidential
Retention: 90 days
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class Remediation(Base):
    """Recommended remediation action for a security finding.

    Each remediation cites a specific tool or technique and provides
    a plain-language explanation of how to address the parent finding.
    Multiple remediations may exist per finding (e.g. one per relevant tool).

    Deletion semantics: hard delete only (Confidential).  No deleted_at or
    is_deleted columns are permitted on this table.
    """

    __tablename__ = "remediation"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — remediation identifier.",
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Owning workspace — tenant scope.",
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("finding.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Parent finding this remediation addresses.",
    )
    tool_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment=(
            "Name of the recommended tool (e.g. Gitleaks, Semgrep, Trivy, "
            "Checkov, Syft, Cosign)."
        ),
    )
    guidance: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Plain-language remediation guidance.  Recommendation only — never executed.",
    )
    reference_url: Mapped[str | None] = mapped_column(
        String(2048),
        nullable=True,
        comment="Optional reference URL for further reading.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # Relationships
    finding: Mapped["Finding"] = relationship(  # type: ignore[name-defined]
        back_populates="remediations",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<Remediation id={self.id!r} "
            f"finding_id={self.finding_id!r} tool={self.tool_name!r}>"
        )
