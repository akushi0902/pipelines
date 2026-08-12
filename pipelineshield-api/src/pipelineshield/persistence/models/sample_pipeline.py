"""SamplePipeline model — bundled demo pipeline configurations.

Data classification: Internal
Retention: indefinite
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class SamplePipeline(Base):
    """Bundled demo pipeline configuration for offline development.

    Sample pipelines are seeded by tests/fixtures/seed_baseline.py and
    allow downstream stories to bootstrap data without external dependencies.
    They are classified as Internal because they contain no Confidential
    user-uploaded content — they are representative, synthetic examples.

    Deletion semantics: hard delete only.
    """

    __tablename__ = "sample_pipeline"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Primary key — sample pipeline identifier.",
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workspace.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Owning workspace — tenant scope.",
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable name for this sample pipeline.",
    )
    pipeline_format: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Pipeline format: github_actions, gitlab_ci, jenkins_declarative.",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
        comment="Description of what this sample demonstrates.",
    )
    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment=(
            "Plain-text pipeline content.  Contains no secrets or "
            "Confidential data — classification: Internal."
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
        back_populates="sample_pipelines",
        lazy="raise",
    )

    def __repr__(self) -> str:
        return (
            f"<SamplePipeline id={self.id!r} "
            f"name={self.name!r} format={self.pipeline_format!r}>"
        )
