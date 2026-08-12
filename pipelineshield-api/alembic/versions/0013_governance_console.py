"""Governance console: retention_policy table and audit_event composite index.

Changes:
- New table: retention_policy (single-row workspace-scoped policy)
- New composite index: audit_event(workspace_id, occurred_at DESC, id)
  for cursor-paginated governance audit viewer

revision: 0013
down_revision: 0012
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name if bind is not None else "sqlite"

    if dialect == "postgresql":
        uuid_type: sa.types.TypeEngine = postgresql.UUID(as_uuid=True)
    else:
        uuid_type = sa.String(36)

    op.create_table(
        "retention_policy",
        sa.Column(
            "id",
            sa.SmallInteger(),
            nullable=False,
            comment="Single-row PK enforced by check constraint (must equal 1).",
        ),
        sa.Column(
            "retention_days",
            sa.Integer(),
            nullable=False,
            server_default="90",
            comment="Number of days Confidential pipeline definitions are retained.",
        ),
        sa.Column(
            "updated_by",
            uuid_type,
            nullable=False,
            comment="FK to app_user.id — last actor to modify retention policy.",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            comment="Timestamp of the last policy update (UTC).",
        ),
        sa.CheckConstraint("id = 1", name="ck_retention_policy_single_row"),
        sa.CheckConstraint(
            "retention_days >= 1 AND retention_days <= 90",
            name="ck_retention_policy_days",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Composite index for governance cursor-paginated audit log
    # (workspace_id, occurred_at DESC, id) backs the common query pattern
    op.create_index(
        "ix_audit_event_workspace_occurred_id",
        "audit_event",
        ["workspace_id", "occurred_at", "id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_audit_event_workspace_occurred_id", table_name="audit_event")
    op.drop_table("retention_policy")
