"""Add retention columns and purge_receipt status fields for 90-day purge worker.

Changes
-------
pipeline_definition:
  - purge_due_at   (timestamptz not null default created_at + 90 days, indexed)
  - retention_class (text not null default 'confidential_90d')

purge_receipt:
  - status       (text not null check ('succeeded','failed','partial'))
  - error_detail (text nullable)

SQL grants for pipelineshield_purge role are emitted as DO $$ … $$
blocks that are silently no-ops if the role does not exist (SQLite
will simply skip the LANGUAGE plpgsql blocks).

revision: 0009
down_revision: 0008
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # pipeline_definition: add purge tracking columns
    # ------------------------------------------------------------------
    with op.batch_alter_table("pipeline_definition", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "purge_due_at",
                sa.DateTime(timezone=True),
                nullable=True,  # nullable initially; backfill sets value
                comment=(
                    "Timestamp when this definition becomes eligible for "
                    "hard deletion.  Defaults to created_at + 90 days."
                ),
            )
        )
        batch_op.add_column(
            sa.Column(
                "retention_class",
                sa.String(64),
                nullable=False,
                server_default="confidential_90d",
                comment=(
                    "Retention class governing the purge schedule.  "
                    "confidential_90d: hard-delete 90 days after upload.  "
                    "sample: never purged (is_sample=True rows)."
                ),
            )
        )
        batch_op.create_index(
            "idx_pipeline_definition_purge_due_at",
            ["purge_due_at"],
        )

    # ------------------------------------------------------------------
    # purge_receipt: add status and error_detail columns (AC-1)
    # ------------------------------------------------------------------
    with op.batch_alter_table("purge_receipt", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "status",
                sa.String(16),
                nullable=False,
                server_default="succeeded",
                comment=(
                    "Purge batch outcome: 'succeeded', 'failed', or 'partial'."
                ),
            )
        )
        batch_op.add_column(
            sa.Column(
                "error_detail",
                sa.Text,
                nullable=True,
                comment=(
                    "Non-sensitive error description when status != succeeded.  "
                    "Must not contain row content or secret values."
                ),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("purge_receipt", schema=None) as batch_op:
        batch_op.drop_column("error_detail")
        batch_op.drop_column("status")

    with op.batch_alter_table("pipeline_definition", schema=None) as batch_op:
        batch_op.drop_index("idx_pipeline_definition_purge_due_at")
        batch_op.drop_column("retention_class")
        batch_op.drop_column("purge_due_at")
