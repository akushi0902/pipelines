"""Add trigger and subject_user_id to purge_receipt for on-demand subject erasure.

Changes:
- purge_receipt.trigger (text, NOT NULL, default 'scheduled')
  Values: 'scheduled' (RetentionWorker), 'on_demand' (SubjectRightsService)
- purge_receipt.subject_user_id (uuid, NULL)
  Populated only for on_demand receipts; links receipt to the data subject.

No changes to audit_event (already has sufficient correlation fields).

revision: 0012
down_revision: 0011
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("purge_receipt", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "trigger",
                sa.String(32),
                nullable=False,
                server_default="scheduled",
                comment=(
                    "Source of the purge: 'scheduled' (RetentionWorker) or "
                    "'on_demand' (SubjectRightsService governance endpoint)."
                ),
            )
        )
        batch_op.add_column(
            sa.Column(
                "subject_user_id",
                sa.dialects.postgresql.UUID(as_uuid=True),
                nullable=True,
                comment=(
                    "Data subject whose Confidential material was erased. "
                    "NULL for scheduled purge batches."
                ),
            )
        )
        batch_op.create_check_constraint(
            "ck_purge_receipt_trigger",
            "trigger IN ('scheduled', 'on_demand')",
        )

    op.create_index(
        "ix_purge_receipt_subject_user_id",
        "purge_receipt",
        ["subject_user_id"],
        postgresql_where=sa.text("subject_user_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_purge_receipt_subject_user_id", table_name="purge_receipt")
    with op.batch_alter_table("purge_receipt", schema=None) as batch_op:
        batch_op.drop_constraint("ck_purge_receipt_trigger", type_="check")
        batch_op.drop_column("subject_user_id")
        batch_op.drop_column("trigger")
