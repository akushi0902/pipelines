"""Add (action, occurred_at DESC) composite index on audit_event.

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-11

WO-011 AC-1 requires four composite indexes on audit_event:
  (workspace_id, occurred_at DESC) — in 0005
  (actor_user_id, occurred_at DESC) — in 0005 as ix_audit_event_actor_user_occurred
  (resource_type, resource_id)     — in 0005 as ix_audit_event_resource
  (action, occurred_at DESC)       — added here

Forward-only. Downgrade drops the index.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if _is_pg():
        op.create_index(
            "ix_audit_event_action_occurred",
            "audit_event",
            ["action", sa.text("occurred_at DESC")],
            postgresql_using="btree",
        )
    else:
        op.create_index(
            "ix_audit_event_action_occurred",
            "audit_event",
            ["action", "occurred_at"],
        )


def downgrade() -> None:
    op.drop_index("ix_audit_event_action_occurred", table_name="audit_event")
