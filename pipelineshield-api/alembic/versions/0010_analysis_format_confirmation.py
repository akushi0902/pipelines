"""Add confirmed_format and format_confirmed_by_user to analysis.

These columns support the format confirmation round-trip (WO-004):

analysis.confirmed_format (nullable text)
    Populated when a user explicitly confirms the pipeline format via
    POST /api/v1/analyses/{id}/format-confirmation.  NULL means the
    system-detected format is the effective format.

analysis.format_confirmed_by_user (boolean, default false)
    Set to true only when the user has supplied an explicit confirmation.
    Immutable after being set to true (enforced by application logic, not
    a DB trigger, because the confirmation endpoint is idempotent once set).

revision: 0010
down_revision: 0009
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("analysis", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "confirmed_format",
                sa.String(64),
                nullable=True,
                comment=(
                    "User-confirmed pipeline format.  NULL = auto-detected. "
                    "Set via POST /api/v1/analyses/{id}/format-confirmation."
                ),
            )
        )
        batch_op.add_column(
            sa.Column(
                "format_confirmed_by_user",
                sa.Boolean,
                nullable=False,
                server_default=sa.false(),
                comment=(
                    "True when the user explicitly confirmed the pipeline format. "
                    "Immutable once set."
                ),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("analysis", schema=None) as batch_op:
        batch_op.drop_column("format_confirmed_by_user")
        batch_op.drop_column("confirmed_format")
