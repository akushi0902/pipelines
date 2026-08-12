"""Add (catalogue_version_id, created_at DESC) index on analysis.

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-11

WO-013 AC-1 requires an index on (catalogue_version_id, created_at DESC)
to support dashboard and trend grouping queries.

The foreign key itself was added in the baseline migration (0001).
This revision adds only the composite covering index.

Forward-only.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if _is_pg():
        op.create_index(
            "idx_analysis_catalogue_version",
            "analysis",
            ["catalogue_version_id", sa.text("created_at DESC")],
            postgresql_using="btree",
        )
    else:
        op.create_index(
            "idx_analysis_catalogue_version",
            "analysis",
            ["catalogue_version_id", "created_at"],
        )


def downgrade() -> None:
    op.drop_index("idx_analysis_catalogue_version", table_name="analysis")
