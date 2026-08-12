"""Report payload: coverage_limitation table + finding.control_id column.

Changes:
1. New table: coverage_limitation — unresolved fragments that caused controls to be
   NOT_ASSESSABLE.  Rows are append-only per analysis lifecycle.
2. New column: finding.control_id VARCHAR(64) NULL — catalogue control identifier
   that produced this finding.  NULL for findings created before this migration.

revision: 0015
down_revision: 0014
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_CL = "coverage_limitation"
_FINDING = "finding"


def _is_pg() -> bool:
    bind = op.get_bind()
    return bind.dialect.name == "postgresql" if bind is not None else False


def upgrade() -> None:
    uuid_type: sa.types.TypeEngine
    jsonb_type: sa.types.TypeEngine
    if _is_pg():
        uuid_type = postgresql.UUID(as_uuid=True)
        jsonb_type = postgresql.JSONB()
    else:
        uuid_type = sa.String(36)
        jsonb_type = sa.JSON()

    # 1. coverage_limitation table
    op.create_table(
        _CL,
        sa.Column(
            "id",
            uuid_type,
            primary_key=True,
            comment="Primary key.",
        ),
        sa.Column(
            "analysis_id",
            uuid_type,
            sa.ForeignKey("analysis.id", ondelete="CASCADE"),
            nullable=False,
            comment="Owning analysis row.",
        ),
        sa.Column(
            "kind",
            sa.String(64),
            nullable=False,
            comment="Fragment kind (scripted_groovy, unresolved_include, etc.).",
        ),
        sa.Column(
            "location",
            sa.String(512),
            nullable=False,
            comment="File path, line reference, or block identifier.",
        ),
        sa.Column(
            "reason",
            sa.Text,
            nullable=False,
            comment="Human-readable explanation of why this fragment was unresolved.",
        ),
        sa.Column(
            "affected_control_ids",
            jsonb_type,
            nullable=False,
            server_default=sa.text("'[]'"),
            comment="Catalogue control IDs rendered NOT_ASSESSABLE.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            comment="Row creation timestamp (UTC).",
        ),
    )
    op.create_index(
        f"ix_{_CL}_analysis_id",
        _CL,
        ["analysis_id"],
    )

    # 2. finding.control_id column
    op.add_column(
        _FINDING,
        sa.Column(
            "control_id",
            sa.String(64),
            nullable=True,
            comment=(
                "Catalogue control identifier that produced this finding. "
                "NULL for findings created before migration 0015."
            ),
        ),
    )


def downgrade() -> None:
    op.drop_column(_FINDING, "control_id")
    op.drop_index(f"ix_{_CL}_analysis_id", table_name=_CL)
    op.drop_table(_CL)
