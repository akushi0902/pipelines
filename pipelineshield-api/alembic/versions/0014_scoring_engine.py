"""Scoring engine: analysis_category_score table + analysis.unscorable_reason column.

Changes:
1. New table: analysis_category_score — per-category earned/possible/excluded_count.
2. New column: analysis.unscorable_reason VARCHAR(128) NULL — reason when no numeric
   score can be produced (e.g. 'all_not_assessable').

The analysis_category_score table is append-only by convention (no UPDATE/DELETE
paths in application code).  The unique constraint on (analysis_id, category_id)
prevents double-scoring the same category.

revision: 0014
down_revision: 0013
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ACS = "analysis_category_score"
_ANALYSIS = "analysis"


def _is_pg() -> bool:
    bind = op.get_bind()
    return bind.dialect.name == "postgresql" if bind is not None else False


def upgrade() -> None:
    uuid_type: sa.types.TypeEngine
    if _is_pg():
        uuid_type = postgresql.UUID(as_uuid=True)
    else:
        uuid_type = sa.String(36)

    # 1. analysis_category_score table
    op.create_table(
        _ACS,
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
            "category_id",
            sa.String(64),
            nullable=False,
            comment="Catalogue category identifier.",
        ),
        sa.Column(
            "earned",
            sa.Numeric(8, 4),
            nullable=False,
            comment="Weighted credit earned for this category.",
        ),
        sa.Column(
            "possible",
            sa.Numeric(8, 4),
            nullable=False,
            comment="Maximum possible credit (excludes NOT_ASSESSABLE controls).",
        ),
        sa.Column(
            "excluded_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
            comment="Number of NOT_ASSESSABLE controls excluded from denominator.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.UniqueConstraint(
            "analysis_id",
            "category_id",
            name="uq_analysis_category_score_analysis_id_category_id",
        ),
        sa.CheckConstraint(
            "excluded_count >= 0",
            name="ck_analysis_category_score_excluded_count_non_negative",
        ),
    )
    op.create_index(
        f"ix_{_ACS}_analysis_id",
        _ACS,
        ["analysis_id"],
    )

    # 2. analysis.unscorable_reason column
    op.add_column(
        _ANALYSIS,
        sa.Column(
            "unscorable_reason",
            sa.String(128),
            nullable=True,
            comment=(
                "Reason the analysis could not be scored "
                "(e.g. 'all_not_assessable').  NULL when a numeric score is present."
            ),
        ),
    )


def downgrade() -> None:
    op.drop_column(_ANALYSIS, "unscorable_reason")
    op.drop_index(f"ix_{_ACS}_analysis_id", table_name=_ACS)
    op.drop_table(_ACS)
