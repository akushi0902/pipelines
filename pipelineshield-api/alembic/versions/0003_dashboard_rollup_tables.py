"""Dashboard rollup tables and is_sample flag.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-11

Changes:
1. pipeline_definition: add is_sample BOOLEAN NOT NULL DEFAULT FALSE.
2. Create workspace_score_rollup table — pre-aggregated weekly score buckets
   keyed by (workspace_id, owner_id, bucket_date, catalogue_version).
3. Create category_gap_rollup table — pre-aggregated weekly category-gap
   counts keyed by (workspace_id, owner_id, bucket_date, control_category_id).
4. Backfill workspace_score_rollup from existing analysis rows (all marked
   non-sample since is_sample defaults to false).

Forward-only: the downgrade drops the new tables and column.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_APP_ROLE = "pipelineshield_app"
_WSR = "workspace_score_rollup"
_CGR = "category_gap_rollup"


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    pg = _is_pg()
    uuid_type = postgresql.UUID(as_uuid=True) if pg else sa.String(36)

    # ------------------------------------------------------------------
    # 1. Add is_sample to pipeline_definition
    # ------------------------------------------------------------------
    with op.batch_alter_table("pipeline_definition", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "is_sample",
                sa.Boolean,
                nullable=False,
                server_default=sa.text("false"),
                comment="True for bundled demo pipelines excluded from posture rollups.",
            )
        )

    # ------------------------------------------------------------------
    # 2. workspace_score_rollup
    # ------------------------------------------------------------------
    op.create_table(
        _WSR,
        sa.Column("id", uuid_type, primary_key=True, comment="Primary key."),
        sa.Column(
            "workspace_id",
            uuid_type,
            nullable=False,
            comment="Owning workspace.",
        ),
        sa.Column(
            "owner_id",
            uuid_type,
            nullable=False,
            comment="Owner of the analyses in this bucket.",
        ),
        sa.Column(
            "bucket_date",
            sa.Date,
            nullable=False,
            comment="ISO week-start (Monday) for this bucket.",
        ),
        sa.Column(
            "catalogue_version",
            sa.Integer,
            nullable=False,
            comment="Catalogue version integer.",
        ),
        sa.Column(
            "analysis_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "score_sum",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("grade_a", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("grade_b", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("grade_c", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("grade_d", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("grade_f", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("sev_critical", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("sev_high", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("sev_medium", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("sev_low", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("sev_info", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name="fk_wsr_workspace_id_workspace",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["owner_id"],
            ["app_user.id"],
            name="fk_wsr_owner_id_app_user",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "owner_id",
            "bucket_date",
            "catalogue_version",
            name="uq_wsr_workspace_owner_bucket_catalogue",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_workspace_score_rollup"),
    )
    op.create_index("ix_wsr_workspace_bucket", _WSR, ["workspace_id", "bucket_date"])

    # ------------------------------------------------------------------
    # 3. category_gap_rollup
    # ------------------------------------------------------------------
    op.create_table(
        _CGR,
        sa.Column("id", uuid_type, primary_key=True, comment="Primary key."),
        sa.Column("workspace_id", uuid_type, nullable=False),
        sa.Column("owner_id", uuid_type, nullable=False),
        sa.Column("bucket_date", sa.Date, nullable=False),
        sa.Column("control_category_id", sa.String(64), nullable=False),
        sa.Column(
            "missing_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "partial_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "not_assessable_count",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name="fk_cgr_workspace_id_workspace",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["owner_id"],
            ["app_user.id"],
            name="fk_cgr_owner_id_app_user",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "owner_id",
            "bucket_date",
            "control_category_id",
            name="uq_cgr_workspace_owner_bucket_category",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_category_gap_rollup"),
    )
    op.create_index("ix_cgr_workspace_bucket", _CGR, ["workspace_id", "bucket_date"])

    # ------------------------------------------------------------------
    # 4. Backfill workspace_score_rollup from existing analyses
    #    (all existing pipeline_definition rows have is_sample = false)
    # ------------------------------------------------------------------
    bind = op.get_bind()
    if pg:
        bind.execute(sa.text(f"""
            INSERT INTO {_WSR}
              (id, workspace_id, owner_id, bucket_date, catalogue_version,
               analysis_count, score_sum,
               grade_a, grade_b, grade_c, grade_d, grade_f,
               sev_critical, sev_high, sev_medium, sev_low, sev_info,
               updated_at)
            SELECT
              gen_random_uuid(),
              a.workspace_id,
              a.owner_id,
              date_trunc('week', a.created_at)::date AS bucket_date,
              ccv.version,
              COUNT(*)                               AS analysis_count,
              SUM(a.score)                           AS score_sum,
              COUNT(*) FILTER (WHERE a.grade = 'A')  AS grade_a,
              COUNT(*) FILTER (WHERE a.grade = 'B')  AS grade_b,
              COUNT(*) FILTER (WHERE a.grade = 'C')  AS grade_c,
              COUNT(*) FILTER (WHERE a.grade = 'D')  AS grade_d,
              COUNT(*) FILTER (WHERE a.grade = 'F')  AS grade_f,
              0, 0, 0, 0, 0,
              now()
            FROM analysis a
            JOIN control_catalogue_version ccv
              ON ccv.id = a.catalogue_version_id
            LEFT JOIN pipeline_definition pd
              ON pd.analysis_id = a.id
            WHERE pd.is_sample IS DISTINCT FROM true
            GROUP BY
              a.workspace_id, a.owner_id,
              date_trunc('week', a.created_at)::date,
              ccv.version
            ON CONFLICT DO NOTHING
        """))

    # ------------------------------------------------------------------
    # 5. PostgreSQL-only: grants, comments
    # ------------------------------------------------------------------
    if pg:
        for tbl in (_WSR, _CGR):
            op.execute(sa.text(f"GRANT INSERT, SELECT, UPDATE ON TABLE {tbl} TO {_APP_ROLE}"))
            op.execute(sa.text(f"REVOKE DELETE ON TABLE {tbl} FROM {_APP_ROLE}"))

        op.execute(sa.text(
            f"COMMENT ON TABLE {_WSR} IS "
            "'Classification: Internal | Retention: indefinite | "
            "Pre-aggregated weekly score rollup for the dashboard.'"
        ))
        op.execute(sa.text(
            f"COMMENT ON TABLE {_CGR} IS "
            "'Classification: Internal | Retention: indefinite | "
            "Pre-aggregated weekly category-gap counts for the dashboard.'"
        ))


def downgrade() -> None:
    """Drop rollup tables and is_sample column."""
    op.drop_index("ix_cgr_workspace_bucket", _CGR)
    op.drop_table(_CGR)
    op.drop_index("ix_wsr_workspace_bucket", _WSR)
    op.drop_table(_WSR)

    with op.batch_alter_table("pipeline_definition", schema=None) as batch_op:
        batch_op.drop_column("is_sample")
