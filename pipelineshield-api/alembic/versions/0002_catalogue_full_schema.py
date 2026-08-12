"""Catalogue full schema — rename and extend control_catalogue_version.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-11

Transforms the minimal scaffold created in 0001 into the full WO-009 schema:

Column renames:
  version_number   → version
  description      → change_notes  (nullable, removes empty-string default)
  controls         → snapshot

New columns:
  status           TEXT NOT NULL CHECK(active|superseded) DEFAULT 'active'
  grade_bands      JSONB/JSON NOT NULL
  created_by       UUID NOT NULL FK → app_user(id) RESTRICT
  content_checksum VARCHAR(64) NOT NULL

New constraints / indexes:
  UNIQUE on version (replaces uq_control_catalogue_version_version_number)
  CHECK  status IN ('active','superseded')
  FK     created_by → app_user.id  ON DELETE RESTRICT
  INDEX  control_catalogue_version(created_at)
  INDEX  control_catalogue_version(status)  [partial WHERE status='active' on PG]

Forward-only: the downgrade restores the 0001 column names and drops the
added columns.  It must not be run on any non-dev database that contains rows.

Uses op.batch_alter_table throughout for SQLite 3.45 compatibility; Alembic
routes this to standard ALTER TABLE on PostgreSQL 16.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "control_catalogue_version"
_APP_ROLE = "pipelineshield_app"


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    pg = _is_pg()

    # Dialect-aware types for column definitions.
    json_col_type = postgresql.JSONB(astext_type=sa.Text()) if pg else sa.JSON()
    uuid_col_type = postgresql.UUID(as_uuid=True) if pg else sa.String(36)
    # PostgreSQL parses '[]'::jsonb; SQLite stores JSON as text so plain '[]' works.
    grade_bands_default = sa.text("'[]'::jsonb") if pg else sa.text("'[]'")

    with op.batch_alter_table(_TABLE, schema=None) as batch_op:
        # ── Rename existing columns ─────────────────────────────────────────
        batch_op.alter_column(
            "version_number",
            new_column_name="version",
            existing_type=sa.Integer(),
            existing_nullable=False,
        )
        # change_notes becomes nullable (was NOT NULL default '').
        batch_op.alter_column(
            "description",
            new_column_name="change_notes",
            existing_type=sa.Text(),
            existing_nullable=False,
            existing_server_default=sa.text("''"),
            nullable=True,
            server_default=None,
        )
        # snapshot: rename controls; also update the reflected type declaration.
        batch_op.alter_column(
            "controls",
            new_column_name="snapshot",
            existing_type=json_col_type,
            type_=json_col_type,
            existing_nullable=False,
        )

        # ── Drop the old version_number unique constraint ───────────────────
        batch_op.drop_constraint(
            "uq_control_catalogue_version_version_number",
            type_="unique",
        )

        # ── Add new columns ─────────────────────────────────────────────────
        batch_op.add_column(
            sa.Column(
                "status",
                sa.String(16),
                nullable=False,
                server_default=sa.text("'active'"),
                comment="Lifecycle status: active or superseded.",
            )
        )
        batch_op.add_column(
            sa.Column(
                "grade_bands",
                json_col_type,
                nullable=False,
                server_default=grade_bands_default,
                comment="Grade-band configuration snapshot.",
            )
        )
        # created_by and content_checksum are NOT NULL — safe here because
        # the table is always empty when this migration runs (no seed has
        # been inserted yet).  Both columns must be provided by the
        # application on every INSERT.
        batch_op.add_column(
            sa.Column(
                "created_by",
                uuid_col_type,
                nullable=False,
                comment="Actor who created this version; never null.",
            )
        )
        batch_op.add_column(
            sa.Column(
                "content_checksum",
                sa.String(64),
                nullable=False,
                comment="SHA-256 hex digest of canonical JSON snapshot.",
            )
        )

        # ── Add new constraints ─────────────────────────────────────────────
        batch_op.create_unique_constraint(
            "uq_control_catalogue_version_version", ["version"]
        )
        batch_op.create_check_constraint(
            "ck_control_catalogue_version_status_valid",
            "status IN ('active', 'superseded')",
        )
        batch_op.create_foreign_key(
            "fk_control_catalogue_version_created_by_app_user",
            "app_user",
            ["created_by"],
            ["id"],
            ondelete="RESTRICT",
        )

    # ── Indexes outside the batch block ────────────────────────────────────
    op.create_index(
        "ix_control_catalogue_version_created_at",
        _TABLE,
        ["created_at"],
    )
    if pg:
        # Partial index: fast lookup for the single active row.
        op.create_index(
            "ix_ccv_status_active",
            _TABLE,
            ["status"],
            postgresql_where=sa.text("status = 'active'"),
        )
    else:
        op.create_index("ix_ccv_status_active", _TABLE, ["status"])

    # ── PostgreSQL-only: updated table comment and re-apply grants ──────────
    if pg:
        op.execute(
            sa.text(
                f"COMMENT ON TABLE {_TABLE} IS"
                " 'Classification: Internal | Retention: indefinite"
                " | Versioned, checksummed, append-only snapshot of the"
                " security control catalogue.'"
            )
        )
        op.execute(
            sa.text(f"GRANT INSERT, SELECT ON TABLE {_TABLE} TO {_APP_ROLE}")
        )
        op.execute(
            sa.text(f"REVOKE UPDATE, DELETE ON TABLE {_TABLE} FROM {_APP_ROLE}")
        )


def downgrade() -> None:
    """Reverse the 0002 changes.

    WARNING: Only safe on a dev database with no catalogue version rows.
    """
    pg = _is_pg()
    json_col_type = postgresql.JSONB(astext_type=sa.Text()) if pg else sa.JSON()

    op.drop_index("ix_ccv_status_active", _TABLE)
    op.drop_index("ix_control_catalogue_version_created_at", _TABLE)

    with op.batch_alter_table(_TABLE, schema=None) as batch_op:
        # Drop added columns.
        batch_op.drop_column("content_checksum")
        batch_op.drop_column("created_by")
        batch_op.drop_column("grade_bands")
        batch_op.drop_column("status")

        # Remove added constraints (dropped columns removed their FKs/checks).
        batch_op.drop_constraint(
            "uq_control_catalogue_version_version", type_="unique"
        )

        # Rename columns back.
        batch_op.alter_column(
            "snapshot",
            new_column_name="controls",
            existing_type=json_col_type,
            type_=json_col_type,
            existing_nullable=False,
        )
        batch_op.alter_column(
            "change_notes",
            new_column_name="description",
            existing_type=sa.Text(),
            existing_nullable=True,
            nullable=False,
            server_default=sa.text("''"),
        )
        batch_op.alter_column(
            "version",
            new_column_name="version_number",
            existing_type=sa.Integer(),
            existing_nullable=False,
        )

        # Restore original unique constraint.
        batch_op.create_unique_constraint(
            "uq_control_catalogue_version_version_number", ["version_number"]
        )
