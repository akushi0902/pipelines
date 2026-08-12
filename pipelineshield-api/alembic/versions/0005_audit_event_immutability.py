"""Audit event immutability enforcement and extended columns.

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-11

Changes:
1. audit_event: add actor_user_id (nullable UUID FK to app_user), actor_reference
   (masked identifier for unauthenticated events), workspace_id (nullable FK),
   source_ip_masked, user_agent_hash, actor_persona_at (rename guard).
2. Indexes: (occurred_at DESC), (actor_user_id, occurred_at DESC),
   (resource_type, resource_id).
3. Immutability trigger:
   - PostgreSQL: a PL/pgSQL function + BEFORE UPDATE OR DELETE trigger.
   - SQLite:    two RAISE(ABORT) triggers (one per UPDATE, one per DELETE).
4. pipeline_definition: partial index on uploaded_at WHERE purged_at IS NULL
   for the daily purge worker.

Forward-only.  The downgrade drops the added indexes and triggers.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_APP_ROLE = "pipelineshield_app"


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    pg = _is_pg()
    uuid_type = postgresql.UUID(as_uuid=True) if pg else sa.String(36)

    # ------------------------------------------------------------------
    # 1. Add new columns to audit_event
    # ------------------------------------------------------------------
    with op.batch_alter_table("audit_event", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "actor_user_id",
                uuid_type,
                nullable=True,
                comment=(
                    "FK to app_user.id — null for unauthenticated events "
                    "(e.g. failed login before identity is established)."
                ),
            )
        )
        batch_op.add_column(
            sa.Column(
                "actor_reference",
                sa.String(255),
                nullable=True,
                comment=(
                    "Masked actor reference for unauthenticated events "
                    "(e.g. hashed IP or opaque token prefix)."
                ),
            )
        )
        batch_op.add_column(
            sa.Column(
                "workspace_id",
                uuid_type,
                nullable=True,
                comment="Workspace context of the event (null for cross-workspace operations).",
            )
        )
        batch_op.add_column(
            sa.Column(
                "source_ip_masked",
                sa.String(64),
                nullable=True,
                comment="Source IP address, masked (last octet zeroed for IPv4).",
            )
        )
        batch_op.add_column(
            sa.Column(
                "user_agent_hash",
                sa.String(64),
                nullable=True,
                comment="SHA-256 hex digest of the User-Agent header (not the raw string).",
            )
        )

    # ------------------------------------------------------------------
    # 2. Additional indexes for audit query performance
    # ------------------------------------------------------------------
    # Index on actor_user_id + occurred_at for per-actor queries
    op.create_index(
        "ix_audit_event_actor_user_occurred",
        "audit_event",
        ["actor_user_id", sa.text("occurred_at DESC")],
        postgresql_using="btree",
    ) if pg else op.create_index(
        "ix_audit_event_actor_user_occurred",
        "audit_event",
        ["actor_user_id", "occurred_at"],
    )

    # Index on resource_type + resource_id for resource-scoped queries
    op.create_index(
        "ix_audit_event_resource",
        "audit_event",
        ["resource_type", "resource_id"],
    )

    # Index on workspace_id + occurred_at for workspace-scoped queries
    op.create_index(
        "ix_audit_event_workspace_occurred",
        "audit_event",
        ["workspace_id", "occurred_at"],
    )

    # ------------------------------------------------------------------
    # 3. pipeline_definition: partial index on uploaded_at for purge worker
    # ------------------------------------------------------------------
    if pg:
        op.create_index(
            "ix_pipeline_definition_uploaded_at_not_purged",
            "pipeline_definition",
            ["uploaded_at"],
            postgresql_where=sa.text("purged_at IS NULL"),
        )

    # ------------------------------------------------------------------
    # 4. Immutability trigger
    # ------------------------------------------------------------------
    bind = op.get_bind()

    if pg:
        # PostgreSQL: PL/pgSQL function + BEFORE UPDATE OR DELETE trigger
        bind.execute(sa.text("""
            CREATE OR REPLACE FUNCTION audit_event_immutable()
            RETURNS TRIGGER
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION
                    'audit_event is append-only: % on audit_event is not permitted. '
                    'Correlation: %',
                    TG_OP,
                    current_setting('application.correlation_id', true);
                RETURN NULL;
            END;
            $$;
        """))
        bind.execute(sa.text("""
            CREATE TRIGGER trg_audit_event_immutable
            BEFORE UPDATE OR DELETE ON audit_event
            FOR EACH ROW EXECUTE FUNCTION audit_event_immutable();
        """))
    else:
        # SQLite: two RAISE(ABORT) triggers
        bind.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_event_no_update
            BEFORE UPDATE ON audit_event
            BEGIN
                SELECT RAISE(ABORT,
                    'audit_event is append-only: UPDATE is not permitted');
            END;
        """))
        bind.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_event_no_delete
            BEFORE DELETE ON audit_event
            BEGIN
                SELECT RAISE(ABORT,
                    'audit_event is append-only: DELETE is not permitted');
            END;
        """))

    # ------------------------------------------------------------------
    # 5. PostgreSQL-only: re-assert REVOKE (defence against grant drift)
    # ------------------------------------------------------------------
    if pg:
        bind.execute(sa.text(
            f"REVOKE UPDATE, DELETE ON TABLE audit_event FROM {_APP_ROLE}"
        ))
        op.execute(sa.text(
            "COMMENT ON TABLE audit_event IS "
            "'Classification: Restricted | Retention: 1 year | "
            "Append-only audit log. UPDATE and DELETE are revoked from "
            "pipelineshield_app and blocked by an immutability trigger.'"
        ))


def downgrade() -> None:
    pg = _is_pg()
    bind = op.get_bind()

    if pg:
        bind.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_event_immutable ON audit_event"))
        bind.execute(sa.text("DROP FUNCTION IF EXISTS audit_event_immutable()"))
        op.drop_index("ix_pipeline_definition_uploaded_at_not_purged", "pipeline_definition")
    else:
        bind.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_event_no_update"))
        bind.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_event_no_delete"))

    op.drop_index("ix_audit_event_workspace_occurred", "audit_event")
    op.drop_index("ix_audit_event_resource", "audit_event")
    op.drop_index("ix_audit_event_actor_user_occurred", "audit_event")

    with op.batch_alter_table("audit_event", schema=None) as batch_op:
        batch_op.drop_column("user_agent_hash")
        batch_op.drop_column("source_ip_masked")
        batch_op.drop_column("workspace_id")
        batch_op.drop_column("actor_reference")
        batch_op.drop_column("actor_user_id")
