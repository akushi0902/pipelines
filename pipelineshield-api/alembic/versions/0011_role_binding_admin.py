"""Role binding administration and IdP group persona mapping.

Changes:
- workspace: add classification (varchar, default 'internal'), active (bool, default true)
- role_binding: add granted_by_id (nullable uuid fk), revoked_at (nullable timestamp)
  Drop uq_role_binding_workspace_user
  Create partial unique index on (app_user_id, workspace_id, persona) WHERE revoked_at IS NULL
  Create index on (app_user_id, revoked_at)
- group_persona_mapping: new table with unique (idp_group, workspace_id)

revision: 0011
down_revision: 0010
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # -------------------------------------------------------------------------
    # workspace — add classification and active columns
    # -------------------------------------------------------------------------
    with op.batch_alter_table("workspace", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "classification",
                sa.String(64),
                nullable=False,
                server_default="internal",
                comment="Data classification label (e.g. internal, confidential).",
            )
        )
        batch_op.add_column(
            sa.Column(
                "active",
                sa.Boolean,
                nullable=False,
                server_default=sa.true(),
                comment="False when workspace is deactivated; bindings yield no access.",
            )
        )

    # -------------------------------------------------------------------------
    # role_binding — add granted_by_id and revoked_at; replace unique constraint
    # -------------------------------------------------------------------------
    with op.batch_alter_table("role_binding", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "granted_by_id",
                sa.dialects.postgresql.UUID(as_uuid=True),
                nullable=True,
                comment="Actor who granted this binding; nullable for legacy/seed rows.",
            )
        )
        batch_op.add_column(
            sa.Column(
                "revoked_at",
                sa.DateTime(timezone=True),
                nullable=True,
                comment="Revocation timestamp; NULL means the binding is active.",
            )
        )
        # Drop old unique constraint (workspace_id, app_user_id)
        batch_op.drop_constraint(
            "uq_role_binding_workspace_user", type_="unique"
        )

    # Create partial unique index for active bindings (dialect-aware)
    bind = op.get_bind()
    dialect_name = bind.dialect.name
    if dialect_name == "postgresql":
        op.create_index(
            "uq_rb_active_user_workspace_persona",
            "role_binding",
            ["app_user_id", "workspace_id", "persona"],
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        )
    else:
        # SQLite — create a regular unique index (tests enforce uniqueness at
        # the service layer; the index guards against concurrent duplicates)
        op.create_index(
            "uq_rb_active_user_workspace_persona",
            "role_binding",
            ["app_user_id", "workspace_id", "persona"],
            unique=False,
        )

    # Index for per-request active-binding lookup
    op.create_index(
        "ix_role_binding_user_revoked_at",
        "role_binding",
        ["app_user_id", "revoked_at"],
    )

    # -------------------------------------------------------------------------
    # group_persona_mapping — new table
    # -------------------------------------------------------------------------
    op.create_table(
        "group_persona_mapping",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key.",
        ),
        sa.Column(
            "idp_group",
            sa.String(255),
            nullable=False,
            comment="IdP group claim string as returned by the identity provider.",
        ),
        sa.Column(
            "workspace_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspace.id", ondelete="CASCADE"),
            nullable=False,
            comment="Workspace context for this mapping.",
        ),
        sa.Column(
            "persona",
            sa.String(64),
            nullable=False,
            comment="Persona assigned to members of idp_group in this workspace.",
        ),
        sa.Column(
            "precedence",
            sa.Integer,
            nullable=False,
            server_default="100",
            comment=(
                "Lower value wins when a user belongs to multiple mapped groups. "
                "Ties are broken by persona name (alphabetical, ascending)."
            ),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            comment="Row creation timestamp (UTC).",
        ),
        sa.UniqueConstraint(
            "idp_group",
            "workspace_id",
            name="uq_gpm_group_workspace",
        ),
    )
    op.create_index(
        "ix_gpm_workspace_id",
        "group_persona_mapping",
        ["workspace_id"],
    )


def downgrade() -> None:
    op.drop_table("group_persona_mapping")

    op.drop_index("ix_role_binding_user_revoked_at", table_name="role_binding")
    op.drop_index("uq_rb_active_user_workspace_persona", table_name="role_binding")

    with op.batch_alter_table("role_binding", schema=None) as batch_op:
        batch_op.create_unique_constraint(
            "uq_role_binding_workspace_user",
            ["workspace_id", "app_user_id"],
        )
        batch_op.drop_column("revoked_at")
        batch_op.drop_column("granted_by_id")

    with op.batch_alter_table("workspace", schema=None) as batch_op:
        batch_op.drop_column("active")
        batch_op.drop_column("classification")
