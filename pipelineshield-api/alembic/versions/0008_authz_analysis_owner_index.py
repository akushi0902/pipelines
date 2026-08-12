"""Add composite indexes for row-level-scoped analysis and finding queries.

For analysis: (workspace_id, owner_id, created_at DESC) supports the
  developer-isolation query where owner_id = :actor_id within a workspace.

For finding: (analysis_id,) already exists as an implicit FK index on most
  engines; verified and explicitly named here for forward-compatibility.

For role_binding: (app_user_id, workspace_id) covers the per-request binding
  resolution used by ActorScope.from_actor().

revision: 0008
down_revision: 0007
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Composite index supporting developer-isolation scoped reads on analysis.
    # analysis:read:own queries filter (workspace_id, owner_id); the created_at
    # DESC trailing column keeps list results in the expected newest-first order
    # without a sort-on-heap.
    with op.batch_alter_table("analysis", schema=None) as batch_op:
        batch_op.create_index(
            "idx_analysis_workspace_owner_created",
            ["workspace_id", "owner_id", "created_at"],
            unique=False,
        )

    # Composite index for fast per-request role binding resolution.
    # ActorScope.from_actor() selects role_binding WHERE app_user_id = :uid
    # AND workspace_id = :wsid; this covers both columns.
    with op.batch_alter_table("role_binding", schema=None) as batch_op:
        batch_op.create_index(
            "idx_role_binding_user_workspace",
            ["app_user_id", "workspace_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("role_binding", schema=None) as batch_op:
        batch_op.drop_index("idx_role_binding_user_workspace")

    with op.batch_alter_table("analysis", schema=None) as batch_op:
        batch_op.drop_index("idx_analysis_workspace_owner_created")
