"""Add idp_subject and last_login_at to app_user.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-11

Changes:
1. app_user: add idp_subject VARCHAR(255) UNIQUE (nullable for existing rows).
2. app_user: add last_login_at TIMESTAMP WITH TIME ZONE (nullable).
3. Add unique index on app_user.idp_subject for O(1) login lookup.
4. Add table comment recording that no password column may ever be added.

INVARIANT: no password column, password hash, or credential reset flow
may ever be added to app_user.  Credential handling is entirely the
IdP's responsibility.  This comment is recorded here and in the code
review checklist so that adding such a column triggers a review failure.

Forward-only: the downgrade drops the two columns and their index.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_APP_ROLE = "pipelineshield_app"


def _is_pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    with op.batch_alter_table("app_user", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "idp_subject",
                sa.String(255),
                nullable=True,
                comment=(
                    "IdP subject claim (opaque, unique per user).  "
                    "Used as the stable JIT-upsert key during OIDC callback.  "
                    "INVARIANT: no password column may ever be added — "
                    "credential handling is the IdP's sole responsibility."
                ),
            )
        )
        batch_op.add_column(
            sa.Column(
                "last_login_at",
                sa.DateTime(timezone=True),
                nullable=True,
                comment="Timestamp of the most recent successful OIDC login (UTC).",
            )
        )
        batch_op.create_unique_constraint(
            "uq_app_user_idp_subject", ["idp_subject"]
        )

    op.create_index(
        "ix_app_user_idp_subject",
        "app_user",
        ["idp_subject"],
        unique=True,
    )

    if _is_pg():
        op.execute(sa.text(
            "COMMENT ON TABLE app_user IS "
            "'Classification: Internal | Retention: indefinite | "
            "INVARIANT: no password column may ever be added — "
            "credential handling is entirely the IdP responsibility.'"
        ))


def downgrade() -> None:
    op.drop_index("ix_app_user_idp_subject", "app_user")

    with op.batch_alter_table("app_user", schema=None) as batch_op:
        batch_op.drop_constraint("uq_app_user_idp_subject", type_="unique")
        batch_op.drop_column("last_login_at")
        batch_op.drop_column("idp_subject")
