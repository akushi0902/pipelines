"""UserRepository — upsert-first user persistence with masked email storage.

Full email addresses must never be stored at rest.  The ``upsert_by_idp_subject``
method masks the email before writing so the PII constraint is enforced at the
persistence boundary.
"""
from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from pipelineshield.persistence.models.app_user import AppUser


def _mask_email(email: str) -> str:
    """Return a masked form of *email*.

    The local part is replaced with its first character followed by ***.
    The domain name is replaced with its first character followed by ***.
    The TLD is preserved.

    Example: ``priya.dev@example.com`` → ``p***@e***.com``
    """
    try:
        local, domain = email.rsplit("@", 1)
        masked_local = (local[0] if local else "*") + "***"
        parts = domain.rsplit(".", 1)
        if len(parts) == 2:
            masked_domain = (parts[0][0] if parts[0] else "*") + "***"
            masked_full_domain = f"{masked_domain}.{parts[1]}"
        else:
            masked_full_domain = (domain[0] if domain else "*") + "***"
        return f"{masked_local}@{masked_full_domain}"
    except Exception:
        return "***@***.***"


class UserRepository:
    """Row-level scoped user persistence.

    All query methods are parameterized; no method returns users outside
    the caller's accessible workspaces.
    """

    def upsert_by_idp_subject(
        self,
        session: Session,
        *,
        idp_subject: str,
        email: str,
        display_name: str,
        workspace_id: uuid.UUID,
    ) -> AppUser:
        """Return the existing AppUser for *idp_subject*, or create a new one.

        The email is masked before storage.  On conflict (same idp_subject),
        masked_email and display_name are updated to reflect the latest IdP claims.
        """
        masked = _mask_email(email)

        stmt = select(AppUser).where(AppUser.idp_subject == idp_subject)
        row = session.execute(stmt).scalar_one_or_none()
        if row is not None:
            row.email = masked
            row.display_name = display_name
            session.flush()
            return row

        row = AppUser(
            id=uuid.uuid4(),
            workspace_id=workspace_id,
            sub_claim=idp_subject,
            idp_subject=idp_subject,
            email=masked,
            display_name=display_name,
        )
        session.add(row)
        session.flush()
        return row

    def get_by_id(
        self,
        session: Session,
        user_id: uuid.UUID,
        *,
        workspace_id: uuid.UUID,
    ) -> AppUser | None:
        """Return the AppUser with *user_id* scoped to *workspace_id*, or None."""
        stmt = select(AppUser).where(
            AppUser.id == user_id,
            AppUser.workspace_id == workspace_id,
        )
        return session.execute(stmt).scalar_one_or_none()

    def list_workspace_members(
        self,
        session: Session,
        *,
        workspace_id: uuid.UUID,
    ) -> Sequence[AppUser]:
        """Return all AppUsers scoped to *workspace_id*.

        This method cannot return members outside *workspace_id*.
        """
        stmt = (
            select(AppUser)
            .where(AppUser.workspace_id == workspace_id)
            .order_by(AppUser.display_name)
        )
        return session.execute(stmt).scalars().all()
