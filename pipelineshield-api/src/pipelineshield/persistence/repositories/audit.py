"""AuditRepository — abstract interface and SQLAlchemy implementation.

The audit_event table is append-only.  This repository exposes only INSERT
and SELECT operations — there are no update or delete methods.

INVARIANT: change_detail MUST NEVER contain definition content or secret
values.  This is enforced by convention and code review.
"""
from __future__ import annotations

import base64
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from ..models.audit_event import AuditEvent


@dataclass
class AuditPage:
    """A cursor-paginated page of audit events."""

    items: Sequence[AuditEvent]
    next_cursor: str | None


def _encode_cursor(occurred_at: datetime, event_id: uuid.UUID) -> str:
    raw = f"{occurred_at.isoformat()}|{event_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID] | None:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts_str, id_str = raw.split("|", 1)
        return datetime.fromisoformat(ts_str), uuid.UUID(id_str)
    except Exception:
        return None


class AuditRepository(ABC):
    """Abstract repository for AuditEvent — append-only operations only.

    No update or delete methods are provided.  The database role enforces this
    constraint at the privilege level; the Python interface reinforces it.
    """

    @abstractmethod
    def append(self, event: AuditEvent) -> AuditEvent:
        """Append a new audit event record and return the managed instance.

        This is the only write method — there is no update or delete.
        """

    @abstractmethod
    def list_scoped(
        self,
        *,
        workspace_id: uuid.UUID | None = None,
        action: str | None = None,
        actor_id: str | None = None,
        resource_type: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> AuditPage:
        """Return a cursor-paginated page of audit events scoped to a workspace."""

    @abstractmethod
    def list_by_resource(
        self,
        resource_type: str,
        resource_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[AuditEvent]:
        """Return audit events for a specific resource, newest first."""

    @abstractmethod
    def list_by_actor(
        self,
        actor_id: str,
        *,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[AuditEvent]:
        """Return audit events for a specific actor, newest first."""


class SQLAlchemyAuditRepository(AuditRepository):
    """SQLAlchemy 2.0 implementation of AuditRepository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, event: AuditEvent) -> AuditEvent:
        self._session.add(event)
        self._session.flush()
        return event

    def list_scoped(
        self,
        *,
        workspace_id: uuid.UUID | None = None,
        action: str | None = None,
        actor_id: str | None = None,
        resource_type: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> AuditPage:
        limit = min(limit, 200)  # hard cap
        stmt = select(AuditEvent)

        if workspace_id is not None:
            stmt = stmt.where(AuditEvent.workspace_id == workspace_id)
        if action is not None:
            stmt = stmt.where(AuditEvent.action == action)
        if actor_id is not None:
            stmt = stmt.where(AuditEvent.actor_id == actor_id)
        if resource_type is not None:
            stmt = stmt.where(AuditEvent.resource_type == resource_type)
        if from_dt is not None:
            stmt = stmt.where(AuditEvent.occurred_at >= from_dt)
        if to_dt is not None:
            stmt = stmt.where(AuditEvent.occurred_at <= to_dt)

        if cursor is not None:
            decoded = _decode_cursor(cursor)
            if decoded is not None:
                cursor_dt, cursor_id = decoded
                stmt = stmt.where(
                    and_(
                        AuditEvent.occurred_at <= cursor_dt,
                        AuditEvent.id != cursor_id,
                    )
                )

        stmt = stmt.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id).limit(limit + 1)
        rows = list(self._session.execute(stmt).scalars().all())

        next_cursor: str | None = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            next_cursor = _encode_cursor(last.occurred_at, last.id)

        return AuditPage(items=rows, next_cursor=next_cursor)

    def list_by_resource(
        self,
        resource_type: str,
        resource_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[AuditEvent]:
        stmt = (
            select(AuditEvent)
            .where(
                AuditEvent.resource_type == resource_type,
                AuditEvent.resource_id == resource_id,
            )
            .order_by(AuditEvent.occurred_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return self._session.execute(stmt).scalars().all()

    def list_by_actor(
        self,
        actor_id: str,
        *,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[AuditEvent]:
        stmt = select(AuditEvent).where(AuditEvent.actor_id == actor_id)
        if since is not None:
            stmt = stmt.where(AuditEvent.occurred_at >= since)
        stmt = (
            stmt.order_by(AuditEvent.occurred_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return self._session.execute(stmt).scalars().all()
