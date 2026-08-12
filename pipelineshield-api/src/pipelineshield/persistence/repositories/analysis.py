"""AnalysisRepository — abstract interface and SQLAlchemy implementation."""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.analysis import Analysis

if TYPE_CHECKING:
    from pipelineshield.api.security.scope import ActorScope


class AnalysisRepository(ABC):
    """Abstract repository interface for Analysis entities.

    All methods are synchronous to match the modular-monolith architecture.
    Row-level scoping by workspace_id is applied inside repository methods
    so that callers never compose ad-hoc WHERE clauses.
    """

    @abstractmethod
    def get_by_id(self, analysis_id: uuid.UUID, workspace_id: uuid.UUID) -> Analysis | None:
        """Return the analysis with *analysis_id* within *workspace_id*, or None."""

    @abstractmethod
    def list_by_workspace(
        self,
        workspace_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Analysis]:
        """Return analyses for *workspace_id*, newest first."""

    @abstractmethod
    def list_by_owner(
        self,
        workspace_id: uuid.UUID,
        owner_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Analysis]:
        """Return analyses owned by *owner_id* within *workspace_id*."""

    @abstractmethod
    def list_scoped(
        self,
        actor_scope: "ActorScope",
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Analysis]:
        """Return analyses visible to *actor_scope*.

        The WHERE clause is built entirely inside this method — no post-fetch
        filtering.  If ``actor_scope.read_all`` is True all rows in accessible
        workspaces are returned; otherwise only rows owned by the actor.
        """

    @abstractmethod
    def get_by_id_owner_scoped(
        self,
        analysis_id: uuid.UUID,
        owner_id: uuid.UUID,
        workspace_id: uuid.UUID,
    ) -> Analysis | None:
        """Return the analysis only if it belongs to *owner_id* in *workspace_id*.

        Returns None when the analysis does not exist or is not owned by the
        given actor.  Callers MUST return 404 (not 403) so existence is not
        disclosed to non-owners.
        """

    @abstractmethod
    def add(self, analysis: Analysis) -> Analysis:
        """Persist a new Analysis and return the managed instance."""

    @abstractmethod
    def delete(self, analysis: Analysis) -> None:
        """Hard-delete *analysis*.  No soft-delete path exists."""


class SQLAlchemyAnalysisRepository(AnalysisRepository):
    """SQLAlchemy 2.0 implementation of AnalysisRepository.

    Accepts a synchronous Session so that the caller controls the unit of
    work boundary and can compose multiple repository calls in a single
    transaction.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_id(
        self, analysis_id: uuid.UUID, workspace_id: uuid.UUID
    ) -> Analysis | None:
        stmt = select(Analysis).where(
            Analysis.id == analysis_id,
            Analysis.workspace_id == workspace_id,
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def list_by_workspace(
        self,
        workspace_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Analysis]:
        stmt = (
            select(Analysis)
            .where(Analysis.workspace_id == workspace_id)
            .order_by(Analysis.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return self._session.execute(stmt).scalars().all()

    def list_by_owner(
        self,
        workspace_id: uuid.UUID,
        owner_id: uuid.UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Analysis]:
        stmt = (
            select(Analysis)
            .where(
                Analysis.workspace_id == workspace_id,
                Analysis.owner_id == owner_id,
            )
            .order_by(Analysis.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return self._session.execute(stmt).scalars().all()

    def list_scoped(
        self,
        actor_scope: "ActorScope",
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Analysis]:
        """Return analyses visible to *actor_scope* via an in-predicate WHERE clause.

        Row-level scoping is applied in the SQL predicate:
        - workspace_id IN (actor_scope.workspace_ids)
        - if not read_all: additionally filter owner_id = actor_scope.actor_id

        This ensures a developer cannot see another developer's analyses even
        if they share a workspace, and a manager gets the same rows as read:all
        but the service layer shapes the response model.
        """
        from pipelineshield.api.security.scope import ActorScope as _ActorScope
        stmt = (
            select(Analysis)
            .where(Analysis.workspace_id.in_(list(actor_scope.workspace_ids)))
        )
        if not actor_scope.read_all:
            stmt = stmt.where(Analysis.owner_id == actor_scope.actor_id)
        stmt = stmt.order_by(Analysis.created_at.desc()).limit(limit).offset(offset)
        return self._session.execute(stmt).scalars().all()

    def get_by_id_owner_scoped(
        self,
        analysis_id: uuid.UUID,
        owner_id: uuid.UUID,
        workspace_id: uuid.UUID,
    ) -> Analysis | None:
        """Return analysis only if owned by *owner_id* in *workspace_id*.

        All three constraints are applied in a single SQL predicate — no
        post-fetch filtering — so the DB never reveals whether the row exists
        to a non-owner.
        """
        stmt = select(Analysis).where(
            Analysis.id == analysis_id,
            Analysis.owner_id == owner_id,
            Analysis.workspace_id == workspace_id,
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def add(self, analysis: Analysis) -> Analysis:
        self._session.add(analysis)
        self._session.flush()
        return analysis

    def delete(self, analysis: Analysis) -> None:
        self._session.delete(analysis)
        self._session.flush()
