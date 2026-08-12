"""FindingRepository — abstract interface and SQLAlchemy implementation."""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.finding import Finding

if TYPE_CHECKING:
    from pipelineshield.analysis.anchoring.models import ValidatedFinding
    from pipelineshield.api.security.scope import ActorScope


class FindingRepository(ABC):
    """Abstract repository interface for Finding entities.

    Row-level scoping by workspace_id is applied inside repository methods.
    """

    @abstractmethod
    def get_by_id(
        self, finding_id: uuid.UUID, workspace_id: uuid.UUID
    ) -> Finding | None:
        """Return the finding with *finding_id* within *workspace_id*, or None."""

    @abstractmethod
    def list_by_analysis(
        self,
        analysis_id: uuid.UUID,
        workspace_id: uuid.UUID,
        *,
        source: str | None = None,
    ) -> Sequence[Finding]:
        """Return findings for *analysis_id*, optionally filtered by *source*."""

    @abstractmethod
    def list_scoped(
        self,
        actor_scope: "ActorScope",
        *,
        analysis_id: uuid.UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Finding]:
        """Return findings visible to *actor_scope*.

        Workspace scoping is applied in the SQL predicate.  Optionally further
        filtered by analysis_id.  Post-fetch filtering is not permitted.
        """

    @abstractmethod
    def add(self, finding: Finding) -> Finding:
        """Persist a new Finding and return the managed instance."""

    @abstractmethod
    def add_many(self, findings: list[Finding]) -> list[Finding]:
        """Bulk-persist a list of Findings."""

    @abstractmethod
    def save_all(self, validated_findings: "list[ValidatedFinding]") -> list[Finding]:
        """Persist validated findings after anchor-gate enforcement.

        Accepts only ValidatedFinding instances — a raw CandidateFinding or any
        other type raises TypeError at this boundary (runtime isinstance guard).
        """

    @abstractmethod
    def delete(self, finding: Finding) -> None:
        """Hard-delete *finding*.  No soft-delete path exists."""


class SQLAlchemyFindingRepository(FindingRepository):
    """SQLAlchemy 2.0 implementation of FindingRepository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_id(
        self, finding_id: uuid.UUID, workspace_id: uuid.UUID
    ) -> Finding | None:
        stmt = select(Finding).where(
            Finding.id == finding_id,
            Finding.workspace_id == workspace_id,
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def list_by_analysis(
        self,
        analysis_id: uuid.UUID,
        workspace_id: uuid.UUID,
        *,
        source: str | None = None,
    ) -> Sequence[Finding]:
        stmt = select(Finding).where(
            Finding.analysis_id == analysis_id,
            Finding.workspace_id == workspace_id,
        )
        if source is not None:
            stmt = stmt.where(Finding.source == source)
        stmt = stmt.order_by(Finding.created_at)
        return self._session.execute(stmt).scalars().all()

    def list_scoped(
        self,
        actor_scope: "ActorScope",
        *,
        analysis_id: uuid.UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Finding]:
        """Return findings visible to *actor_scope* via an in-predicate WHERE clause.

        Row-level scoping: workspace_id IN (actor_scope.workspace_ids).
        Optionally filtered by analysis_id for per-analysis views.
        """
        stmt = select(Finding).where(
            Finding.workspace_id.in_(list(actor_scope.workspace_ids))
        )
        if analysis_id is not None:
            stmt = stmt.where(Finding.analysis_id == analysis_id)
        stmt = stmt.order_by(Finding.created_at).limit(limit).offset(offset)
        return self._session.execute(stmt).scalars().all()

    def add(self, finding: Finding) -> Finding:
        self._session.add(finding)
        self._session.flush()
        return finding

    def add_many(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            self._session.add(f)
        self._session.flush()
        return findings

    def save_all(self, validated_findings: "list[ValidatedFinding]") -> list[Finding]:
        from pipelineshield.analysis.anchoring.models import ValidatedFinding as _VF

        for item in validated_findings:
            if not isinstance(item, _VF):
                raise TypeError(
                    f"save_all() accepts only ValidatedFinding instances; "
                    f"got {type(item).__name__!r}. "
                    "Route candidates through AnchorValidator.validate() first."
                )

        db_source_map = {"ai_advisory": "ai", "deterministic": "deterministic"}
        db_findings: list[Finding] = []
        for vf in validated_findings:
            db_source = db_source_map.get(vf.source, vf.source)
            f = Finding(
                workspace_id=vf.workspace_id,
                analysis_id=vf.analysis_id,
                source=db_source,
                requires_human_review=vf.requires_human_review,
                control_id=vf.control_id,
                control_category=vf.category,
                rule_id=vf.rule_id,
                severity=vf.severity,
                weight=vf.weight,
                title=vf.title,
                description=vf.description,
                anchor_line=vf.anchor_line,
                anchor_column=vf.anchor_column,
                evidence={**vf.evidence, "snippet": vf.snippet},
            )
            db_findings.append(f)

        return self.add_many(db_findings)

    def delete(self, finding: Finding) -> None:
        self._session.delete(finding)
        self._session.flush()
