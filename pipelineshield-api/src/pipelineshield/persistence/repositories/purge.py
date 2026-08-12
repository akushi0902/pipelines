"""PurgeRepository — abstract interface and SQLAlchemy 2.0 implementation.

The purge repository is the only code path that issues DELETE statements on
Confidential tables.  All statements use parameterized values — no string
interpolation or raw SQL literals.

FK-safe deletion order
----------------------
1. generated_draft  (FK → analysis.id)
2. remediation      (FK → finding.id)
3. finding          (FK → analysis.id)
4. pipeline_definition (FK → analysis.id)
5. analysis         (FK → workspace.id, owner_id, catalogue_version_id)

Counts are returned per entity type so the caller can build an accurate
purge_receipt.entity_counts document.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from ..models.analysis import Analysis
from ..models.finding import Finding
from ..models.generated_draft import GeneratedDraft
from ..models.pipeline_definition import PipelineDefinition
from ..models.purge_receipt import PurgeReceipt
from ..models.remediation import Remediation


@dataclass
class DefinitionRef:
    """Minimal reference to a purgeable definition row."""

    definition_id: uuid.UUID
    analysis_id: uuid.UUID


@dataclass
class EntityCounts:
    """Row counts deleted per entity type in one batch."""

    generated_draft: int = 0
    remediation: int = 0
    finding: int = 0
    pipeline_definition: int = 0
    analysis: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "generated_draft": self.generated_draft,
            "remediation": self.remediation,
            "finding": self.finding,
            "pipeline_definition": self.pipeline_definition,
            "analysis": self.analysis,
        }

    @property
    def total(self) -> int:
        return (
            self.generated_draft
            + self.remediation
            + self.finding
            + self.pipeline_definition
            + self.analysis
        )


class PurgeRepository(ABC):
    """Abstract interface for the retention purge repository."""

    @abstractmethod
    def acquire_advisory_lock(self) -> bool:
        """Acquire an exclusive advisory lock for this purge run.

        Returns True if the lock was acquired (caller may proceed).
        Returns False if another instance holds the lock (caller must exit cleanly).
        On non-PostgreSQL backends this is a no-op that always returns True.
        """

    @abstractmethod
    def select_due_definitions(
        self,
        now: datetime,
        batch_size: int = 200,
    ) -> Sequence[DefinitionRef]:
        """Return up to *batch_size* definitions whose purge_due_at <= now.

        Excludes sample definitions (retention_class = 'sample').
        """

    @abstractmethod
    def delete_derived_rows_for(
        self,
        analysis_ids: Sequence[uuid.UUID],
    ) -> EntityCounts:
        """Hard-delete all derived rows for *analysis_ids* in FK-safe order.

        Returns counts per entity type.  Does NOT delete analysis or
        pipeline_definition rows — call delete_definitions/delete_analyses
        for those.
        """

    @abstractmethod
    def delete_definitions(
        self,
        definition_ids: Sequence[uuid.UUID],
    ) -> int:
        """Hard-delete pipeline_definition rows.  Returns count deleted."""

    @abstractmethod
    def delete_analyses(
        self,
        analysis_ids: Sequence[uuid.UUID],
    ) -> int:
        """Hard-delete analysis rows.  Returns count deleted."""

    @abstractmethod
    def verify_absent(
        self,
        definition_ids: Sequence[uuid.UUID],
        analysis_ids: Sequence[uuid.UUID],
    ) -> bool:
        """Return True if none of the given ids survive in the DB.

        Used as a post-delete existence check; any surviving row returns False.
        """

    @abstractmethod
    def insert_receipt(
        self,
        batch_id: uuid.UUID,
        executed_at: datetime,
        entity_counts: EntityCounts,
        verification_digest: str,
        status: str,
        error_detail: str | None = None,
        trigger: str = "scheduled",
        subject_user_id: uuid.UUID | None = None,
    ) -> PurgeReceipt:
        """Insert a purge_receipt row and return the managed instance."""

    @abstractmethod
    def count_sla_breaches(self, now: datetime) -> int:
        """Return the number of definitions past their purge_due_at with no receipt.

        A breach is a definition whose purge_due_at <= now and for which no
        purge_receipt covers the matching analysis (i.e. the definition
        was never purged).
        """


class SQLAlchemyPurgeRepository(PurgeRepository):
    """SQLAlchemy 2.0 implementation using parameterized statements only."""

    # Stable advisory-lock key for the purge worker (namespace + discriminator).
    _ADVISORY_LOCK_KEY: int = 0x70_75_72_67_65  # ASCII "purge" as int

    def __init__(self, session: Session) -> None:
        self._session = session

    def acquire_advisory_lock(self) -> bool:
        """Attempt to acquire a PostgreSQL transaction-level advisory lock.

        Falls back to True on non-PostgreSQL engines (SQLite in tests).
        """
        dialect = self._session.bind.dialect.name if self._session.bind else "unknown"  # type: ignore[union-attr]
        if dialect != "postgresql":
            return True
        result = self._session.execute(
            text("SELECT pg_try_advisory_xact_lock(:key)"),
            {"key": self._ADVISORY_LOCK_KEY},
        )
        return bool(result.scalar())

    def select_due_definitions(
        self,
        now: datetime,
        batch_size: int = 200,
    ) -> Sequence[DefinitionRef]:
        stmt = (
            select(PipelineDefinition.id, PipelineDefinition.analysis_id)
            .where(
                PipelineDefinition.purge_due_at <= now,
                PipelineDefinition.retention_class != "sample",
            )
            .order_by(PipelineDefinition.purge_due_at)
            .limit(batch_size)
        )
        rows = self._session.execute(stmt).fetchall()
        return [DefinitionRef(definition_id=r[0], analysis_id=r[1]) for r in rows]

    def delete_derived_rows_for(
        self,
        analysis_ids: Sequence[uuid.UUID],
    ) -> EntityCounts:
        if not analysis_ids:
            return EntityCounts()

        ids = list(analysis_ids)
        counts = EntityCounts()

        # 1. generated_draft (FK → analysis.id)
        stmt_gd = delete(GeneratedDraft).where(GeneratedDraft.analysis_id.in_(ids))
        counts.generated_draft = self._session.execute(stmt_gd).rowcount

        # 2. remediation (FK → finding.id) — must delete before finding
        finding_ids_stmt = select(Finding.id).where(Finding.analysis_id.in_(ids))
        finding_ids = [r[0] for r in self._session.execute(finding_ids_stmt).fetchall()]
        if finding_ids:
            stmt_rem = delete(Remediation).where(Remediation.finding_id.in_(finding_ids))
            counts.remediation = self._session.execute(stmt_rem).rowcount

        # 3. finding (FK → analysis.id)
        stmt_f = delete(Finding).where(Finding.analysis_id.in_(ids))
        counts.finding = self._session.execute(stmt_f).rowcount

        return counts

    def delete_definitions(
        self,
        definition_ids: Sequence[uuid.UUID],
    ) -> int:
        if not definition_ids:
            return 0
        stmt = delete(PipelineDefinition).where(
            PipelineDefinition.id.in_(list(definition_ids))
        )
        return self._session.execute(stmt).rowcount

    def delete_analyses(
        self,
        analysis_ids: Sequence[uuid.UUID],
    ) -> int:
        if not analysis_ids:
            return 0
        stmt = delete(Analysis).where(Analysis.id.in_(list(analysis_ids)))
        return self._session.execute(stmt).rowcount

    def verify_absent(
        self,
        definition_ids: Sequence[uuid.UUID],
        analysis_ids: Sequence[uuid.UUID],
    ) -> bool:
        """Return True if no purged rows survive (COUNT(*) = 0 for all id sets)."""
        def_ids = list(definition_ids)
        ana_ids = list(analysis_ids)

        if def_ids:
            count_def = self._session.execute(
                select(func.count()).where(PipelineDefinition.id.in_(def_ids))
            ).scalar_one()
            if count_def > 0:
                return False

        if ana_ids:
            count_ana = self._session.execute(
                select(func.count()).where(Analysis.id.in_(ana_ids))
            ).scalar_one()
            if count_ana > 0:
                return False

        return True

    def insert_receipt(
        self,
        batch_id: uuid.UUID,
        executed_at: datetime,
        entity_counts: EntityCounts,
        verification_digest: str,
        status: str,
        error_detail: str | None = None,
        trigger: str = "scheduled",
        subject_user_id: uuid.UUID | None = None,
    ) -> PurgeReceipt:
        receipt = PurgeReceipt(
            id=uuid.uuid4(),
            batch_id=batch_id,
            executed_at=executed_at,
            deleted_counts=entity_counts.as_dict(),
            verification_digest=verification_digest,
            status=status,
            error_detail=error_detail,
            trigger=trigger,
            subject_user_id=subject_user_id,
        )
        self._session.add(receipt)
        self._session.flush()
        return receipt

    def count_sla_breaches(self, now: datetime) -> int:
        """Count definitions past their retention window with no purge receipt.

        A definition is a breach if purge_due_at <= now and the corresponding
        analysis_id does not appear in any purge batch that succeeded/partially
        succeeded.  This is a conservative approximation: uses
        pipeline_definition.purge_due_at as the breach signal.
        """
        stmt = (
            select(func.count())
            .select_from(PipelineDefinition)
            .where(
                PipelineDefinition.purge_due_at <= now,
                PipelineDefinition.retention_class != "sample",
            )
        )
        return self._session.execute(stmt).scalar_one()
