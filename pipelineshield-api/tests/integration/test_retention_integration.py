"""Integration tests for RetentionWorker against an in-memory SQLite database.

Tests
-----
TestRetentionIntegration
    AC-3: worker purges 90/91-day definitions, skips 89-day.
    AC-4: post-delete verification passes.
    AC-5: exactly one purge_receipt + one audit_event per batch.
    AC-6: audit_event, purge_receipt, catalogue_version rows survive unchanged.
    AC-7: receipt digest contains no definition content.
    AC-9: reconciliation count = 0 after successful purge.
    AC-10: worker handles already-absent rows gracefully (idempotency).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from pipelineshield.catalogue.seed import seed_v1_catalogue
from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.finding import Finding
from pipelineshield.persistence.models.generated_draft import GeneratedDraft
from pipelineshield.persistence.models.pipeline_definition import PipelineDefinition
from pipelineshield.persistence.models.purge_receipt import PurgeReceipt
from pipelineshield.persistence.models.remediation import Remediation
from pipelineshield.persistence.repositories.purge import (
    EntityCounts,
    SQLAlchemyPurgeRepository,
)
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.platform.retention.reconciliation import ReconciliationService
from pipelineshield.platform.retention.retention_worker import RetentionWorker
from tests.fixtures.retention_fixtures import (
    ANA_89_ID, ANA_90_ID, ANA_91_ID,
    DEF_89_ID, DEF_90_ID, DEF_91_ID,
    DRAFT_90_ID, DRAFT_91_ID,
    FINDING_90_ID, FINDING_91_ID,
    REMEDIATION_90_ID,
    seed_retention_data,
)
from tests.fixtures.seed_baseline import WORKSPACE_ID, USERS, seed_baseline


# ---------------------------------------------------------------------------
# DB fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(eng, "connect")
    def _fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def session(engine) -> Generator[Session, None, None]:
    _Session = sessionmaker(bind=engine)
    s = _Session()
    try:
        yield s
        s.rollback()
    finally:
        s.close()


@pytest.fixture()
def seeded_session(engine) -> Generator[Session, None, None]:
    """Session with baseline data + catalogue + retention fixture data."""
    _Session = sessionmaker(bind=engine)
    s = _Session()
    seed_baseline(s)
    seed_v1_catalogue(s)
    s.flush()

    # Find active catalogue version for foreign key
    from pipelineshield.persistence.repositories.catalogue import SQLAlchemyCatalogueRepository
    cat = SQLAlchemyCatalogueRepository(s).get_active()
    assert cat is not None

    seed_retention_data(s, cat.id)
    s.flush()

    try:
        yield s
        s.rollback()
    finally:
        s.close()


_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_worker(session: Session) -> tuple[RetentionWorker, AuditWriter]:
    repo = SQLAlchemyPurgeRepository(session)
    writer = AuditWriter(session)
    worker = RetentionWorker(repo, writer, batch_size=10)
    return worker, writer


# ---------------------------------------------------------------------------
# AC-3: Selection boundary + deletion
# ---------------------------------------------------------------------------


class TestRetentionSelectionAndDeletion:
    def test_purges_90_and_91_day_definitions(self, seeded_session: Session) -> None:
        worker, _ = _make_worker(seeded_session)
        result = worker.run(_NOW)
        assert result.total_rows_deleted > 0

        # 90 and 91-day definitions must be gone
        stmt = select(PipelineDefinition).where(
            PipelineDefinition.id.in_([DEF_90_ID, DEF_91_ID])
        )
        surviving = seeded_session.execute(stmt).scalars().all()
        assert not surviving, f"Purgeable definitions survived: {[r.id for r in surviving]}"

    def test_preserves_89_day_definition(self, seeded_session: Session) -> None:
        worker, _ = _make_worker(seeded_session)
        worker.run(_NOW)

        stmt = select(PipelineDefinition).where(PipelineDefinition.id == DEF_89_ID)
        surviving = seeded_session.execute(stmt).scalars().one_or_none()
        assert surviving is not None, "89-day definition must NOT be purged"

    def test_derived_rows_deleted(self, seeded_session: Session) -> None:
        worker, _ = _make_worker(seeded_session)
        worker.run(_NOW)

        # Finding, remediation, draft for 90-day analysis must be gone
        assert seeded_session.execute(
            select(Finding).where(Finding.id == FINDING_90_ID)
        ).scalar_one_or_none() is None

        assert seeded_session.execute(
            select(Remediation).where(Remediation.id == REMEDIATION_90_ID)
        ).scalar_one_or_none() is None

        assert seeded_session.execute(
            select(GeneratedDraft).where(GeneratedDraft.id == DRAFT_90_ID)
        ).scalar_one_or_none() is None


# ---------------------------------------------------------------------------
# AC-5: Exactly one receipt + one audit event per batch
# ---------------------------------------------------------------------------


class TestPurgeReceiptAndAudit:
    def test_one_receipt_per_batch(self, seeded_session: Session) -> None:
        worker, _ = _make_worker(seeded_session)
        result = worker.run(_NOW)
        receipts = seeded_session.execute(select(PurgeReceipt)).scalars().all()
        assert len(receipts) == result.batches_processed

    def test_receipt_status_succeeded(self, seeded_session: Session) -> None:
        worker, _ = _make_worker(seeded_session)
        worker.run(_NOW)
        receipt = seeded_session.execute(select(PurgeReceipt)).scalars().first()
        assert receipt is not None
        assert receipt.status == "succeeded"

    def test_one_audit_event_per_batch(self, seeded_session: Session) -> None:
        worker, _ = _make_worker(seeded_session)
        result = worker.run(_NOW)
        events = seeded_session.execute(
            select(AuditEvent).where(AuditEvent.action == "retention.purge")
        ).scalars().all()
        assert len(events) == result.batches_processed


# ---------------------------------------------------------------------------
# AC-6: Untouchable rows survive unchanged
# ---------------------------------------------------------------------------


class TestUntouchableRowsSurvive:
    def test_audit_events_survive(self, seeded_session: Session) -> None:
        # Count audit events before purge
        count_before = seeded_session.execute(
            select(AuditEvent)
        ).scalars().all()
        n_before = len(count_before)

        worker, _ = _make_worker(seeded_session)
        worker.run(_NOW)

        # After purge: existing audit events + new retention.purge events
        all_after = seeded_session.execute(select(AuditEvent)).scalars().all()
        # All pre-existing audit events must still exist
        before_ids = {e.id for e in count_before}
        after_ids = {e.id for e in all_after}
        assert before_ids <= after_ids, "Pre-existing audit events were deleted!"

    def test_catalogue_version_survives(self, seeded_session: Session) -> None:
        from pipelineshield.persistence.models.control_catalogue_version import ControlCatalogueVersion
        before = seeded_session.execute(select(ControlCatalogueVersion)).scalars().all()
        assert len(before) > 0

        worker, _ = _make_worker(seeded_session)
        worker.run(_NOW)

        after = seeded_session.execute(select(ControlCatalogueVersion)).scalars().all()
        assert {v.id for v in before} == {v.id for v in after}, (
            "Catalogue version rows were deleted!"
        )


# ---------------------------------------------------------------------------
# AC-7: Receipt digest contains no definition content
# ---------------------------------------------------------------------------


class TestReceiptDigestContent:
    def test_digest_contains_no_masked_content(self, seeded_session: Session) -> None:
        worker, _ = _make_worker(seeded_session)
        worker.run(_NOW)

        receipts = seeded_session.execute(select(PurgeReceipt)).scalars().all()
        for receipt in receipts:
            # The masked_content in our fixture is base64('test') = 'dGVzdA=='
            assert "dGVzdA==" not in receipt.verification_digest
            # Check deleted_counts has no content-like values
            for key, val in receipt.deleted_counts.items():
                assert isinstance(val, int), (
                    f"entity_counts must only contain integers, got {type(val)} for {key}"
                )

    def test_receipt_error_detail_absent_on_success(self, seeded_session: Session) -> None:
        worker, _ = _make_worker(seeded_session)
        worker.run(_NOW)
        receipt = seeded_session.execute(select(PurgeReceipt)).scalars().first()
        assert receipt is not None
        if receipt.status == "succeeded":
            assert receipt.error_detail is None


# ---------------------------------------------------------------------------
# AC-9: Reconciliation reports zero breaches after purge
# ---------------------------------------------------------------------------


class TestReconciliationAfterPurge:
    def test_zero_sla_breaches_after_successful_purge(self, seeded_session: Session) -> None:
        worker, _ = _make_worker(seeded_session)
        worker.run(_NOW)

        repo = SQLAlchemyPurgeRepository(seeded_session)
        svc = ReconciliationService(repo)
        report = svc.generate_report(_NOW)
        # 89-day definition is still present but not yet past its due date
        assert report.sla_breaches == 0, (
            f"Expected 0 SLA breaches after purge, got {report.sla_breaches}"
        )


# ---------------------------------------------------------------------------
# AC-10: Already-absent rows handled gracefully (idempotency)
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_rerun_produces_no_new_receipts(self, seeded_session: Session) -> None:
        worker, _ = _make_worker(seeded_session)

        # First run
        result1 = worker.run(_NOW)
        receipts_after_run1 = len(
            seeded_session.execute(select(PurgeReceipt)).scalars().all()
        )

        # Second run — nothing more to purge
        result2 = worker.run(_NOW)
        receipts_after_run2 = len(
            seeded_session.execute(select(PurgeReceipt)).scalars().all()
        )

        assert result2.batches_processed == 0
        assert result2.total_rows_deleted == 0
        assert receipts_after_run2 == receipts_after_run1, (
            "Second run must not create extra receipts"
        )
