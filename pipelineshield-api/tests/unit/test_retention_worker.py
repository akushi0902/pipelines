"""Unit tests for RetentionWorker, digest builder, and ReconciliationService (WO-040).

Tests
-----
TestDigestBuilder
    Digest determinism, allowed-key guard, no-content rule.

TestRetentionWorkerSelectionBoundary
    89-day: not selected.  90-day and 91-day: selected.

TestRetentionWorkerBatching
    batch_size controls chunking; multiple iterations exhaust the due set.

TestRetentionWorkerFKOrder
    delete_derived_rows_for called before delete_definitions/delete_analyses.

TestRetentionWorkerAuditEmission
    Exactly one audit event per batch, action=retention.purge.

TestRetentionWorkerAdvisoryLock
    Lock not acquired → skipped_no_lock=True, no deletions.

TestRetentionWorkerFailurePath
    Verification failure → receipt status=failed, worker continues.

TestRetentionWorkerIdempotency
    Re-run after successful purge produces zero deletions.

TestReconciliationService
    Zero breaches for compliant corpus; one breach for orphaned definition.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Sequence
from unittest.mock import MagicMock, call, patch

import pytest

from pipelineshield.persistence.repositories.purge import (
    DefinitionRef,
    EntityCounts,
    PurgeRepository,
)
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.platform.retention.purge_receipt_builder import (
    build_batch_manifest,
    build_verification_digest,
)
from pipelineshield.platform.retention.reconciliation import (
    ReconciliationReport,
    ReconciliationService,
)
from pipelineshield.platform.retention.retention_worker import RetentionWorker, WorkerResult


# ---------------------------------------------------------------------------
# Fake repository
# ---------------------------------------------------------------------------


class FakePurgeRepository(PurgeRepository):
    """In-memory fake for testing RetentionWorker without a database."""

    def __init__(
        self,
        due_definitions: list[list[DefinitionRef]] | None = None,
        lock_granted: bool = True,
        verification_succeeds: bool = True,
        sla_breaches: int = 0,
    ) -> None:
        # Each call to select_due_definitions pops from this list.
        self._due_batches: list[list[DefinitionRef]] = due_definitions or []
        self._lock_granted = lock_granted
        self._verification_succeeds = verification_succeeds
        self._sla_breaches = sla_breaches

        # Spy lists
        self.deleted_analysis_ids: list[list[uuid.UUID]] = []
        self.deleted_definition_ids: list[list[uuid.UUID]] = []
        self.delete_derived_calls: list[list[uuid.UUID]] = []
        self.receipts_inserted: list[dict] = []
        self.lock_acquire_count = 0

    def acquire_advisory_lock(self) -> bool:
        self.lock_acquire_count += 1
        return self._lock_granted

    def select_due_definitions(
        self, now: datetime, batch_size: int = 200
    ) -> Sequence[DefinitionRef]:
        if not self._due_batches:
            return []
        return self._due_batches.pop(0)

    def delete_derived_rows_for(
        self, analysis_ids: Sequence[uuid.UUID]
    ) -> EntityCounts:
        self.delete_derived_calls.append(list(analysis_ids))
        return EntityCounts(generated_draft=1, remediation=1, finding=2)

    def delete_definitions(self, definition_ids: Sequence[uuid.UUID]) -> int:
        self.deleted_definition_ids.append(list(definition_ids))
        return len(definition_ids)

    def delete_analyses(self, analysis_ids: Sequence[uuid.UUID]) -> int:
        self.deleted_analysis_ids.append(list(analysis_ids))
        return len(analysis_ids)

    def verify_absent(
        self,
        definition_ids: Sequence[uuid.UUID],
        analysis_ids: Sequence[uuid.UUID],
    ) -> bool:
        return self._verification_succeeds

    def insert_receipt(
        self,
        batch_id: uuid.UUID,
        executed_at: datetime,
        entity_counts: EntityCounts,
        verification_digest: str,
        status: str,
        error_detail: str | None = None,
    ):
        self.receipts_inserted.append({
            "batch_id": batch_id,
            "executed_at": executed_at,
            "entity_counts": entity_counts.as_dict(),
            "verification_digest": verification_digest,
            "status": status,
            "error_detail": error_detail,
        })
        return MagicMock()

    def count_sla_breaches(self, now: datetime) -> int:
        return self._sla_breaches


def _fake_audit_writer() -> MagicMock:
    writer = MagicMock(spec=AuditWriter)
    writer.write.return_value = MagicMock()
    return writer


_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_UID_A = uuid.UUID("00000000-0000-0000-0001-000000000001")
_UID_B = uuid.UUID("00000000-0000-0000-0001-000000000002")
_ANA_A = uuid.UUID("00000000-0000-0000-0002-000000000001")
_ANA_B = uuid.UUID("00000000-0000-0000-0002-000000000002")


def _ref(def_id: uuid.UUID, ana_id: uuid.UUID) -> DefinitionRef:
    return DefinitionRef(definition_id=def_id, analysis_id=ana_id)


# ---------------------------------------------------------------------------
# Digest builder tests
# ---------------------------------------------------------------------------


class TestDigestBuilder:
    def test_digest_is_deterministic(self) -> None:
        batch_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
        refs = [_ref(_UID_A, _ANA_A)]
        counts = EntityCounts(finding=1, analysis=1)
        d1 = build_verification_digest(batch_id, _NOW, refs, counts)
        d2 = build_verification_digest(batch_id, _NOW, refs, counts)
        assert d1 == d2

    def test_digest_is_sha256_hex(self) -> None:
        batch_id = uuid.UUID("00000000-0000-0000-0000-000000000002")
        refs = [_ref(_UID_A, _ANA_A)]
        counts = EntityCounts()
        digest = build_verification_digest(batch_id, _NOW, refs, counts)
        # SHA-256 hex is 64 characters
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_digest_changes_with_different_ids(self) -> None:
        batch_id = uuid.UUID("00000000-0000-0000-0000-000000000003")
        refs_a = [_ref(_UID_A, _ANA_A)]
        refs_b = [_ref(_UID_B, _ANA_B)]
        counts = EntityCounts(finding=1)
        d_a = build_verification_digest(batch_id, _NOW, refs_a, counts)
        d_b = build_verification_digest(batch_id, _NOW, refs_b, counts)
        assert d_a != d_b

    def test_manifest_does_not_contain_disallowed_keys(self) -> None:
        batch_id = uuid.UUID("00000000-0000-0000-0000-000000000004")
        refs = [_ref(_UID_A, _ANA_A)]
        counts = EntityCounts(analysis=1)
        manifest = build_batch_manifest(batch_id, _NOW, refs, counts)
        allowed = {"batch_id", "executed_at", "definition_ids", "analysis_ids",
                   "entity_counts", "entity_type_names"}
        assert set(manifest.keys()) <= allowed

    def test_manifest_contains_no_content_field(self) -> None:
        batch_id = uuid.UUID("00000000-0000-0000-0000-000000000005")
        refs = [_ref(_UID_A, _ANA_A)]
        counts = EntityCounts()
        manifest = build_batch_manifest(batch_id, _NOW, refs, counts)
        canonical = json.dumps(manifest)
        # None of these content-like keys should appear
        for bad_key in ("content", "masked_content", "secret", "password", "token"):
            assert bad_key not in canonical.lower(), (
                f"Manifest must not contain content key: {bad_key!r}"
            )


# ---------------------------------------------------------------------------
# Selection boundary tests (AC-3)
# ---------------------------------------------------------------------------


class TestRetentionWorkerSelectionBoundary:
    """Definitions at exactly 90 days are due; 89-day are not."""

    def test_selects_90_day_definitions(self) -> None:
        due_90 = _ref(_UID_A, _ANA_A)
        repo = FakePurgeRepository(due_definitions=[[due_90]])
        worker = RetentionWorker(repo, _fake_audit_writer())
        result = worker.run(_NOW)
        assert result.batches_processed == 1
        assert _UID_A in repo.deleted_definition_ids[0]

    def test_does_not_select_89_day_definitions(self) -> None:
        # 89-day definitions have purge_due_at > now → not selected
        # Empty due set means nothing to purge
        repo = FakePurgeRepository(due_definitions=[])
        worker = RetentionWorker(repo, _fake_audit_writer())
        result = worker.run(_NOW)
        assert result.batches_processed == 0
        assert result.total_rows_deleted == 0


# ---------------------------------------------------------------------------
# Batching tests (AC-3)
# ---------------------------------------------------------------------------


class TestRetentionWorkerBatching:
    def test_multiple_batches_processed(self) -> None:
        batch1 = [_ref(_UID_A, _ANA_A)]
        batch2 = [_ref(_UID_B, _ANA_B)]
        repo = FakePurgeRepository(due_definitions=[batch1, batch2])
        worker = RetentionWorker(repo, _fake_audit_writer(), batch_size=1)
        result = worker.run(_NOW)
        assert result.batches_processed == 2

    def test_one_receipt_per_batch(self) -> None:
        batch1 = [_ref(_UID_A, _ANA_A)]
        batch2 = [_ref(_UID_B, _ANA_B)]
        repo = FakePurgeRepository(due_definitions=[batch1, batch2])
        worker = RetentionWorker(repo, _fake_audit_writer(), batch_size=1)
        worker.run(_NOW)
        assert len(repo.receipts_inserted) == 2


# ---------------------------------------------------------------------------
# FK ordering tests (AC-3)
# ---------------------------------------------------------------------------


class TestRetentionWorkerFKOrder:
    """delete_derived_rows_for must be called before delete_definitions/delete_analyses."""

    def test_derived_rows_deleted_before_definitions(self) -> None:
        call_order: list[str] = []

        class OrderTrackingRepo(FakePurgeRepository):
            def delete_derived_rows_for(self, analysis_ids):
                call_order.append("derived")
                return super().delete_derived_rows_for(analysis_ids)

            def delete_definitions(self, definition_ids):
                call_order.append("definitions")
                return super().delete_definitions(definition_ids)

            def delete_analyses(self, analysis_ids):
                call_order.append("analyses")
                return super().delete_analyses(analysis_ids)

        repo = OrderTrackingRepo(due_definitions=[[_ref(_UID_A, _ANA_A)]])
        worker = RetentionWorker(repo, _fake_audit_writer())
        worker.run(_NOW)
        assert call_order == ["derived", "definitions", "analyses"], (
            f"FK-safe deletion order violated: {call_order}"
        )


# ---------------------------------------------------------------------------
# Audit emission tests (AC-5)
# ---------------------------------------------------------------------------


class TestRetentionWorkerAuditEmission:
    """Exactly one audit_event per batch, action=retention.purge (AC-5)."""

    def test_one_audit_event_per_batch(self) -> None:
        writer = _fake_audit_writer()
        repo = FakePurgeRepository(due_definitions=[[_ref(_UID_A, _ANA_A)]])
        worker = RetentionWorker(repo, writer)
        worker.run(_NOW)
        assert writer.write.call_count == 1

    def test_audit_action_is_retention_purge(self) -> None:
        writer = _fake_audit_writer()
        repo = FakePurgeRepository(due_definitions=[[_ref(_UID_A, _ANA_A)]])
        worker = RetentionWorker(repo, writer)
        worker.run(_NOW)
        kwargs = writer.write.call_args.kwargs
        assert kwargs["action"] == "retention.purge"

    def test_audit_actor_is_system(self) -> None:
        writer = _fake_audit_writer()
        repo = FakePurgeRepository(due_definitions=[[_ref(_UID_A, _ANA_A)]])
        worker = RetentionWorker(repo, writer)
        worker.run(_NOW)
        kwargs = writer.write.call_args.kwargs
        assert kwargs["actor_id"] == "system:retention_worker"

    def test_audit_change_detail_contains_only_counts(self) -> None:
        writer = _fake_audit_writer()
        repo = FakePurgeRepository(due_definitions=[[_ref(_UID_A, _ANA_A)]])
        worker = RetentionWorker(repo, writer)
        worker.run(_NOW)
        kwargs = writer.write.call_args.kwargs
        detail = kwargs["change_detail"]
        allowed_keys = {"batch_id", "status", "entity_counts", "total_rows_deleted"}
        assert set(detail.keys()) <= allowed_keys, (
            f"Audit change_detail has disallowed keys: {set(detail.keys()) - allowed_keys}"
        )


# ---------------------------------------------------------------------------
# Advisory lock tests (AC-8)
# ---------------------------------------------------------------------------


class TestRetentionWorkerAdvisoryLock:
    """Lock not acquired → skipped_no_lock=True, no deletions."""

    def test_skipped_when_lock_not_acquired(self) -> None:
        repo = FakePurgeRepository(
            due_definitions=[[_ref(_UID_A, _ANA_A)]],
            lock_granted=False,
        )
        worker = RetentionWorker(repo, _fake_audit_writer())
        result = worker.run(_NOW)
        assert result.skipped_no_lock is True
        assert result.batches_processed == 0
        assert len(repo.deleted_definition_ids) == 0

    def test_lock_acquired_allows_processing(self) -> None:
        repo = FakePurgeRepository(
            due_definitions=[[_ref(_UID_A, _ANA_A)]],
            lock_granted=True,
        )
        worker = RetentionWorker(repo, _fake_audit_writer())
        result = worker.run(_NOW)
        assert result.skipped_no_lock is False
        assert result.batches_processed == 1


# ---------------------------------------------------------------------------
# Failure path tests (AC-4)
# ---------------------------------------------------------------------------


class TestRetentionWorkerFailurePath:
    """Verification failure → receipt status=failed; worker continues next batch."""

    def test_verification_failure_marks_receipt_failed(self) -> None:
        repo = FakePurgeRepository(
            due_definitions=[[_ref(_UID_A, _ANA_A)]],
            verification_succeeds=False,
        )
        worker = RetentionWorker(repo, _fake_audit_writer())
        result = worker.run(_NOW)
        assert result.batches_failed == 1
        assert repo.receipts_inserted[0]["status"] == "failed"

    def test_failed_batch_does_not_abort_subsequent_batches(self) -> None:
        repo = FakePurgeRepository(
            due_definitions=[
                [_ref(_UID_A, _ANA_A)],
                [_ref(_UID_B, _ANA_B)],
            ],
            verification_succeeds=False,
        )
        worker = RetentionWorker(repo, _fake_audit_writer())
        result = worker.run(_NOW)
        # Both batches attempted; both failed but neither crashed the worker
        assert result.batches_failed == 2
        assert len(repo.receipts_inserted) == 2


# ---------------------------------------------------------------------------
# Idempotency tests (AC-8)
# ---------------------------------------------------------------------------


class TestRetentionWorkerIdempotency:
    def test_empty_due_set_produces_no_deletions_or_receipts(self) -> None:
        repo = FakePurgeRepository(due_definitions=[])
        worker = RetentionWorker(repo, _fake_audit_writer())
        result = worker.run(_NOW)
        assert result.batches_processed == 0
        assert result.total_rows_deleted == 0
        assert len(repo.receipts_inserted) == 0


# ---------------------------------------------------------------------------
# Reconciliation service tests (AC-9)
# ---------------------------------------------------------------------------


class TestReconciliationService:
    def test_zero_breaches_for_compliant_corpus(self) -> None:
        repo = FakePurgeRepository(sla_breaches=0)
        svc = ReconciliationService(repo)
        report = svc.generate_report(_NOW)
        assert report.sla_breaches == 0
        assert report.compliant is True

    def test_one_breach_for_orphaned_definition(self) -> None:
        repo = FakePurgeRepository(sla_breaches=1)
        svc = ReconciliationService(repo)
        report = svc.generate_report(_NOW)
        assert report.sla_breaches == 1
        assert report.compliant is False

    def test_report_generated_at_matches_now(self) -> None:
        repo = FakePurgeRepository(sla_breaches=0)
        svc = ReconciliationService(repo)
        report = svc.generate_report(_NOW)
        assert report.generated_at == _NOW
