"""RetentionWorker — scheduled hard-delete worker for 90-day retention policy.

The worker is a framework-free class with all dependencies injected via
the constructor.  It has no imports from FastAPI, Celery, or any scheduler
so it can be invoked from any external cron/CronJob.

Execution model
---------------
1. Acquire advisory lock (PostgreSQL: pg_try_advisory_xact_lock; SQLite: no-op).
2. Select a batch of pipeline_definition rows with purge_due_at <= now.
3. For each batch:
   a. Hard-delete derived rows in FK-safe order inside one transaction.
   b. Verify absence (COUNT(*) = 0 for purged id sets).
   c. Insert purge_receipt + exactly one audit_event (retention.purge).
   d. On failure: record receipt with status=failed, log, continue.
4. Return a summary dict (batches processed, total rows deleted, SLA breaches).

Security constraints
--------------------
- The worker NEVER issues DELETE/UPDATE against audit_event, purge_receipt,
  control_catalogue_version or sample_pipeline.
- No exception message includes row content — only ids and counts.
- The verification digest is computed from metadata only (see purge_receipt_builder).
"""
from __future__ import annotations

import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from pipelineshield.persistence.repositories.purge import (
    DefinitionRef,
    EntityCounts,
    PurgeRepository,
)
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.platform.retention.purge_receipt_builder import build_verification_digest

__all__ = ["RetentionWorker", "WorkerResult", "RETENTION_METRICS"]

_LOG = logging.getLogger(__name__)

# In-process counters — replace with Prometheus/MetricsEmitter in production.
RETENTION_METRICS: dict[str, int] = {
    "retention_rows_deleted_total": 0,
    "retention_batches_failed_total": 0,
    "purge_sla_breaches": 0,
}

_DEFAULT_BATCH_SIZE = 200
_ACTOR_SYSTEM = "system:retention_worker"


@dataclass
class WorkerResult:
    """Summary of one RetentionWorker.run() invocation."""

    batches_processed: int = 0
    batches_failed: int = 0
    total_rows_deleted: int = 0
    skipped_no_lock: bool = False
    sla_breaches: int = 0
    batch_ids: list[uuid.UUID] = field(default_factory=list)


class RetentionWorker:
    """Scheduled retention purge worker.

    Parameters
    ----------
    purge_repository:
        Repository used for all purge SQL.  Must be a new instance per run
        (owns a single SQLAlchemy Session for the duration of each batch).
    audit_writer:
        AuditWriter instance for emitting retention.purge audit events.
    batch_size:
        Maximum number of definitions per batch (default 200).
    clock:
        Callable returning the current UTC datetime.  Defaults to
        ``datetime.now(tz=timezone.utc)``.  Inject a frozen clock in tests.
    session_factory:
        Optional callable returning a new Session per batch.  When provided
        each batch runs in its own session/transaction.  When None the
        repository's embedded session is used for all batches (integration
        test pattern).
    """

    def __init__(
        self,
        purge_repository: PurgeRepository,
        audit_writer: AuditWriter,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repo = purge_repository
        self._audit_writer = audit_writer
        self._batch_size = batch_size
        self._clock = clock or (lambda: datetime.now(tz=timezone.utc))

    def run(self, now: datetime | None = None) -> WorkerResult:
        """Execute the full purge run.

        Parameters
        ----------
        now:
            Override the current time (useful for tests).  Defaults to
            ``self._clock()``.
        """
        if now is None:
            now = self._clock()

        result = WorkerResult()
        start_time = time.monotonic()

        _LOG.info(
            "retention_worker_started",
            extra={"run_at": now.isoformat(), "batch_size": self._batch_size},
        )

        # Acquire advisory lock — prevents concurrent runs.
        if not self._repo.acquire_advisory_lock():
            _LOG.warning(
                "retention_worker_lock_not_acquired",
                extra={"reason": "another instance holds the advisory lock"},
            )
            result.skipped_no_lock = True
            return result

        while True:
            due = self._repo.select_due_definitions(now, self._batch_size)
            if not due:
                break

            batch_id = uuid.uuid4()
            result.batch_ids.append(batch_id)
            batch_start = time.monotonic()
            definition_ids = [r.definition_id for r in due]
            analysis_ids = [r.analysis_id for r in due]
            correlation_id = secrets.token_hex(8)

            try:
                counts = self._run_batch(due, analysis_ids, definition_ids)
                duration_ms = int((time.monotonic() - batch_start) * 1000)

                # Verify absence (post-delete existence check).
                verified = self._repo.verify_absent(definition_ids, analysis_ids)
                if not verified:
                    _LOG.error(
                        "retention_batch_verification_failed",
                        extra={
                            "batch_id": str(batch_id),
                            "correlation_id": correlation_id,
                            "definition_count": len(definition_ids),
                        },
                    )
                    digest = build_verification_digest(batch_id, now, due, counts)
                    self._repo.insert_receipt(
                        batch_id=batch_id,
                        executed_at=now,
                        entity_counts=counts,
                        verification_digest=digest,
                        status="failed",
                        error_detail="post-delete verification failed: surviving rows detected",
                    )
                    self._emit_audit(batch_id, counts, status="failed", correlation_id=correlation_id)
                    result.batches_failed += 1
                    RETENTION_METRICS["retention_batches_failed_total"] += 1
                    continue

                digest = build_verification_digest(batch_id, now, due, counts)
                self._repo.insert_receipt(
                    batch_id=batch_id,
                    executed_at=now,
                    entity_counts=counts,
                    verification_digest=digest,
                    status="succeeded",
                )
                self._emit_audit(batch_id, counts, status="succeeded", correlation_id=correlation_id)

                result.batches_processed += 1
                result.total_rows_deleted += counts.total
                RETENTION_METRICS["retention_rows_deleted_total"] += counts.total

                _LOG.info(
                    "retention_batch_completed",
                    extra={
                        "batch_id": str(batch_id),
                        "definition_count": len(definition_ids),
                        "rows_deleted": counts.total,
                        "duration_ms": duration_ms,
                        "status": "succeeded",
                    },
                )

            except Exception as exc:
                _LOG.error(
                    "retention_batch_error",
                    extra={
                        "batch_id": str(batch_id),
                        "correlation_id": correlation_id,
                        "error_type": type(exc).__name__,
                        "definition_count": len(definition_ids),
                    },
                    exc_info=False,
                )
                result.batches_failed += 1
                RETENTION_METRICS["retention_batches_failed_total"] += 1
                try:
                    empty_counts = EntityCounts()
                    digest = build_verification_digest(batch_id, now, due, empty_counts)
                    self._repo.insert_receipt(
                        batch_id=batch_id,
                        executed_at=now,
                        entity_counts=empty_counts,
                        verification_digest=digest,
                        status="failed",
                        error_detail=f"batch error: {type(exc).__name__}",
                    )
                    self._emit_audit(batch_id, empty_counts, status="failed", correlation_id=correlation_id)
                except Exception:
                    _LOG.error(
                        "retention_receipt_write_failed",
                        extra={"batch_id": str(batch_id)},
                        exc_info=False,
                    )

        # Reconcile SLA breaches (definitions still past due after run).
        sla_breaches = self._repo.count_sla_breaches(now)
        result.sla_breaches = sla_breaches
        RETENTION_METRICS["purge_sla_breaches"] = sla_breaches

        duration_total_ms = int((time.monotonic() - start_time) * 1000)
        _LOG.info(
            "retention_worker_completed",
            extra={
                "batches_processed": result.batches_processed,
                "batches_failed": result.batches_failed,
                "total_rows_deleted": result.total_rows_deleted,
                "sla_breaches": result.sla_breaches,
                "duration_ms": duration_total_ms,
            },
        )

        return result

    def _run_batch(
        self,
        due: list[DefinitionRef],
        analysis_ids: list[uuid.UUID],
        definition_ids: list[uuid.UUID],
    ) -> EntityCounts:
        """Execute FK-safe deletes for one batch and return counts."""
        counts = self._repo.delete_derived_rows_for(analysis_ids)
        counts.pipeline_definition = self._repo.delete_definitions(definition_ids)
        counts.analysis = self._repo.delete_analyses(analysis_ids)
        return counts

    def _emit_audit(
        self,
        batch_id: uuid.UUID,
        counts: EntityCounts,
        status: str,
        correlation_id: str,
    ) -> None:
        """Write exactly one audit_event per batch."""
        self._audit_writer.write(
            actor_id=_ACTOR_SYSTEM,
            actor_persona="system",
            action="retention.purge",
            resource_type="purge_batch",
            resource_id=str(batch_id),
            correlation_id=correlation_id,
            change_detail={
                "batch_id": str(batch_id),
                "status": status,
                "entity_counts": counts.as_dict(),
                "total_rows_deleted": counts.total,
            },
        )
