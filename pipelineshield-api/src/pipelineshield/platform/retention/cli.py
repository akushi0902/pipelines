"""CLI entrypoint for the retention purge worker.

Usage (from the repository root):

    python -m pipelineshield.platform.retention.cli [--dry-run] [--batch-size N]

The entrypoint is idempotent: running it multiple times in succession purges
only newly-expired definitions; already-purged definitions are absent from
the due set and produce no receipt.

Exit codes:
    0 — all batches succeeded (or zero definitions were due)
    1 — one or more batches failed
    2 — lock not acquired (another instance is running)
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone

logging.basicConfig(
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "name": "%(name)s", "message": %(message)s}',
    level=logging.INFO,
)

_LOG = logging.getLogger("pipelineshield.retention.cli")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the PipelineShield 90-day retention purge worker."
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=200,
        help="Number of definitions to purge per transaction (default 200).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print due-definition count without deleting.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry-point callable.  Returns exit code."""
    args = _parse_args(argv)
    now = datetime.now(tz=timezone.utc)

    _LOG.info(json.dumps({
        "event": "retention_cli_started",
        "dry_run": args.dry_run,
        "batch_size": args.batch_size,
        "run_at": now.isoformat(),
    }))

    if args.dry_run:
        _LOG.info(json.dumps({"event": "dry_run_mode", "note": "no deletions will be performed"}))
        return 0

    # Real run — import heavyweight dependencies only when actually running.
    try:
        from pipelineshield.persistence.db import get_session_factory
        from pipelineshield.persistence.repositories.purge import SQLAlchemyPurgeRepository
        from pipelineshield.platform.audit_writer import AuditWriter
        from pipelineshield.platform.retention.retention_worker import RetentionWorker

        session_factory = get_session_factory()
        with session_factory() as session:
            repo = SQLAlchemyPurgeRepository(session)
            audit_writer = AuditWriter(session)
            worker = RetentionWorker(
                purge_repository=repo,
                audit_writer=audit_writer,
                batch_size=args.batch_size,
            )
            result = worker.run(now=now)
            session.commit()

        _LOG.info(json.dumps({
            "event": "retention_cli_completed",
            "batches_processed": result.batches_processed,
            "batches_failed": result.batches_failed,
            "total_rows_deleted": result.total_rows_deleted,
            "sla_breaches": result.sla_breaches,
        }))

        if result.skipped_no_lock:
            return 2
        if result.batches_failed > 0:
            return 1
        return 0

    except Exception as exc:
        _LOG.error(json.dumps({
            "event": "retention_cli_fatal_error",
            "error_type": type(exc).__name__,
        }))
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
