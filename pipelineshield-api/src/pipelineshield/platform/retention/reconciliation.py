"""Reconciliation service — monthly upload-vs-receipt report.

Produces the purge_sla_breaches metric and a summary report pairing
uploaded definitions against purge receipts so the governance console
can confirm zero retention SLA violations.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from pipelineshield.persistence.repositories.purge import PurgeRepository
from pipelineshield.platform.retention.retention_worker import RETENTION_METRICS

__all__ = ["ReconciliationReport", "ReconciliationService"]

_LOG = logging.getLogger(__name__)


@dataclass
class ReconciliationReport:
    """Result of one reconciliation run."""

    generated_at: datetime
    definitions_past_due: int
    sla_breaches: int

    @property
    def compliant(self) -> bool:
        return self.sla_breaches == 0


class ReconciliationService:
    """Read-only service producing the monthly retention compliance report.

    Injected with a PurgeRepository to keep the reconciliation query inside
    the repository layer (parameterized SQL, no post-fetch filtering).
    """

    def __init__(self, purge_repository: PurgeRepository) -> None:
        self._repo = purge_repository

    def generate_report(self, now: datetime) -> ReconciliationReport:
        """Generate a compliance report as of *now*.

        Counts definitions past their purge_due_at and updates the in-process
        ``purge_sla_breaches`` metric for the governance console.
        """
        breaches = self._repo.count_sla_breaches(now)
        RETENTION_METRICS["purge_sla_breaches"] = breaches

        _LOG.info(
            "retention_reconciliation_report",
            extra={
                "generated_at": now.isoformat(),
                "sla_breaches": breaches,
                "compliant": breaches == 0,
            },
        )

        return ReconciliationReport(
            generated_at=now,
            definitions_past_due=breaches,
            sla_breaches=breaches,
        )
