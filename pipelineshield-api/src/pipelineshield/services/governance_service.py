"""GovernanceService — read-oriented governance console data composition.

Composes AuditRepository, PurgeRepository, RetentionPolicy reads, and the
static classification registry. All SQL lives inside repositories; this
service only delegates, transforms, and computes.

No business logic for analysis, findings, or scoring lives here.
"""
from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.purge_receipt import PurgeReceipt
from pipelineshield.persistence.models.retention_policy import RetentionPolicy
from pipelineshield.persistence.repositories.audit import (
    SQLAlchemyAuditRepository,
    AuditPage,
)
from pipelineshield.persistence.repositories.purge import SQLAlchemyPurgeRepository
from pipelineshield.platform.audit_writer import AuditWriter


# ---------------------------------------------------------------------------
# Classification inventory registry (static — no DB required)
# ---------------------------------------------------------------------------

_CLASSIFICATION_REGISTRY: list[dict[str, str]] = [
    {
        "name": "pipeline_definition",
        "tier": "Confidential",
        "retention": "90 days (configurable, max 90)",
        "encryption": "Application-layer AES-256-GCM envelope encryption",
        "masking_rule": "Secrets redacted before encryption via RedactionEngine",
        "access_rule": "analysis:read:own (owner) or analysis:read:all (devsecops/appsec)",
    },
    {
        "name": "analysis",
        "tier": "Confidential",
        "retention": "90 days (follows pipeline_definition)",
        "encryption": "Row linked to encrypted pipeline_definition; score/grade are plaintext",
        "masking_rule": "No raw definition content stored; pipeline_ir_json contains masked IR only",
        "access_rule": "analysis:read:own or analysis:read:all",
    },
    {
        "name": "finding",
        "tier": "Confidential",
        "retention": "90 days (cascade-deleted with analysis)",
        "encryption": "None — findings reference masked IR nodes only, no raw pipeline content",
        "masking_rule": "Finding evidence references masked line numbers and construct names only",
        "access_rule": "analysis:read:own or analysis:read:all",
    },
    {
        "name": "generated_draft",
        "tier": "Confidential",
        "retention": "90 days (cascade-deleted with analysis)",
        "encryption": "None — draft text references masked constructs only",
        "masking_rule": "LLM prompts use masked IR; raw secrets never passed to model",
        "access_rule": "analysis:read:own or analysis:read:all",
    },
    {
        "name": "remediation",
        "tier": "Confidential",
        "retention": "90 days (cascade-deleted with finding)",
        "encryption": "None — remediation text is generic, not pipeline-specific",
        "masking_rule": "N/A — no pipeline content in remediation text",
        "access_rule": "analysis:read:own or analysis:read:all",
    },
    {
        "name": "audit_event",
        "tier": "Restricted",
        "retention": "1 year minimum (append-only, no deletion permitted)",
        "encryption": "None — change_detail must never contain secret values (ContentGuard enforced)",
        "masking_rule": "ContentGuard rejects events containing secret patterns before append",
        "access_rule": "audit:read (devsecops_engineer, appsec_lead) or governance:data",
    },
    {
        "name": "app_user",
        "tier": "Internal",
        "retention": "Until subject erasure request fulfilled",
        "encryption": "None — PII is display_name and email only; no password column",
        "masking_rule": "Source IP masked (last octet zeroed) in audit events",
        "access_rule": "governance:data for DSAR; admin:write for binding changes",
    },
    {
        "name": "purge_receipt",
        "tier": "Internal",
        "retention": "Indefinite (evidence record)",
        "encryption": "None",
        "masking_rule": "N/A — receipts contain counts and digests only, no pipeline content",
        "access_rule": "governance:data",
    },
    {
        "name": "role_binding",
        "tier": "Internal",
        "retention": "Until binding is revoked or user is erased",
        "encryption": "None",
        "masking_rule": "N/A",
        "access_rule": "admin:write for mutations; governance:data for read",
    },
    {
        "name": "retention_policy",
        "tier": "Internal",
        "retention": "Indefinite (single-row configuration)",
        "encryption": "None",
        "masking_rule": "N/A",
        "access_rule": "governance:data",
    },
    {
        "name": "workspace_score_rollup",
        "tier": "Internal",
        "retention": "Indefinite (aggregate, no raw content)",
        "encryption": "None",
        "masking_rule": "N/A — aggregated scores only",
        "access_rule": "analysis:read:all or engineering_manager summary view",
    },
    {
        "name": "control_catalogue_version",
        "tier": "Internal",
        "retention": "Indefinite (immutable version history)",
        "encryption": "None",
        "masking_rule": "N/A — control metadata only",
        "access_rule": "catalogue:read",
    },
]


# ---------------------------------------------------------------------------
# Cursor helpers for purge receipts (uses executed_at + batch_id)
# ---------------------------------------------------------------------------

def _encode_purge_cursor(executed_at: datetime, batch_id: uuid.UUID) -> str:
    raw = f"{executed_at.isoformat()}|{batch_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_purge_cursor(cursor: str) -> tuple[datetime, uuid.UUID] | None:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts_str, id_str = raw.split("|", 1)
        return datetime.fromisoformat(ts_str), uuid.UUID(id_str)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Dataclass results
# ---------------------------------------------------------------------------


@dataclass
class PurgePage:
    items: list[PurgeReceipt]
    next_cursor: str | None
    has_more: bool


@dataclass
class ExportPage:
    items: list[AuditEvent]
    next_cursor: str | None
    has_more: bool


@dataclass
class RetentionPolicyInfo:
    retention_days: int
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_run_status: str | None
    purge_sla_breaches: int
    updated_by: str | None
    updated_at: datetime | None


# ---------------------------------------------------------------------------
# GovernanceService
# ---------------------------------------------------------------------------


class GovernanceService:
    """Read-oriented governance data service.

    All SQL is delegated to repositories.  No business logic for scoring,
    findings, or analysis lives here.
    """

    # ----------------------------------------------------------------
    # Classification inventory
    # ----------------------------------------------------------------

    def get_classification_inventory(self) -> list[dict[str, str]]:
        """Return the static entity classification inventory."""
        return _CLASSIFICATION_REGISTRY

    # ----------------------------------------------------------------
    # Audit events (governance view — same data as audit_router but
    # requires governance:data instead of audit:read)
    # ----------------------------------------------------------------

    def get_audit_events(
        self,
        session: Session,
        *,
        workspace_id: uuid.UUID | None = None,
        actor_id: str | None = None,
        action: str | None = None,
        resource_type: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> AuditPage:
        repo = SQLAlchemyAuditRepository(session)
        return repo.list_scoped(
            workspace_id=workspace_id,
            action=action,
            actor_id=actor_id,
            resource_type=resource_type,
            from_dt=from_dt,
            to_dt=to_dt,
            cursor=cursor,
            limit=min(limit, 200),
        )

    # ----------------------------------------------------------------
    # Retention policy
    # ----------------------------------------------------------------

    def get_retention_policy(self, session: Session) -> RetentionPolicyInfo:
        """Read the current retention policy row and compute SLA breach count."""
        purge_repo = SQLAlchemyPurgeRepository(session)

        policy = session.execute(
            select(RetentionPolicy).where(RetentionPolicy.id == 1)
        ).scalar_one_or_none()

        # Last run: most recent purge receipt
        last_receipt = session.execute(
            select(PurgeReceipt)
            .order_by(PurgeReceipt.executed_at.desc())
            .limit(1)
        ).scalar_one_or_none()

        now = datetime.now(tz=timezone.utc)
        sla_breaches = purge_repo.count_sla_breaches(now)

        return RetentionPolicyInfo(
            retention_days=policy.retention_days if policy else 90,
            next_run_at=None,  # computed by scheduler; not persisted
            last_run_at=last_receipt.executed_at if last_receipt else None,
            last_run_status=last_receipt.status if last_receipt else None,
            purge_sla_breaches=sla_breaches,
            updated_by=str(policy.updated_by) if policy else None,
            updated_at=policy.updated_at if policy else None,
        )

    def update_retention_policy(
        self,
        session: Session,
        *,
        retention_days: int,
        actor_id: uuid.UUID,
        audit_writer: AuditWriter,
        workspace_id: uuid.UUID | None = None,
    ) -> RetentionPolicyInfo:
        """Upsert the single-row retention policy and emit exactly one audit event."""
        if retention_days < 1 or retention_days > 90:
            raise ValueError(
                f"retention_days must be between 1 and 90, got {retention_days}"
            )

        existing = session.execute(
            select(RetentionPolicy).where(RetentionPolicy.id == 1)
        ).scalar_one_or_none()

        before_days = existing.retention_days if existing else None

        if existing is None:
            policy = RetentionPolicy(
                id=1,
                retention_days=retention_days,
                updated_by=actor_id,
                updated_at=datetime.now(tz=timezone.utc),
            )
            session.add(policy)
        else:
            existing.retention_days = retention_days
            existing.updated_by = actor_id
            existing.updated_at = datetime.now(tz=timezone.utc)
            policy = existing

        session.flush()

        # Emit exactly one audit event with before/after values
        audit_writer.write(
            actor_id=str(actor_id),
            actor_user_id=actor_id,
            workspace_id=workspace_id,
            resource_type="retention_policy",
            resource_id="1",
            action="retention_policy.update",
            change_detail={
                "before": {"retention_days": before_days},
                "after": {"retention_days": retention_days},
            },
        )

        now = datetime.now(tz=timezone.utc)
        purge_repo = SQLAlchemyPurgeRepository(session)
        sla_breaches = purge_repo.count_sla_breaches(now)

        return RetentionPolicyInfo(
            retention_days=policy.retention_days,
            next_run_at=None,
            last_run_at=None,
            last_run_status=None,
            purge_sla_breaches=sla_breaches,
            updated_by=str(policy.updated_by),
            updated_at=policy.updated_at,
        )

    # ----------------------------------------------------------------
    # Purge receipts
    # ----------------------------------------------------------------

    def get_purge_receipts(
        self,
        session: Session,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ) -> PurgePage:
        limit = min(limit, 200)
        stmt = select(PurgeReceipt).order_by(
            PurgeReceipt.executed_at.desc(), PurgeReceipt.id
        )

        if cursor is not None:
            decoded = _decode_purge_cursor(cursor)
            if decoded is None:
                raise ValueError("Invalid pagination cursor.")
            cursor_dt, cursor_id = decoded
            from sqlalchemy import and_
            stmt = stmt.where(
                and_(
                    PurgeReceipt.executed_at <= cursor_dt,
                    PurgeReceipt.id != cursor_id,
                )
            )

        stmt = stmt.limit(limit + 1)
        rows = list(session.execute(stmt).scalars().all())

        next_cursor: str | None = None
        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]
            last = rows[-1]
            next_cursor = _encode_purge_cursor(last.executed_at, last.batch_id)

        return PurgePage(items=rows, next_cursor=next_cursor, has_more=has_more)

    # ----------------------------------------------------------------
    # Export history (reads audit events with action starting export.)
    # ----------------------------------------------------------------

    def get_export_history(
        self,
        session: Session,
        *,
        workspace_id: uuid.UUID | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> ExportPage:
        repo = SQLAlchemyAuditRepository(session)
        page = repo.list_scoped(
            workspace_id=workspace_id,
            action="export.create",
            cursor=cursor,
            limit=min(limit, 200),
        )
        return ExportPage(
            items=list(page.items),
            next_cursor=page.next_cursor,
            has_more=page.next_cursor is not None,
        )
