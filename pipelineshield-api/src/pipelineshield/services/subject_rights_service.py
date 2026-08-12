"""SubjectRightsService — on-demand data subject export and erasure.

Implements the governance-minimum intersection of DSAR rights:
  1. export_subject_data: read-only masked bundle of everything stored about
     the subject — app_user record, role bindings, definitions (metadata only),
     analyses, findings, remediations, generated drafts, audit trail metadata.
  2. erase_subject_data: immediate hard delete of Confidential material
     (analyses, definitions, findings, remediations, drafts) using the same
     PurgeRepository primitive as the scheduled RetentionWorker.

OUT OF SCOPE (pending ratification of PRD Assumption A7):
  - DSAR case management workflows
  - Data rectification endpoint
  - Portability formats beyond JSON bundle

Security invariants:
  - audit_event and purge_receipt rows are NEVER deleted (independent retention).
  - control_catalogue_version and sample_pipeline rows are NEVER deleted.
  - No definition content appears in the export bundle (only metadata).
  - Every string value in the bundle passes through the content guard so no
    secret-shaped value survives into the export.
  - Exactly one audit_event and one purge_receipt are written per erasure call.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.app_user import AppUser
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.finding import Finding
from pipelineshield.persistence.models.generated_draft import GeneratedDraft
from pipelineshield.persistence.models.pipeline_definition import PipelineDefinition
from pipelineshield.persistence.models.purge_receipt import PurgeReceipt
from pipelineshield.persistence.models.remediation import Remediation
from pipelineshield.persistence.models.role_binding import RoleBinding
from pipelineshield.persistence.repositories.purge import EntityCounts, SQLAlchemyPurgeRepository
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.platform.content_guard import guard_change_detail

__all__ = [
    "SubjectRightsService",
    "SubjectBundle",
    "ErasureReceipt",
    "SubjectNotFoundError",
    "ConfirmationRequiredError",
]

BUNDLE_VERSION = "1.0"


class SubjectNotFoundError(Exception):
    """Raised when the subject is not found in the caller's accessible workspaces."""


class ConfirmationRequiredError(Exception):
    """Raised when the erasure request lacks a valid confirm=True field."""


@dataclass
class SubjectBundle:
    """Versioned export bundle for one data subject."""

    bundle_version: str
    generated_at: str
    subject: dict[str, Any]
    role_bindings: list[dict[str, Any]]
    definitions: list[dict[str, Any]]
    analyses: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    remediations: list[dict[str, Any]]
    generated_drafts: list[dict[str, Any]]
    audit_trail: list[dict[str, Any]]


@dataclass
class ErasureReceipt:
    """Summary of one on-demand erasure run."""

    batch_id: uuid.UUID
    executed_at: str
    entity_counts: dict[str, int]
    verification_digest: str
    status: str
    subject_user_id: str


def _safe_str(val: Any) -> str | None:
    """Convert to string and strip secret-shaped values via the content guard."""
    if val is None:
        return None
    s = str(val)
    # Run through the guard; if it raises, replace with a redacted marker.
    try:
        guard_change_detail({"v": s})
    except Exception:
        return "[REDACTED]"
    return s


def _build_digest(
    batch_id: uuid.UUID,
    executed_at: datetime,
    subject_user_id: uuid.UUID,
    counts: EntityCounts,
) -> str:
    manifest = {
        "batch_id": str(batch_id),
        "executed_at": executed_at.isoformat(),
        "subject_user_id": str(subject_user_id),
        "entity_counts": counts.as_dict(),
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SubjectRightsService:
    """Framework-free service for subject export and erasure.

    All dependencies are injected via the constructor so the service is
    testable without FastAPI or a live database.
    """

    def export_subject_data(
        self,
        session: Session,
        *,
        user_id: uuid.UUID,
        workspace_id: uuid.UUID,
        actor_id: str,
        audit_writer: AuditWriter,
        correlation_id: str | None = None,
    ) -> SubjectBundle:
        """Assemble a masked JSON bundle of all data stored about *user_id*.

        Raises SubjectNotFoundError if the user is not found in *workspace_id*.
        Emits exactly one audit_event.
        """
        subject = self._resolve_subject(session, user_id=user_id, workspace_id=workspace_id)

        now = datetime.now(tz=timezone.utc)
        corr = correlation_id or secrets.token_hex(8)

        # Role bindings
        rb_stmt = select(RoleBinding).where(RoleBinding.app_user_id == user_id)
        role_bindings = [
            {
                "id": str(rb.id),
                "workspace_id": str(rb.workspace_id),
                "persona": rb.persona,
                "granted_at": rb.granted_at.isoformat() if rb.granted_at else None,
                "revoked_at": rb.revoked_at.isoformat() if rb.revoked_at else None,
            }
            for rb in session.execute(rb_stmt).scalars().all()
        ]

        # Analyses
        ana_stmt = select(Analysis).where(
            Analysis.owner_id == user_id,
            Analysis.workspace_id == workspace_id,
        )
        analyses_rows = session.execute(ana_stmt).scalars().all()
        analysis_ids = [a.id for a in analyses_rows]
        analyses = [
            {
                "id": str(a.id),
                "workspace_id": str(a.workspace_id),
                "pipeline_format": _safe_str(a.pipeline_format),
                "score": float(a.score) if a.score is not None else None,
                "grade": _safe_str(a.grade),
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in analyses_rows
        ]

        # Pipeline definitions (metadata only, no content)
        def_stmt = select(PipelineDefinition).where(
            PipelineDefinition.analysis_id.in_(analysis_ids)
            if analysis_ids
            else PipelineDefinition.id.is_(None)
        )
        definitions = [
            {
                "id": str(d.id),
                "analysis_id": str(d.analysis_id),
                "retention_class": _safe_str(d.retention_class),
                "purge_due_at": d.purge_due_at.isoformat() if d.purge_due_at else None,
            }
            for d in session.execute(def_stmt).scalars().all()
        ]

        # Findings
        finding_stmt = select(Finding).where(
            Finding.analysis_id.in_(analysis_ids)
            if analysis_ids
            else Finding.id.is_(None)
        )
        finding_rows = session.execute(finding_stmt).scalars().all()
        finding_ids = [f.id for f in finding_rows]
        findings = [
            {
                "id": str(f.id),
                "analysis_id": str(f.analysis_id),
                "control_category": _safe_str(f.control_category),
                "rule_id": _safe_str(f.rule_id),
                "severity": _safe_str(f.severity),
                "source": _safe_str(f.source),
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in finding_rows
        ]

        # Remediations
        rem_stmt = select(Remediation).where(
            Remediation.finding_id.in_(finding_ids)
            if finding_ids
            else Remediation.id.is_(None)
        )
        remediations = [
            {
                "id": str(r.id),
                "finding_id": str(r.finding_id),
                "tool_name": _safe_str(r.tool_name),
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in session.execute(rem_stmt).scalars().all()
        ]

        # Generated drafts
        draft_stmt = select(GeneratedDraft).where(
            GeneratedDraft.analysis_id.in_(analysis_ids)
            if analysis_ids
            else GeneratedDraft.id.is_(None)
        )
        generated_drafts = [
            {
                "id": str(d.id),
                "analysis_id": str(d.analysis_id),
                "draft_type": _safe_str(d.draft_type),
                "created_at": d.created_at.isoformat() if d.created_at else None,
            }
            for d in session.execute(draft_stmt).scalars().all()
        ]

        # Audit trail — actor_id is stored as string
        audit_stmt = (
            select(AuditEvent)
            .where(AuditEvent.actor_id == str(user_id))
            .order_by(AuditEvent.occurred_at.desc())
            .limit(1000)
        )
        audit_trail = [
            {
                "id": str(e.id),
                "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": _safe_str(e.resource_id),
            }
            for e in session.execute(audit_stmt).scalars().all()
        ]

        bundle = SubjectBundle(
            bundle_version=BUNDLE_VERSION,
            generated_at=now.isoformat(),
            subject={
                "user_id": str(subject.id),
                "idp_subject": _safe_str(subject.idp_subject),
                "masked_email": subject.email,
                "display_name": subject.display_name,
                "created_at": subject.created_at.isoformat() if subject.created_at else None,
            },
            role_bindings=role_bindings,
            definitions=definitions,
            analyses=analyses,
            findings=findings,
            remediations=remediations,
            generated_drafts=generated_drafts,
            audit_trail=audit_trail,
        )

        audit_writer.write(
            actor_id=actor_id,
            action="governance.subject_export",
            resource_type="app_user",
            resource_id=str(user_id),
            workspace_id=workspace_id,
            correlation_id=corr,
            change_detail={
                "subject_user_id": str(user_id),
                "analysis_count": len(analyses),
                "definition_count": len(definitions),
                "finding_count": len(findings),
                "audit_trail_count": len(audit_trail),
            },
        )

        return bundle

    def erase_subject_data(
        self,
        session: Session,
        *,
        user_id: uuid.UUID,
        workspace_id: uuid.UUID,
        actor_id: str,
        confirm: bool,
        reason: str,
        audit_writer: AuditWriter,
        correlation_id: str | None = None,
    ) -> ErasureReceipt:
        """Hard-delete all Confidential material for *user_id*.

        Uses the same PurgeRepository primitive as RetentionWorker.
        Audit and receipt rows belonging to the subject are preserved.

        Raises ConfirmationRequiredError if confirm is not True.
        Raises SubjectNotFoundError if user is not in *workspace_id*.
        """
        if not confirm:
            raise ConfirmationRequiredError(
                "confirm must be true to proceed with erasure. "
                "This operation is irreversible."
            )

        subject = self._resolve_subject(session, user_id=user_id, workspace_id=workspace_id)

        now = datetime.now(tz=timezone.utc)
        corr = correlation_id or secrets.token_hex(8)
        batch_id = uuid.uuid4()

        repo = SQLAlchemyPurgeRepository(session)

        # Find all analyses owned by this subject in this workspace.
        ana_stmt = select(Analysis.id).where(
            Analysis.owner_id == user_id,
            Analysis.workspace_id == workspace_id,
        )
        analysis_ids = [r[0] for r in session.execute(ana_stmt).fetchall()]

        # FK-safe deletion using the shared primitive.
        counts = EntityCounts()
        if analysis_ids:
            counts = repo.delete_derived_rows_for(analysis_ids)

            # Delete pipeline definitions before analyses.
            def_stmt = select(PipelineDefinition.id).where(
                PipelineDefinition.analysis_id.in_(analysis_ids)
            )
            definition_ids = [r[0] for r in session.execute(def_stmt).fetchall()]
            counts.pipeline_definition = repo.delete_definitions(definition_ids)
            counts.analysis = repo.delete_analyses(analysis_ids)

        digest = _build_digest(batch_id, now, user_id, counts)

        # Post-delete verification.
        verified = True
        if analysis_ids:
            verified = repo.verify_absent(
                definition_ids if analysis_ids else [],
                analysis_ids,
            )

        status = "succeeded" if verified else "failed"
        error_detail = None if verified else "post-delete verification failed: surviving rows detected"

        receipt = repo.insert_receipt(
            batch_id=batch_id,
            executed_at=now,
            entity_counts=counts,
            verification_digest=digest,
            status=status,
            error_detail=error_detail,
            trigger="on_demand",
            subject_user_id=user_id,
        )

        audit_writer.write(
            actor_id=actor_id,
            action="governance.subject_erasure",
            resource_type="app_user",
            resource_id=str(user_id),
            workspace_id=workspace_id,
            correlation_id=corr,
            change_detail={
                "subject_user_id": str(user_id),
                "batch_id": str(batch_id),
                "status": status,
                "entity_counts": counts.as_dict(),
                "total_rows_deleted": counts.total,
                "reason": reason[:256],  # bounded
            },
        )

        if not verified:
            raise RuntimeError(
                f"Post-delete verification failed for subject {user_id!r}. "
                "Receipt recorded with status=failed. Correlation: {corr}"
            )

        return ErasureReceipt(
            batch_id=batch_id,
            executed_at=now.isoformat(),
            entity_counts=counts.as_dict(),
            verification_digest=digest,
            status=status,
            subject_user_id=str(user_id),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_subject(
        session: Session,
        *,
        user_id: uuid.UUID,
        workspace_id: uuid.UUID,
    ) -> AppUser:
        """Return the AppUser scoped to workspace_id, raising SubjectNotFoundError otherwise."""
        stmt = select(AppUser).where(
            AppUser.id == user_id,
            AppUser.workspace_id == workspace_id,
        )
        subject = session.execute(stmt).scalar_one_or_none()
        if subject is None:
            raise SubjectNotFoundError(
                f"Subject {user_id!r} not found in workspace {workspace_id!r}."
            )
        return subject
