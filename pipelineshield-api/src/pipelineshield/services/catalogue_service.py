"""CatalogueService — business logic for catalogue read and version creation.

All domain rules live here; the router stays thin.

Transaction contract
--------------------
``apply_changes`` expects the SQLAlchemy Session to be in an open transaction
(the FastAPI ``get_db`` dependency begins one).  The service flushes but never
commits or rolls back — the caller owns the transaction boundary.  Any
exception raised by this method causes the caller to roll back.

Immutability contract
---------------------
``apply_changes`` never calls UPDATE on an existing snapshot column.  The only
permitted write to an existing row is ``mark_superseded`` (status column only),
performed by the repository's transition guard.
"""
from __future__ import annotations

import copy
import logging
import uuid
from typing import Any

from sqlalchemy.orm import Session

from pipelineshield.catalogue.schemas import (
    CatalogueSnapshot,
    CatalogueValidationError,
    CatalogueVersionConflictError,
)
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.app_user import AppUser
from pipelineshield.persistence.repositories.audit import SQLAlchemyAuditRepository
from pipelineshield.persistence.repositories.catalogue import (
    SQLAlchemyCatalogueRepository,
)
from pipelineshield.api.v1.schemas.catalogue import (
    CatalogueGetResponse,
    CataloguePatchRequest,
    CataloguePatchResponse,
    CategoryOut,
    ControlOut,
    DiffEntry,
    GradeBandOut,
)
from pipelineshield.api.security.authz_guard import CurrentActor
from pipelineshield.analysis.redactor import redact

__all__ = ["CatalogueService", "CatalogueNotFoundError"]

_LOG = logging.getLogger(__name__)

# Simple in-process metrics counters — incremented and logged; a future
# WO will wire Prometheus exporters.
_METRICS: dict[str, int] = {
    "catalogue_version_created_total": 0,
    "catalogue_patch_rejected_total_400": 0,
    "catalogue_patch_rejected_total_403": 0,
    "catalogue_patch_rejected_total_409": 0,
}


class CatalogueNotFoundError(RuntimeError):
    """Raised when no active catalogue version exists."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_get_response(row: Any, display_name: str) -> CatalogueGetResponse:
    """Convert a ControlCatalogueVersion ORM row into the GET response model."""
    snap = row.snapshot
    categories = [
        CategoryOut(
            id=c["id"],
            name=c["name"],
            weight=c["weight"],
            enabled=c["enabled"],
        )
        for c in snap.get("categories", [])
    ]
    controls = [
        ControlOut(
            id=ctrl["id"],
            category_id=ctrl["category_id"],
            severity=ctrl["severity"],
            enabled=ctrl["enabled"],
            reference_tools=ctrl.get("reference_tools", []),
        )
        for c in snap.get("categories", [])
        for ctrl in c.get("controls", [])
    ]
    grade_bands = [
        GradeBandOut(
            grade=gb["grade"],
            min_score=gb["min_score"],
            max_score=gb["max_score"],
        )
        for gb in (row.grade_bands or [])
    ]
    return CatalogueGetResponse(
        version=row.version,
        status=row.status,
        created_at=row.created_at,
        created_by=display_name,
        grade_bands=grade_bands,
        categories=categories,
        controls=controls,
    )


def _apply_ops_to_snapshot(
    snapshot_dict: dict[str, Any],
    request: CataloguePatchRequest,
) -> tuple[dict[str, Any], list[DiffEntry]]:
    """Apply change operations to an in-memory snapshot copy.

    Returns the modified snapshot dict and the diff list.
    Raises ValueError on unknown IDs or invalid field targets.
    """
    updated = copy.deepcopy(snapshot_dict)
    diff: list[DiffEntry] = []

    for op in request.changes:
        field_map = op.fields.model_dump(exclude_none=True)
        if not field_map:
            continue  # no-op change; skip silently

        if op.target == "category":
            cat_match = next(
                (c for c in updated["categories"] if c["id"] == op.id), None
            )
            if cat_match is None:
                raise CatalogueValidationError(
                    f"Unknown category id: {op.id!r}",
                    field="changes.id",
                    value=op.id,
                )
            for field, new_val in field_map.items():
                if field in ("severity", "reference_tools"):
                    raise CatalogueValidationError(
                        f"Field {field!r} is not applicable to a category target.",
                        field="changes.fields",
                        value=field,
                    )
                old_val = cat_match.get(field)
                if old_val != new_val:
                    diff.append(
                        DiffEntry(
                            path=f"categories.{op.id}.{field}",
                            old_value=old_val,
                            new_value=new_val,
                        )
                    )
                    cat_match[field] = new_val

        elif op.target == "control":
            ctrl_match = None
            cat_of_ctrl = None
            for cat in updated["categories"]:
                for ctrl in cat.get("controls", []):
                    if ctrl["id"] == op.id:
                        ctrl_match = ctrl
                        cat_of_ctrl = cat
                        break
                if ctrl_match is not None:
                    break

            if ctrl_match is None:
                raise CatalogueValidationError(
                    f"Unknown control id: {op.id!r}",
                    field="changes.id",
                    value=op.id,
                )
            for field, new_val in field_map.items():
                if field == "weight":
                    raise CatalogueValidationError(
                        "Field 'weight' is not applicable to a control target.",
                        field="changes.fields",
                        value=field,
                    )
                old_val = ctrl_match.get(field)
                if old_val != new_val:
                    diff.append(
                        DiffEntry(
                            path=f"controls.{op.id}.{field}",
                            old_value=old_val,
                            new_value=new_val,
                        )
                    )
                    ctrl_match[field] = new_val

    return updated, diff


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class CatalogueService:
    """Business logic for catalogue read and versioned PATCH."""

    def get_active_catalogue(
        self, session: Session
    ) -> CatalogueGetResponse:
        """Return the current active catalogue version."""
        repo = SQLAlchemyCatalogueRepository(session)
        row = repo.get_active()
        if row is None:
            raise CatalogueNotFoundError("No active catalogue version exists.")
        display_name = self._resolve_display_name(session, row.created_by)
        return _build_get_response(row, display_name)

    def apply_changes(
        self,
        session: Session,
        actor: CurrentActor,
        request: CataloguePatchRequest,
    ) -> CataloguePatchResponse:
        """Apply a change set, create a new version, mark predecessor superseded.

        All writes (new version INSERT, predecessor status UPDATE, audit INSERT)
        happen in the caller's transaction.  Any exception causes rollback.
        """
        cat_repo = SQLAlchemyCatalogueRepository(session)
        audit_repo = SQLAlchemyAuditRepository(session)

        # 1. Load active version — concurrency check inside the same transaction.
        active = cat_repo.get_active()
        if active is None:
            raise CatalogueNotFoundError("No active catalogue version exists.")

        if active.version != request.base_version:
            _METRICS["catalogue_patch_rejected_total_409"] += 1
            _LOG.warning(
                "catalogue_patch_stale_base_version",
                extra={
                    "base_version": request.base_version,
                    "active_version": active.version,
                    "actor_id": str(actor.user_id),
                },
            )
            raise CatalogueVersionConflictError(
                f"base_version {request.base_version} is stale; "
                f"current active version is {active.version}."
            )

        # 2. Apply operations to in-memory copy.
        try:
            updated_snapshot_dict, diff = _apply_ops_to_snapshot(
                active.snapshot, request
            )
        except CatalogueValidationError:
            _METRICS["catalogue_patch_rejected_total_400"] += 1
            raise

        # 3. Revalidate the mutated snapshot through CatalogueSnapshot.
        try:
            new_snapshot = CatalogueSnapshot.model_validate(updated_snapshot_dict)
        except Exception as exc:
            _METRICS["catalogue_patch_rejected_total_400"] += 1
            raise CatalogueValidationError(
                str(exc), field="changes", value=None
            ) from exc

        # 4. Persist new version.
        new_version_num = active.version + 1
        new_row = cat_repo.create_version(
            version=new_version_num,
            snapshot=new_snapshot,
            created_by=actor.user_id,
            change_notes=None,  # rationale goes to audit, not change_notes
        )

        # 5. Transition predecessor to superseded (status column only).
        cat_repo.mark_superseded(active.id)

        # 6. Write audit event — change_detail contains diff counts/paths only;
        #    never spans or secret values.  Rationale is redacted before storage.
        redacted_rationale = redact(request.rationale).masked_text
        audit_event = AuditEvent(
            id=uuid.uuid4(),
            actor_id=str(actor.user_id),
            actor_persona=actor.persona,
            resource_type="control_catalogue_version",
            resource_id=str(new_row.id),
            action="catalogue.version_created",
            change_detail={
                "new_version": new_version_num,
                "base_version": request.base_version,
                "change_count": len(diff),
                "diff": [d.model_dump() for d in diff],
                "rationale_redacted": redacted_rationale,
            },
        )
        audit_repo.append(audit_event)

        _METRICS["catalogue_version_created_total"] += 1
        _LOG.info(
            "catalogue_patch_applied",
            extra={
                "actor_id": str(actor.user_id),
                "base_version": request.base_version,
                "new_version": new_version_num,
                "change_count": len(diff),
            },
        )

        display_name = self._resolve_display_name(session, actor.user_id)
        snapshot_response = _build_get_response(new_row, display_name)

        return CataloguePatchResponse(
            version=new_version_num,
            created_at=new_row.created_at,
            created_by=display_name,
            diff=diff,
            snapshot=snapshot_response,
        )

    @staticmethod
    def _resolve_display_name(session: Session, user_id: uuid.UUID) -> str:
        """Look up the display name for a user id; fall back to the UUID string."""
        user = session.get(AppUser, user_id)
        if user is None:
            return str(user_id)
        return user.display_name
