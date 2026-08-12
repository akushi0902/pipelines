"""ArchitectureService — loads persisted analysis data and invokes the recommender.

The service is a thin orchestration layer: it handles row-level security
scoping, data hydration, and converts between persistence types and domain
objects.  No scoring logic, no SQL WHERE composition outside repository calls.

Pattern:
  1. Load Analysis with row-level scoping via AnalysisRepository.
  2. Check analysis is in a complete state (has score or unscorable_reason).
  3. Load the pinned CatalogueSnapshot from ControlCatalogueVersion.
  4. Reconstruct control statuses from persisted Finding rows and
     CoverageLimitation rows (the full EvaluationResult is not stored).
  5. Invoke ArchitectureRecommender.recommend().
  6. Convert the ArchitectureBlueprint to a Pydantic ArchitectureResponse.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from pipelineshield.analysis.architecture.models import ArchitectureBlueprint
from pipelineshield.analysis.architecture.recommender import ArchitectureRecommender
from pipelineshield.api.security.authz_guard import PERSONA_CAPABILITIES, CurrentActor
from pipelineshield.api.v1.schemas.analysis import ADVISORY_DISCLAIMER
from pipelineshield.api.v1.schemas.architecture import (
    ArchitectureResponse,
    ControlOut,
    CoverageLimitationOut,
    GapSummaryOut,
    ReferenceToolOut,
    StageOut,
)
from pipelineshield.catalogue.schemas import CatalogueSnapshot
from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.control_catalogue_version import ControlCatalogueVersion
from pipelineshield.persistence.models.coverage_limitation import CoverageLimitation
from pipelineshield.persistence.models.finding import Finding
from pipelineshield.persistence.repositories.analysis import SQLAlchemyAnalysisRepository

_LOG = logging.getLogger(__name__)

__all__ = [
    "ArchitectureService",
    "AnalysisNotFoundError",
    "AnalysisNotCompleteError",
]


class AnalysisNotFoundError(Exception):
    """Raised when the analysis is not visible to the requesting actor.

    Callers must return 404 (not 403) to prevent existence disclosure.
    """


class AnalysisNotCompleteError(Exception):
    """Raised when the analysis has no score and no unscorable_reason.

    Maps to HTTP 409 with code analysis_not_complete.
    """


class ArchitectureService:
    """Orchestrates architecture blueprint generation for one analysis."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._recommender = ArchitectureRecommender()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_blueprint(
        self,
        analysis_id: uuid.UUID,
        actor: CurrentActor,
    ) -> ArchitectureResponse:
        """Load and return the architecture blueprint for *analysis_id*.

        Row-level scoping:
        - app_developer: only their own analyses (get_by_id_owner_scoped).
        - All other read-capable personas: any workspace analysis (get_by_id).
        - engineering_manager (analysis:read:summary): full blueprint returned;
          the summary projection is sufficient for the full blueprint since no
          finding-level secrets are included.

        Raises AnalysisNotFoundError when the analysis is not visible.
        Raises AnalysisNotCompleteError when the analysis lacks a scoring result.
        """
        repo = SQLAlchemyAnalysisRepository(self._session)
        actor_caps = PERSONA_CAPABILITIES.get(actor.persona, frozenset())

        if "analysis:read:all" in actor_caps or "analysis:read:summary" in actor_caps:
            analysis = repo.get_by_id(analysis_id, actor.workspace_id)
        else:
            analysis = repo.get_by_id_owner_scoped(analysis_id, actor.user_id, actor.workspace_id)

        if analysis is None:
            raise AnalysisNotFoundError(str(analysis_id))

        # Check analysis is complete.
        if analysis.score is None and not analysis.unscorable_reason:
            raise AnalysisNotCompleteError(
                f"Analysis {analysis_id} has no score and no unscorable_reason; "
                "it may still be processing."
            )

        # Load the pinned catalogue snapshot.
        cat_version = self._session.get(ControlCatalogueVersion, analysis.catalogue_version_id)
        if cat_version is None:
            _LOG.error(
                "architecture_catalogue_version_missing",
                extra={
                    "analysis_id": str(analysis_id),
                    "catalogue_version_id": str(analysis.catalogue_version_id),
                },
            )
            raise AnalysisNotCompleteError(
                f"Catalogue version {analysis.catalogue_version_id} not found."
            )

        try:
            snapshot = CatalogueSnapshot.model_validate(cat_version.snapshot)
        except Exception as exc:
            _LOG.error(
                "architecture_catalogue_snapshot_invalid",
                extra={
                    "analysis_id": str(analysis_id),
                    "catalogue_version_id": str(analysis.catalogue_version_id),
                    "error": str(exc),
                },
                exc_info=False,
            )
            raise AnalysisNotCompleteError(
                f"Catalogue snapshot for version {cat_version.version} is invalid."
            ) from exc

        # Reconstruct control statuses from persisted findings + coverage limitations.
        control_statuses = self._build_control_statuses(analysis, snapshot)
        cov_limit_pairs = self._load_coverage_limitation_pairs(analysis.id)

        generated_at = datetime.now(timezone.utc).isoformat()

        blueprint = self._recommender.recommend(
            catalogue_snapshot=snapshot,
            control_statuses=control_statuses,
            coverage_limitations=cov_limit_pairs,
            analysis_id=str(analysis.id),
            catalogue_version=int(cat_version.version),
            advisory_disclaimer=ADVISORY_DISCLAIMER,
            generated_at=generated_at,
        )

        _LOG.info(
            "architecture_blueprint_built",
            extra={
                "analysis_id": str(analysis.id),
                "catalogue_version": int(cat_version.version),
                "missing_count": blueprint.gap_summary.missing_count,
                "partial_count": blueprint.gap_summary.partial_count,
                "not_assessable_count": blueprint.gap_summary.not_assessable_count,
                "actor_id": str(actor.user_id),
                "persona": actor.persona,
            },
        )

        return self._to_response(blueprint)

    # ------------------------------------------------------------------
    # Data hydration helpers
    # ------------------------------------------------------------------

    def _build_control_statuses(
        self,
        analysis: Analysis,
        snapshot: CatalogueSnapshot,
    ) -> dict[str, str]:
        """Reconstruct control statuses from persisted data.

        Logic:
        - Controls whose control_id appears in any CoverageLimitation row's
          affected_control_ids → "not_assessable".
        - Controls with at least one deterministic Finding → "missing".
        - All others → "satisfied".

        Note: PARTIAL state requires per-rule satisfied+violated evidence which
        is not persisted.  We conservatively render such controls as "satisfied"
        (findings exist only for violations).
        """
        # NOT_ASSESSABLE set from coverage limitations
        not_assessable_ids: set[str] = set()
        for cl in self._load_coverage_limitations(analysis.id):
            for ctrl_id in (cl.affected_control_ids or []):
                not_assessable_ids.add(ctrl_id)

        # MISSING set from deterministic findings
        missing_ids: set[str] = set()
        for finding in self._load_findings(analysis.id, analysis.workspace_id):
            if finding.source == "deterministic" and finding.control_id:
                missing_ids.add(finding.control_id)

        # Build the map over all enabled catalogue controls.
        result: dict[str, str] = {}
        for category in snapshot.categories:
            for control in category.controls:
                if not control.enabled:
                    continue
                if control.id in not_assessable_ids:
                    result[control.id] = "not_assessable"
                elif control.id in missing_ids:
                    result[control.id] = "missing"
                else:
                    result[control.id] = "satisfied"

        return result

    def _load_findings(
        self, analysis_id: uuid.UUID, workspace_id: uuid.UUID
    ) -> Sequence[Finding]:
        stmt = select(Finding).where(
            Finding.analysis_id == analysis_id,
            Finding.workspace_id == workspace_id,
        )
        return self._session.execute(stmt).scalars().all()

    def _load_coverage_limitations(
        self, analysis_id: uuid.UUID
    ) -> Sequence[CoverageLimitation]:
        stmt = select(CoverageLimitation).where(
            CoverageLimitation.analysis_id == analysis_id,
        )
        return self._session.execute(stmt).scalars().all()

    def _load_coverage_limitation_pairs(
        self, analysis_id: uuid.UUID
    ) -> list[tuple[str, str]]:
        """Return (scope, reason) pairs for coverage limitations."""
        return [
            (cl.kind, cl.reason)
            for cl in self._load_coverage_limitations(analysis_id)
        ]

    # ------------------------------------------------------------------
    # Domain → Pydantic conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _to_response(blueprint: ArchitectureBlueprint) -> ArchitectureResponse:
        """Convert an ArchitectureBlueprint domain object to an ArchitectureResponse."""
        stages = [
            StageOut(
                stage_id=stage.stage_id,
                display_name=stage.display_name,
                order=stage.order,
                controls=[
                    ControlOut(
                        control_id=ctrl.control_id,
                        category=ctrl.category,
                        severity=ctrl.severity,
                        status=ctrl.status,
                        reference_tools=[
                            ReferenceToolOut(name=t.name, purpose=t.purpose)
                            for t in ctrl.reference_tools
                        ],
                        rationale=ctrl.rationale,
                        advisory_narrative_present=ctrl.advisory_narrative_present,
                    )
                    for ctrl in stage.controls
                ],
            )
            for stage in blueprint.stages
        ]

        cov_limits = [
            CoverageLimitationOut(scope=cl.scope, reason=cl.reason)
            for cl in blueprint.coverage_limitations
        ]

        return ArchitectureResponse(
            analysis_id=blueprint.analysis_id,
            catalogue_version=blueprint.catalogue_version,
            generated_at=blueprint.generated_at,
            advisory_disclaimer=blueprint.advisory_disclaimer,
            coverage_limitations=cov_limits,
            stages=stages,
            gap_summary=GapSummaryOut(
                missing_count=blueprint.gap_summary.missing_count,
                partial_count=blueprint.gap_summary.partial_count,
                not_assessable_count=blueprint.gap_summary.not_assessable_count,
            ),
        )
