"""ReportService — compose the AnalysisReport payload from persisted data.

The service is thin: it queries pre-computed rows (score, category scores,
findings, coverage limitations) and assembles them into the validated
AnalysisReport Pydantic model. No scoring logic lives here — all scoring
is done by ScoringEngine during ingestion (WO-020).

Business rule BR-02 compliance: grade language in the AnalysisReport model
itself (report.py) ensures no completeness claim. This service passes raw
numeric values only and never constructs narrative strings.
"""

from __future__ import annotations

import logging
import uuid
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from pipelineshield.api.v1.schemas.analysis import ADVISORY_DISCLAIMER
from pipelineshield.api.v1.schemas.report import (
    AnalysisReport,
    AnchorDetail,
    CategoryScoreItem,
    CoverageLimitationItem,
    FindingSummary,
    HumanReviewItem,
    SeverityDistribution,
)
from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.analysis_category_score import (
    AnalysisCategoryScore,
)
from pipelineshield.persistence.models.control_catalogue_version import (
    ControlCatalogueVersion,
)
from pipelineshield.persistence.models.coverage_limitation import (
    CoverageLimitation,
)
from pipelineshield.persistence.models.finding import Finding

_LOG = logging.getLogger(__name__)

__all__ = ["ReportService", "MissingScoringResultError"]

_SEVERITY_ORDER = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    "info",
)


class MissingScoringResultError(Exception):
    """Raised when the analysis row has no valid scoring state.

    Maps to HTTP 500 with correlation_id; no stack trace is forwarded to
    the client.
    """


class ReportService:
    """Assemble an AnalysisReport from the persisted analysis rows.

    All SQL is read-only. The session must already be open; the service does
    not manage transaction boundaries.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_report(self, analysis: Analysis) -> AnalysisReport:
        """Compose and validate an AnalysisReport for *analysis*.

        Raises MissingScoringResultError if the analysis row is in an
        inconsistent state (no score and no unscorable_reason).
        """
        cat_scores = self._load_category_scores(analysis.id)
        findings = self._load_findings(analysis.id, analysis.workspace_id)
        cov_limits = self._load_coverage_limitations(analysis.id)
        catalogue_version_int = self._resolve_catalogue_version(
            analysis.catalogue_version_id
        )

        # Validate scoring state.
        total_score: float | None = None
        letter_grade: str | None = None

        if not analysis.unscorable_reason:
            if analysis.score is None or not analysis.grade:
                raise MissingScoringResultError(
                    f"Analysis {analysis.id} has no score/grade and no "
                    "unscorable_reason; scoring state is inconsistent."
                )

            total_score = float(analysis.score)
            letter_grade = analysis.grade

        return AnalysisReport(
            analysis_id=analysis.id,
            workspace_id=analysis.workspace_id,
            format=analysis.pipeline_format,
            format_confidence=float(analysis.format_confidence),
            catalogue_version=catalogue_version_int,
            total_score=total_score,
            letter_grade=letter_grade,
            unscorable_reason=analysis.unscorable_reason,
            category_scores=self._build_category_scores(cat_scores),
            severity_distribution=self._build_severity_distribution(findings),
            findings=self._build_finding_summaries(findings),
            coverage_limitations=self._build_coverage_limitations(cov_limits),
            requires_human_review=self._build_human_review_items(
                findings,
                cov_limits,
            ),
            advisory_disclaimer=ADVISORY_DISCLAIMER,
            created_at=analysis.created_at,
        )

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def _load_category_scores(
        self,
        analysis_id: uuid.UUID,
    ) -> Sequence[AnalysisCategoryScore]:
        stmt = (
            select(AnalysisCategoryScore)
            .where(AnalysisCategoryScore.analysis_id == analysis_id)
            .order_by(AnalysisCategoryScore.category_id)
        )
        return self._session.execute(stmt).scalars().all()

    def _load_findings(
        self,
        analysis_id: uuid.UUID,
        workspace_id: uuid.UUID,
    ) -> Sequence[Finding]:
        findings = (
            self._session.execute(
                select(Finding)
                .where(
                    Finding.analysis_id == analysis_id,
                    Finding.workspace_id == workspace_id,
                )
                .order_by(Finding.created_at)
            )
            .scalars()
            .all()
        )

        if findings:
            return findings

        return (
            self._session.execute(
                select(Finding)
                .where(Finding.analysis_id == analysis_id)
                .order_by(Finding.created_at)
            )
            .scalars()
            .all()
        )

    def _load_coverage_limitations(
        self,
        analysis_id: uuid.UUID,
    ) -> Sequence[CoverageLimitation]:
        stmt = (
            select(CoverageLimitation)
            .where(CoverageLimitation.analysis_id == analysis_id)
            .order_by(CoverageLimitation.created_at)
        )
        return self._session.execute(stmt).scalars().all()

    def _resolve_catalogue_version(
        self,
        catalogue_version_id: uuid.UUID,
    ) -> int:
        stmt = select(ControlCatalogueVersion.version).where(
            ControlCatalogueVersion.id == catalogue_version_id
        )

        version_int = self._session.execute(stmt).scalar_one_or_none()

        if version_int is None:
            _LOG.warning(
                "catalogue_version_missing",
                extra={
                    "catalogue_version_id": str(catalogue_version_id),
                },
            )
            return 0

        return int(version_int)

    # ------------------------------------------------------------------
    # Assembly helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_category_scores(
        rows: Sequence[AnalysisCategoryScore],
    ) -> list[CategoryScoreItem]:
        return [
            CategoryScoreItem(
                category=row.category_id,
                earned=float(row.earned),
                possible=float(row.possible),
                excluded_count=int(row.excluded_count),
            )
            for row in rows
        ]

    @staticmethod
    def _build_severity_distribution(
        findings: Sequence[Finding],
    ) -> SeverityDistribution:
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }

        for finding in findings:
            if finding.source != "deterministic":
                continue

            severity = finding.severity.lower()

            if severity == "info":
                severity = "informational"

            if severity in counts:
                counts[severity] += 1

        return SeverityDistribution(**counts)

    @staticmethod
    def _build_finding_summaries(
        findings: Sequence[Finding],
    ) -> list[FindingSummary]:
        summaries: list[FindingSummary] = []

        for finding in findings:
            anchor: AnchorDetail | None = None

            if finding.anchor_line is not None:
                excerpt = ""

                if isinstance(finding.evidence, dict):
                    excerpt = str(
                        finding.evidence.get("snippet", "")
                    )

                anchor = AnchorDetail(
                    start_line=finding.anchor_line,
                    end_line=(
                        finding.evidence.get("anchor_end_line")
                        if isinstance(finding.evidence, dict)
                        else None
                    ),
                    excerpt=excerpt,
                )

            summaries.append(
                FindingSummary(
                    finding_id=finding.id,
                    control_id=finding.control_id or "",
                    category=finding.control_category,
                    severity=finding.severity,
                    title=finding.title,
                    anchor=anchor,
                    source=finding.source,
                    requires_human_review=finding.requires_human_review,
                )
            )

        return summaries

    @staticmethod
    def _build_coverage_limitations(
        rows: Sequence[CoverageLimitation],
    ) -> list[CoverageLimitationItem]:
        return [
            CoverageLimitationItem(
                kind=row.kind,
                location=row.location,
                reason=row.reason,
                affected_control_ids=list(
                    row.affected_control_ids or []
                ),
            )
            for row in rows
        ]

    @staticmethod
    def _build_human_review_items(
        findings: Sequence[Finding],
        cov_limits: Sequence[CoverageLimitation],
    ) -> list[HumanReviewItem]:
        items: list[HumanReviewItem] = []

        # AI-sourced findings.
        for finding in findings:
            if finding.source == "ai":
                items.append(
                    HumanReviewItem(
                        finding_id=finding.id,
                        control_id=finding.control_id or "",
                        reason="ai_advisory",
                    )
                )

        # NOT_ASSESSABLE controls from coverage limitations.
        seen_control_ids: set[str] = set()

        for limitation in cov_limits:
            for control_id in (
                limitation.affected_control_ids or []
            ):
                if control_id in seen_control_ids:
                    continue

                seen_control_ids.add(control_id)

                items.append(
                    HumanReviewItem(
                        finding_id=None,
                        control_id=control_id,
                        reason="not_assessable",
                    )
                )

        return items
