"""Fixture helpers for retention worker tests (WO-040 AC-12).

Creates seeded definition+analysis+derived-rows at 89/90/91 days of age,
plus untouchable audit_event and catalogue_version rows.

All IDs are stable so tests can assert before/after state.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.finding import Finding
from pipelineshield.persistence.models.generated_draft import GeneratedDraft
from pipelineshield.persistence.models.pipeline_definition import PipelineDefinition
from pipelineshield.persistence.models.remediation import Remediation

# Stable IDs — 89-day definition should NOT be purged; 90/91-day should be.
_WS_ID = uuid.UUID("00000000-0000-0000-0010-000000000001")
_USER_ID = uuid.UUID("00000000-0000-0000-0010-000000000002")
_CAT_VER_ID = uuid.UUID("00000000-0000-0000-0010-000000000003")

DEF_89_ID = uuid.UUID("00000000-0000-0000-0010-000000000010")
DEF_90_ID = uuid.UUID("00000000-0000-0000-0010-000000000011")
DEF_91_ID = uuid.UUID("00000000-0000-0000-0010-000000000012")

ANA_89_ID = uuid.UUID("00000000-0000-0000-0010-000000000020")
ANA_90_ID = uuid.UUID("00000000-0000-0000-0010-000000000021")
ANA_91_ID = uuid.UUID("00000000-0000-0000-0010-000000000022")

FINDING_90_ID = uuid.UUID("00000000-0000-0000-0010-000000000030")
FINDING_91_ID = uuid.UUID("00000000-0000-0000-0010-000000000031")

REMEDIATION_90_ID = uuid.UUID("00000000-0000-0000-0010-000000000040")

DRAFT_90_ID = uuid.UUID("00000000-0000-0000-0010-000000000050")
DRAFT_91_ID = uuid.UUID("00000000-0000-0000-0010-000000000051")


def _now() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def seed_retention_data(session: Session, catalogue_version_id: uuid.UUID) -> dict:
    """Seed analyses and definitions at 89, 90 and 91 days old.

    Returns a dict of stable IDs for assertion in tests.
    """
    now = _now()

    def _make_analysis(ana_id: uuid.UUID, days_ago: int) -> Analysis:
        created = now - timedelta(days=days_ago)
        return Analysis(
            id=ana_id,
            workspace_id=_WS_ID,
            owner_id=_USER_ID,
            catalogue_version_id=catalogue_version_id,
            pipeline_format="github_actions",
            format_confidence=0.95,
            score=70,
            grade="C",
            coverage_report={},
            status="completed",
            created_at=created,
        )

    def _make_definition(def_id: uuid.UUID, ana_id: uuid.UUID, days_ago: int) -> PipelineDefinition:
        created = now - timedelta(days=days_ago)
        purge_at = created + timedelta(days=90)
        return PipelineDefinition(
            id=def_id,
            workspace_id=_WS_ID,
            analysis_id=ana_id,
            masked_content="dGVzdA==",  # base64 'test' — no real content
            key_id="test-key-v1",
            original_filename="ci.yml",
            line_count=10,
            is_sample=False,
            created_at=created,
            purge_due_at=purge_at,
            retention_class="confidential_90d",
        )

    # Analyses
    ana_89 = _make_analysis(ANA_89_ID, 89)
    ana_90 = _make_analysis(ANA_90_ID, 90)
    ana_91 = _make_analysis(ANA_91_ID, 91)
    session.add_all([ana_89, ana_90, ana_91])
    session.flush()

    # Definitions
    def_89 = _make_definition(DEF_89_ID, ANA_89_ID, 89)
    def_90 = _make_definition(DEF_90_ID, ANA_90_ID, 90)
    def_91 = _make_definition(DEF_91_ID, ANA_91_ID, 91)
    session.add_all([def_89, def_90, def_91])
    session.flush()

    # Derived rows for 90-day definition
    finding_90 = Finding(
        id=FINDING_90_ID,
        workspace_id=_WS_ID,
        analysis_id=ANA_90_ID,
        source="deterministic",
        requires_human_review=False,
        control_category="secrets_hygiene",
        rule_id="sh-001",
        severity="high",
        weight=10,
        title="Plaintext secret detected",
        description="A secret pattern was found.",
        evidence={},
    )
    session.add(finding_90)
    session.flush()

    remediation_90 = Remediation(
        id=REMEDIATION_90_ID,
        workspace_id=_WS_ID,
        finding_id=FINDING_90_ID,
        tool_name="Gitleaks",
        guidance="Rotate the credential and use a secrets manager.",
    )
    session.add(remediation_90)

    draft_90 = GeneratedDraft(
        id=DRAFT_90_ID,
        workspace_id=_WS_ID,
        analysis_id=ANA_90_ID,
        draft_type="hardened_configuration",
        content="# hardened",
        model_id="test-model",
        requires_human_review=True,
    )
    session.add(draft_90)

    # Derived rows for 91-day definition
    finding_91 = Finding(
        id=FINDING_91_ID,
        workspace_id=_WS_ID,
        analysis_id=ANA_91_ID,
        source="deterministic",
        requires_human_review=False,
        control_category="artifact_signing",
        rule_id="as-001",
        severity="medium",
        weight=5,
        title="Unsigned artifact",
        description="No signing step detected.",
        evidence={},
    )
    session.add(finding_91)

    draft_91 = GeneratedDraft(
        id=DRAFT_91_ID,
        workspace_id=_WS_ID,
        analysis_id=ANA_91_ID,
        draft_type="hardened_configuration",
        content="# hardened v91",
        model_id="test-model",
        requires_human_review=True,
    )
    session.add(draft_91)
    session.flush()

    return {
        "now": now,
        "workspace_id": _WS_ID,
        "user_id": _USER_ID,
        "def_89_id": DEF_89_ID,
        "def_90_id": DEF_90_ID,
        "def_91_id": DEF_91_ID,
        "ana_89_id": ANA_89_ID,
        "ana_90_id": ANA_90_ID,
        "ana_91_id": ANA_91_ID,
        "finding_90_id": FINDING_90_ID,
        "finding_91_id": FINDING_91_ID,
        "remediation_90_id": REMEDIATION_90_ID,
        "draft_90_id": DRAFT_90_ID,
        "draft_91_id": DRAFT_91_ID,
    }
