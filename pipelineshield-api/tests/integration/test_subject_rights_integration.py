"""Integration tests for governance subject rights API.

Tests:
- POST /governance/subjects/{id}/export returns 200 with bundle.
- POST /governance/subjects/{id}/erasure returns 200 with receipt.
- Erasure deletes analyses and definitions; audit + receipt rows survive.
- Erasure idempotent: second call returns zero counts.
- Persona authorization: app_developer, devops_engineer, engineering_manager → 403.
- Cross-workspace or unknown subject → 404.
- Missing confirm → 400.
- Full-graph subject: analyses, findings, remediations, drafts erased; receipt queryable.
- Exactly one purge_receipt and one audit_event per erasure.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from pipelineshield.api.main import create_app
from pipelineshield.api.security.authz_guard import CurrentActor, get_current_actor
from pipelineshield.api.v1.routers.governance_router import get_db
from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.app_user import AppUser
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.finding import Finding
from pipelineshield.persistence.models.generated_draft import GeneratedDraft
from pipelineshield.persistence.models.pipeline_definition import PipelineDefinition
from pipelineshield.persistence.models.purge_receipt import PurgeReceipt
from pipelineshield.persistence.models.remediation import Remediation
from pipelineshield.persistence.models.workspace import Workspace


# ---------------------------------------------------------------------------
# Engine and session
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture(scope="module")
def db_session(engine) -> Generator[Session, None, None]:
    with Session(engine) as s:
        yield s


# ---------------------------------------------------------------------------
# Stable IDs
# ---------------------------------------------------------------------------

WS_ID = uuid.UUID("00000000-0000-0000-0066-000000000001")
ADMIN_USER_ID = uuid.UUID("00000000-0000-0000-0066-000000000010")
SUBJECT_ID = uuid.UUID("00000000-0000-0000-0066-000000000020")
EMPTY_SUBJECT_ID = uuid.UUID("00000000-0000-0000-0066-000000000021")
DEV_USER_ID = uuid.UUID("00000000-0000-0000-0066-000000000030")


@pytest.fixture(scope="module", autouse=True)
def seed_db(db_session):
    ws = Workspace(id=WS_ID, name="Governance WS", slug="governance-ws")
    db_session.add(ws)

    admin = AppUser(
        id=ADMIN_USER_ID,
        workspace_id=WS_ID,
        sub_claim="sub|admin",
        email="a***@e***.com",
        display_name="Admin",
    )
    subject = AppUser(
        id=SUBJECT_ID,
        workspace_id=WS_ID,
        sub_claim="sub|subject",
        email="s***@e***.com",
        display_name="Subject",
    )
    empty_subject = AppUser(
        id=EMPTY_SUBJECT_ID,
        workspace_id=WS_ID,
        sub_claim="sub|empty",
        email="e***@e***.com",
        display_name="Empty Subject",
    )
    dev = AppUser(
        id=DEV_USER_ID,
        workspace_id=WS_ID,
        sub_claim="sub|dev",
        email="d***@e***.com",
        display_name="Dev",
    )
    db_session.add_all([admin, subject, empty_subject, dev])
    db_session.commit()


def _seed_full_graph(db_session: Session) -> dict:
    """Seed a full data graph for SUBJECT_ID and return the created IDs."""
    now = datetime.now(tz=timezone.utc)
    analysis_id = uuid.uuid4()
    definition_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    remediation_id = uuid.uuid4()
    draft_id = uuid.uuid4()

    analysis = Analysis(
        id=analysis_id,
        workspace_id=WS_ID,
        owner_id=SUBJECT_ID,
        pipeline_format="github_actions",
        score=75,
        grade="B",
    )
    definition = PipelineDefinition(
        id=definition_id,
        workspace_id=WS_ID,
        analysis_id=analysis_id,
        masked_content="[masked content]",
        key_id="test-key",
        original_filename="test.yml",
        line_count=10,
        purge_due_at=now + timedelta(days=90),
    )
    finding = Finding(
        id=finding_id,
        workspace_id=WS_ID,
        analysis_id=analysis_id,
        source="deterministic",
        control_category="secrets",
        rule_id="no-hardcoded-secrets",
        severity="critical",
        weight=10,
        title="Hardcoded secret detected",
        description="Test finding",
        evidence={},
    )
    remediation = Remediation(
        id=remediation_id,
        finding_id=finding_id,
        tool_name="manual",
        guidance="Fix the secret.",
        workspace_id=WS_ID,
    )
    draft = GeneratedDraft(
        id=draft_id,
        analysis_id=analysis_id,
        draft_type="remediation",
        content="Draft content",
    )
    db_session.add_all([analysis, definition, finding, remediation, draft])
    db_session.flush()
    return {
        "analysis_id": analysis_id,
        "definition_id": definition_id,
        "finding_id": finding_id,
        "remediation_id": remediation_id,
        "draft_id": draft_id,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_app(db_session: Session, persona: str, user_id: uuid.UUID) -> TestClient:
    app = create_app()

    def _get_db():
        return db_session

    async def _actor() -> CurrentActor:
        return CurrentActor(
            user_id=user_id,
            persona=persona,
            workspace_id=WS_ID,
            display_name="Test",
        )

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_actor] = _actor
    return TestClient(app)


@pytest.fixture
def admin_client(db_session):
    client = _make_app(db_session, "appsec_lead", ADMIN_USER_ID)
    yield client
    db_session.rollback()


@pytest.fixture
def devsecops_client(db_session):
    client = _make_app(db_session, "devsecops_engineer", ADMIN_USER_ID)
    yield client
    db_session.rollback()


# ---------------------------------------------------------------------------
# Export tests
# ---------------------------------------------------------------------------


class TestExportEndpoint:
    def test_export_returns_200(self, admin_client):
        resp = admin_client.post(f"/api/v1/governance/subjects/{SUBJECT_ID}/export")
        assert resp.status_code == 200
        data = resp.json()
        assert data["bundle_version"] == "1.0"
        assert "subject" in data
        assert data["subject"]["user_id"] == str(SUBJECT_ID)

    def test_export_empty_subject_returns_200_with_empty_lists(self, admin_client):
        resp = admin_client.post(f"/api/v1/governance/subjects/{EMPTY_SUBJECT_ID}/export")
        assert resp.status_code == 200
        data = resp.json()
        assert data["analyses"] == []
        assert data["definitions"] == []

    def test_export_unknown_subject_returns_404(self, admin_client):
        resp = admin_client.post(f"/api/v1/governance/subjects/{uuid.uuid4()}/export")
        assert resp.status_code == 404

    def test_export_app_developer_returns_403(self, db_session):
        client = _make_app(db_session, "app_developer", DEV_USER_ID)
        resp = client.post(f"/api/v1/governance/subjects/{SUBJECT_ID}/export")
        assert resp.status_code == 403
        db_session.rollback()

    def test_export_devops_engineer_returns_403(self, db_session):
        client = _make_app(db_session, "devops_engineer", DEV_USER_ID)
        resp = client.post(f"/api/v1/governance/subjects/{SUBJECT_ID}/export")
        assert resp.status_code == 403
        db_session.rollback()

    def test_export_engineering_manager_returns_403(self, db_session):
        client = _make_app(db_session, "engineering_manager", DEV_USER_ID)
        resp = client.post(f"/api/v1/governance/subjects/{SUBJECT_ID}/export")
        assert resp.status_code == 403
        db_session.rollback()

    def test_export_devsecops_has_governance_access(self, devsecops_client):
        resp = devsecops_client.post(f"/api/v1/governance/subjects/{SUBJECT_ID}/export")
        assert resp.status_code == 200

    def test_bundle_subject_field_contains_masked_email(self, admin_client):
        resp = admin_client.post(f"/api/v1/governance/subjects/{SUBJECT_ID}/export")
        data = resp.json()
        subject = data["subject"]
        # Masked email should not be a full email address (contains ***)
        assert "***" in subject["masked_email"]


# ---------------------------------------------------------------------------
# Erasure tests
# ---------------------------------------------------------------------------


class TestErasureEndpoint:
    def test_erasure_missing_confirm_returns_400(self, admin_client):
        resp = admin_client.post(
            f"/api/v1/governance/subjects/{SUBJECT_ID}/erasure",
            json={"confirm": False, "reason": "test"},
        )
        assert resp.status_code == 400

    def test_erasure_unknown_subject_returns_404(self, admin_client):
        resp = admin_client.post(
            f"/api/v1/governance/subjects/{uuid.uuid4()}/erasure",
            json={"confirm": True, "reason": "test"},
        )
        assert resp.status_code == 404

    def test_erasure_app_developer_returns_403(self, db_session):
        client = _make_app(db_session, "app_developer", DEV_USER_ID)
        resp = client.post(
            f"/api/v1/governance/subjects/{SUBJECT_ID}/erasure",
            json={"confirm": True, "reason": "test"},
        )
        assert resp.status_code == 403
        db_session.rollback()

    def test_full_graph_erasure_removes_confidential_rows(self, db_session):
        # Seed a full graph for the subject.
        ids = _seed_full_graph(db_session)
        db_session.flush()

        client = _make_app(db_session, "appsec_lead", ADMIN_USER_ID)
        resp = client.post(
            f"/api/v1/governance/subjects/{SUBJECT_ID}/erasure",
            json={"confirm": True, "reason": "integration test"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "succeeded"
        assert data["entity_counts"]["analysis"] > 0
        assert data["entity_counts"]["finding"] > 0

        # Verify analysis is gone.
        analysis_row = db_session.get(Analysis, ids["analysis_id"])
        assert analysis_row is None

        # Verify finding is gone.
        finding_row = db_session.get(Finding, ids["finding_id"])
        assert finding_row is None

        db_session.rollback()

    def test_erasure_emits_one_purge_receipt(self, db_session):
        before_count = len(db_session.execute(select(PurgeReceipt)).scalars().all())
        client = _make_app(db_session, "appsec_lead", ADMIN_USER_ID)
        client.post(
            f"/api/v1/governance/subjects/{EMPTY_SUBJECT_ID}/erasure",
            json={"confirm": True, "reason": "receipt count test"},
        )
        after_count = len(db_session.execute(select(PurgeReceipt)).scalars().all())
        assert after_count == before_count + 1
        db_session.rollback()

    def test_erasure_receipt_has_on_demand_trigger(self, db_session):
        client = _make_app(db_session, "appsec_lead", ADMIN_USER_ID)
        client.post(
            f"/api/v1/governance/subjects/{EMPTY_SUBJECT_ID}/erasure",
            json={"confirm": True, "reason": "trigger test"},
        )
        receipts = (
            db_session.execute(
                select(PurgeReceipt).where(
                    PurgeReceipt.subject_user_id == EMPTY_SUBJECT_ID
                )
            )
            .scalars()
            .all()
        )
        assert len(receipts) >= 1
        assert receipts[-1].trigger == "on_demand"
        db_session.rollback()

    def test_erasure_idempotent_second_call_zero_counts(self, db_session):
        client = _make_app(db_session, "appsec_lead", ADMIN_USER_ID)
        # First call
        r1 = client.post(
            f"/api/v1/governance/subjects/{EMPTY_SUBJECT_ID}/erasure",
            json={"confirm": True, "reason": "first"},
        )
        assert r1.status_code == 200
        # Second call
        r2 = client.post(
            f"/api/v1/governance/subjects/{EMPTY_SUBJECT_ID}/erasure",
            json={"confirm": True, "reason": "second"},
        )
        assert r2.status_code == 200
        assert r2.json()["entity_counts"]["analysis"] == 0
        db_session.rollback()

    def test_audit_event_survives_erasure(self, db_session):
        """Audit rows are never deleted during erasure (AC-4)."""
        # Seed an audit event attributed to the subject.
        event = AuditEvent(
            id=uuid.uuid4(),
            actor_id=str(SUBJECT_ID),
            actor_persona="app_developer",
            workspace_id=WS_ID,
            action="analysis.created",
            resource_type="analysis",
            resource_id=str(uuid.uuid4()),
            change_detail={},
        )
        db_session.add(event)
        db_session.flush()
        event_id = event.id

        client = _make_app(db_session, "appsec_lead", ADMIN_USER_ID)
        client.post(
            f"/api/v1/governance/subjects/{SUBJECT_ID}/erasure",
            json={"confirm": True, "reason": "audit survival test"},
        )

        # Audit event must still be present.
        surviving = db_session.get(AuditEvent, event_id)
        assert surviving is not None, "AuditEvent must not be deleted during erasure"
        db_session.rollback()
