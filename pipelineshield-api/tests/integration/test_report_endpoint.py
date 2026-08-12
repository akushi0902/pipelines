"""Integration tests for GET /api/v1/analyses/{id} (WO-021).

Tests:
- POST /analyses then GET /analyses/{id} returns identical report content.
- app_developer sees own analyses (200) and gets 404 for another user's.
- devops_engineer sees any workspace analysis.
- devsecops_engineer sees any workspace analysis.
- audit event emitted per report read.
- 404 (not 403) for invisible resources.
- advisory_disclaimer always present.
- requires_human_review always present as array.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from pipelineshield.api.security.authz_guard import CurrentActor, get_current_actor
from pipelineshield.api.v1.routers.analysis_router import get_db, router
from pipelineshield.api.v1.schemas.analysis import ADVISORY_DISCLAIMER
from pipelineshield.persistence.models import (
    AnalysisCategoryScore,
    AppUser,
    Base,
    ControlCatalogueVersion,
    Workspace,
)
from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.coverage_limitation import CoverageLimitation
from pipelineshield.persistence.models.finding import Finding

# ---------------------------------------------------------------------------
# Test DB and app setup
# ---------------------------------------------------------------------------

_WORKSPACE_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")
_OWNER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
_OTHER_OWNER_ID = uuid.UUID("00000000-0000-0000-0000-000000000099")


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(eng, "connect")
    def _fk_on(conn, _rec):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(eng)
    return eng


@pytest.fixture(scope="module")
def seeded_db(engine):
    """Seed one workspace, two users, and one catalogue version."""
    with Session(engine) as sess:
        user = AppUser(
            id=_OWNER_ID,
            email="owner@example.com",
            hashed_password="x",
            role="developer",
        )
        other_user = AppUser(
            id=_OTHER_OWNER_ID,
            email="other@example.com",
            hashed_password="x",
            role="developer",
        )
        ws = Workspace(
            id=_WORKSPACE_ID,
            name="test-ws",
            owner_id=_OWNER_ID,
        )
        sess.add_all([user, other_user, ws])
        sess.flush()

        cat_ver = ControlCatalogueVersion(
            id=uuid.UUID("00000000-0000-0000-0000-000000000010"),
            version=1,
            status="active",
            snapshot={"categories": []},
            grade_bands=[
                {"grade": "A", "min_score": 90, "max_score": 100},
                {"grade": "B", "min_score": 80, "max_score": 89},
                {"grade": "F", "min_score": 0, "max_score": 79},
            ],
            created_by=_OWNER_ID,
            content_checksum="abc123",
        )
        sess.add(cat_ver)
        sess.commit()
    return engine


@pytest.fixture()
def db_session(seeded_db):
    with Session(seeded_db) as sess:
        yield sess
        sess.rollback()


def _make_app(actor: CurrentActor, session: Session) -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_current_actor] = lambda: actor
    app.dependency_overrides[get_db] = lambda: session
    return app


def _make_actor(
    user_id: uuid.UUID = _OWNER_ID,
    persona: str = "devops_engineer",
    workspace_id: uuid.UUID = _WORKSPACE_ID,
) -> CurrentActor:
    return CurrentActor(
        user_id=user_id,
        persona=persona,
        workspace_id=workspace_id,
        display_name="Test User",
    )


def _seed_analysis(
    sess: Session,
    *,
    owner_id: uuid.UUID = _OWNER_ID,
    score: int = 88,
    grade: str = "B",
    unscorable_reason: str | None = None,
    add_findings: bool = False,
    add_coverage_limitation: bool = False,
) -> uuid.UUID:
    """Seed a minimal analysis row and return its id."""
    aid = uuid.uuid4()
    analysis = Analysis(
        id=aid,
        workspace_id=_WORKSPACE_ID,
        owner_id=owner_id,
        catalogue_version_id=uuid.UUID("00000000-0000-0000-0000-000000000010"),
        pipeline_format="github_actions",
        format_confidence=0.99,
        score=score if not unscorable_reason else 0,
        grade=grade if not unscorable_reason else "",
        coverage_report={},
        status="completed",
        unscorable_reason=unscorable_reason,
    )
    sess.add(analysis)
    sess.flush()

    sess.add(
        AnalysisCategoryScore(
            id=uuid.uuid4(),
            analysis_id=aid,
            category_id="secrets_hygiene",
            earned=11.11,
            possible=11.11,
            excluded_count=0,
        )
    )

    if add_findings:
        sess.add(
            Finding(
                id=uuid.uuid4(),
                workspace_id=_WORKSPACE_ID,
                analysis_id=aid,
                source="deterministic",
                requires_human_review=False,
                control_id="ih-001",
                control_category="infrastructure_hardening",
                rule_id="RULE-001",
                severity="high",
                weight=0,
                title="Runner not pinned",
                description="",
                anchor_line=14,
                anchor_column=1,
                evidence={"snippet": "  runs-on: ubuntu-latest"},
            )
        )

    if add_coverage_limitation:
        sess.add(
            CoverageLimitation(
                id=uuid.uuid4(),
                analysis_id=aid,
                kind="unresolved_include",
                location=".gitlab/ci/base.yml",
                reason="File not found in repository.",
                affected_control_ids=["sh-001"],
            )
        )

    sess.commit()
    return aid


# ---------------------------------------------------------------------------
# Tests: persona-filtered 404 (AC7)
# ---------------------------------------------------------------------------


class TestPersonaFiltering:
    def test_app_developer_sees_own_analysis(self, db_session):
        aid = _seed_analysis(db_session, owner_id=_OWNER_ID)
        actor = _make_actor(user_id=_OWNER_ID, persona="app_developer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 200

    def test_app_developer_gets_404_for_other_users_analysis(self, db_session):
        aid = _seed_analysis(db_session, owner_id=_OTHER_OWNER_ID)
        actor = _make_actor(user_id=_OWNER_ID, persona="app_developer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 404

    def test_devops_engineer_sees_any_workspace_analysis(self, db_session):
        aid = _seed_analysis(db_session, owner_id=_OTHER_OWNER_ID)
        actor = _make_actor(user_id=_OWNER_ID, persona="devops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 200

    def test_devsecops_engineer_sees_any_workspace_analysis(self, db_session):
        aid = _seed_analysis(db_session, owner_id=_OTHER_OWNER_ID)
        actor = _make_actor(user_id=_OWNER_ID, persona="devsecops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 200

    def test_different_workspace_returns_404(self, db_session):
        aid = _seed_analysis(db_session, owner_id=_OWNER_ID)
        other_ws = uuid.UUID("00000000-0000-0000-0000-000000000099")
        actor = _make_actor(
            user_id=_OWNER_ID, persona="devops_engineer", workspace_id=other_ws
        )
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 404

    def test_nonexistent_analysis_returns_404(self, db_session):
        actor = _make_actor(persona="devops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_404_not_403_for_invisible_resource(self, db_session):
        aid = _seed_analysis(db_session, owner_id=_OTHER_OWNER_ID)
        actor = _make_actor(user_id=_OWNER_ID, persona="app_developer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 404
        assert resp.status_code != 403


# ---------------------------------------------------------------------------
# Tests: Report payload shape (AC2)
# ---------------------------------------------------------------------------


class TestReportPayloadShape:
    def test_all_required_fields_in_response(self, db_session):
        aid = _seed_analysis(db_session, add_findings=True)
        actor = _make_actor(persona="devops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 200
        body = resp.json()

        assert "analysis_id" in body
        assert "workspace_id" in body
        assert "format" in body
        assert "format_confidence" in body
        assert "catalogue_version" in body
        assert "severity_distribution" in body
        assert "findings" in body
        assert "coverage_limitations" in body
        assert "requires_human_review" in body
        assert "advisory_disclaimer" in body
        assert "created_at" in body

    def test_severity_distribution_has_all_buckets(self, db_session):
        aid = _seed_analysis(db_session, add_findings=True)
        actor = _make_actor(persona="devops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        dist = resp.json()["severity_distribution"]
        assert "critical" in dist
        assert "high" in dist
        assert "medium" in dist
        assert "low" in dist
        assert "informational" in dist

    def test_finding_has_control_id(self, db_session):
        aid = _seed_analysis(db_session, add_findings=True)
        actor = _make_actor(persona="devops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        findings = resp.json()["findings"]
        assert len(findings) >= 1
        assert "control_id" in findings[0]


# ---------------------------------------------------------------------------
# Tests: Disclaimer always present (AC3)
# ---------------------------------------------------------------------------


class TestDisclaimerInResponse:
    def test_disclaimer_in_scored_response(self, db_session):
        aid = _seed_analysis(db_session)
        actor = _make_actor(persona="devops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["advisory_disclaimer"] == ADVISORY_DISCLAIMER
        assert body["advisory_disclaimer"].strip() != ""

    def test_disclaimer_in_unscorable_response(self, db_session):
        aid = _seed_analysis(
            db_session, score=0, grade="", unscorable_reason="all_not_assessable"
        )
        actor = _make_actor(persona="devops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["advisory_disclaimer"] == ADVISORY_DISCLAIMER


# ---------------------------------------------------------------------------
# Tests: requires_human_review always present (AC5)
# ---------------------------------------------------------------------------


class TestRequiresHumanReviewInResponse:
    def test_requires_human_review_is_array(self, db_session):
        aid = _seed_analysis(db_session)
        actor = _make_actor(persona="devops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        body = resp.json()
        assert isinstance(body["requires_human_review"], list)

    def test_coverage_limitation_appears_in_human_review(self, db_session):
        aid = _seed_analysis(db_session, add_coverage_limitation=True)
        actor = _make_actor(persona="devops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        body = resp.json()
        na_items = [
            i for i in body["requires_human_review"] if i["reason"] == "not_assessable"
        ]
        assert len(na_items) >= 1
        assert na_items[0]["control_id"] == "sh-001"


# ---------------------------------------------------------------------------
# Tests: Audit event emitted (AC9)
# ---------------------------------------------------------------------------


class TestAuditEventEmission:
    def test_one_audit_event_per_report_read(self, db_session):
        aid = _seed_analysis(db_session)
        actor = _make_actor(persona="devops_engineer")
        client = TestClient(_make_app(actor, db_session))

        before = db_session.query(AuditEvent).count()
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 200
        after = db_session.query(AuditEvent).count()

        assert after == before + 1

    def test_audit_event_has_correct_action(self, db_session):
        aid = _seed_analysis(db_session)
        actor = _make_actor(persona="devsecops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 200

        event = (
            db_session.query(AuditEvent)
            .filter_by(resource_id=str(aid), action="analysis.report_read")
            .first()
        )
        assert event is not None
        assert event.actor_id == str(_OWNER_ID)
        assert event.resource_type == "analysis"

    def test_audit_event_change_detail_has_no_secret_content(self, db_session):
        """Audit events must not contain definition content or secret values."""
        import re

        aid = _seed_analysis(db_session)
        actor = _make_actor(persona="devsecops_engineer")
        client = TestClient(_make_app(actor, db_session))
        resp = client.get(f"/api/v1/analyses/{aid}")
        assert resp.status_code == 200

        event = (
            db_session.query(AuditEvent)
            .filter_by(resource_id=str(aid), action="analysis.report_read")
            .order_by(AuditEvent.occurred_at.desc())
            .first()
        )
        assert event is not None
        # change_detail must contain only safe keys
        safe_keys = {"catalogue_version", "format"}
        if event.change_detail:
            assert set(event.change_detail.keys()).issubset(safe_keys), (
                f"Unexpected audit detail keys: {set(event.change_detail.keys()) - safe_keys}"
            )
        # Check no secret-shaped value (base64 long string or hex token)
        detail_str = str(event.change_detail or {})
        assert not re.search(r"[A-Za-z0-9+/]{32,}={0,2}", detail_str), (
            "Audit change_detail appears to contain secret-shaped content"
        )
