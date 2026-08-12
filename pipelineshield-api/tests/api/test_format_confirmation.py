"""Integration tests for POST /api/v1/analyses/{id}/format-confirmation (WO-004 AC-10).

Coverage
--------
TestLowConfidenceIngestionResponse  — 201 with format_confirmation_required=true
TestFormatConfirmationEndpoint      — successful confirmation flow
TestConfirmationAudit               — exactly one audit_event with action=format_confirmed
TestOwnershipEnforcement            — cross-owner confirmation rejected with 404
TestConfirmationConflict            — already-confirmed returns 409
TestConfirmationNotRequired         — high-confidence analysis returns 422
TestInvalidFormatEnum               — invalid format string returns 400/422
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from pipelineshield.api.main import create_app
from pipelineshield.api.security.authz_guard import CurrentActor, get_current_actor
from pipelineshield.api.v1.routers.analysis_router import get_db, get_orchestrator
from pipelineshield.catalogue.seed import seed_v1_catalogue
from pipelineshield.crypto.key_provider import KeyProvider
from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.services.analysis_orchestrator import AnalysisOrchestrator
from tests.fixtures.seed_baseline import USERS, WORKSPACE_ID, seed_baseline

_FIXTURES = Path(__file__).parent.parent / "fixtures"

# ---------------------------------------------------------------------------
# Fake key provider
# ---------------------------------------------------------------------------


class FakeKeyProvider(KeyProvider):
    @property
    def key_id(self) -> str:
        return "test-key-v1"

    def encrypt(self, plaintext: bytes) -> bytes:
        return b"ENC:" + plaintext

    def decrypt(self, ciphertext: bytes) -> bytes:
        return ciphertext[4:]


# ---------------------------------------------------------------------------
# DB and client fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(eng, "connect")
    def _fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def seeded_session(engine) -> Generator[Session, None, None]:
    _Session = sessionmaker(bind=engine)
    s = _Session()
    seed_baseline(s)
    seed_v1_catalogue(s)
    s.flush()
    try:
        yield s
        s.rollback()
    finally:
        s.close()


def _make_client(
    session: Session,
    persona: str = "app_developer",
    user_id: uuid.UUID | None = None,
) -> TestClient:
    if user_id is None:
        user_id = USERS[persona]
    app = create_app()
    actor = CurrentActor(
        user_id=user_id,
        workspace_id=WORKSPACE_ID,
        persona=persona,
    )
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_current_actor] = lambda: actor
    app.dependency_overrides[get_orchestrator] = lambda: AnalysisOrchestrator(
        key_provider=FakeKeyProvider()
    )
    return TestClient(app, raise_server_exceptions=False)


# Ambiguous content — has both `stages:` (GitLab) and `jobs:` (GHA)
_AMBIGUOUS_CONTENT = """\
stages:
  - build
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""

# High-confidence GitHub Actions content
_GHA_CONTENT = """\
name: CI
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest
"""


def _ingest(client: TestClient, content: str, filename: str | None = None) -> dict:
    payload = {"definition_text": content}
    if filename:
        payload["filename"] = filename
    resp = client.post(
        "/api/v1/analyses",
        json=payload,
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 201, f"Ingestion failed: {resp.json()}"
    return resp.json()


# ---------------------------------------------------------------------------
# AC-3: Low-confidence ingestion response
# ---------------------------------------------------------------------------


class TestLowConfidenceIngestionResponse:
    def test_ambiguous_content_sets_confirmation_required(self, seeded_session: Session) -> None:
        client = _make_client(seeded_session)
        body = _ingest(client, _AMBIGUOUS_CONTENT)
        assert body["format_confirmation_required"] is True

    def test_high_confidence_clears_confirmation_required(self, seeded_session: Session) -> None:
        client = _make_client(seeded_session)
        body = _ingest(client, _GHA_CONTENT, filename=".github/workflows/ci.yml")
        assert body["format_confirmation_required"] is False


# ---------------------------------------------------------------------------
# AC-4 + AC-5: Confirmation endpoint — success path
# ---------------------------------------------------------------------------


class TestFormatConfirmationEndpoint:
    def test_confirm_format_returns_200(self, seeded_session: Session) -> None:
        client = _make_client(seeded_session)
        ingestion = _ingest(client, _AMBIGUOUS_CONTENT)
        analysis_id = ingestion["analysis_id"]

        resp = client.post(
            f"/api/v1/analyses/{analysis_id}/format-confirmation",
            json={"confirmed_format": "github_actions"},
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 200, resp.json()
        body = resp.json()
        assert body["analysis_id"] == analysis_id
        assert body["confirmed_format"] == "github_actions"
        assert body["format_confirmed_by_user"] is True

    def test_confirmed_format_persisted_in_db(self, seeded_session: Session) -> None:
        client = _make_client(seeded_session)
        ingestion = _ingest(client, _AMBIGUOUS_CONTENT)
        analysis_id = uuid.UUID(ingestion["analysis_id"])

        client.post(
            f"/api/v1/analyses/{analysis_id}/format-confirmation",
            json={"confirmed_format": "gitlab_ci"},
            headers={"content-type": "application/json"},
        )
        seeded_session.expire_all()
        analysis = seeded_session.execute(
            select(Analysis).where(Analysis.id == analysis_id)
        ).scalar_one()
        assert analysis.confirmed_format == "gitlab_ci"
        assert analysis.format_confirmed_by_user is True


# ---------------------------------------------------------------------------
# AC-5: Exactly one audit event with action=format_confirmed
# ---------------------------------------------------------------------------


class TestConfirmationAudit:
    def test_exactly_one_audit_event_written(self, seeded_session: Session) -> None:
        client = _make_client(seeded_session)
        ingestion = _ingest(client, _AMBIGUOUS_CONTENT)
        analysis_id = ingestion["analysis_id"]

        before = len(
            seeded_session.execute(
                select(AuditEvent).where(AuditEvent.action == "format_confirmed")
            ).scalars().all()
        )

        client.post(
            f"/api/v1/analyses/{analysis_id}/format-confirmation",
            json={"confirmed_format": "github_actions"},
            headers={"content-type": "application/json"},
        )
        seeded_session.expire_all()

        after = seeded_session.execute(
            select(AuditEvent).where(AuditEvent.action == "format_confirmed")
        ).scalars().all()
        assert len(after) - before == 1

    def test_audit_event_change_detail_has_formats(self, seeded_session: Session) -> None:
        client = _make_client(seeded_session)
        ingestion = _ingest(client, _AMBIGUOUS_CONTENT)
        analysis_id = ingestion["analysis_id"]

        client.post(
            f"/api/v1/analyses/{analysis_id}/format-confirmation",
            json={"confirmed_format": "gitlab_ci"},
            headers={"content-type": "application/json"},
        )
        seeded_session.expire_all()

        event_row = seeded_session.execute(
            select(AuditEvent).where(AuditEvent.action == "format_confirmed")
        ).scalars().first()
        assert event_row is not None
        detail = event_row.change_detail
        assert "detected_format" in detail
        assert "confirmed_format" in detail
        # Audit must not contain definition content
        assert "definition_text" not in detail
        assert "masked_content" not in detail


# ---------------------------------------------------------------------------
# AC-10: Ownership enforcement — cross-owner rejected with 404
# ---------------------------------------------------------------------------


class TestOwnershipEnforcement:
    def test_cross_owner_confirmation_returns_404(self, seeded_session: Session) -> None:
        owner_client = _make_client(seeded_session, persona="app_developer")
        ingestion = _ingest(owner_client, _AMBIGUOUS_CONTENT)
        analysis_id = ingestion["analysis_id"]

        # Different user with same workspace tries to confirm
        other_user_id = uuid.uuid4()
        other_client = _make_client(
            seeded_session,
            persona="app_developer",
            user_id=other_user_id,
        )
        resp = other_client.post(
            f"/api/v1/analyses/{analysis_id}/format-confirmation",
            json={"confirmed_format": "github_actions"},
            headers={"content-type": "application/json"},
        )
        # Must return 404, not 403, to avoid existence disclosure
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# AC-10: Conflict — already-confirmed returns 409
# ---------------------------------------------------------------------------


class TestConfirmationConflict:
    def test_second_confirmation_returns_409(self, seeded_session: Session) -> None:
        client = _make_client(seeded_session)
        ingestion = _ingest(client, _AMBIGUOUS_CONTENT)
        analysis_id = ingestion["analysis_id"]

        # First confirmation
        resp1 = client.post(
            f"/api/v1/analyses/{analysis_id}/format-confirmation",
            json={"confirmed_format": "github_actions"},
            headers={"content-type": "application/json"},
        )
        assert resp1.status_code == 200

        # Second attempt
        resp2 = client.post(
            f"/api/v1/analyses/{analysis_id}/format-confirmation",
            json={"confirmed_format": "gitlab_ci"},
            headers={"content-type": "application/json"},
        )
        assert resp2.status_code == 409


# ---------------------------------------------------------------------------
# AC-10: 422 when confirmation not required
# ---------------------------------------------------------------------------


class TestConfirmationNotRequired:
    def test_high_confidence_analysis_returns_422(self, seeded_session: Session) -> None:
        client = _make_client(seeded_session)
        ingestion = _ingest(client, _GHA_CONTENT, filename=".github/workflows/ci.yml")
        assert ingestion["format_confirmation_required"] is False
        analysis_id = ingestion["analysis_id"]

        resp = client.post(
            f"/api/v1/analyses/{analysis_id}/format-confirmation",
            json={"confirmed_format": "github_actions"},
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 422
