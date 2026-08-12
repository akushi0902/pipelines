"""Integration tests for GET /api/v1/catalogue and PATCH /api/v1/catalogue.

Uses FastAPI TestClient with an in-memory SQLite database.  The
``get_current_actor`` and ``get_db`` dependencies are overridden per test
so that no external services are needed.

Coverage:
  - GET: 200 for every persona; 401 unauthenticated
  - PATCH: 201 for DevSecOps and AppSec personas; 403 for others
  - PATCH 400: invalid weights, empty change set, unknown id
  - PATCH 409: stale base_version
  - PATCH 422: malformed payload (unknown field in fields map)
  - Transactional rollback: audit write failure → no orphan version row
  - Exactly one audit_event per successful PATCH
  - Predecessor version content_checksum unchanged after PATCH
"""
from __future__ import annotations

import uuid
from typing import Generator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from pipelineshield.api.main import create_app
from pipelineshield.api.security.authz_guard import CurrentActor, get_current_actor
from pipelineshield.api.v1.routers.catalogue_router import get_db
from pipelineshield.catalogue.schemas import CatalogueSnapshot
from pipelineshield.catalogue.seed import seed_v1_catalogue
from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.control_catalogue_version import (
    ControlCatalogueVersion,
)
from pipelineshield.persistence.repositories.catalogue import (
    SQLAlchemyCatalogueRepository,
)
from tests.fixtures.seed_baseline import USERS, WORKSPACE_ID, seed_baseline

# ---------------------------------------------------------------------------
# Database fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(engine, autoflush=False)
    session = Session(engine)
    yield session
    session.rollback()
    session.close()


@pytest.fixture(scope="function")
def seeded_session(db_session: Session) -> Session:
    """Session with baseline users + catalogue v1."""
    ids = seed_baseline(db_session)
    db_session.flush()
    seed_v1_catalogue(db_session, created_by=USERS["devsecops_engineer"])
    db_session.flush()
    return db_session


# ---------------------------------------------------------------------------
# TestClient factory
# ---------------------------------------------------------------------------


def _make_client(
    session: Session,
    actor: CurrentActor | None,
) -> TestClient:
    """Create a TestClient with overridden dependencies."""
    app = create_app()

    async def _get_db_override():
        yield session

    app.dependency_overrides[get_db] = _get_db_override

    if actor is not None:
        async def _actor_override() -> CurrentActor:
            return actor
        app.dependency_overrides[get_current_actor] = _actor_override

    return TestClient(app, raise_server_exceptions=False)


def _actor(persona: str) -> CurrentActor:
    return CurrentActor(
        user_id=USERS[persona],
        persona=persona,
        workspace_id=WORKSPACE_ID,
        display_name=f"Test {persona}",
    )


# ---------------------------------------------------------------------------
# GET /api/v1/catalogue — 200 for all personas
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "persona",
    ["app_developer", "devops_engineer", "devsecops_engineer", "appsec_lead", "engineering_manager"],
)
def test_get_catalogue_200_all_personas(seeded_session, persona):
    client = _make_client(seeded_session, _actor(persona))
    resp = client.get("/api/v1/catalogue")
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 1
    assert body["status"] == "active"
    assert len(body["categories"]) > 0
    assert len(body["controls"]) > 0
    assert len(body["grade_bands"]) > 0
    assert "created_at" in body
    assert "created_by" in body


def test_get_catalogue_payload_shape(seeded_session):
    client = _make_client(seeded_session, _actor("app_developer"))
    resp = client.get("/api/v1/catalogue")
    body = resp.json()
    # Verify category shape
    cat = body["categories"][0]
    assert "id" in cat and "name" in cat and "weight" in cat and "enabled" in cat
    # Verify control shape
    ctrl = body["controls"][0]
    assert "id" in ctrl and "category_id" in ctrl and "severity" in ctrl
    assert "enabled" in ctrl and "reference_tools" in ctrl
    # Verify grade_band shape
    gb = body["grade_bands"][0]
    assert "grade" in gb and "min_score" in gb and "max_score" in gb


# ---------------------------------------------------------------------------
# GET — 401 unauthenticated
# ---------------------------------------------------------------------------


def test_get_catalogue_401_unauthenticated(seeded_session):
    # No actor override → stub raises 401
    app = create_app()
    async def _get_db_override():
        yield seeded_session
    app.dependency_overrides[get_db] = _get_db_override
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/v1/catalogue")
    assert resp.status_code == 401
    # No catalogue content in error body
    body = resp.json()
    assert "categories" not in body
    assert "controls" not in body


# ---------------------------------------------------------------------------
# PATCH — 201 for write-capable personas
# ---------------------------------------------------------------------------


def _valid_patch_payload(base_version: int = 1) -> dict:
    """Build a valid PATCH payload that rebalances two categories.

    secrets_hygiene: 15 → 14
    artifact_signing: 15 → 16
    Net change: 0 (total stays 100).
    """
    return {
        "base_version": base_version,
        "rationale": "Test weight rebalance for CI",
        "changes": [
            {
                "target": "category",
                "id": "secrets_hygiene",
                "fields": {"weight": 14},
            },
            {
                "target": "category",
                "id": "artifact_signing",
                "fields": {"weight": 16},
            },
        ],
    }


@pytest.mark.parametrize("persona", ["devsecops_engineer", "appsec_lead"])
def test_patch_catalogue_201_write_personas(seeded_session, persona):
    client = _make_client(seeded_session, _actor(persona))
    payload = _valid_patch_payload()
    resp = client.patch("/api/v1/catalogue", json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["version"] == 2
    assert "diff" in body
    assert "snapshot" in body
    assert body["snapshot"]["version"] == 2


def test_patch_catalogue_creates_new_version_row(seeded_session):
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    payload = _valid_patch_payload()
    client.patch("/api/v1/catalogue", json=payload)

    repo = SQLAlchemyCatalogueRepository(seeded_session)
    versions = list(repo.list_versions())
    assert len(versions) == 2
    assert versions[0].status == "superseded"
    assert versions[1].status == "active"
    assert versions[1].version == 2


def test_patch_predecessor_checksum_unchanged(seeded_session):
    """The predecessor's content_checksum must not change after a PATCH."""
    repo = SQLAlchemyCatalogueRepository(seeded_session)
    original = repo.get_active()
    original_checksum = original.content_checksum
    original_id = original.id

    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    client.patch("/api/v1/catalogue", json=_valid_patch_payload())

    # Re-fetch predecessor
    predecessor = seeded_session.get(ControlCatalogueVersion, original_id)
    assert predecessor is not None
    assert predecessor.content_checksum == original_checksum
    assert predecessor.status == "superseded"


def test_patch_returns_structured_diff(seeded_session):
    """A weight rebalance produces diff entries for each changed field."""
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    resp = client.patch("/api/v1/catalogue", json=_valid_patch_payload())
    assert resp.status_code == 201, resp.text
    diff = resp.json()["diff"]
    # Two weight changes → two diff entries
    assert len(diff) == 2
    paths = {e["path"] for e in diff}
    assert "categories.secrets_hygiene.weight" in paths
    assert "categories.artifact_signing.weight" in paths


def test_patch_exactly_one_audit_event(seeded_session):
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    client.patch("/api/v1/catalogue", json=_valid_patch_payload())

    events = seeded_session.execute(
        select(AuditEvent).where(AuditEvent.action == "catalogue.version_created")
    ).scalars().all()
    assert len(events) == 1
    evt = events[0]
    assert evt.actor_persona == "devsecops_engineer"
    assert evt.resource_type == "control_catalogue_version"
    assert "diff" in evt.change_detail


def test_patch_audit_detail_no_secret_content(seeded_session):
    """change_detail in the audit event must not contain secret-shaped values."""
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    payload = {
        "base_version": 1,
        "rationale": "Rationale with no secrets ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGG1234",
        "changes": [{"target": "category", "id": "secrets_hygiene", "fields": {"weight": 15}}],
    }
    client.patch("/api/v1/catalogue", json=payload)

    evt = seeded_session.execute(
        select(AuditEvent).where(AuditEvent.action == "catalogue.version_created")
    ).scalar_one()
    detail_str = str(evt.change_detail)
    # The GitHub PAT in rationale must have been redacted
    assert "ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGG1234" not in detail_str


# ---------------------------------------------------------------------------
# PATCH — 403 for read-only personas
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "persona",
    ["app_developer", "devops_engineer", "engineering_manager"],
)
def test_patch_catalogue_403_read_only_personas(seeded_session, persona):
    client = _make_client(seeded_session, _actor(persona))
    resp = client.patch("/api/v1/catalogue", json=_valid_patch_payload())
    assert resp.status_code == 403
    body = resp.json()
    assert "403" in str(body["detail"]["status"])


def test_patch_403_creates_no_version_row(seeded_session):
    client = _make_client(seeded_session, _actor("app_developer"))
    client.patch("/api/v1/catalogue", json=_valid_patch_payload())
    repo = SQLAlchemyCatalogueRepository(seeded_session)
    versions = list(repo.list_versions())
    assert len(versions) == 1  # still only version 1


# ---------------------------------------------------------------------------
# PATCH — 400 invalid weight total
# ---------------------------------------------------------------------------


def _get_real_category_ids(session: Session) -> list[str]:
    repo = SQLAlchemyCatalogueRepository(session)
    active = repo.get_active()
    return [c["id"] for c in active.snapshot.get("categories", [])]


def test_patch_400_invalid_weight_total(seeded_session):
    """A change that breaks the enabled-weight-total-equals-100 invariant → 400."""
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    payload = {
        "base_version": 1,
        "rationale": "Break the weight total",
        "changes": [
            {
                "target": "category",
                "id": "secrets_hygiene",
                "fields": {"weight": 99},  # Will make total != 100
            }
        ],
    }
    resp = client.patch("/api/v1/catalogue", json=payload)
    assert resp.status_code == 400
    body = resp.json()
    assert body["detail"]["status"] == 400


def test_patch_400_no_version_created_on_invalid_weight(seeded_session):
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    payload = {
        "base_version": 1,
        "rationale": "Break weight",
        "changes": [
            {"target": "category", "id": "secrets_hygiene", "fields": {"weight": 99}}
        ],
    }
    client.patch("/api/v1/catalogue", json=payload)
    repo = SQLAlchemyCatalogueRepository(seeded_session)
    assert len(list(repo.list_versions())) == 1


def test_patch_400_empty_changes(seeded_session):
    """Empty changes list is rejected at the Pydantic boundary (min_length=1)."""
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    payload = {"base_version": 1, "rationale": "No changes", "changes": []}
    resp = client.patch("/api/v1/catalogue", json=payload)
    assert resp.status_code == 422


def test_patch_400_unknown_category_id(seeded_session):
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    payload = {
        "base_version": 1,
        "rationale": "Unknown id",
        "changes": [
            {
                "target": "category",
                "id": "nonexistent_category_xyz",
                "fields": {"weight": 15},
            }
        ],
    }
    resp = client.patch("/api/v1/catalogue", json=payload)
    assert resp.status_code == 400


def test_patch_400_unknown_control_id(seeded_session):
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    payload = {
        "base_version": 1,
        "rationale": "Unknown control",
        "changes": [
            {
                "target": "control",
                "id": "nonexistent_control_xyz",
                "fields": {"enabled": False},
            }
        ],
    }
    resp = client.patch("/api/v1/catalogue", json=payload)
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# PATCH — 409 stale base_version
# ---------------------------------------------------------------------------


def test_patch_409_stale_base_version(seeded_session):
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    # First successful PATCH creates version 2
    client.patch("/api/v1/catalogue", json=_valid_patch_payload(base_version=1))

    # Second PATCH still claims base_version=1 → 409
    resp = client.patch(
        "/api/v1/catalogue", json=_valid_patch_payload(base_version=1)
    )
    assert resp.status_code == 409
    body = resp.json()
    assert body["detail"]["status"] == 409
    # Current active version should be in the response
    assert "2" in body["detail"]["detail"]


def test_patch_409_no_version_gap(seeded_session):
    """Two concurrent PATCHes: exactly one succeeds, no version number gap."""
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    r1 = client.patch("/api/v1/catalogue", json=_valid_patch_payload(base_version=1))
    r2 = client.patch("/api/v1/catalogue", json=_valid_patch_payload(base_version=1))

    statuses = {r1.status_code, r2.status_code}
    assert 201 in statuses
    assert 409 in statuses

    repo = SQLAlchemyCatalogueRepository(seeded_session)
    versions = list(repo.list_versions())
    # Version numbers must be consecutive — no gap
    version_nums = sorted(v.version for v in versions)
    assert version_nums == list(range(1, len(version_nums) + 1))


# ---------------------------------------------------------------------------
# PATCH — 422 malformed payload
# ---------------------------------------------------------------------------


def test_patch_422_unknown_field_in_fields_map(seeded_session):
    """A field outside the allowed map is rejected with 422."""
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    payload = {
        "base_version": 1,
        "rationale": "Try to patch an illegal field",
        "changes": [
            {
                "target": "category",
                "id": "secrets_hygiene",
                "fields": {"weight": 15, "remediation_template_ref": "hack"},
            }
        ],
    }
    resp = client.patch("/api/v1/catalogue", json=payload)
    assert resp.status_code == 422


def test_patch_422_invalid_target_value(seeded_session):
    client = _make_client(seeded_session, _actor("devsecops_engineer"))
    payload = {
        "base_version": 1,
        "rationale": "Bad target",
        "changes": [{"target": "workspace", "id": "foo", "fields": {"enabled": True}}],
    }
    resp = client.patch("/api/v1/catalogue", json=payload)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Transactional rollback: audit failure → no orphan version row
# ---------------------------------------------------------------------------


def test_patch_transactional_rollback_on_audit_failure(seeded_session):
    """If AuditWriter raises after version INSERT, the whole tx rolls back."""
    from pipelineshield.persistence.repositories.audit import SQLAlchemyAuditRepository

    original_append = SQLAlchemyAuditRepository.append

    def _failing_append(self, event):
        raise RuntimeError("Simulated audit write failure")

    with patch.object(SQLAlchemyAuditRepository, "append", _failing_append):
        client = _make_client(seeded_session, _actor("devsecops_engineer"))
        resp = client.patch("/api/v1/catalogue", json=_valid_patch_payload())
        assert resp.status_code == 500

    # Session is rolled back — only version 1 should exist
    seeded_session.rollback()
    repo = SQLAlchemyCatalogueRepository(seeded_session)
    versions = list(repo.list_versions())
    assert len(versions) == 1
    assert versions[0].version == 1
    assert versions[0].status == "active"


# ---------------------------------------------------------------------------
# Unit tests: CatalogueService directly
# ---------------------------------------------------------------------------


def test_service_get_active_returns_correct_shape(seeded_session):
    from pipelineshield.services.catalogue_service import CatalogueService

    svc = CatalogueService()
    result = svc.get_active_catalogue(seeded_session)
    assert result.version == 1
    assert result.status == "active"
    assert len(result.categories) > 0
    assert len(result.controls) > 0


def test_service_apply_changes_diff_generation(seeded_session):
    from pipelineshield.api.v1.schemas.catalogue import CataloguePatchRequest
    from pipelineshield.services.catalogue_service import CatalogueService

    svc = CatalogueService()
    request = CataloguePatchRequest(
        base_version=1,
        rationale="Direct service test",
        changes=[
            {"target": "category", "id": "secrets_hygiene", "fields": {"weight": 14}},
            {"target": "category", "id": "artifact_signing", "fields": {"weight": 16}},
        ],
    )
    actor = _actor("devsecops_engineer")
    result = svc.apply_changes(seeded_session, actor, request)
    assert result.version == 2
    assert len(result.diff) == 2


def test_service_stale_base_version_raises_conflict(seeded_session):
    from pipelineshield.api.v1.schemas.catalogue import CataloguePatchRequest
    from pipelineshield.catalogue.schemas import CatalogueVersionConflictError
    from pipelineshield.services.catalogue_service import CatalogueService

    svc = CatalogueService()
    request = CataloguePatchRequest(
        base_version=99,
        rationale="Stale test",
        changes=[
            {"target": "category", "id": "secrets_hygiene", "fields": {"weight": 15}}
        ],
    )
    actor = _actor("devsecops_engineer")
    with pytest.raises(CatalogueVersionConflictError):
        svc.apply_changes(seeded_session, actor, request)


def test_service_invalid_weight_raises_validation_error(seeded_session):
    from pipelineshield.api.v1.schemas.catalogue import CataloguePatchRequest
    from pipelineshield.services.catalogue_service import CatalogueService

    svc = CatalogueService()
    # secrets_hygiene: 15 → 99 (total becomes 184, fails validation)
    request = CataloguePatchRequest(
        base_version=1,
        rationale="Weight break",
        changes=[
            {"target": "category", "id": "secrets_hygiene", "fields": {"weight": 99}}
        ],
    )
    actor = _actor("devsecops_engineer")
    with pytest.raises(Exception):
        svc.apply_changes(seeded_session, actor, request)
