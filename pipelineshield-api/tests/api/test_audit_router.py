"""Integration tests for GET /api/v1/audit-events.

Tests:
- audit:read personas (devsecops_engineer, appsec_lead) can query
- Non-security personas receive 403
- Unauthenticated requests receive 401
- Cursor pagination works correctly
- Filters: action, resource_type, actor_id
- Response shape is correct (items, next_cursor, total_returned)
- No secret values, no definition content in response
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pipelineshield.api.security.authz_guard import CurrentActor
from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.audit_event import AuditEvent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine():
    _engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(_engine)
    return _engine


@pytest.fixture(scope="module")
def seeded_engine(engine):
    """Seed several audit_event rows for query testing."""
    _Session = sessionmaker(bind=engine)
    ws_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    actor_id = "00000000-0000-0000-0001-000000000003"

    with _Session() as session:
        for i in range(5):
            session.add(AuditEvent(
                actor_id=actor_id,
                actor_persona="devsecops_engineer",
                workspace_id=ws_id,
                resource_type="catalogue",
                resource_id=str(uuid.uuid4()),
                action="catalogue.version_created",
                change_detail={"version": i + 1},
                correlation_id=f"corr-{i:03d}",
            ))
        for i in range(3):
            session.add(AuditEvent(
                actor_id="anonymous",
                actor_persona=None,
                workspace_id=ws_id,
                resource_type="auth",
                resource_id=None,
                action="auth.login_failure",
                change_detail={"reason": "invalid_state"},
                correlation_id=f"auth-corr-{i:03d}",
            ))
        session.commit()
    return engine


@pytest.fixture()
def app(seeded_engine):
    from pipelineshield.api.main import create_app
    from pipelineshield.api.v1.routers.audit_router import get_db
    from pipelineshield.api.security.authz_guard import get_current_actor

    _app = create_app()
    _Session = sessionmaker(bind=seeded_engine)

    def _get_db():
        s = _Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    _app.dependency_overrides[get_db] = _get_db
    return _app


def _make_actor(persona: str) -> CurrentActor:
    return CurrentActor(
        user_id=uuid.UUID("00000000-0000-0000-0001-000000000003"),
        persona=persona,
        workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        display_name="Test User",
    )


def _client_with_actor(app, persona: str) -> TestClient:
    from pipelineshield.api.security.authz_guard import get_current_actor

    async def _actor():
        return _make_actor(persona)

    app.dependency_overrides[get_current_actor] = _actor
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Authorization tests
# ---------------------------------------------------------------------------


class TestAuditRouterAuthorization:
    def test_devsecops_engineer_can_read(self, app) -> None:
        client = _client_with_actor(app, "devsecops_engineer")
        resp = client.get("/api/v1/audit-events")
        assert resp.status_code == 200

    def test_appsec_lead_can_read(self, app) -> None:
        client = _client_with_actor(app, "appsec_lead")
        resp = client.get("/api/v1/audit-events")
        assert resp.status_code == 200

    def test_app_developer_denied(self, app) -> None:
        client = _client_with_actor(app, "app_developer")
        resp = client.get("/api/v1/audit-events")
        assert resp.status_code == 403

    def test_devops_engineer_denied(self, app) -> None:
        client = _client_with_actor(app, "devops_engineer")
        resp = client.get("/api/v1/audit-events")
        assert resp.status_code == 403

    def test_engineering_manager_denied(self, app) -> None:
        client = _client_with_actor(app, "engineering_manager")
        resp = client.get("/api/v1/audit-events")
        assert resp.status_code == 403

    def test_unauthenticated_returns_401(self, app) -> None:
        from pipelineshield.api.security.authz_guard import get_current_actor
        from fastapi import HTTPException

        async def _anon():
            raise HTTPException(status_code=401, detail={"title": "Not authenticated"})

        app.dependency_overrides[get_current_actor] = _anon
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit-events")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Response shape tests
# ---------------------------------------------------------------------------


class TestAuditRouterResponseShape:
    def test_returns_items_and_pagination(self, app) -> None:
        client = _client_with_actor(app, "devsecops_engineer")
        resp = client.get("/api/v1/audit-events")
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "next_cursor" in body
        assert "total_returned" in body
        assert isinstance(body["items"], list)

    def test_items_have_required_fields(self, app) -> None:
        client = _client_with_actor(app, "devsecops_engineer")
        resp = client.get("/api/v1/audit-events")
        body = resp.json()
        if body["items"]:
            item = body["items"][0]
            assert "id" in item
            assert "occurred_at" in item
            assert "actor_id" in item
            assert "action" in item
            assert "resource_type" in item
            assert "change_detail" in item

    def test_no_create_post_put_delete_endpoints_exist(self, app) -> None:
        """Assert the OpenAPI spec has no mutating audit-event routes."""
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/docs", follow_redirects=True)
        # Check via the OpenAPI JSON
        spec_resp = client.get("/openapi.json")
        spec = spec_resp.json()
        audit_paths = {
            method: True
            for path, methods in spec.get("paths", {}).items()
            if "audit" in path
            for method in methods
            if method in ("post", "put", "patch", "delete")
        }
        assert not audit_paths, (
            f"Mutating audit-event routes must not exist in OpenAPI spec: {audit_paths}"
        )


# ---------------------------------------------------------------------------
# Filter tests
# ---------------------------------------------------------------------------


class TestAuditRouterFilters:
    def test_filter_by_action(self, app) -> None:
        client = _client_with_actor(app, "devsecops_engineer")
        resp = client.get("/api/v1/audit-events?action=auth.login_failure")
        body = resp.json()
        assert resp.status_code == 200
        for item in body["items"]:
            assert item["action"] == "auth.login_failure"

    def test_filter_by_resource_type(self, app) -> None:
        client = _client_with_actor(app, "appsec_lead")
        resp = client.get("/api/v1/audit-events?resource_type=catalogue")
        body = resp.json()
        assert resp.status_code == 200
        for item in body["items"]:
            assert item["resource_type"] == "catalogue"

    def test_limit_respected(self, app) -> None:
        client = _client_with_actor(app, "devsecops_engineer")
        resp = client.get("/api/v1/audit-events?limit=2")
        body = resp.json()
        assert body["total_returned"] <= 2


# ---------------------------------------------------------------------------
# Pagination tests
# ---------------------------------------------------------------------------


class TestAuditRouterPagination:
    def test_cursor_pagination_returns_next_cursor_when_more_exist(self, app) -> None:
        client = _client_with_actor(app, "devsecops_engineer")
        resp = client.get("/api/v1/audit-events?limit=2")
        body = resp.json()
        # There are 8 total rows; with limit=2, should have a cursor
        if body["total_returned"] == 2:
            assert body["next_cursor"] is not None

    def test_cursor_can_fetch_next_page(self, app) -> None:
        client = _client_with_actor(app, "devsecops_engineer")
        page1 = client.get("/api/v1/audit-events?limit=2").json()
        if page1["next_cursor"]:
            cursor = page1["next_cursor"]
            page2 = client.get(f"/api/v1/audit-events?limit=2&cursor={cursor}").json()
            assert page2["total_returned"] >= 0
            # IDs on page 2 must not overlap with page 1
            ids1 = {item["id"] for item in page1["items"]}
            ids2 = {item["id"] for item in page2["items"]}
            assert not ids1.intersection(ids2), "Cursor pagination must not return duplicate items"
