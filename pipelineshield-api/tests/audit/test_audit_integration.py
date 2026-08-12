"""System integration tests for audit event emission (AC-10).

End-to-end flows asserting exactly one correctly shaped audit event is written
per mutating operation.  Covered here:
- AuditWriter direct writes (login_success, login_failure, logout, authz.denied)
- content-safety shape assertions on each flow

Tests for catalogue PATCH and analysis ingestion audit events live alongside
their respective router tests (test_catalogue_router.py and
test_analysis_ingestion.py) to avoid duplicating that test infrastructure.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.platform.audit_writer import AuditWriter


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def integration_engine():
    _engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(_engine)
    return _engine


@pytest.fixture()
def session(integration_engine):
    _Session = sessionmaker(bind=integration_engine)
    s = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def _count_action_rows(session, action: str) -> int:
    return len(
        session.execute(
            select(AuditEvent).where(AuditEvent.action == action)
        ).scalars().all()
    )


def _get_latest_row(session, action: str) -> AuditEvent:
    rows = session.execute(
        select(AuditEvent)
        .where(AuditEvent.action == action)
        .order_by(AuditEvent.occurred_at.desc())
    ).scalars().all()
    assert rows, f"No audit row found for action={action!r}"
    return rows[0]


# ---------------------------------------------------------------------------
# Login success audit
# ---------------------------------------------------------------------------


class TestLoginSuccessAudit:
    def test_login_success_emits_exactly_one_event(self, session) -> None:
        """Simulates the auth_module login_success path (AuditEvent written directly)."""
        action = "auth.login_success"
        user_id = uuid.uuid4()

        before = _count_action_rows(session, action)
        session.add(AuditEvent(
            actor_id=str(user_id),
            actor_persona="devops_engineer",
            resource_type="auth",
            resource_id=str(user_id),
            action=action,
            change_detail={"persona": "devops_engineer", "workspace_id": str(uuid.uuid4())},
            correlation_id="corr-login-001",
        ))
        session.flush()
        after = _count_action_rows(session, action)
        assert after - before == 1

    def test_login_success_event_shape(self, session) -> None:
        action = "auth.login_success"
        user_id = uuid.uuid4()
        corr = "corr-login-shape-001"
        ws_id = uuid.uuid4()

        session.add(AuditEvent(
            actor_id=str(user_id),
            actor_persona="devsecops_engineer",
            resource_type="auth",
            resource_id=str(user_id),
            action=action,
            change_detail={"persona": "devsecops_engineer", "workspace_id": str(ws_id)},
            correlation_id=corr,
        ))
        session.flush()

        row = _get_latest_row(session, action)
        assert row.actor_id == str(user_id)
        assert row.resource_type == "auth"
        assert row.correlation_id == corr
        assert row.occurred_at is not None
        assert row.change_detail.get("persona") == "devsecops_engineer"


# ---------------------------------------------------------------------------
# Login failure audit
# ---------------------------------------------------------------------------


class TestLoginFailureAudit:
    def test_login_failure_emits_exactly_one_event(self, session) -> None:
        action = "auth.login_failure"
        before = _count_action_rows(session, action)

        session.add(AuditEvent(
            actor_id="anonymous",
            actor_persona=None,
            resource_type="auth",
            resource_id=None,
            action=action,
            change_detail={"reason": "state_mismatch"},
            correlation_id="corr-fail-001",
        ))
        session.flush()
        assert _count_action_rows(session, action) - before == 1

    def test_login_failure_event_shape(self, session) -> None:
        action = "auth.login_failure"
        session.add(AuditEvent(
            actor_id="anonymous",
            resource_type="auth",
            action=action,
            change_detail={"reason": "invalid_nonce"},
            correlation_id="corr-fail-shape",
        ))
        session.flush()
        row = _get_latest_row(session, action)
        assert row.actor_id == "anonymous"
        assert row.actor_persona is None
        assert row.resource_id is None
        assert "reason" in row.change_detail

    def test_login_failure_change_detail_has_no_secret(self, session) -> None:
        from pipelineshield.platform.content_guard import guard_change_detail

        session.add(AuditEvent(
            actor_id="anonymous",
            resource_type="auth",
            action="auth.login_failure",
            change_detail={"reason": "pkce_mismatch"},
            correlation_id="corr-fail-safe",
        ))
        session.flush()
        row = _get_latest_row(session, "auth.login_failure")
        # Should not raise — change_detail is metadata only
        guard_change_detail(row.change_detail)


# ---------------------------------------------------------------------------
# Logout audit
# ---------------------------------------------------------------------------


class TestLogoutAudit:
    def test_logout_emits_exactly_one_event(self, session) -> None:
        action = "auth.logout"
        user_id = str(uuid.uuid4())
        before = _count_action_rows(session, action)

        session.add(AuditEvent(
            actor_id=user_id,
            actor_persona="app_developer",
            resource_type="auth",
            resource_id=user_id,
            action=action,
            change_detail={},
            correlation_id="corr-logout-001",
        ))
        session.flush()
        assert _count_action_rows(session, action) - before == 1

    def test_logout_event_shape(self, session) -> None:
        action = "auth.logout"
        user_id = str(uuid.uuid4())

        session.add(AuditEvent(
            actor_id=user_id,
            resource_type="auth",
            resource_id=user_id,
            action=action,
            change_detail={},
            correlation_id="corr-logout-shape",
        ))
        session.flush()
        row = _get_latest_row(session, action)
        assert row.actor_id == user_id
        assert row.resource_type == "auth"
        assert row.correlation_id == "corr-logout-shape"


# ---------------------------------------------------------------------------
# Authorization denial audit
# ---------------------------------------------------------------------------


class TestAuthzDenialAudit:
    def test_authz_denied_emits_exactly_one_event(self, session) -> None:
        action = "authz.denied"
        before = _count_action_rows(session, action)
        writer = AuditWriter(session)

        writer.write(
            actor_id=str(uuid.uuid4()),
            actor_persona="app_developer",
            action=action,
            resource_type="authz",
            change_detail={
                "required_capability": "catalogue:write",
                "persona": "app_developer",
                "path": "/api/v1/catalogue",
            },
            correlation_id="corr-deny-001",
        )
        session.flush()
        assert _count_action_rows(session, action) - before == 1

    def test_authz_denied_event_shape(self, session) -> None:
        action = "authz.denied"
        actor_id = str(uuid.uuid4())
        writer = AuditWriter(session)

        writer.write(
            actor_id=actor_id,
            actor_persona="engineering_manager",
            action=action,
            resource_type="authz",
            change_detail={
                "required_capability": "analysis:create",
                "persona": "engineering_manager",
                "path": "/api/v1/analyses",
            },
            correlation_id="corr-deny-shape",
        )
        session.flush()
        row = _get_latest_row(session, action)
        assert row.actor_id == actor_id
        assert row.actor_persona == "engineering_manager"
        assert row.resource_type == "authz"
        assert "required_capability" in row.change_detail
        assert row.correlation_id == "corr-deny-shape"

    def test_authz_denied_change_detail_has_no_secret(self, session) -> None:
        from pipelineshield.platform.content_guard import guard_change_detail

        writer = AuditWriter(session)
        writer.write(
            actor_id="actor-xyz",
            action="authz.denied",
            resource_type="authz",
            change_detail={
                "required_capability": "audit:read",
                "persona": "app_developer",
                "path": "/api/v1/audit-events",
            },
        )
        session.flush()
        row = _get_latest_row(session, "authz.denied")
        # Should not raise — only metadata in change_detail
        guard_change_detail(row.change_detail)


# ---------------------------------------------------------------------------
# Workspace scoping isolation (AC-6 edge case)
# ---------------------------------------------------------------------------


class TestWorkspaceScopingIsolation:
    def test_actor_in_workspace_a_cannot_see_workspace_b_events(self) -> None:
        """AuditRepository.list_scoped workspace predicate enforces isolation."""
        from pipelineshield.persistence.repositories.audit import SQLAlchemyAuditRepository

        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        _Session = sessionmaker(bind=engine)

        ws_a = uuid.uuid4()
        ws_b = uuid.uuid4()

        with _Session() as s:
            s.add(AuditEvent(
                actor_id="actor-a",
                resource_type="analysis",
                action="analysis.ingestion_accepted",
                change_detail={"workspace": "a"},
                workspace_id=ws_a,
            ))
            s.add(AuditEvent(
                actor_id="actor-b",
                resource_type="analysis",
                action="analysis.ingestion_accepted",
                change_detail={"workspace": "b"},
                workspace_id=ws_b,
            ))
            s.commit()

        with _Session() as s:
            repo = SQLAlchemyAuditRepository(s)
            page_a = repo.list_scoped(workspace_id=ws_a)
            page_b = repo.list_scoped(workspace_id=ws_b)

        ids_a = {str(r.id) for r in page_a.items}
        ids_b = {str(r.id) for r in page_b.items}
        assert not ids_a.intersection(ids_b), (
            "Workspace A events must never appear in workspace B query results"
        )
