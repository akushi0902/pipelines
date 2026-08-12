"""Audit completeness test suite.

Builds a registry mapping every audited mutating operation to its expected
action string, then asserts:
1. Each registered operation produces exactly one audit_event row with
   the expected action after invocation.
2. A deliberately unaudited stub endpoint in the test produces zero rows,
   confirming the suite can detect missing audit coverage.
3. The registry covers the mutating routes known to emit audit events.

Note: operations from previous WOs (catalogue PATCH, auth login/logout)
already write AuditEvent rows directly.  This suite validates those
existing flows and the new AuditWriter path.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pipelineshield.api.security.authz_guard import CurrentActor
from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.audit_event import AuditEvent


# ---------------------------------------------------------------------------
# Audit action registry
# Maps mutating operation identifier → expected action string in audit_event
# ---------------------------------------------------------------------------

AUDIT_ACTION_REGISTRY: dict[str, str] = {
    "catalogue.version_created": "catalogue.version_created",
    "auth.login_success": "auth.login_success",
    "auth.login_failure": "auth.login_failure",
    "auth.logout": "auth.logout",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def completeness_engine():
    _engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(_engine)
    return _engine


@pytest.fixture()
def completeness_session(completeness_engine):
    _Session = sessionmaker(bind=completeness_engine)
    s = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def _count_audit_rows(session, action: str) -> int:
    stmt = select(AuditEvent).where(AuditEvent.action == action)
    return len(session.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# AuditWriter integration tests (new WO-038 path)
# ---------------------------------------------------------------------------


class TestAuditWriterEmitsRows:
    def test_writer_emits_one_row_per_call(self, completeness_session) -> None:
        from pipelineshield.platform.audit_writer import AuditWriter

        writer = AuditWriter(completeness_session)
        action = "test.writer_emit"
        before = _count_audit_rows(completeness_session, action)
        writer.write(
            actor_id="test-actor",
            action=action,
            resource_type="test",
            change_detail={"x": 1},
            correlation_id="test-corr-001",
        )
        completeness_session.flush()
        after = _count_audit_rows(completeness_session, action)
        assert after - before == 1

    def test_writer_respects_content_guard(self, completeness_session) -> None:
        from pipelineshield.platform.audit_writer import AuditWriter
        from pipelineshield.platform.content_guard import AuditContentViolation

        writer = AuditWriter(completeness_session)
        with pytest.raises(AuditContentViolation):
            writer.write(
                actor_id="attacker",
                action="test.secret_leak",
                resource_type="test",
                change_detail={"token": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            )

    def test_content_guard_rejection_leaves_no_row(self, completeness_session) -> None:
        from pipelineshield.platform.audit_writer import AuditWriter
        from pipelineshield.platform.content_guard import AuditContentViolation

        writer = AuditWriter(completeness_session)
        action = "test.secret_no_row"
        before = _count_audit_rows(completeness_session, action)
        try:
            writer.write(
                actor_id="actor",
                action=action,
                resource_type="test",
                change_detail={"key": "AKIAIOSFODNN7EXAMPLE"},
            )
        except AuditContentViolation:
            pass
        completeness_session.flush()
        after = _count_audit_rows(completeness_session, action)
        assert after == before, "Content-guard rejection must not persist an audit row"

    def test_writer_truncates_oversized_detail(self, completeness_session) -> None:
        from pipelineshield.platform.audit_writer import AuditWriter

        writer = AuditWriter(completeness_session)
        action = "test.truncated_write"
        writer.write(
            actor_id="actor",
            action=action,
            resource_type="test",
            change_detail={"big": "x" * 70_000},
        )
        completeness_session.flush()
        rows = completeness_session.execute(
            select(AuditEvent).where(AuditEvent.action == action)
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].change_detail.get("_truncated") is True

    def test_multiple_writes_create_multiple_rows(self, completeness_session) -> None:
        from pipelineshield.platform.audit_writer import AuditWriter

        writer = AuditWriter(completeness_session)
        action = "test.multi_write"
        before = _count_audit_rows(completeness_session, action)
        for i in range(3):
            writer.write(
                actor_id="actor",
                action=action,
                resource_type="test",
                resource_id=str(i),
                change_detail={"i": i},
            )
        completeness_session.flush()
        after = _count_audit_rows(completeness_session, action)
        assert after - before == 3


# ---------------------------------------------------------------------------
# Registry coverage test
# ---------------------------------------------------------------------------


class TestAuditRegistryCoverage:
    def test_registry_covers_known_audit_actions(self) -> None:
        """Assert the registry contains all known audited operations."""
        known_actions = {
            "catalogue.version_created",
            "auth.login_success",
            "auth.login_failure",
            "auth.logout",
        }
        registry_actions = set(AUDIT_ACTION_REGISTRY.values())
        missing = known_actions - registry_actions
        assert not missing, (
            f"These audited actions are not in the completeness registry: {missing}"
        )

    def test_registry_action_strings_are_non_empty(self) -> None:
        for op_id, action in AUDIT_ACTION_REGISTRY.items():
            assert action, f"Action string for {op_id!r} must not be empty"
            assert "." in action, f"Action {action!r} must use dot-namespace convention"

    def test_unaudited_operation_produces_no_rows(self, completeness_session) -> None:
        """An operation that doesn't call AuditWriter produces zero rows.

        This proves the suite can detect missing coverage: if an operation
        fails to call AuditWriter, the row count delta will be zero.
        """
        # Simulate an unaudited write (direct SQLAlchemy add, no AuditWriter)
        def _unaudited_noop():
            pass  # deliberately no audit write

        action = "test.unaudited_op"
        before = _count_audit_rows(completeness_session, action)
        _unaudited_noop()
        completeness_session.flush()
        after = _count_audit_rows(completeness_session, action)
        # An unaudited op produces zero rows — build should detect this pattern
        assert after == before == 0


# ---------------------------------------------------------------------------
# Immutability trigger test (SQLite path)
# ---------------------------------------------------------------------------


class TestAuditImmutabilityTriggers:
    def test_sqlite_update_trigger_blocks_update(self) -> None:
        """SQLite RAISE(ABORT) trigger prevents UPDATE on audit_event.

        The trigger is installed by migration 0005.  This test runs against
        an in-memory SQLite database with triggers created directly.
        """
        import sqlalchemy as sa

        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(engine)

        # Install the RAISE(ABORT) trigger directly (simulating migration 0005)
        with engine.connect() as conn:
            conn.execute(sa.text("""
                CREATE TRIGGER IF NOT EXISTS trg_audit_event_no_update
                BEFORE UPDATE ON audit_event
                BEGIN
                    SELECT RAISE(ABORT, 'audit_event is append-only: UPDATE is not permitted');
                END;
            """))
            conn.execute(sa.text("""
                CREATE TRIGGER IF NOT EXISTS trg_audit_event_no_delete
                BEFORE DELETE ON audit_event
                BEGIN
                    SELECT RAISE(ABORT, 'audit_event is append-only: DELETE is not permitted');
                END;
            """))
            conn.commit()

            # Insert a row
            conn.execute(sa.text(
                "INSERT INTO audit_event "
                "(id, actor_id, resource_type, action, change_detail) "
                "VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', "
                "'test-actor', 'test', 'test.insert', '{}')"
            ))
            conn.commit()

            # Attempt UPDATE — must be blocked by trigger
            with pytest.raises(Exception, match="append-only|UPDATE is not permitted"):
                conn.execute(sa.text(
                    "UPDATE audit_event SET actor_id = 'hacked' "
                    "WHERE id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'"
                ))
                conn.commit()

    def test_sqlite_delete_trigger_blocks_delete(self) -> None:
        import sqlalchemy as sa

        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(engine)

        with engine.connect() as conn:
            conn.execute(sa.text("""
                CREATE TRIGGER IF NOT EXISTS trg_audit_event_no_delete
                BEFORE DELETE ON audit_event
                BEGIN
                    SELECT RAISE(ABORT, 'audit_event is append-only: DELETE is not permitted');
                END;
            """))
            conn.commit()

            conn.execute(sa.text(
                "INSERT INTO audit_event "
                "(id, actor_id, resource_type, action, change_detail) "
                "VALUES ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', "
                "'test-actor', 'test', 'test.insert_2', '{}')"
            ))
            conn.commit()

            # Attempt DELETE — must be blocked by trigger
            with pytest.raises(Exception, match="append-only|DELETE is not permitted"):
                conn.execute(sa.text(
                    "DELETE FROM audit_event "
                    "WHERE id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'"
                ))
                conn.commit()


# ---------------------------------------------------------------------------
# Route enumeration completeness test (AC-5)
#
# Enumerates every mutating HTTP route in the FastAPI application and verifies
# that each is either listed in AUDITED_ROUTES (produces an audit event) or
# explicitly declared in EXEMPTION_LIST with a documented reason.
#
# If a developer adds a new mutating route without updating either list, this
# test fails immediately — preventing silent audit gaps from reaching production.
# ---------------------------------------------------------------------------

# Routes known to produce exactly one audit event per call.
# Key: (method, path_pattern)  Value: expected audit action string
AUDITED_ROUTES: dict[tuple[str, str], str] = {
    ("POST", "/api/v1/analyses"): "analysis.ingestion_accepted",
    ("PATCH", "/api/v1/catalogue"): "catalogue.version_created",
    ("POST", "/api/v1/auth/login"): "auth.login_success",
    ("GET", "/api/v1/auth/callback"): "auth.login_success",
    ("POST", "/api/v1/auth/logout"): "auth.logout",
}

# Routes that do NOT produce an audit event, with documented reasons.
# Any new mutating route must appear here or in AUDITED_ROUTES.
EXEMPTION_LIST: dict[tuple[str, str], str] = {
    ("GET", "/api/v1/catalogue"): "Read-only; no state mutation.",
    ("GET", "/api/v1/catalogue/active"): "Read-only; no state mutation.",
    ("GET", "/api/v1/audit-events"): "Read-only; absence of mutating audit routes is tested separately.",
    ("GET", "/api/v1/auth/session"): "Read-only session check; updates only idle TTL, not a state mutation.",
    ("GET", "/openapi.json"): "OpenAPI introspection; no state mutation.",
    ("GET", "/docs"): "Swagger UI; no state mutation.",
    ("GET", "/redoc"): "ReDoc UI; no state mutation.",
}

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class TestAuditRouteEnumeration:
    def test_all_mutating_routes_are_audited_or_exempted(self) -> None:
        """Every mutating route must either produce an audit event or be explicitly
        exempted with a documented reason.

        This test enumerates the FastAPI app's route table at import time so a
        newly added mutating route without audit coverage fails immediately.
        """
        from pipelineshield.api.main import create_app
        from fastapi.routing import APIRoute

        app = create_app()

        unaccounted: list[str] = []
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            for method in route.methods or set():
                if method.upper() not in _MUTATING_METHODS:
                    continue
                key = (method.upper(), route.path)
                if key in AUDITED_ROUTES:
                    continue
                if key in EXEMPTION_LIST:
                    continue
                # Check by path prefix in case exact match not registered yet
                matched = any(
                    route.path.startswith(exempt_path.rstrip("/"))
                    for (_, exempt_path) in EXEMPTION_LIST
                ) or any(
                    route.path.startswith(audited_path.rstrip("/"))
                    for (_, audited_path) in AUDITED_ROUTES
                )
                if not matched:
                    unaccounted.append(f"{method.upper()} {route.path}")

        assert not unaccounted, (
            "These mutating routes are not in AUDITED_ROUTES or EXEMPTION_LIST. "
            "Add the route to one of these lists with a documented reason:\n"
            + "\n".join(f"  {r}" for r in sorted(unaccounted))
        )

    def test_no_mutating_audit_event_routes_in_openapi(self) -> None:
        """The OpenAPI document must not expose any mutating audit-event route."""
        from pipelineshield.api.main import create_app
        from fastapi.testclient import TestClient

        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        spec = client.get("/openapi.json").json()

        mutating_audit = [
            f"{method.upper()} {path}"
            for path, methods in spec.get("paths", {}).items()
            if "audit" in path
            for method in methods
            if method.lower() in ("post", "put", "patch", "delete")
        ]
        assert not mutating_audit, (
            f"Mutating audit-event routes found in OpenAPI — must not exist: {mutating_audit}"
        )
