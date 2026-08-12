"""Integration tests for the Alembic baseline migration.

These tests require a live PostgreSQL 16 container.  They are skipped
automatically when the ``POSTGRES_TEST_URL`` environment variable is not
set, which means they pass in unit-test-only CI runs without the
``postgres`` service.

Tests:
1. Upgrade creates all twelve tables.
2. Every table has a COMMENT containing the classification and retention strings.
3. Upgrade → downgrade → upgrade is reversible.
4. pipelineshield_app can INSERT and SELECT on audit_event.
5. pipelineshield_app cannot UPDATE or DELETE on audit_event
   (both raise InsufficientPrivilege / permission denied).
6. AI finding with weight > 0 is rejected by the CHECK constraint.
7. Seed baseline fixture creates the expected rows.

Prerequisites (set in CI via docker-compose or testcontainers):
    POSTGRES_TEST_URL=postgresql+psycopg://postgres:postgres@localhost:5432/pipelineshield_test
    POSTGRES_APP_USER_URL=postgresql+psycopg://pipelineshield_app@localhost:5432/pipelineshield_test
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Generator

import pytest
import sqlalchemy as sa
from sqlalchemy import inspect, text

# ---------------------------------------------------------------------------
# Skip marker — integration tests require a live PostgreSQL instance.
# ---------------------------------------------------------------------------
POSTGRES_TEST_URL = os.environ.get("POSTGRES_TEST_URL")
pytestmark = pytest.mark.skipif(
    not POSTGRES_TEST_URL,
    reason="POSTGRES_TEST_URL not set — skipping integration tests",
)


@pytest.fixture(scope="module")
def pg_engine():
    """Engine connected to the test PostgreSQL database (migration role)."""
    engine = sa.create_engine(POSTGRES_TEST_URL, pool_pre_ping=True)  # type: ignore[arg-type]
    yield engine
    engine.dispose()


@pytest.fixture(scope="module", autouse=True)
def run_upgrade(pg_engine):
    """Apply the baseline migration before the integration test suite runs.

    Tears down by running the downgrade after the suite completes.
    """
    from alembic.config import Config
    from alembic import command

    alembic_cfg = Config(str(Path(__file__).parents[2] / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", str(pg_engine.url))

    # Downgrade to base first (idempotent if already at base).
    command.downgrade(alembic_cfg, "base")
    # Run the migration under test.
    command.upgrade(alembic_cfg, "head")
    yield
    # Teardown: downgrade back to base after suite.
    command.downgrade(alembic_cfg, "base")


# ---------------------------------------------------------------------------
# 1. All twelve tables exist after upgrade
# ---------------------------------------------------------------------------


def test_all_tables_created(pg_engine):
    inspector = inspect(pg_engine)
    table_names = set(inspector.get_table_names())
    required = {
        "workspace",
        "app_user",
        "role_binding",
        "analysis",
        "pipeline_definition",
        "finding",
        "remediation",
        "generated_draft",
        "audit_event",
        "purge_receipt",
        "control_catalogue_version",
        "sample_pipeline",
    }
    missing = required - table_names
    assert not missing, f"Tables missing after upgrade: {missing}"


# ---------------------------------------------------------------------------
# 2. Every table carries a COMMENT with classification and retention
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "table_name, classification, retention",
    [
        ("workspace", "Internal", "indefinite"),
        ("app_user", "Internal", "indefinite"),
        ("role_binding", "Internal", "indefinite"),
        ("analysis", "Confidential", "90 days"),
        ("pipeline_definition", "Confidential", "90 days"),
        ("finding", "Confidential", "90 days"),
        ("remediation", "Confidential", "90 days"),
        ("generated_draft", "Confidential", "90 days"),
        ("audit_event", "Restricted", "1 year"),
        ("purge_receipt", "Internal", "indefinite"),
        ("control_catalogue_version", "Internal", "indefinite"),
        ("sample_pipeline", "Internal", "indefinite"),
    ],
)
def test_table_comment_contains_classification_and_retention(
    pg_engine, table_name, classification, retention
):
    """Every table comment must include the classification and retention strings."""
    with pg_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT obj_description(c.oid) "
                "FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE c.relname = :table AND n.nspname = 'public'"
            ),
            {"table": table_name},
        ).fetchone()

    assert row is not None, f"No pg_class entry for table {table_name}"
    comment = row[0] or ""
    assert classification in comment, (
        f"Table {table_name} comment {comment!r} missing classification "
        f"{classification!r}"
    )
    assert retention in comment, (
        f"Table {table_name} comment {comment!r} missing retention {retention!r}"
    )


# ---------------------------------------------------------------------------
# 3. Upgrade → downgrade → upgrade is reversible
# ---------------------------------------------------------------------------


def test_upgrade_downgrade_upgrade_reversible(pg_engine):
    """The migration is reversible: downgrade then upgrade succeeds."""
    from alembic.config import Config
    from alembic import command

    alembic_cfg = Config(str(Path(__file__).parents[2] / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", str(pg_engine.url))

    command.downgrade(alembic_cfg, "base")

    inspector = inspect(pg_engine)
    assert "workspace" not in inspector.get_table_names(), (
        "workspace table should be gone after downgrade"
    )

    command.upgrade(alembic_cfg, "head")

    inspector = inspect(pg_engine)
    assert "workspace" in inspector.get_table_names(), (
        "workspace table should exist after re-upgrade"
    )


# ---------------------------------------------------------------------------
# 4 & 5. pipelineshield_app role privilege assertions
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def app_engine(pg_engine):
    """Engine connected as pipelineshield_app (no UPDATE/DELETE on audit_event)."""
    app_url = os.environ.get("POSTGRES_APP_USER_URL")
    if not app_url:
        pytest.skip("POSTGRES_APP_USER_URL not set — skipping privilege tests")
    engine = sa.create_engine(app_url, pool_pre_ping=True)
    yield engine
    engine.dispose()


def test_app_role_can_insert_audit_event(pg_engine, app_engine):
    """pipelineshield_app must be able to INSERT into audit_event."""
    event_id = uuid.uuid4()
    with app_engine.connect() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_event "
                "(id, actor_id, resource_type, action, change_detail) "
                "VALUES (:id, :actor, :rt, :action, :detail::jsonb)"
            ),
            {
                "id": str(event_id),
                "actor": "test-actor",
                "rt": "test",
                "action": "test_insert",
                "detail": "{}",
            },
        )
        conn.commit()


def test_app_role_can_select_audit_event(app_engine):
    """pipelineshield_app must be able to SELECT from audit_event."""
    with app_engine.connect() as conn:
        result = conn.execute(
            text("SELECT COUNT(*) FROM audit_event")
        ).scalar()
    assert result is not None


def test_app_role_cannot_update_audit_event(app_engine):
    """pipelineshield_app must NOT be able to UPDATE audit_event rows."""
    with pytest.raises(Exception) as exc_info:
        with app_engine.connect() as conn:
            conn.execute(
                text(
                    "UPDATE audit_event SET actor_id = 'tampered' "
                    "WHERE actor_id = 'test-actor'"
                )
            )
            conn.commit()
    error_msg = str(exc_info.value).lower()
    assert "permission" in error_msg or "privilege" in error_msg or "denied" in error_msg


def test_app_role_cannot_delete_audit_event(app_engine):
    """pipelineshield_app must NOT be able to DELETE from audit_event."""
    with pytest.raises(Exception) as exc_info:
        with app_engine.connect() as conn:
            conn.execute(
                text("DELETE FROM audit_event WHERE actor_id = 'test-actor'")
            )
            conn.commit()
    error_msg = str(exc_info.value).lower()
    assert "permission" in error_msg or "privilege" in error_msg or "denied" in error_msg


# ---------------------------------------------------------------------------
# 6. AI finding CHECK constraint in PostgreSQL
# ---------------------------------------------------------------------------


def test_ai_finding_nonzero_weight_rejected_postgres(pg_engine):
    """The ai_source_zero_weight CHECK constraint must be enforced in PostgreSQL."""
    ws_id = uuid.uuid4()
    user_id = uuid.uuid4()
    ccv_id = uuid.uuid4()
    analysis_id = uuid.uuid4()

    with pg_engine.connect() as conn:
        conn.execute(
            text(
                "INSERT INTO workspace (id, name, slug) "
                "VALUES (:id, :name, :slug)"
            ),
            {"id": str(ws_id), "name": "check-test-ws", "slug": f"check-{ws_id}"},
        )
        conn.execute(
            text(
                "INSERT INTO app_user "
                "(id, workspace_id, sub_claim, email, display_name) "
                "VALUES (:id, :ws, :sub, :email, :dn)"
            ),
            {
                "id": str(user_id),
                "ws": str(ws_id),
                "sub": "sub|check",
                "email": "check@example.com",
                "dn": "Check User",
            },
        )
        conn.execute(
            text(
                "INSERT INTO control_catalogue_version "
                "(id, version, status, snapshot, grade_bands, created_by, content_checksum) "
                "VALUES (:id, 99, 'active', :snapshot::jsonb, '[]'::jsonb, :created_by, :checksum)"
            ),
            {
                "id": str(ccv_id),
                "snapshot": '{"categories": [], "grade_bands": []}',
                "created_by": str(user_id),
                "checksum": "a" * 64,
            },
        )
        conn.execute(
            text(
                "INSERT INTO analysis "
                "(id, workspace_id, owner_id, catalogue_version_id, "
                " pipeline_format, format_confidence, score, grade) "
                "VALUES (:id, :ws, :owner, :ccv, 'github_actions', 0.9, 70, 'B')"
            ),
            {
                "id": str(analysis_id),
                "ws": str(ws_id),
                "owner": str(user_id),
                "ccv": str(ccv_id),
            },
        )

        with pytest.raises(Exception) as exc_info:
            conn.execute(
                text(
                    "INSERT INTO finding "
                    "(id, workspace_id, analysis_id, source, "
                    " control_category, rule_id, severity, weight, title) "
                    "VALUES (:id, :ws, :analysis, 'ai', "
                    "'secrets', 'ai-001', 'high', 5, 'AI bad weight')"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "ws": str(ws_id),
                    "analysis": str(analysis_id),
                },
            )
            conn.commit()

    error_msg = str(exc_info.value).lower()
    assert "check" in error_msg or "constraint" in error_msg or "violat" in error_msg


# ---------------------------------------------------------------------------
# 7. Seed baseline fixture
# ---------------------------------------------------------------------------


def test_seed_baseline_creates_expected_rows(pg_engine):
    """The seed fixture must create 1 workspace, 4 role_bindings, 1 sample_pipeline."""
    from sqlalchemy.orm import Session
    from tests.fixtures.seed_baseline import seed_baseline, WORKSPACE_ID, USERS

    with Session(pg_engine) as session:
        result = seed_baseline(session)
        session.commit()

    with pg_engine.connect() as conn:
        ws_count = conn.execute(
            text("SELECT COUNT(*) FROM workspace WHERE id = :id"),
            {"id": str(WORKSPACE_ID)},
        ).scalar()
        assert ws_count == 1, "Expected 1 workspace after seeding"

        rb_count = conn.execute(
            text(
                "SELECT COUNT(*) FROM role_binding "
                "WHERE workspace_id = :ws"
            ),
            {"ws": str(WORKSPACE_ID)},
        ).scalar()
        assert rb_count == 4, f"Expected 4 role_bindings, got {rb_count}"

        sp_count = conn.execute(
            text(
                "SELECT COUNT(*) FROM sample_pipeline "
                "WHERE workspace_id = :ws"
            ),
            {"ws": str(WORKSPACE_ID)},
        ).scalar()
        assert sp_count == 1, f"Expected 1 sample_pipeline, got {sp_count}"
