"""Unit tests for SQLAlchemy 2.0 models.

Tests assert:
- Column types, nullability, unique constraints, and foreign keys.
- The AI zero-weight CHECK constraint on the finding table.
- Absence of soft-delete columns on Confidential entities.

These tests use SQLite in-memory (via create_engine) so they run without
a PostgreSQL container.  The CHECK constraint is expressed in standard SQL
and is enforced by SQLite as well as PostgreSQL.

Note: dialect-specific types (UUID, JSONB) degrade gracefully under SQLite.
The test is about schema shape and constraints, not dialect features.

SQLAlchemy 2.0 notes:
- StaticPool is used so all sessions share the same SQLite in-memory connection
  and therefore see the same tables created by Base.metadata.create_all().
- The session fixture uses Session(engine) without the deprecated bind= kwarg
  and rolls back after each test for isolation.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from pipelineshield.persistence.models import (
    Base,
    Workspace,
    AppUser,
    RoleBinding,
    Analysis,
    PipelineDefinition,
    Finding,
    Remediation,
    GeneratedDraft,
    AuditEvent,
    PurgeReceipt,
    ControlCatalogueVersion,
    SamplePipeline,
)


@pytest.fixture(scope="module")
def engine():
    """Create an in-memory SQLite engine with the full schema.

    StaticPool forces all connections to reuse the same underlying SQLite
    in-memory database, which is required for multiple Session instances to
    see the same tables within a single test run.
    """
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Enable FK enforcement for every connection checked out from the pool.
    @event.listens_for(eng, "connect")
    def _enable_fk(dbapi_conn, connection_record):  # type: ignore[misc]
        dbapi_conn.execute("PRAGMA foreign_keys = ON")

    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture
def session(engine):
    """Provide a test session that rolls back after each test.

    Uses SQLAlchemy 2.0 style: Session(engine) with explicit rollback for
    isolation.  Each test's changes are flushed (written to the in-session
    transaction) but never committed, so the rollback restores a clean state.
    """
    sess = Session(engine)
    yield sess
    sess.rollback()
    sess.close()


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _ws(session: Session) -> Workspace:
    ws = Workspace(id=uuid.uuid4(), name="Test Workspace", slug="test-ws")
    session.add(ws)
    session.flush()
    return ws


def _user(session: Session, ws: Workspace) -> AppUser:
    u = AppUser(
        id=uuid.uuid4(),
        workspace_id=ws.id,
        sub_claim="sub|test",
        email="test@example.com",
        display_name="Test User",
    )
    session.add(u)
    session.flush()
    return u


def _catalogue(session: Session, user_id: uuid.UUID) -> ControlCatalogueVersion:
    ccv = ControlCatalogueVersion(
        id=uuid.uuid4(),
        version=1,
        status="active",
        snapshot={"categories": [], "grade_bands": []},
        grade_bands=[],
        created_by=user_id,
        change_notes="v1",
        content_checksum="a" * 64,
    )
    session.add(ccv)
    session.flush()
    return ccv


def _analysis(
    session: Session,
    ws: Workspace,
    user: AppUser,
    ccv: ControlCatalogueVersion,
) -> Analysis:
    a = Analysis(
        id=uuid.uuid4(),
        workspace_id=ws.id,
        owner_id=user.id,
        catalogue_version_id=ccv.id,
        pipeline_format="github_actions",
        format_confidence=0.95,
        score=72,
        grade="B",
        coverage_report={},
        status="completed",
    )
    session.add(a)
    session.flush()
    return a


# ---------------------------------------------------------------------------
# Table presence tests
# ---------------------------------------------------------------------------


def test_all_twelve_tables_exist(engine):
    """All twelve baseline tables must be present."""
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    expected = {
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
    assert expected.issubset(table_names), (
        f"Missing tables: {expected - table_names}"
    )


# ---------------------------------------------------------------------------
# Column type and nullability tests
# ---------------------------------------------------------------------------


def test_workspace_columns(engine):
    inspector = inspect(engine)
    cols = {c["name"]: c for c in inspector.get_columns("workspace")}
    assert "id" in cols
    assert "name" in cols and not cols["name"]["nullable"]
    assert "slug" in cols and not cols["slug"]["nullable"]
    assert "created_at" in cols and not cols["created_at"]["nullable"]


def test_finding_has_required_columns(engine):
    inspector = inspect(engine)
    cols = {c["name"]: c for c in inspector.get_columns("finding")}
    assert "source" in cols, "finding must have source column"
    assert "requires_human_review" in cols, "finding must have requires_human_review"
    assert "weight" in cols, "finding must have weight column"


def test_pipeline_definition_has_masked_content(engine):
    inspector = inspect(engine)
    cols = {c["name"]: c for c in inspector.get_columns("pipeline_definition")}
    assert "masked_content" in cols, "pipeline_definition must have masked_content"
    assert "key_id" in cols, "pipeline_definition must have key_id"
    # Must NOT have a plaintext content column.
    assert "content" not in cols, (
        "pipeline_definition must not have a plaintext 'content' column"
    )


def test_audit_event_columns(engine):
    inspector = inspect(engine)
    cols = {c["name"]: c for c in inspector.get_columns("audit_event")}
    required = {
        "id", "actor_id", "actor_persona", "occurred_at",
        "resource_type", "resource_id", "action", "change_detail",
    }
    for col in required:
        assert col in cols, f"audit_event missing column: {col}"


def test_purge_receipt_columns(engine):
    inspector = inspect(engine)
    cols = {c["name"]: c for c in inspector.get_columns("purge_receipt")}
    for col in ("batch_id", "executed_at", "deleted_counts", "verification_digest"):
        assert col in cols, f"purge_receipt missing column: {col}"


# ---------------------------------------------------------------------------
# No soft-delete columns on Confidential entities
# ---------------------------------------------------------------------------


CONFIDENTIAL_TABLES = [
    "analysis",
    "pipeline_definition",
    "finding",
    "remediation",
    "generated_draft",
]


@pytest.mark.parametrize("table_name", CONFIDENTIAL_TABLES)
def test_no_soft_delete_columns(engine, table_name):
    """Confidential entities must not have deleted_at or is_deleted columns."""
    inspector = inspect(engine)
    cols = {c["name"] for c in inspector.get_columns(table_name)}
    assert "deleted_at" not in cols, f"{table_name} has forbidden deleted_at column"
    assert "is_deleted" not in cols, f"{table_name} has forbidden is_deleted column"


# ---------------------------------------------------------------------------
# workspace_id FK on all tenant-scoped tables
# ---------------------------------------------------------------------------


TENANT_SCOPED_TABLES = [
    "app_user",
    "role_binding",
    "analysis",
    "pipeline_definition",
    "finding",
    "remediation",
    "generated_draft",
    "sample_pipeline",
]


@pytest.mark.parametrize("table_name", TENANT_SCOPED_TABLES)
def test_tenant_scoped_table_has_workspace_id_fk(engine, table_name):
    """All tenant-scoped tables must have workspace_id as a foreign key."""
    inspector = inspect(engine)
    fks = inspector.get_foreign_keys(table_name)
    fk_cols = {col for fk in fks for col in fk["constrained_columns"]}
    assert "workspace_id" in fk_cols, (
        f"{table_name} missing workspace_id foreign key"
    )


# ---------------------------------------------------------------------------
# Unique constraint tests
# ---------------------------------------------------------------------------


def test_workspace_slug_unique(session):
    """workspace.slug must be globally unique."""
    ws1 = Workspace(id=uuid.uuid4(), name="A", slug="same-slug")
    ws2 = Workspace(id=uuid.uuid4(), name="B", slug="same-slug")
    session.add(ws1)
    session.flush()
    session.add(ws2)
    with pytest.raises(Exception):  # IntegrityError from SQLite or PostgreSQL
        session.flush()


def test_role_binding_workspace_user_unique(session):
    """A user may hold only one persona per workspace."""
    ws = _ws(session)
    user = _user(session, ws)
    rb1 = RoleBinding(
        workspace_id=ws.id, app_user_id=user.id, persona="app_developer"
    )
    rb2 = RoleBinding(
        workspace_id=ws.id, app_user_id=user.id, persona="devops_engineer"
    )
    session.add(rb1)
    session.flush()
    session.add(rb2)
    with pytest.raises(Exception):
        session.flush()


def test_pipeline_definition_analysis_unique(session):
    """A single analysis may have at most one pipeline_definition."""
    ws = _ws(session)
    user = _user(session, ws)
    ccv = _catalogue(session, user.id)
    a = _analysis(session, ws, user, ccv)

    pd1 = PipelineDefinition(
        id=uuid.uuid4(),
        workspace_id=ws.id,
        analysis_id=a.id,
        masked_content="cipher1",
        key_id="k1",
        line_count=10,
    )
    pd2 = PipelineDefinition(
        id=uuid.uuid4(),
        workspace_id=ws.id,
        analysis_id=a.id,
        masked_content="cipher2",
        key_id="k1",
        line_count=10,
    )
    session.add(pd1)
    session.flush()
    session.add(pd2)
    with pytest.raises(Exception):
        session.flush()


# ---------------------------------------------------------------------------
# AI zero-weight CHECK constraint
# ---------------------------------------------------------------------------


def test_ai_finding_weight_zero_accepted(session):
    """AI finding with weight=0 is valid."""
    ws = _ws(session)
    user = _user(session, ws)
    ccv = _catalogue(session, user.id)
    a = _analysis(session, ws, user, ccv)

    f = Finding(
        id=uuid.uuid4(),
        workspace_id=ws.id,
        analysis_id=a.id,
        source="ai",
        requires_human_review=True,
        control_category="secrets",
        rule_id="ai-001",
        severity="high",
        weight=0,  # valid for AI source
        title="AI candidate finding",
    )
    session.add(f)
    session.flush()  # must not raise


def test_ai_finding_nonzero_weight_rejected(session):
    """AI finding with weight > 0 must be rejected by the CHECK constraint."""
    ws = _ws(session)
    user = _user(session, ws)
    ccv = _catalogue(session, user.id)
    a = _analysis(session, ws, user, ccv)

    f = Finding(
        id=uuid.uuid4(),
        workspace_id=ws.id,
        analysis_id=a.id,
        source="ai",
        requires_human_review=True,
        control_category="secrets",
        rule_id="ai-002",
        severity="high",
        weight=5,  # INVALID — AI source must have weight=0
        title="Invalid AI finding",
    )
    session.add(f)
    with pytest.raises(Exception):
        session.flush()


def test_deterministic_finding_nonzero_weight_accepted(session):
    """Deterministic finding with weight > 0 is valid."""
    ws = _ws(session)
    user = _user(session, ws)
    ccv = _catalogue(session, user.id)
    a = _analysis(session, ws, user, ccv)

    f = Finding(
        id=uuid.uuid4(),
        workspace_id=ws.id,
        analysis_id=a.id,
        source="deterministic",
        requires_human_review=False,
        control_category="secrets",
        rule_id="det-001",
        severity="critical",
        weight=15,  # valid for deterministic source
        title="Deterministic finding",
    )
    session.add(f)
    session.flush()  # must not raise


# ---------------------------------------------------------------------------
# FK RESTRICT (no CASCADE) — workspace deletion blocked by analyses
# ---------------------------------------------------------------------------


def test_workspace_delete_blocked_when_analyses_exist(session):
    """Workspace cannot be deleted while analyses exist (RESTRICT FK)."""
    ws = _ws(session)
    user = _user(session, ws)
    ccv = _catalogue(session, user.id)
    _analysis(session, ws, user, ccv)

    with pytest.raises(Exception):
        session.delete(ws)
        session.flush()


# ---------------------------------------------------------------------------
# Key provider unit tests
# ---------------------------------------------------------------------------


def test_env_key_provider_encrypt_decrypt(monkeypatch):
    """EnvKeyProvider round-trips plaintext through AES-256-GCM envelope."""
    monkeypatch.setenv("PIPELINE_SHIELD_DEF_KEY", "test-secret-passphrase-for-unit-test")
    from pipelineshield.crypto.key_provider import EnvKeyProvider

    provider = EnvKeyProvider()
    plaintext = "name: My Pipeline\non: push\njobs:\n  build:\n    runs-on: ubuntu-22.04\n"
    ciphertext = provider.encrypt(plaintext)

    assert ciphertext != plaintext
    assert provider.decrypt(ciphertext) == plaintext


def test_env_key_provider_missing_key_raises(monkeypatch):
    """EnvKeyProvider raises KeyUnavailableError when the key env var is absent."""
    monkeypatch.delenv("PIPELINE_SHIELD_DEF_KEY", raising=False)
    from pipelineshield.crypto.key_provider import EnvKeyProvider, KeyUnavailableError

    with pytest.raises(KeyUnavailableError):
        EnvKeyProvider()


def test_env_key_provider_key_id_does_not_contain_secret(monkeypatch):
    """key_id must be a stable hash, not the passphrase itself."""
    passphrase = "my-super-secret-passphrase"
    monkeypatch.setenv("PIPELINE_SHIELD_DEF_KEY", passphrase)
    from pipelineshield.crypto.key_provider import EnvKeyProvider

    provider = EnvKeyProvider()
    assert passphrase not in provider.key_id
