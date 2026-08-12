"""Integration tests for CatalogueRepository against a SQLite in-memory database.

Tests:
- seed_v1_catalogue inserts exactly one row.
- seed_v1_catalogue is idempotent (calling twice → still one row).
- get_active returns the seeded version.
- Snapshot round-trip equality including category ids and weights.
- list_versions returns rows in ascending version order.
- create_version with a duplicate version number raises CatalogueVersionConflictError.
- No UPDATE statement is emitted against control_catalogue_version (event listener).
- created_by and created_at are non-null on the seeded row.
- content_checksum is a 64-character hex string.

These tests use SQLite in-memory with StaticPool (no PostgreSQL container
required) and create the schema via Base.metadata.create_all() so they run
in CI without migration infrastructure.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from pipelineshield.catalogue import CatalogueVersionConflictError, compute_checksum
from pipelineshield.catalogue.seed import seed_v1_catalogue
from pipelineshield.persistence.models import AppUser, Base, ControlCatalogueVersion, Workspace
from pipelineshield.persistence.repositories.catalogue import SQLAlchemyCatalogueRepository

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(eng, "connect")
    def _enable_fk(dbapi_conn, connection_record):  # type: ignore[misc]
        dbapi_conn.execute("PRAGMA foreign_keys = ON")

    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture
def session(engine):
    sess = Session(engine)
    yield sess
    sess.rollback()
    sess.close()


@pytest.fixture
def actor(session) -> uuid.UUID:
    """Create a minimal workspace + user and return the user's UUID."""
    ws = Workspace(id=uuid.uuid4(), name="Seed Test WS", slug=f"seed-{uuid.uuid4().hex[:8]}")
    session.add(ws)
    session.flush()
    user = AppUser(
        id=uuid.uuid4(),
        workspace_id=ws.id,
        sub_claim=f"sub|{uuid.uuid4().hex}",
        email=f"seed-{uuid.uuid4().hex[:6]}@test.example.com",
        display_name="Seed Actor",
    )
    session.add(user)
    session.flush()
    return user.id


# ---------------------------------------------------------------------------
# Seed — idempotency and basic correctness
# ---------------------------------------------------------------------------


def test_seed_inserts_exactly_one_row(session, actor):
    seed_v1_catalogue(session, actor, fixture_path=_FIXTURES / "catalogue_v1.json")
    repo = SQLAlchemyCatalogueRepository(session)
    assert len(repo.list_versions()) == 1


def test_seed_is_idempotent(session, actor):
    fp = _FIXTURES / "catalogue_v1.json"
    seed_v1_catalogue(session, actor, fixture_path=fp)
    seed_v1_catalogue(session, actor, fixture_path=fp)  # second call
    repo = SQLAlchemyCatalogueRepository(session)
    assert len(repo.list_versions()) == 1


def test_seed_row_has_version_1(session, actor):
    row = seed_v1_catalogue(session, actor, fixture_path=_FIXTURES / "catalogue_v1.json")
    assert row.version == 1


def test_seed_row_has_active_status(session, actor):
    row = seed_v1_catalogue(session, actor, fixture_path=_FIXTURES / "catalogue_v1.json")
    assert row.status == "active"


def test_seed_row_created_by_is_set(session, actor):
    row = seed_v1_catalogue(session, actor, fixture_path=_FIXTURES / "catalogue_v1.json")
    assert row.created_by == actor


def test_seed_row_created_at_is_not_none(session, actor):
    row = seed_v1_catalogue(session, actor, fixture_path=_FIXTURES / "catalogue_v1.json")
    assert row.created_at is not None


def test_seed_row_content_checksum_is_64_char_hex(session, actor):
    row = seed_v1_catalogue(session, actor, fixture_path=_FIXTURES / "catalogue_v1.json")
    assert len(row.content_checksum) == 64
    assert all(c in "0123456789abcdef" for c in row.content_checksum)


def test_seed_checksum_matches_snapshot(session, actor):
    row = seed_v1_catalogue(session, actor, fixture_path=_FIXTURES / "catalogue_v1.json")
    expected = compute_checksum(row.snapshot)
    assert row.content_checksum == expected


# ---------------------------------------------------------------------------
# get_active
# ---------------------------------------------------------------------------


def test_get_active_returns_seeded_row(session, actor):
    seed_v1_catalogue(session, actor, fixture_path=_FIXTURES / "catalogue_v1.json")
    repo = SQLAlchemyCatalogueRepository(session)
    active = repo.get_active()
    assert active is not None
    assert active.version == 1
    assert active.status == "active"


def test_get_active_returns_none_when_empty(session):
    repo = SQLAlchemyCatalogueRepository(session)
    assert repo.get_active() is None


# ---------------------------------------------------------------------------
# Snapshot round-trip
# ---------------------------------------------------------------------------


def test_snapshot_round_trip_weights(session, actor):
    """Weight values survive the JSON round-trip without mutation."""
    seed_v1_catalogue(session, actor, fixture_path=_FIXTURES / "catalogue_v1.json")
    repo = SQLAlchemyCatalogueRepository(session)
    row = repo.get_active()
    assert row is not None
    weights = {c["id"]: c["weight"] for c in row.snapshot["categories"]}
    assert weights["secrets_hygiene"] == 15
    assert weights["artifact_signing"] == 15
    assert weights["sbom"] == 8
    assert weights["approval_gates"] == 6


def test_snapshot_category_ids_intact(session, actor):
    seed_v1_catalogue(session, actor, fixture_path=_FIXTURES / "catalogue_v1.json")
    repo = SQLAlchemyCatalogueRepository(session)
    row = repo.get_active()
    assert row is not None
    ids = {c["id"] for c in row.snapshot["categories"]}
    assert "secrets_hygiene" in ids
    assert "artifact_signing" in ids
    assert len(ids) == 9


# ---------------------------------------------------------------------------
# list_versions ordering
# ---------------------------------------------------------------------------


def test_list_versions_ascending_order(session, actor):
    fp = _FIXTURES / "catalogue_v1.json"
    row1 = seed_v1_catalogue(session, actor, fixture_path=fp)
    repo = SQLAlchemyCatalogueRepository(session)
    # Manually insert a v2 row to test ordering.
    from pipelineshield.catalogue import CatalogueSnapshot
    import json
    snap = CatalogueSnapshot.model_validate(json.loads(fp.read_text()))
    row2 = repo.create_version(
        version=2,
        snapshot=snap,
        created_by=actor,
        change_notes="v2 test",
    )
    rows = repo.list_versions()
    assert len(rows) == 2
    assert rows[0].version == 1
    assert rows[1].version == 2


# ---------------------------------------------------------------------------
# Version conflict
# ---------------------------------------------------------------------------


def test_duplicate_version_raises_conflict(session, actor):
    fp = _FIXTURES / "catalogue_v1.json"
    from pipelineshield.catalogue import CatalogueSnapshot
    import json
    snap = CatalogueSnapshot.model_validate(json.loads(fp.read_text()))
    repo = SQLAlchemyCatalogueRepository(session)
    repo.create_version(version=99, snapshot=snap, created_by=actor)
    with pytest.raises(CatalogueVersionConflictError):
        repo.create_version(version=99, snapshot=snap, created_by=actor)


# ---------------------------------------------------------------------------
# Immutability: no UPDATE/DELETE emitted
# ---------------------------------------------------------------------------


def test_no_update_delete_on_catalogue_version(session, actor):
    """create_version must only emit INSERT; never UPDATE or DELETE."""
    mutations: list[str] = []

    @event.listens_for(session, "after_bulk_delete")
    def _on_bulk_delete(delete_context):  # type: ignore[misc]
        mutations.append("bulk_delete")

    @event.listens_for(session, "after_bulk_update")
    def _on_bulk_update(update_context):  # type: ignore[misc]
        mutations.append("bulk_update")

    @event.listens_for(session, "before_flush")
    def _on_flush(sess, flush_ctx, instances):  # type: ignore[misc]
        for obj in sess.dirty:
            if isinstance(obj, ControlCatalogueVersion):
                mutations.append(f"UPDATE:{obj!r}")
        for obj in sess.deleted:
            if isinstance(obj, ControlCatalogueVersion):
                mutations.append(f"DELETE:{obj!r}")

    fp = _FIXTURES / "catalogue_v1.json"
    from pipelineshield.catalogue import CatalogueSnapshot
    import json
    snap = CatalogueSnapshot.model_validate(json.loads(fp.read_text()))
    repo = SQLAlchemyCatalogueRepository(session)
    repo.create_version(version=50, snapshot=snap, created_by=actor)

    # Remove listeners to avoid interfering with teardown.
    event.remove(session, "before_flush", _on_flush)
    event.remove(session, "after_bulk_delete", _on_bulk_delete)
    event.remove(session, "after_bulk_update", _on_bulk_update)

    assert mutations == [], f"Unexpected mutations: {mutations}"


# ---------------------------------------------------------------------------
# get_by_version
# ---------------------------------------------------------------------------


def test_get_by_version_returns_correct_row(session, actor):
    fp = _FIXTURES / "catalogue_v1.json"
    seed_v1_catalogue(session, actor, fixture_path=fp)
    repo = SQLAlchemyCatalogueRepository(session)
    row = repo.get_by_version(1)
    assert row is not None
    assert row.version == 1


def test_get_by_version_returns_none_for_missing(session):
    repo = SQLAlchemyCatalogueRepository(session)
    assert repo.get_by_version(999) is None
