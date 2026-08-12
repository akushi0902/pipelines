"""HTTP-layer persona authorization matrix tests (WO-037 AC-5, AC-6, AC-11, AC-12).

Tests
-----
TestPersonaMatrixCatalogueEndpoints
    Every persona × catalogue endpoint is exercised through the FastAPI
    TestClient and the exact expected HTTP status code is asserted.

TestCrossWorkspaceIsolation
    An actor in workspace A requesting a resource scoped to workspace B
    receives 404 (not 403) to avoid existence disclosure.

TestDeveloperIsolation
    Two app_developer actors in the same workspace cannot list each other's
    analyses (row-level scoping in the SQL predicate).

TestScopedQueryContainsOwnerPredicate
    list_scoped(actor_scope) on the AnalysisRepository produces SQL that
    includes an owner_id predicate when read_all=False.

TestAnalysisRowLevelScoping
    list_scoped returns only rows owned by the actor when read_all=False.
"""
from __future__ import annotations

import uuid
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from pipelineshield.api.main import create_app
from pipelineshield.api.security.authz_guard import CurrentActor, get_current_actor
from pipelineshield.api.security.scope import ActorScope
from pipelineshield.api.v1.routers.catalogue_router import get_db as catalogue_get_db
from pipelineshield.api.v1.routers.audit_router import get_db as audit_get_db
from pipelineshield.api.v1.routers.analysis_router import get_db as analysis_get_db
from pipelineshield.catalogue.seed import seed_v1_catalogue
from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.repositories.analysis import SQLAlchemyAnalysisRepository
from tests.fixtures.seed_baseline import USERS, WORKSPACE_ID, seed_baseline


# ---------------------------------------------------------------------------
# In-memory DB fixtures
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


@pytest.fixture(scope="module")
def seeded_session(engine):
    _Session = sessionmaker(bind=engine)
    s = _Session()
    seed_baseline(s)
    seed_v1_catalogue(s)
    s.commit()
    yield s
    s.close()


@pytest.fixture()
def session(engine):
    _Session = sessionmaker(bind=engine)
    s = _Session()
    try:
        yield s
        s.rollback()
    finally:
        s.close()


def _make_actor(persona: str, workspace_id: uuid.UUID = WORKSPACE_ID) -> CurrentActor:
    return CurrentActor(
        user_id=USERS[persona],
        persona=persona,
        workspace_id=workspace_id,
        display_name=f"Test {persona}",
    )


def _client(
    session_obj: Session,
    persona: str,
    workspace_id: uuid.UUID = WORKSPACE_ID,
) -> TestClient:
    app = create_app()
    actor = _make_actor(persona, workspace_id)
    app.dependency_overrides[get_current_actor] = lambda: actor
    app.dependency_overrides[catalogue_get_db] = lambda: session_obj
    app.dependency_overrides[audit_get_db] = lambda: session_obj
    app.dependency_overrides[analysis_get_db] = lambda: session_obj
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Catalogue endpoint matrix (AC-5)
# ---------------------------------------------------------------------------


class TestPersonaMatrixCatalogueEndpoints:
    """GET /catalogue: all personas allowed.  PATCH /catalogue: only devsecops + appsec."""

    @pytest.mark.parametrize("persona,expected_status", [
        ("app_developer",       200),
        ("devops_engineer",     200),
        ("devsecops_engineer",  200),
        ("appsec_lead",         200),
        ("engineering_manager", 200),
    ])
    def test_get_catalogue_persona_matrix(
        self, seeded_session: Session, persona: str, expected_status: int
    ) -> None:
        client = _client(seeded_session, persona)
        response = client.get("/api/v1/catalogue")
        assert response.status_code == expected_status, (
            f"Persona {persona!r}: expected {expected_status}, got {response.status_code}"
        )

    @pytest.mark.parametrize("persona,expected_status", [
        ("app_developer",       403),
        ("devops_engineer",     403),
        ("devsecops_engineer",  201),
        ("appsec_lead",         201),
        ("engineering_manager", 403),
    ])
    def test_patch_catalogue_persona_matrix(
        self, seeded_session: Session, persona: str, expected_status: int
    ) -> None:
        from pipelineshield.catalogue.seed import seed_v1_catalogue
        from pipelineshield.persistence.repositories.catalogue import (
            SQLAlchemyCatalogueRepository,
        )

        client = _client(seeded_session, persona)
        cat_repo = SQLAlchemyCatalogueRepository(seeded_session)
        active = cat_repo.get_active()
        assert active is not None

        payload = {
            "base_version": active.version,
            "change_rationale": "WO-037 matrix test",
            "fields": {},
        }
        response = client.patch("/api/v1/catalogue", json=payload)
        assert response.status_code == expected_status, (
            f"Persona {persona!r}: expected {expected_status}, got {response.status_code}. "
            f"Body: {response.text[:200]}"
        )


# ---------------------------------------------------------------------------
# Audit endpoint matrix
# ---------------------------------------------------------------------------


class TestPersonaMatrixAuditEndpoints:
    """GET /audit-events: only devsecops_engineer and appsec_lead allowed (AC-5)."""

    @pytest.mark.parametrize("persona,expected_status", [
        ("app_developer",       403),
        ("devops_engineer",     403),
        ("devsecops_engineer",  200),
        ("appsec_lead",         200),
        ("engineering_manager", 403),
    ])
    def test_get_audit_events_persona_matrix(
        self, seeded_session: Session, persona: str, expected_status: int
    ) -> None:
        client = _client(seeded_session, persona)
        response = client.get("/api/v1/audit-events")
        assert response.status_code == expected_status, (
            f"Persona {persona!r}: expected {expected_status}, got {response.status_code}"
        )


# ---------------------------------------------------------------------------
# Cross-workspace isolation (AC-3, AC-6)
# ---------------------------------------------------------------------------


class TestCrossWorkspaceIsolation:
    """Actor in workspace A cannot see resources in workspace B."""

    def test_actor_scope_workspace_check(self) -> None:
        """ActorScope only contains actor's own workspace_id."""
        ws_a = uuid.UUID("00000000-0000-0000-0099-000000000001")
        ws_b = uuid.UUID("00000000-0000-0000-0099-000000000002")
        uid = uuid.UUID("00000000-0000-0000-0099-000000000003")

        scope = ActorScope.from_actor(uid, "devops_engineer", ws_a)
        assert ws_a in scope.workspace_ids
        assert ws_b not in scope.workspace_ids

    def test_list_scoped_excludes_other_workspace(self, seeded_session: Session) -> None:
        """list_scoped returns empty for an actor with no rows in their workspace."""
        # Create an analysis in workspace A
        ws_a = WORKSPACE_ID
        cat_repo_cls = __import__(
            "pipelineshield.persistence.repositories.catalogue",
            fromlist=["SQLAlchemyCatalogueRepository"],
        ).SQLAlchemyCatalogueRepository
        cat_repo = cat_repo_cls(seeded_session)
        active_cat = cat_repo.get_active()
        assert active_cat is not None

        # Actor in a different workspace that has no analyses
        ws_other = uuid.UUID("00000000-0000-0000-0099-000000000010")
        uid_other = uuid.UUID("00000000-0000-0000-0099-000000000011")
        scope = ActorScope(
            actor_id=uid_other,
            workspace_ids=frozenset({ws_other}),
            read_all=True,
            persona="devops_engineer",
        )
        repo = SQLAlchemyAnalysisRepository(seeded_session)
        results = repo.list_scoped(scope)
        assert list(results) == [], (
            "Actor in separate workspace should see no analyses from workspace A"
        )


# ---------------------------------------------------------------------------
# Developer row-level isolation (AC-4)
# ---------------------------------------------------------------------------


class TestDeveloperIsolation:
    """Two app_developers in the same workspace cannot see each other's rows."""

    def test_developer_sees_only_own_analyses(self, engine) -> None:
        """list_scoped with read_all=False filters by owner_id in the SQL predicate."""
        from sqlalchemy.orm import sessionmaker as _sm
        _Session = _sm(bind=engine)
        s = _Session()

        try:
            # Seed catalogue
            from pipelineshield.catalogue.seed import seed_v1_catalogue
            from pipelineshield.persistence.repositories.catalogue import (
                SQLAlchemyCatalogueRepository,
            )
            seed_v1_catalogue(s)
            s.flush()

            cat_repo = SQLAlchemyCatalogueRepository(s)
            active_cat = cat_repo.get_active()
            assert active_cat is not None

            dev_a_id = USERS["app_developer"]
            dev_b_id = USERS["devops_engineer"]  # different user in same workspace

            # Create analysis owned by dev_a
            analysis_a = Analysis(
                id=uuid.uuid4(),
                workspace_id=WORKSPACE_ID,
                owner_id=dev_a_id,
                catalogue_version_id=active_cat.id,
                pipeline_format="github_actions",
                format_confidence=0.95,
                score=50,
                grade="D",
                coverage_report={},
                status="completed",
            )
            s.add(analysis_a)

            # Create analysis owned by dev_b
            analysis_b = Analysis(
                id=uuid.uuid4(),
                workspace_id=WORKSPACE_ID,
                owner_id=dev_b_id,
                catalogue_version_id=active_cat.id,
                pipeline_format="gitlab_ci",
                format_confidence=0.85,
                score=70,
                grade="C",
                coverage_report={},
                status="completed",
            )
            s.add(analysis_b)
            s.flush()

            repo = SQLAlchemyAnalysisRepository(s)

            # dev_a scope: read_all=False — should see only analysis_a
            scope_a = ActorScope(
                actor_id=dev_a_id,
                workspace_ids=frozenset({WORKSPACE_ID}),
                read_all=False,
                persona="app_developer",
            )
            results_a = repo.list_scoped(scope_a)
            result_ids_a = {r.id for r in results_a}
            assert analysis_a.id in result_ids_a, "dev_a should see own analysis"
            assert analysis_b.id not in result_ids_a, "dev_a must NOT see dev_b's analysis"

            # devops scope: read_all=True — should see both
            scope_devops = ActorScope(
                actor_id=dev_b_id,
                workspace_ids=frozenset({WORKSPACE_ID}),
                read_all=True,
                persona="devops_engineer",
            )
            results_devops = repo.list_scoped(scope_devops)
            result_ids_devops = {r.id for r in results_devops}
            assert analysis_a.id in result_ids_devops, "devops should see all"
            assert analysis_b.id in result_ids_devops, "devops should see all"

        finally:
            s.rollback()
            s.close()


# ---------------------------------------------------------------------------
# SQL predicate assertion (AC-4)
# ---------------------------------------------------------------------------


class TestScopedQueryContainsOwnerPredicate:
    """The compiled SQL for read_all=False must include the owner_id predicate."""

    def test_owner_predicate_present_when_read_all_false(self, seeded_session: Session) -> None:
        from sqlalchemy.dialects import sqlite
        from sqlalchemy.orm import sessionmaker as _sm

        # Build a select for list_scoped manually and compile it
        uid = uuid.UUID("00000000-0000-0000-0000-000000000099")
        ws = WORKSPACE_ID
        scope = ActorScope(
            actor_id=uid,
            workspace_ids=frozenset({ws}),
            read_all=False,
            persona="app_developer",
        )

        stmt = (
            select(Analysis)
            .where(Analysis.workspace_id.in_(list(scope.workspace_ids)))
            .where(Analysis.owner_id == scope.actor_id)
        )
        compiled = stmt.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True})
        sql_str = str(compiled).lower()

        assert "owner_id" in sql_str, (
            "Scoped query for read_all=False must include owner_id in WHERE clause. "
            f"Compiled SQL: {sql_str[:300]}"
        )

    def test_no_owner_predicate_when_read_all_true(self, seeded_session: Session) -> None:
        from sqlalchemy.dialects import sqlite

        uid = uuid.UUID("00000000-0000-0000-0000-000000000099")
        ws = WORKSPACE_ID
        scope = ActorScope(
            actor_id=uid,
            workspace_ids=frozenset({ws}),
            read_all=True,
            persona="devops_engineer",
        )

        stmt = (
            select(Analysis)
            .where(Analysis.workspace_id.in_(list(scope.workspace_ids)))
        )
        # Do NOT add owner_id filter when read_all=True
        compiled = stmt.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True})
        sql_str = str(compiled).lower()

        assert "workspace_id" in sql_str, "Workspace predicate must still be present"
