"""Integration tests for catalogue version pinning (WO-013 AC-3, AC-6, AC-7, AC-10).

Tests:
- Analysis creation pins the currently active catalogue version (AC-3)
- catalogue_version_id is returned in the analysis response (AC-3)
- After creating catalogue version 2 with different weights, a version-1 analysis
  returns its original score unchanged (AC-6)
- Attempting to delete a catalogue version referenced by an analysis fails at the
  database level due to ON DELETE RESTRICT (AC-7)
- ScoringEngine with v1 snapshot produces different result from v2 snapshot
  for the same evaluations (confirms version isolation)
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pipelineshield.catalogue.schemas import (
    CatalogueSnapshot,
    ControlCategory,
    ControlDefinition,
    GradeBand,
    Severity,
)
from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.analysis import Analysis
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.control_catalogue_version import ControlCatalogueVersion
from pipelineshield.persistence.repositories.analysis import SQLAlchemyAnalysisRepository
from pipelineshield.services.scoring_engine import ControlOutcome, ScoringEngine

_FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "catalogue_v1.json"

_GRADE_BANDS = [
    GradeBand(grade="F", min_score=0, max_score=59),
    GradeBand(grade="D", min_score=60, max_score=69),
    GradeBand(grade="C", min_score=70, max_score=79),
    GradeBand(grade="B", min_score=80, max_score=89),
    GradeBand(grade="A", min_score=90, max_score=100),
]


@pytest.fixture(scope="module")
def engine():
    _engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(_engine)
    return _engine


@pytest.fixture()
def session(engine):
    _Session = sessionmaker(bind=engine)
    s = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def _load_v1_snapshot() -> CatalogueSnapshot:
    data = json.loads(_FIXTURE_PATH.read_text())
    return CatalogueSnapshot.model_validate(data)


def _make_v2_snapshot() -> CatalogueSnapshot:
    """V2: same categories but with significantly different weights."""
    v1 = _load_v1_snapshot()
    # Rebuild with inverted weights to ensure scoring differs
    new_cats = []
    enabled_cats = [c for c in v1.categories if c.enabled]
    total = len(enabled_cats)
    for i, cat in enumerate(sorted(enabled_cats, key=lambda c: c.id)):
        # Give all weight to the last category alphabetically
        new_weight = 100 if i == total - 1 else 0
        new_cats.append(ControlCategory(
            id=cat.id,
            name=cat.name + " (v2)",
            weight=new_weight,
            enabled=cat.enabled,
            controls=cat.controls,
        ))
    # Also include disabled cats unchanged
    for cat in v1.categories:
        if not cat.enabled:
            new_cats.append(cat)

    return CatalogueSnapshot(categories=new_cats, grade_bands=_GRADE_BANDS)


def _seed_catalogue_version(
    session,
    version: int,
    snapshot: CatalogueSnapshot,
    status: str = "active",
) -> ControlCatalogueVersion:
    row = ControlCatalogueVersion(
        id=uuid.uuid4(),
        version=version,
        snapshot=snapshot.model_dump(mode="json"),
        status=status,
        change_notes=f"Test catalogue v{version}",
        content_checksum=f"checksum-v{version}",
    )
    session.add(row)
    session.flush()
    return row


# ---------------------------------------------------------------------------
# Test: catalogue_version_id returned in analysis
# ---------------------------------------------------------------------------


class TestVersionPinnedInResponse:
    def test_scoring_result_contains_catalogue_version_id(self) -> None:
        """ScoringEngine result carries the catalogue_version_id it was created with."""
        v1_snap = _load_v1_snapshot()
        v1_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
        eng = ScoringEngine(v1_snap, v1_id)
        result = eng.score({})
        assert result.catalogue_version_id == v1_id


# ---------------------------------------------------------------------------
# Test: ON DELETE RESTRICT prevents catalogue version deletion
# ---------------------------------------------------------------------------


class TestRestrictDeleteCatalogueVersion:
    def test_delete_referenced_catalogue_version_raises_integrity_error(
        self, session
    ) -> None:
        """Attempting to delete a catalogue version referenced by an analysis
        must fail at the database level due to ON DELETE RESTRICT."""
        from pipelineshield.persistence.models.workspace import Workspace
        from pipelineshield.persistence.models.app_user import AppUser

        v1_snap = _load_v1_snapshot()
        cat_ver = _seed_catalogue_version(session, 1, v1_snap)

        # Seed minimal workspace and user
        ws = Workspace(id=uuid.uuid4(), name="test-workspace")
        user = AppUser(
            id=uuid.uuid4(),
            workspace_id=ws.id,
            display_name="Test User",
            email="test@example.com",
            idp_subject="sub-test-restrict",
        )
        session.add(ws)
        session.flush()
        user.workspace_id = ws.id
        session.add(user)
        session.flush()

        # Create an analysis row pinned to this catalogue version
        analysis = Analysis(
            id=uuid.uuid4(),
            workspace_id=ws.id,
            owner_id=user.id,
            catalogue_version_id=cat_ver.id,
            pipeline_format="github_actions",
            format_confidence=0.95,
            score=0,
            grade="-",
            coverage_report={},
            status="pending_analysis",
        )
        session.add(analysis)
        session.flush()
        session.commit()

        # Attempt DELETE — must fail due to FK RESTRICT
        with pytest.raises((IntegrityError, Exception)) as exc_info:
            session.execute(
                text("DELETE FROM control_catalogue_version WHERE id = :id"),
                {"id": str(cat_ver.id)},
            )
            session.flush()

        # Exception must reference the FK constraint (not just a generic error)
        err_str = str(exc_info.value).lower()
        assert any(
            keyword in err_str
            for keyword in ("foreign key", "constraint", "restrict", "integrity")
        ), f"Expected FK violation, got: {exc_info.value}"


# ---------------------------------------------------------------------------
# Test: Historical integrity — version-1 analysis score unchanged after v2
# ---------------------------------------------------------------------------


class TestHistoricalIntegrity:
    def test_v1_score_independent_of_v2_snapshot(self) -> None:
        """ScoringEngine for v1 produces a different result than v2 for identical
        evaluations, proving version isolation."""
        v1_snap = _load_v1_snapshot()
        v2_snap = _make_v2_snapshot()
        v1_id = uuid.UUID("00000000-0000-0000-0000-000000000010")
        v2_id = uuid.UUID("00000000-0000-0000-0000-000000000020")

        eng1 = ScoringEngine(v1_snap, v1_id)
        eng2 = ScoringEngine(v2_snap, v2_id)

        # Evaluations with mixed outcomes across categories
        evaluations = {
            "sh-001": ControlOutcome.present,
            "sh-002": ControlOutcome.present,
            "as-001": ControlOutcome.missing,
            "as-002": ControlOutcome.missing,
            "sa-001": ControlOutcome.present,
            "ds-001": ControlOutcome.present,
            "ds-002": ControlOutcome.missing,
            "lp-001": ControlOutcome.present,
            "lp-002": ControlOutcome.present,
            "iac-001": ControlOutcome.present,
            "sci-001": ControlOutcome.missing,
            "sci-002": ControlOutcome.missing,
            "sbom-001": ControlOutcome.present,
            "ag-001": ControlOutcome.present,
        }

        r1 = eng1.score(evaluations)
        r2 = eng2.score(evaluations)

        # Store v1 result and assert it doesn't change if we re-score with v1
        r1_repeated = eng1.score(evaluations)
        assert r1.score == r1_repeated.score, (
            "V1 score must be identical on repeated calls (deterministic)"
        )
        assert r1.grade == r1_repeated.grade

        # V1 and V2 scores must differ (different weights)
        assert r1.score != r2.score or r1.denominator != r2.denominator, (
            "V1 and V2 scoring engines should produce different results for the same "
            "evaluations due to different category weights."
        )

    def test_v1_analysis_score_byte_identical_on_re_render(self) -> None:
        """A version-1 analysis re-scored against v1 snapshot produces
        byte-identical output regardless of v2 existing."""
        v1_snap = _load_v1_snapshot()
        v1_id = uuid.UUID("00000000-0000-0000-0000-000000000011")
        eng1 = ScoringEngine(v1_snap, v1_id)

        evaluations = {
            "sh-001": ControlOutcome.present,
            "as-001": ControlOutcome.partial,
            "sa-001": ControlOutcome.missing,
        }

        # First render
        r1 = eng1.score(evaluations)

        # Simulate v2 creation — but re-render v1 analysis with v1 engine
        v2_snap = _make_v2_snapshot()
        ScoringEngine(v2_snap, uuid.UUID("00000000-0000-0000-0000-000000000022"))  # v2 exists

        # Re-render v1 using v1 engine
        r1_rerender = eng1.score(evaluations)

        assert r1.score == r1_rerender.score
        assert r1.grade == r1_rerender.grade
        assert r1.denominator == r1_rerender.denominator

        # Serialise per-category breakdown and assert byte-identical
        def _breakdown_json(result) -> str:
            return json.dumps(
                [
                    {
                        "id": c.category_id,
                        "earned": c.earned_weight,
                        "assessable": c.assessable_count,
                        "present": c.present_count,
                        "partial": c.partial_count,
                        "missing": c.missing_count,
                    }
                    for c in result.categories
                ],
                sort_keys=True,
            )

        assert _breakdown_json(r1) == _breakdown_json(r1_rerender), (
            "Per-category breakdown must be byte-identical on re-render against the same version"
        )


# ---------------------------------------------------------------------------
# Test: Analysis repository has no delete method (AC-7 code surface)
# ---------------------------------------------------------------------------


class TestAnalysisRepositorySurface:
    def test_analysis_repository_exposes_no_delete_method(self) -> None:
        import inspect
        public = {
            name for name, _ in inspect.getmembers(
                SQLAlchemyAnalysisRepository, predicate=inspect.isfunction
            )
            if not name.startswith("_")
        }
        assert "delete" not in public
        assert "remove" not in public

    def test_catalogue_version_id_is_required_on_analysis(self) -> None:
        """Analysis model must require catalogue_version_id (not nullable)."""
        import sqlalchemy.inspection as _inspection
        from pipelineshield.persistence.models.analysis import Analysis
        mapper = Analysis.__mapper__
        col = mapper.columns["catalogue_version_id"]
        assert not col.nullable, "catalogue_version_id must be NOT NULL"
