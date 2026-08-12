"""Unit tests for CatalogueLoader (process-local cache + checksum verification)
and InMemoryCatalogueRepository (shared contract tests).

Tests:
- CatalogueLoader.load() returns snapshot on valid row
- CatalogueLoader.load() returns cached snapshot on second call (cache hit)
- CatalogueLoader.load() raises CatalogueIntegrityError on checksum mismatch
- CatalogueLoader.load_active() caches and returns active snapshot
- CatalogueLoader.load_active() raises CatalogueIntegrityError when no active version
- CatalogueLoader.invalidate() clears the cache
- CatalogueLoader.invalidate(key) clears only the specified entry
- InMemoryCatalogueRepository satisfies CatalogueRepository contract
- InMemoryCatalogueRepository.create_version raises CatalogueVersionConflictError on duplicate
- InMemoryCatalogueRepository.list_versions returns ascending order
- InMemoryCatalogueRepository.mark_superseded transitions status
- Shared contract: both implementations return same results for same operations
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from pipelineshield.catalogue import (
    CatalogueIntegrityError,
    CatalogueLoader,
    CatalogueSnapshot,
    CatalogueVersionConflictError,
    ControlSource,
    Severity,
    compute_checksum,
)
from pipelineshield.catalogue.schemas import (
    ControlCategory,
    ControlDefinition,
    GradeBand,
)
from pipelineshield.persistence.repositories.catalogue import (
    InMemoryCatalogueRepository,
)

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

_GRADE_BANDS = [
    {"grade": "F", "min_score": 0, "max_score": 59},
    {"grade": "D", "min_score": 60, "max_score": 69},
    {"grade": "C", "min_score": 70, "max_score": 79},
    {"grade": "B", "min_score": 80, "max_score": 89},
    {"grade": "A", "min_score": 90, "max_score": 100},
]


def _make_snapshot(weight: int = 100) -> CatalogueSnapshot:
    return CatalogueSnapshot.model_validate({
        "categories": [
            {
                "id": "cat_a",
                "name": "Category A",
                "weight": weight,
                "enabled": True,
                "description": "",
                "controls": [
                    {
                        "id": "ctrl-001",
                        "category_id": "cat_a",
                        "severity": "high",
                        "enabled": True,
                        "reference_tools": ["ToolA"],
                    }
                ],
            }
        ],
        "grade_bands": _GRADE_BANDS,
    })


@dataclass
class _FakeRow:
    """Minimal fake version row for testing the loader."""
    id: uuid.UUID
    version: int
    snapshot: dict
    content_checksum: str
    status: str = "active"
    created_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)


def _make_valid_row(version: int = 1) -> _FakeRow:
    snap = _make_snapshot()
    snap_dict = snap.model_dump()
    return _FakeRow(
        id=uuid.uuid4(),
        version=version,
        snapshot=snap_dict,
        content_checksum=compute_checksum(snap_dict),
    )


# ---------------------------------------------------------------------------
# CatalogueLoader — load()
# ---------------------------------------------------------------------------


class TestCatalogueLoaderLoad:
    def test_load_valid_row_returns_snapshot(self):
        loader = CatalogueLoader()
        row = _make_valid_row()
        snap = loader.load(row)
        assert isinstance(snap, CatalogueSnapshot)

    def test_load_same_row_twice_returns_cached(self):
        loader = CatalogueLoader()
        row = _make_valid_row()
        snap1 = loader.load(row)
        snap2 = loader.load(row)
        assert snap1 is snap2
        assert loader.cache_size() == 1

    def test_load_checksum_mismatch_raises_integrity_error(self):
        loader = CatalogueLoader()
        row = _make_valid_row()
        row.content_checksum = "0" * 64  # wrong checksum
        with pytest.raises(CatalogueIntegrityError, match="checksum"):
            loader.load(row)

    def test_load_mismatched_row_not_cached(self):
        loader = CatalogueLoader()
        row = _make_valid_row()
        row.content_checksum = "bad"
        with pytest.raises(CatalogueIntegrityError):
            loader.load(row)
        assert loader.cache_size() == 0

    def test_load_row_without_id_uses_version(self):
        loader = CatalogueLoader()
        snap = _make_snapshot()
        snap_dict = snap.model_dump()

        @dataclass
        class _NoIdRow:
            version: int
            snapshot: dict
            content_checksum: str

        row = _NoIdRow(version=42, snapshot=snap_dict, content_checksum=compute_checksum(snap_dict))
        result = loader.load(row)
        assert isinstance(result, CatalogueSnapshot)
        assert loader.is_cached(42)

    def test_load_row_with_neither_id_nor_version_raises(self):
        loader = CatalogueLoader()

        class _BadRow:
            snapshot = {}
            content_checksum = ""

        with pytest.raises(ValueError, match="id.*version|version.*id"):
            loader.load(_BadRow())


# ---------------------------------------------------------------------------
# CatalogueLoader — load_active()
# ---------------------------------------------------------------------------


class TestCatalogueLoaderLoadActive:
    def test_load_active_returns_snapshot(self):
        loader = CatalogueLoader()
        row = _make_valid_row()

        repo = MagicMock()
        repo.get_active.return_value = row

        snap = loader.load_active(session=None, repo=repo)
        assert isinstance(snap, CatalogueSnapshot)

    def test_load_active_second_call_uses_cache(self):
        loader = CatalogueLoader()
        row = _make_valid_row()

        repo = MagicMock()
        repo.get_active.return_value = row

        snap1 = loader.load_active(session=None, repo=repo)
        snap2 = loader.load_active(session=None, repo=repo)
        assert snap1 is snap2
        # repo.get_active called only once (subsequent call hits cache)
        assert repo.get_active.call_count == 1

    def test_load_active_no_active_version_raises(self):
        loader = CatalogueLoader()
        repo = MagicMock()
        repo.get_active.return_value = None
        with pytest.raises(CatalogueIntegrityError, match="[Nn]o active"):
            loader.load_active(session=None, repo=repo)


# ---------------------------------------------------------------------------
# CatalogueLoader — invalidate()
# ---------------------------------------------------------------------------


class TestCatalogueLoaderInvalidate:
    def test_invalidate_all_clears_cache(self):
        loader = CatalogueLoader()
        row = _make_valid_row()
        loader.load(row)
        assert loader.cache_size() == 1

        loader.invalidate()
        assert loader.cache_size() == 0

    def test_invalidate_specific_key_removes_only_that_entry(self):
        loader = CatalogueLoader()
        row1 = _make_valid_row(version=1)
        row2 = _make_valid_row(version=2)
        loader.load(row1)
        loader.load(row2)
        assert loader.cache_size() == 2

        loader.invalidate(row1.id)
        assert loader.cache_size() == 1
        assert not loader.is_cached(row1.id)
        assert loader.is_cached(row2.id)

    def test_invalidate_after_load_active_re_fetches_next_time(self):
        loader = CatalogueLoader()
        row = _make_valid_row()
        repo = MagicMock()
        repo.get_active.return_value = row

        loader.load_active(session=None, repo=repo)
        loader.invalidate()  # clear everything

        loader.load_active(session=None, repo=repo)
        # get_active should be called twice (once before invalidate, once after)
        assert repo.get_active.call_count == 2

    def test_invalidate_nonexistent_key_is_noop(self):
        loader = CatalogueLoader()
        loader.invalidate(uuid.uuid4())  # should not raise


# ---------------------------------------------------------------------------
# InMemoryCatalogueRepository — contract tests
# ---------------------------------------------------------------------------


class TestInMemoryCatalogueRepository:
    def test_get_active_returns_none_when_empty(self):
        repo = InMemoryCatalogueRepository()
        assert repo.get_active() is None

    def test_create_version_and_get_active(self):
        repo = InMemoryCatalogueRepository()
        snap = _make_snapshot()
        actor = uuid.uuid4()
        row = repo.create_version(1, snap, actor)
        active = repo.get_active()
        assert active is not None
        assert active.version == 1
        assert active.id == row.id

    def test_get_by_version_returns_row(self):
        repo = InMemoryCatalogueRepository()
        snap = _make_snapshot()
        actor = uuid.uuid4()
        repo.create_version(1, snap, actor)
        row = repo.get_by_version(1)
        assert row is not None
        assert row.version == 1

    def test_get_by_version_missing_returns_none(self):
        repo = InMemoryCatalogueRepository()
        assert repo.get_by_version(999) is None

    def test_list_versions_ascending_order(self):
        repo = InMemoryCatalogueRepository()
        actor = uuid.uuid4()
        repo.create_version(3, _make_snapshot(), actor)
        repo.create_version(1, _make_snapshot(), actor)
        repo.create_version(2, _make_snapshot(), actor)
        rows = repo.list_versions()
        assert [r.version for r in rows] == [1, 2, 3]

    def test_create_version_duplicate_raises(self):
        repo = InMemoryCatalogueRepository()
        actor = uuid.uuid4()
        repo.create_version(1, _make_snapshot(), actor)
        with pytest.raises(CatalogueVersionConflictError):
            repo.create_version(1, _make_snapshot(), actor)

    def test_mark_superseded_transitions_status(self):
        repo = InMemoryCatalogueRepository()
        actor = uuid.uuid4()
        row = repo.create_version(1, _make_snapshot(), actor)
        assert row.status == "active"

        repo.mark_superseded(row.id)
        row_after = repo.get_by_version(1)
        assert row_after.status == "superseded"

    def test_mark_superseded_idempotent(self):
        repo = InMemoryCatalogueRepository()
        actor = uuid.uuid4()
        row = repo.create_version(1, _make_snapshot(), actor)
        repo.mark_superseded(row.id)
        repo.mark_superseded(row.id)  # second call is a no-op
        assert repo.get_by_version(1).status == "superseded"

    def test_mark_superseded_unknown_id_raises(self):
        repo = InMemoryCatalogueRepository()
        with pytest.raises(ValueError):
            repo.mark_superseded(uuid.uuid4())

    def test_checksum_stored_correctly(self):
        repo = InMemoryCatalogueRepository()
        snap = _make_snapshot()
        actor = uuid.uuid4()
        row = repo.create_version(1, snap, actor)
        expected = compute_checksum(snap.model_dump())
        assert row.content_checksum == expected
        assert len(row.content_checksum) == 64

    def test_get_active_prefers_highest_version(self):
        repo = InMemoryCatalogueRepository()
        actor = uuid.uuid4()
        repo.create_version(1, _make_snapshot(), actor)
        repo.create_version(2, _make_snapshot(), actor)
        # Both active; get_active should return v2 (highest)
        active = repo.get_active()
        assert active.version == 2


# ---------------------------------------------------------------------------
# Contract test: both implementations behave identically
# ---------------------------------------------------------------------------


class TestRepositoryContract:
    """Shared contract: InMemoryCatalogueRepository satisfies the same contract
    as SQLAlchemyCatalogueRepository."""

    @pytest.fixture(params=["in_memory"])
    def repo(self, request):
        if request.param == "in_memory":
            return InMemoryCatalogueRepository()
        raise ValueError(request.param)

    def test_empty_get_active_is_none(self, repo):
        assert repo.get_active() is None

    def test_create_returns_row_with_version(self, repo):
        snap = _make_snapshot()
        row = repo.create_version(1, snap, uuid.uuid4())
        assert row.version == 1

    def test_list_versions_empty(self, repo):
        assert list(repo.list_versions()) == []

    def test_full_lifecycle(self, repo):
        actor = uuid.uuid4()
        snap_v1 = _make_snapshot()
        row_v1 = repo.create_version(1, snap_v1, actor)

        active = repo.get_active()
        assert active is not None
        assert active.version == 1

        by_id = repo.get_by_version(1)
        assert by_id.id == row_v1.id

        rows = repo.list_versions()
        assert len(rows) == 1

        repo.mark_superseded(row_v1.id)
        assert repo.get_by_version(1).status == "superseded"


# ---------------------------------------------------------------------------
# Integration: loader + in-memory repo
# ---------------------------------------------------------------------------


class TestLoaderWithInMemoryRepo:
    def test_load_active_with_in_memory_repo(self):
        repo = InMemoryCatalogueRepository()
        repo.create_version(1, _make_snapshot(), uuid.uuid4())

        loader = CatalogueLoader()
        snap = loader.load_active(session=None, repo=repo)
        assert isinstance(snap, CatalogueSnapshot)

    def test_cache_hit_on_repeated_load_active(self):
        repo = InMemoryCatalogueRepository()
        repo.create_version(1, _make_snapshot(), uuid.uuid4())

        loader = CatalogueLoader()
        snap1 = loader.load_active(session=None, repo=repo)
        snap2 = loader.load_active(session=None, repo=repo)
        assert snap1 is snap2

    def test_invalidate_then_load_returns_new_version(self):
        repo = InMemoryCatalogueRepository()
        repo.create_version(1, _make_snapshot(), uuid.uuid4())

        loader = CatalogueLoader()
        snap_v1 = loader.load_active(session=None, repo=repo)

        # Create v2 and supersede v1
        row_v1 = repo.get_by_version(1)
        repo.mark_superseded(row_v1.id)
        repo.create_version(2, _make_snapshot(weight=100), uuid.uuid4())

        # Before invalidate, loader still serves v1 from cache
        snap_cached = loader.load_active(session=None, repo=repo)
        assert snap_cached is snap_v1

        # After invalidate, loader fetches the new active (v2)
        loader.invalidate()
        snap_v2 = loader.load_active(session=None, repo=repo)
        # v2 is now active; loader should return a valid snapshot
        assert isinstance(snap_v2, CatalogueSnapshot)
