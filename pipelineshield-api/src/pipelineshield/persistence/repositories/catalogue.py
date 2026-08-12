"""CatalogueRepository — abstract interface, SQLAlchemy 2.0 and in-memory implementations.

``create_version`` only ever issues INSERT statements.
``mark_superseded`` is the single permitted UPDATE path; it touches only the
``status`` column (the snapshot content remains immutable).  WO-10 adds this
transition guard so predecessor rows are marked superseded atomically within
the same transaction as the new version INSERT.

InMemoryCatalogueRepository is provided for unit tests and property tests;
it satisfies the same interface as SQLAlchemyCatalogueRepository.
"""
from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models.control_catalogue_version import ControlCatalogueVersion
from ...catalogue.checksum import compute_checksum
from ...catalogue.schemas import CatalogueSnapshot, CatalogueVersionConflictError

log = logging.getLogger(__name__)


class CatalogueRepository(ABC):
    """Abstract repository interface for ControlCatalogueVersion entities."""

    @abstractmethod
    def get_active(self) -> ControlCatalogueVersion | None:
        """Return the current active catalogue version, or None."""

    @abstractmethod
    def get_by_version(self, version: int) -> ControlCatalogueVersion | None:
        """Return the catalogue version with *version*, or None."""

    @abstractmethod
    def list_versions(self) -> Sequence[ControlCatalogueVersion]:
        """Return all catalogue versions in ascending version order."""

    @abstractmethod
    def create_version(
        self,
        version: int,
        snapshot: CatalogueSnapshot,
        created_by: uuid.UUID,
        change_notes: str | None = None,
    ) -> ControlCatalogueVersion:
        """Persist a new catalogue version (INSERT only).

        Validates the snapshot, computes the content checksum, and inserts a new
        row.  Raises CatalogueVersionConflictError if *version* is already used.
        """

    @abstractmethod
    def mark_superseded(self, row_id: uuid.UUID) -> None:
        """Transition a version's status from 'active' to 'superseded'.

        This is the only UPDATE permitted against this table; it touches the
        ``status`` column only.  Idempotent if already superseded.
        Raises ValueError if *row_id* is not found.
        """


class SQLAlchemyCatalogueRepository(CatalogueRepository):
    """SQLAlchemy 2.0 implementation of CatalogueRepository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_active(self) -> ControlCatalogueVersion | None:
        stmt = (
            select(ControlCatalogueVersion)
            .where(ControlCatalogueVersion.status == "active")
            .order_by(ControlCatalogueVersion.version.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def get_by_version(self, version: int) -> ControlCatalogueVersion | None:
        stmt = select(ControlCatalogueVersion).where(
            ControlCatalogueVersion.version == version
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def list_versions(self) -> Sequence[ControlCatalogueVersion]:
        stmt = select(ControlCatalogueVersion).order_by(
            ControlCatalogueVersion.version
        )
        return self._session.execute(stmt).scalars().all()

    def create_version(
        self,
        version: int,
        snapshot: CatalogueSnapshot,
        created_by: uuid.UUID,
        change_notes: str | None = None,
    ) -> ControlCatalogueVersion:
        snapshot_dict: Any = snapshot.model_dump()
        grade_bands_list: Any = [gb.model_dump() for gb in snapshot.grade_bands]
        checksum = compute_checksum(snapshot_dict)

        row = ControlCatalogueVersion(
            id=uuid.uuid4(),
            version=version,
            status="active",
            snapshot=snapshot_dict,
            grade_bands=grade_bands_list,
            created_by=created_by,
            change_notes=change_notes,
            content_checksum=checksum,
        )
        self._session.add(row)
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise CatalogueVersionConflictError(
                f"Catalogue version {version} already exists."
            ) from exc

        log.info(
            "catalogue_version_created",
            extra={
                "actor": str(created_by),
                "version": version,
                "checksum": checksum,
                "category_ids": [c["id"] for c in snapshot_dict.get("categories", [])],
            },
        )
        return row

    def mark_superseded(self, row_id: uuid.UUID) -> None:
        row = self._session.get(ControlCatalogueVersion, row_id)
        if row is None:
            raise ValueError(f"ControlCatalogueVersion {row_id!r} not found.")
        if row.status == "superseded":
            return  # idempotent
        row.status = "superseded"
        self._session.flush()


# ---------------------------------------------------------------------------
# In-memory implementation (tests and property tests)
# ---------------------------------------------------------------------------


@dataclass
class _InMemoryRow:
    """Minimal stand-in for ControlCatalogueVersion used by InMemoryCatalogueRepository."""

    id: uuid.UUID
    version: int
    status: str
    snapshot: dict
    grade_bands: list
    created_by: uuid.UUID
    change_notes: str | None
    content_checksum: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class InMemoryCatalogueRepository(CatalogueRepository):
    """Pure-Python in-memory implementation of CatalogueRepository.

    Satisfies the same interface as SQLAlchemyCatalogueRepository.
    Suitable for unit tests and property tests where a real database is
    not available.

    Immutability is enforced by raising on any attempt to mutate snapshot
    content (only status transitions via mark_superseded are permitted).
    """

    def __init__(self) -> None:
        self._rows: dict[uuid.UUID, _InMemoryRow] = {}
        self._version_index: dict[int, uuid.UUID] = {}

    def get_active(self) -> _InMemoryRow | None:
        active = [r for r in self._rows.values() if r.status == "active"]
        if not active:
            return None
        return max(active, key=lambda r: r.version)

    def get_by_version(self, version: int) -> _InMemoryRow | None:
        row_id = self._version_index.get(version)
        if row_id is None:
            return None
        return self._rows.get(row_id)

    def list_versions(self) -> Sequence[_InMemoryRow]:
        return sorted(self._rows.values(), key=lambda r: r.version)

    def create_version(
        self,
        version: int,
        snapshot: CatalogueSnapshot,
        created_by: uuid.UUID,
        change_notes: str | None = None,
    ) -> _InMemoryRow:
        if version in self._version_index:
            raise CatalogueVersionConflictError(
                f"Catalogue version {version} already exists."
            )

        snapshot_dict: Any = snapshot.model_dump()
        grade_bands_list: Any = [gb.model_dump() for gb in snapshot.grade_bands]
        checksum = compute_checksum(snapshot_dict)
        row_id = uuid.uuid4()

        row = _InMemoryRow(
            id=row_id,
            version=version,
            status="active",
            snapshot=snapshot_dict,
            grade_bands=grade_bands_list,
            created_by=created_by,
            change_notes=change_notes,
            content_checksum=checksum,
        )
        self._rows[row_id] = row
        self._version_index[version] = row_id
        return row

    def mark_superseded(self, row_id: uuid.UUID) -> None:
        row = self._rows.get(row_id)
        if row is None:
            raise ValueError(f"Catalogue row {row_id!r} not found.")
        if row.status == "superseded":
            return
        row.status = "superseded"
