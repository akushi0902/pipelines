"""Idempotent seed routine for the ratified version 1 control catalogue.

Loads catalogue_v1.json from package data, validates it against
CatalogueSnapshot, and inserts a single row if no active version exists.
Re-running does not create a duplicate row.
"""

from __future__ import annotations

import json
import logging
import uuid
from importlib.resources import files
from pathlib import Path

from sqlalchemy.orm import Session

from ..persistence.models.control_catalogue_version import (
    ControlCatalogueVersion,
)
from ..persistence.repositories.catalogue import (
    SQLAlchemyCatalogueRepository,
)
from .schemas import CatalogueSnapshot

log = logging.getLogger(__name__)

# Package resource containing the catalogue fixture.
#
# Expected location:
#
# pipelineshield/
# └── catalogue/
#     └── data/
#         └── catalogue_v1.json
#

_V1_VERSION = 1


def _load_catalogue_fixture(
    fixture_path: Path | None = None,
) -> dict:
    """Load catalogue fixture from override path or package data."""

    if fixture_path is not None:
        return json.loads(
            fixture_path.read_text(encoding="utf-8")
        )

    return json.loads(
        files("pipelineshield.catalogue.data")
        .joinpath("catalogue_v1.json")
        .read_text(encoding="utf-8")
    )


def seed_v1_catalogue(
    session: Session,
    created_by: uuid.UUID,
    fixture_path: Path | None = None,
) -> ControlCatalogueVersion:
    """Insert the ratified v1 catalogue if no active version exists.

    Idempotent: calling this function multiple times returns the
    existing active catalogue instead of creating duplicates.

    Args:
        session: SQLAlchemy session.
        created_by: UUID of the actor creating the catalogue.
        fixture_path: Optional override fixture path for tests.

    Returns:
        Active ControlCatalogueVersion row.
    """

    repo = SQLAlchemyCatalogueRepository(session)

    existing = repo.get_active()
    if existing is not None:
        log.info(
            "catalogue_seed_skipped: active version %s already exists",
            existing.version,
        )
        return existing

    raw = _load_catalogue_fixture(fixture_path)

    snapshot = CatalogueSnapshot.model_validate(raw)

    row = repo.create_version(
        version=_V1_VERSION,
        snapshot=snapshot,
        created_by=created_by,
        change_notes="Initial ratified v1 catalogue.",
    )

    log.info(
        "catalogue_seed_inserted: version=%s checksum=%s",
        row.version,
        row.content_checksum,
    )

    return row
