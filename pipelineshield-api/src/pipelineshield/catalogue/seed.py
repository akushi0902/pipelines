"""Idempotent seed routine for the ratified version 1 control catalogue.

Loads catalogue_v1.json from the committed fixtures directory, validates it
against CatalogueSnapshot, and inserts a single row if no active version
exists.  Re-running does not create a duplicate row.
"""
from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from ..persistence.models.control_catalogue_version import ControlCatalogueVersion
from ..persistence.repositories.catalogue import SQLAlchemyCatalogueRepository
from .schemas import CatalogueSnapshot

log = logging.getLogger(__name__)

# Path to the committed fixture relative to this file's location.
_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]  # pipelineshield-api/
    / "tests"
    / "fixtures"
    / "catalogue_v1.json"
)

# Stable version number for the ratified v1 catalogue.
_V1_VERSION = 1


def seed_v1_catalogue(
    session: Session,
    created_by: uuid.UUID,
    fixture_path: Path | None = None,
) -> ControlCatalogueVersion:
    """Insert the ratified v1 catalogue if no active version exists.

    Idempotent: calling this function a second time returns the existing row
    without creating a duplicate.  Always returns the active v1 row.

    Args:
        session: SQLAlchemy session (caller manages transaction lifetime).
        created_by: UUID of the actor creating the seed record (required; no
            row may have a null author).
        fixture_path: Override the fixture path for testing.  Defaults to
            tests/fixtures/catalogue_v1.json relative to the repo root.

    Returns:
        The active ControlCatalogueVersion row (new or pre-existing).
    """
    repo = SQLAlchemyCatalogueRepository(session)
    existing = repo.get_active()
    if existing is not None:
        log.info("catalogue_seed_skipped: active version %s already exists", existing.version)
        return existing

    path = fixture_path or _FIXTURE_PATH
    raw = json.loads(path.read_text(encoding="utf-8"))
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
