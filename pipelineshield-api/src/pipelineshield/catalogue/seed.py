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
# Expected location:
#
# pipelineshield/
# └── catalogue/
#     └── data/
#         └── catalogue_v1.json
#
_FIXTURE_RESOURCE = files(
    "pipelineshield.catalogue.data"
).joinpath("catalogue_v1.json")

_V1_VERSION = 1


def seed_v1_catalogue(
    session: Session,
    created_by: uuid.UUID,
    fixture_path: Path | None = None,
) -> ControlCatalogueVersion:
    """Insert the ratified v1 catalogue if no active version exists."""

    repo = SQLAlchemyCatalogueRepository(session)

    existing = repo.get_active()
    if existing is not None:
        log.info(
            "catalogue_seed_skipped: active version %s already exists",
            existing.version,
        )
        return existing

    if fixture_path is not None:
        raw = json.loads(
            fixture_path.read_text(encoding="utf-8")
        )
    else:
        raw = json.loads(
            _FIXTURE_RESOURCE.read_text(encoding="utf-8")
        )

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
