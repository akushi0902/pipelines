"""Catalogue domain — versioned immutable control catalogue.

Exports:
- Pydantic schemas (CatalogueSnapshot, ControlCategory, ControlDefinition, GradeBand)
- Enums (Severity, ControlSource)
- Canonical JSON serialisation and SHA-256 checksum helpers
- CatalogueValidationError, CatalogueVersionConflictError, CatalogueIntegrityError
"""
from .schemas import (
    CatalogueSnapshot,
    CatalogueIntegrityError,
    CatalogueValidationError,
    CatalogueVersionConflictError,
    ControlCategory,
    ControlDefinition,
    ControlSource,
    GradeBand,
    Severity,
)
from .checksum import canonical_json, compute_checksum
from .loader import CatalogueLoader

__all__ = [
    "CatalogueIntegrityError",
    "CatalogueLoader",
    "CatalogueSnapshot",
    "CatalogueValidationError",
    "CatalogueVersionConflictError",
    "ControlCategory",
    "ControlDefinition",
    "ControlSource",
    "GradeBand",
    "Severity",
    "canonical_json",
    "compute_checksum",
]
