"""Verification digest builder for purge receipts.

The digest is computed exclusively from non-Confidential metadata:
row identifiers, entity type names, counts, and the batch timestamp.

No definition content, secret-shaped strings, or masked excerpts may
appear in the digest input.  An explicit allowlist of fields enforces
this at the function boundary.

Algorithm: SHA-256 over a canonical JSON document (keys sorted,
separators=(',', ':') for stable serialisation).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any, Sequence

from pipelineshield.persistence.repositories.purge import DefinitionRef, EntityCounts

__all__ = ["build_verification_digest", "build_batch_manifest"]

# Fields permitted in the digest document.  Only ids, type names, counts
# and timestamps — never content, credentials or user-supplied values.
_ALLOWED_MANIFEST_KEYS = frozenset({
    "batch_id",
    "executed_at",
    "definition_ids",
    "analysis_ids",
    "entity_counts",
    "entity_type_names",
})


def build_batch_manifest(
    batch_id: uuid.UUID,
    executed_at: datetime,
    definition_refs: Sequence[DefinitionRef],
    entity_counts: EntityCounts,
) -> dict[str, Any]:
    """Build the canonical manifest document for digest computation.

    Only non-Confidential metadata is included.  The manifest is the
    source of truth for the verification digest.
    """
    sorted_def_ids = sorted(str(r.definition_id) for r in definition_refs)
    sorted_ana_ids = sorted(str(r.analysis_id) for r in definition_refs)

    manifest: dict[str, Any] = {
        "batch_id": str(batch_id),
        "executed_at": executed_at.isoformat(),
        "definition_ids": sorted_def_ids,
        "analysis_ids": sorted_ana_ids,
        "entity_counts": entity_counts.as_dict(),
        "entity_type_names": sorted(entity_counts.as_dict().keys()),
    }

    # Guard: ensure no disallowed key crept in
    unexpected = set(manifest.keys()) - _ALLOWED_MANIFEST_KEYS
    if unexpected:
        raise ValueError(
            f"Digest manifest contains disallowed keys: {unexpected!r}. "
            "Only non-Confidential metadata may appear in the manifest."
        )

    return manifest


def build_verification_digest(
    batch_id: uuid.UUID,
    executed_at: datetime,
    definition_refs: Sequence[DefinitionRef],
    entity_counts: EntityCounts,
) -> str:
    """Return a SHA-256 hex digest over the canonical batch manifest.

    The digest is deterministic: same inputs always produce the same output.
    The manifest uses sorted keys and compact separators for stability.
    """
    manifest = build_batch_manifest(batch_id, executed_at, definition_refs, entity_counts)
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
