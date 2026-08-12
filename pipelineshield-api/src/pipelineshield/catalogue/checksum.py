"""Canonical JSON serialisation and SHA-256 checksum for catalogue snapshots.

Canonical form: sorted keys, compact separators (no whitespace), ASCII-safe.
This makes the digest reproducible across Python versions, platforms, and
key insertion orders.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(data: Any) -> str:
    """Serialise *data* to canonical JSON (sorted keys, no whitespace).

    The output is deterministic regardless of the original key insertion order,
    making it safe to use as input for a content checksum.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_checksum(data: Any) -> str:
    """Return the SHA-256 hex digest of the canonical JSON serialisation of *data*.

    Identical logical values with different key orders produce the same digest.
    The digest is a 64-character lowercase hex string.
    """
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()
