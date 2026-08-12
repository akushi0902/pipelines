"""CatalogueLoader — process-local cached read path for catalogue snapshots.

The loader maintains a process-local dict keyed by version id (immutable once
created) so repeated analysis requests pay at most one indexed query per unique
catalogue version per process lifetime.

Checksum verification is run on every cache miss to detect silent storage drift.
A mismatch raises CatalogueIntegrityError, failing the caller closed rather than
scoring against a tampered catalogue.
"""
from __future__ import annotations

import threading
from typing import Any

from .checksum import compute_checksum
from .schemas import CatalogueIntegrityError, CatalogueSnapshot

__all__ = ["CatalogueLoader"]


class CatalogueLoader:
    """Thread-safe process-local cache for CatalogueSnapshot objects.

    Versions are immutable once persisted, so the cache has no TTL.
    Call ``invalidate()`` after creating a new catalogue version to ensure
    the next ``load_active()`` call sees the freshly inserted row.

    Usage::

        loader = CatalogueLoader()
        snapshot = loader.load(version_row)        # verifies checksum
        snapshot = loader.load_active(session, repo)  # cached after first call
        loader.invalidate()                        # call after create_version
    """

    def __init__(self) -> None:
        self._cache: dict[Any, CatalogueSnapshot] = {}
        self._active_key: Any = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, version_row: Any) -> CatalogueSnapshot:
        """Load and verify a snapshot from *version_row*.

        *version_row* must have:
          - ``.id`` or ``.version`` — used as the cache key
          - ``.snapshot`` — the raw snapshot dict
          - ``.content_checksum`` — the stored SHA-256 hex digest

        Raises CatalogueIntegrityError if the computed checksum does not
        match the stored one.  Returns the cached snapshot on a cache hit.
        """
        key = getattr(version_row, "id", None) or getattr(version_row, "version", None)
        if key is None:
            raise ValueError("version_row must have an 'id' or 'version' attribute")

        with self._lock:
            if key in self._cache:
                return self._cache[key]

        snapshot_data = version_row.snapshot
        stored_checksum = version_row.content_checksum
        computed = compute_checksum(snapshot_data)
        if computed != stored_checksum:
            raise CatalogueIntegrityError(
                f"Catalogue checksum mismatch for version {key!r}. "
                f"Stored: {stored_checksum!r}, Computed: {computed!r}. "
                "This catalogue snapshot may have been tampered with."
            )

        snapshot = CatalogueSnapshot.model_validate(snapshot_data)

        with self._lock:
            self._cache[key] = snapshot
        return snapshot

    def load_active(self, session: Any, repo: Any) -> CatalogueSnapshot:
        """Load the currently active catalogue version, using the cache.

        *repo* must implement ``get_active() -> version_row | None``.

        Raises CatalogueIntegrityError if no active version exists or the
        checksum fails.
        """
        with self._lock:
            if self._active_key is not None and self._active_key in self._cache:
                return self._cache[self._active_key]

        row = repo.get_active()
        if row is None:
            raise CatalogueIntegrityError(
                "No active catalogue version found. "
                "Run the seed migration or create a catalogue version before starting analysis."
            )

        snapshot = self.load(row)
        key = getattr(row, "id", None) or getattr(row, "version", None)
        with self._lock:
            self._active_key = key
        return snapshot

    def invalidate(self, version_key: Any = None) -> None:
        """Invalidate the cache.

        If *version_key* is provided, only that entry is removed.
        If None, the entire cache is cleared (including the active pointer).

        Call after ``create_version`` so the next ``load_active`` fetches
        the newly inserted row rather than serving the previous active.
        """
        with self._lock:
            if version_key is None:
                self._cache.clear()
                self._active_key = None
            else:
                self._cache.pop(version_key, None)
                if self._active_key == version_key:
                    self._active_key = None

    def cache_size(self) -> int:
        """Return the number of cached snapshots (for testing)."""
        with self._lock:
            return len(self._cache)

    def is_cached(self, version_key: Any) -> bool:
        """Return True if *version_key* is present in the cache (for testing)."""
        with self._lock:
            return version_key in self._cache
