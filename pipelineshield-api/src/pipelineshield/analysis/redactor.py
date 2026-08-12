"""Length-preserving secret redactor.

Entry point: ``redact(text: str) -> RedactedDoc``

The redactor applies all patterns in a single left-to-right pass, resolves
overlapping spans deterministically, and replaces each secret span with a
length-preserving mask token:

  [REDACTED:<pattern_id>]XXXXXXX...  (padded to span length)

For spans shorter than the token:

  XXXXXXX...  (span length of pad characters; pattern id still recorded)

Newlines inside multi-line spans (e.g. PEM blocks) are kept in place so that
line and column offsets for ALL non-secret tokens remain identical.

The ``RedactedDoc.redaction_map`` is excluded from serialisation and its repr
shows only a count — it must never be persisted, logged, or sent over a wire.
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FuturesTimeout
from dataclasses import dataclass, field
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from .redaction_patterns import ORDERED_PATTERNS, RedactionPattern

__all__ = ["redact", "RedactedDoc", "RedactionTimeoutError"]

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MASK_CHAR = "X"

# Shannon entropy threshold for high-entropy candidate detection.
# Rationale: hex-only SHA pins score ≈4.0 bits/char (log₂(16));
# random base64/alphanumeric secrets score ≥4.5 bits/char.
_ENTROPY_THRESHOLD: float = 4.5

# Minimum token length for entropy-based detection.
_ENTROPY_MIN_LEN: int = 32

# Candidate characters for the high-entropy scan (printable non-whitespace
# ASCII that commonly appear in base64, hex, alphanumeric secrets).
_ENTROPY_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,1024}")

# Pattern id used in the map and token for entropy-detected spans.
_ENTROPY_PATTERN_ID = "high_entropy"

# Redaction timeout (seconds) — catastrophic-backtracking guard.
_TIMEOUT_SECONDS: float = 5.0


# ---------------------------------------------------------------------------
# Redaction map — opaque, never serialised
# ---------------------------------------------------------------------------

class _MapEntry(NamedTuple):
    start: int
    end: int
    pattern_id: str


class _RedactionMap:
    """Opaque container; repr shows only a count, never span contents."""

    def __init__(self, entries: list[_MapEntry]) -> None:
        self._entries: list[_MapEntry] = entries

    def __repr__(self) -> str:
        return f"<RedactionMap spans={len(self._entries)}>"

    def __str__(self) -> str:
        return repr(self)

    def counts_by_pattern(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self._entries:
            counts[e.pattern_id] = counts.get(e.pattern_id, 0) + 1
        return counts

    def __iter__(self):  # type: ignore[override]
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# RedactedDoc
# ---------------------------------------------------------------------------

class RedactedDoc(BaseModel):
    """Immutable result of a redact() call.

    ``masked_text``: text with all secret spans replaced by length-preserving
    mask tokens.

    ``pattern_counts``: mapping of pattern_id → count (safe to log or return
    in an API response).

    ``redaction_map``: excluded from serialisation; repr shows span count only.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    masked_text: str
    pattern_counts: dict[str, int]
    redaction_map: _RedactionMap = Field(exclude=True, repr=False)

    def __repr__(self) -> str:
        return (
            f"RedactedDoc(masked_text=<{len(self.masked_text)} chars>, "
            f"pattern_counts={self.pattern_counts!r})"
        )

    def __str__(self) -> str:
        return repr(self)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class RedactionTimeoutError(RuntimeError):
    """Raised when redaction exceeds the wall-clock guard threshold."""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def redact(text: str, timeout_seconds: float = _TIMEOUT_SECONDS) -> RedactedDoc:
    """Mask all secret-shaped content in *text* and return a :class:`RedactedDoc`.

    The redactor runs inside a thread with a wall-clock limit.  If the limit is
    exceeded, a :class:`RedactionTimeoutError` is raised and no partial result is
    returned (fail-closed).
    """
    if not text:
        return RedactedDoc(
            masked_text=text,
            pattern_counts={},
            redaction_map=_RedactionMap([]),
        )

    with ThreadPoolExecutor(max_workers=1) as exe:
        future = exe.submit(_do_redact, text)
        try:
            return future.result(timeout=timeout_seconds)
        except _FuturesTimeout:
            raise RedactionTimeoutError(
                f"Redaction exceeded the {timeout_seconds}s wall-clock guard. "
                "Request failed closed — no content is echoed."
            )


# ---------------------------------------------------------------------------
# Internal implementation
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _make_mask(original_span: str, pattern_id: str) -> str:
    """Return a mask string with the same length and newline positions.

    Newlines are preserved in-place so per-line column offsets are unchanged.
    The token ``[REDACTED:<pattern_id>]`` is written into the available
    (non-newline) character positions; any remainder is filled with
    ``_MASK_CHAR``.
    """
    token = f"[REDACTED:{pattern_id}]"
    chars = list(original_span)

    # Mark all non-newline positions with the mask character.
    for i, ch in enumerate(chars):
        if ch != "\n" and ch != "\r":
            chars[i] = _MASK_CHAR

    # Overlay token onto the non-newline positions from the left.
    t_idx = 0
    for i, orig_ch in enumerate(original_span):
        if orig_ch not in ("\n", "\r") and t_idx < len(token):
            chars[i] = token[t_idx]
            t_idx += 1

    return "".join(chars)


@dataclass
class _Span:
    start: int
    end: int
    pattern_id: str
    registry_index: int  # lower index = higher priority


def _collect_explicit_spans(text: str) -> list[_Span]:
    """Find all spans matched by the explicit pattern registry."""
    spans: list[_Span] = []
    for idx, pattern in enumerate(ORDERED_PATTERNS):
        for m in pattern.regex.finditer(text):
            if pattern.capture_group == 0:
                start, end = m.start(), m.end()
            else:
                grp = pattern.capture_group
                if m.start(grp) == -1:
                    continue
                start, end = m.start(grp), m.end(grp)
            if start < end:
                spans.append(_Span(start, end, pattern.pattern_id, idx))
    return spans


def _collect_entropy_spans(text: str, registry_base: int) -> list[_Span]:
    """Find candidate tokens with Shannon entropy above the threshold."""
    spans: list[_Span] = []
    for m in _ENTROPY_CANDIDATE_RE.finditer(text):
        candidate = m.group()
        if (
            len(candidate) >= _ENTROPY_MIN_LEN
            and _shannon_entropy(candidate) >= _ENTROPY_THRESHOLD
        ):
            spans.append(
                _Span(m.start(), m.end(), _ENTROPY_PATTERN_ID, registry_base)
            )
    return spans


def _resolve_overlaps(spans: list[_Span]) -> list[_Span]:
    """Keep non-overlapping spans; ties on start resolved by registry_index."""
    spans.sort(key=lambda s: (s.start, s.registry_index))
    result: list[_Span] = []
    last_end = 0
    for span in spans:
        if span.start >= last_end:
            result.append(span)
            last_end = span.end
    return result


def _do_redact(text: str) -> RedactedDoc:
    """Core redaction logic (runs inside a timeout thread)."""
    all_spans = _collect_explicit_spans(text)
    all_spans += _collect_entropy_spans(text, registry_base=len(ORDERED_PATTERNS))

    accepted = _resolve_overlaps(all_spans)

    if not accepted:
        return RedactedDoc(
            masked_text=text,
            pattern_counts={},
            redaction_map=_RedactionMap([]),
        )

    # Build masked text by reconstructing character by character.
    parts: list[str] = []
    cursor = 0
    map_entries: list[_MapEntry] = []

    for span in accepted:
        if span.start > cursor:
            parts.append(text[cursor : span.start])
        original_span_text = text[span.start : span.end]
        parts.append(_make_mask(original_span_text, span.pattern_id))
        map_entries.append(_MapEntry(span.start, span.end, span.pattern_id))
        cursor = span.end

    if cursor < len(text):
        parts.append(text[cursor:])

    masked = "".join(parts)

    # Invariant: length preserved.
    assert len(masked) == len(text), (
        f"Length invariant violated: input={len(text)} output={len(masked)}"
    )

    rmap = _RedactionMap(map_entries)
    counts = rmap.counts_by_pattern()

    _LOG.info(
        "redaction_applied",
        extra={
            "total": len(map_entries),
            "by_pattern": counts,
        },
    )

    return RedactedDoc(
        masked_text=masked,
        pattern_counts=counts,
        redaction_map=rmap,
    )
