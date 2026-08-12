"""RedactedDocument — line-indexed, fingerprinted wrapper over a redacted document.

The fingerprint per line is sha256(line.rstrip()) computed post-redaction so
that length-preserving mask tokens are included and the hash still matches when
the validator re-checks the current document state.

CRLF and bare CR are normalized to LF before indexing so that line numbering
is stable across platforms.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from pipelineshield.analysis.redactor import RedactedDoc

_CRLF_RE = re.compile(r"\r\n|\r")


@dataclass(frozen=True)
class _RedactedLine:
    line_no: int
    content: str
    fingerprint: str


def _line_fingerprint(content: str) -> str:
    return hashlib.sha256(content.rstrip().encode()).hexdigest()


@dataclass(frozen=True)
class RedactedDocument:
    """Line-indexed, fingerprinted view of a redacted pipeline definition.

    Attributes:
        line_index: tuple of _RedactedLine, zero-indexed (line_no i+1 at index i).
        fragment_resolution: maps (start_line, end_line) → resolution_status.
        total_lines: total number of lines (== len(line_index)).
        is_normalized: always True for documents produced by build_redacted_document();
            the validator refuses documents where this is False.
    """

    line_index: tuple[_RedactedLine, ...]
    fragment_resolution: dict[tuple[int, int], str]
    total_lines: int
    is_normalized: bool

    def get_line(self, line_no: int) -> _RedactedLine | None:
        if line_no < 1 or line_no > self.total_lines:
            return None
        return self.line_index[line_no - 1]

    def resolution_status_for_line(self, line_no: int) -> str | None:
        """Return the resolution_status of the fragment covering line_no, or None."""
        for (start, end), status in self.fragment_resolution.items():
            if start <= line_no <= end:
                return status
        return None


def build_redacted_document(
    doc: RedactedDoc,
    fragment_resolution: dict[tuple[int, int], str] | None = None,
) -> RedactedDocument:
    """Build a RedactedDocument from an already-redacted RedactedDoc.

    Args:
        doc: output of redactor.redact() — masked_text contains redacted content.
        fragment_resolution: optional map of line ranges to fragment resolution
            statuses from PipelineIR.coverage_report (e.g. "unresolved").
    """
    normalized = _CRLF_RE.sub("\n", doc.masked_text)
    raw_lines = normalized.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines = raw_lines[:-1]

    line_index: tuple[_RedactedLine, ...] = tuple(
        _RedactedLine(
            line_no=i + 1,
            content=raw_lines[i],
            fingerprint=_line_fingerprint(raw_lines[i]),
        )
        for i in range(len(raw_lines))
    )

    return RedactedDocument(
        line_index=line_index,
        fragment_resolution=dict(fragment_resolution or {}),
        total_lines=len(line_index),
        is_normalized=True,
    )
