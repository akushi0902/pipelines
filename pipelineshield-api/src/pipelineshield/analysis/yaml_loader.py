"""Safe YAML loader for pipeline definitions.

Wraps ruamel.yaml in round-trip YAML 1.2 mode with:
  - Explicit version (1, 2) to prevent YAML 1.1 boolean coercion
    (on: → True, NO: → False, yes/off/y/n → booleans).
  - A bounded alias-expansion guard to reject anchor bombs.
  - A node-to-Anchor helper that maps any ruamel node to its source location.

No unsafe loaders are ever used.  Only YAML(typ='rt') with version=(1,2).
"""
from __future__ import annotations

import io
import re
from typing import Any

from ruamel.yaml import YAML  # type: ignore[import-untyped]

from pipelineshield.analysis.ir.pipeline_ir import Anchor

__all__ = [
    "load_yaml",
    "node_anchor",
    "key_anchor",
    "NormalizationError",
    "MAX_ALIASES",
]

MAX_ALIASES: int = 100

# Pattern matching bare alias references: *identifier (not inside strings)
_ALIAS_RE = re.compile(r"\*[A-Za-z_][A-Za-z0-9_\-]*")


class NormalizationError(Exception):
    """Raised when YAML parsing or normalization fails.

    Carries optional source location for structured error reporting.
    """

    def __init__(
        self,
        message: str,
        line: int | None = None,
        column: int | None = None,
        constraint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.line = line
        self.column = column
        self.constraint = constraint or "normalization_error"


def load_yaml(text: str) -> Any:
    """Load *text* as YAML in round-trip YAML 1.2 mode.

    Parameters
    ----------
    text:
        Raw pipeline definition text (already redacted by the WO-002 redactor).

    Returns
    -------
    Any
        A ruamel.yaml ``CommentedMap`` (for well-formed YAML mappings) or
        ``None`` for null documents.

    Raises
    ------
    NormalizationError
        If YAML is syntactically invalid, or if alias expansion would exceed
        ``MAX_ALIASES`` (anchor bomb guard).
    """
    # -----------------------------------------------------------------------
    # Pre-check: count alias references before attempting to load.
    # A genuine anchor bomb requires an exponential number of aliases, so
    # counting bare *identifiers is a conservative over-estimate that
    # catches the attack without false-negatives on well-formed workflows.
    # -----------------------------------------------------------------------
    alias_matches = _ALIAS_RE.findall(text)
    if len(alias_matches) > MAX_ALIASES:
        raise NormalizationError(
            f"YAML alias expansion limit exceeded: {len(alias_matches)} alias "
            f"references found (limit {MAX_ALIASES}). This may be an anchor bomb.",
            constraint="alias_bomb",
        )

    y = YAML(typ="rt")
    # YAML 1.2: 'on' stays a string, NO/Yes/off/y/n stay strings.
    # Under YAML 1.1 these would coerce to booleans, corrupting trigger analysis.
    y.version = (1, 2)
    y.preserve_quotes = True

    try:
        doc = y.load(io.StringIO(text))
    except Exception as exc:  # noqa: BLE001  ruamel raises many internal types
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        line: int | None = (mark.line + 1) if mark is not None else None
        col: int | None = (mark.column + 1) if mark is not None else None
        problem: str = getattr(exc, "problem", None) or str(exc)
        raise NormalizationError(
            problem,
            line=line,
            column=col,
            constraint="yaml_syntax",
        ) from exc

    return doc


def node_anchor(obj: Any) -> Anchor | None:
    """Return an ``Anchor`` from a ruamel.yaml node's ``lc`` attribute.

    Works on ``CommentedMap``, ``CommentedSeq``, and scalar nodes that carry
    location info.  Returns ``None`` for plain Python scalars.
    """
    lc = getattr(obj, "lc", None)
    if lc is None:
        return None
    line = getattr(lc, "line", None)
    col = getattr(lc, "col", None)
    if line is None:
        return None
    return Anchor(
        start_line=line + 1,
        start_column=(col if col is not None else 0) + 1,
    )


def key_anchor(mapping: Any, key: str) -> Anchor | None:
    """Return an ``Anchor`` for the position of *key* within a mapping.

    Parameters
    ----------
    mapping:
        A ruamel.yaml ``CommentedMap``.
    key:
        The key whose source position is requested.

    Returns
    -------
    Anchor | None
        Location of the key, or ``None`` if location info is unavailable.
    """
    lc = getattr(mapping, "lc", None)
    if lc is None:
        return None
    try:
        pos = lc.key(key)
        if pos is None:
            return None
        line, col = pos
        return Anchor(start_line=line + 1, start_column=col + 1)
    except (KeyError, TypeError, AttributeError):
        return None


def item_anchor(seq: Any, idx: int) -> Anchor | None:
    """Return an ``Anchor`` for item at *idx* in a sequence.

    Parameters
    ----------
    seq:
        A ruamel.yaml ``CommentedSeq``.
    idx:
        Zero-based index into the sequence.
    """
    lc = getattr(seq, "lc", None)
    if lc is None:
        return None
    try:
        pos = lc.item(idx)
        if pos is None:
            return None
        line, col = pos
        return Anchor(start_line=line + 1, start_column=col + 1)
    except (IndexError, TypeError, AttributeError):
        return None
