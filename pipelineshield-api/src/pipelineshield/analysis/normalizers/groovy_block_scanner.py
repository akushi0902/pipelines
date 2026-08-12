"""Groovy brace-matching scanner for Jenkins declarative pipeline extraction.

Walks Groovy source text tracking brace depth while correctly ignoring braces
inside:
  - single-quoted strings ('...')
  - double-quoted strings ("...")
  - triple-single-quoted strings ('''...''')
  - triple-double-quoted strings (\"\"\"...\"\"\")
  - line comments (// ...)
  - block comments (/* ... */)

Regex is intentionally *not* used for block structure — only for finding
directive name keywords. Block delimitation is done by the brace scanner, which
avoids catastrophic backtracking and correctly handles braces inside strings or
comments.

Public API
----------
find_matching_brace(text, open_pos, deadline=None) -> int | None
find_block(text, name, start=0, deadline=None) -> Block | None
find_all_blocks(text, name, start=0, deadline=None) -> list[Block]
offset_to_line_col(text, offset) -> tuple[int, int]
ExtractionBudgetExceeded
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

__all__ = [
    "Block",
    "ExtractionBudgetExceeded",
    "find_matching_brace",
    "find_block",
    "find_all_blocks",
    "offset_to_line_col",
]

# ---------------------------------------------------------------------------
# Lexical state constants
# ---------------------------------------------------------------------------

_NORMAL = 0
_SQ = 1    # single-quoted string
_DQ = 2    # double-quoted string
_TSQ = 3   # triple-single-quoted string
_TDQ = 4   # triple-double-quoted string
_LC = 5    # line comment
_BC = 6    # block comment


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Block:
    """A brace-delimited block found by scanning Groovy source."""

    name: str          # directive keyword (e.g. "pipeline", "stage")
    label: str | None  # string label from directive('label') { ... } form
    content: str       # text between '{' and matching '}'
    outer_start: int   # char offset of the directive keyword
    inner_start: int   # char offset of opening '{'
    inner_end: int     # char offset of matching '}'
    start_line: int    # 1-based line of the directive keyword
    end_line: int      # 1-based line of the closing '}'


class ExtractionBudgetExceeded(Exception):
    """Raised when the wall-clock or iteration extraction budget is exceeded."""


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def offset_to_line_col(text: str, offset: int) -> tuple[int, int]:
    """Return (1-based line, 1-based column) for *offset* in *text*.

    Handles both LF and CRLF line endings.
    """
    prefix = text[:offset]
    line = prefix.count('\n') + 1
    last_nl = prefix.rfind('\n')
    col = offset - last_nl  # rfind returns -1 if no newline → col = offset + 1
    return line, col


# ---------------------------------------------------------------------------
# Core: find matching closing brace
# ---------------------------------------------------------------------------


def find_matching_brace(
    text: str,
    open_pos: int,
    deadline: float | None = None,
) -> int | None:
    """Return the offset of the '}' that closes the '{' at *open_pos*.

    Respects Groovy lexical rules: braces inside strings or comments are
    ignored.  Returns None if no matching brace is found before end of text.

    Parameters
    ----------
    text:      Groovy source text.
    open_pos:  Offset of the opening '{'.  Must be exactly '{'.
    deadline:  monotonic() deadline; raises ExtractionBudgetExceeded if exceeded.
    """
    if text[open_pos] != '{':
        raise ValueError(f"Expected '{{' at offset {open_pos}, got {text[open_pos]!r}")

    n = len(text)
    i = open_pos + 1
    depth = 1
    state = _NORMAL

    while i < n:
        # Budget check every 4096 characters
        if deadline is not None and (i & 0xFFF) == 0 and time.monotonic() > deadline:
            raise ExtractionBudgetExceeded(
                f"Groovy brace matching exceeded wall-clock budget near offset {i}."
            )

        c = text[i]

        if state == _NORMAL:
            t3 = text[i:i + 3]
            if t3 == "'''":
                state = _TSQ
                i += 3
                continue
            if t3 == '"""':
                state = _TDQ
                i += 3
                continue
            t2 = text[i:i + 2]
            if t2 == '//':
                state = _LC
                i += 2
                continue
            if t2 == '/*':
                state = _BC
                i += 2
                continue
            if c == "'":
                state = _SQ
                i += 1
                continue
            if c == '"':
                state = _DQ
                i += 1
                continue
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return i

        elif state == _SQ:
            if c == '\\':
                i += 2
                continue
            if c == "'":
                state = _NORMAL

        elif state == _DQ:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                state = _NORMAL

        elif state == _TSQ:
            if text[i:i + 3] == "'''":
                state = _NORMAL
                i += 3
                continue

        elif state == _TDQ:
            if text[i:i + 3] == '"""':
                state = _NORMAL
                i += 3
                continue

        elif state == _LC:
            if c == '\n':
                state = _NORMAL

        elif state == _BC:
            if text[i:i + 2] == '*/':
                state = _NORMAL
                i += 2
                continue

        i += 1

    return None


# ---------------------------------------------------------------------------
# State-at-position helper
# ---------------------------------------------------------------------------


def _state_at(text: str, pos: int) -> int:
    """Return the Groovy lexical state immediately before character at *pos*.

    O(pos) — only called for candidate positions found by keyword regex, so
    total work is O(n * k) for k candidates per file.
    """
    state = _NORMAL
    i = 0
    while i < pos:
        c = text[i]
        if state == _NORMAL:
            t3 = text[i:i + 3]
            if t3 == "'''":
                state = _TSQ
                i += 3
                continue
            if t3 == '"""':
                state = _TDQ
                i += 3
                continue
            t2 = text[i:i + 2]
            if t2 == '//':
                state = _LC
                i += 2
                continue
            if t2 == '/*':
                state = _BC
                i += 2
                continue
            if c == "'":
                state = _SQ
                i += 1
                continue
            if c == '"':
                state = _DQ
                i += 1
                continue
        elif state == _SQ:
            if c == '\\':
                i += 2
                continue
            if c == "'":
                state = _NORMAL
        elif state == _DQ:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                state = _NORMAL
        elif state == _TSQ:
            if text[i:i + 3] == "'''":
                state = _NORMAL
                i += 3
                continue
        elif state == _TDQ:
            if text[i:i + 3] == '"""':
                state = _NORMAL
                i += 3
                continue
        elif state == _LC:
            if c == '\n':
                state = _NORMAL
        elif state == _BC:
            if text[i:i + 2] == '*/':
                state = _NORMAL
                i += 2
                continue
        i += 1
    return state


# ---------------------------------------------------------------------------
# Find the block-opening brace: first '{' at paren depth 0 in NORMAL state
# ---------------------------------------------------------------------------


def _find_block_open_brace(
    text: str,
    start: int,
    deadline: float | None = None,
) -> int | None:
    """Return the first '{' in NORMAL state and at parenthesis depth 0.

    Starting from *start*, scans forward respecting Groovy lexical rules and
    tracking `(` / `)` depth.  A '{' at paren_depth > 0 is skipped — it is
    inside a function argument, not a block opener.

    This correctly handles directives with complex arguments such as::

        withCredentials([usernamePassword(credentialsId: 'id', ...)]) {

    Returns None if no such '{' is found before end of text.
    """
    n = len(text)
    i = start
    state = _NORMAL
    paren_depth = 0

    while i < n:
        if deadline is not None and (i & 0xFFF) == 0 and time.monotonic() > deadline:
            raise ExtractionBudgetExceeded(
                f"Groovy forward scan exceeded budget near offset {i}."
            )

        c = text[i]

        if state == _NORMAL:
            t3 = text[i:i + 3]
            if t3 == "'''":
                state = _TSQ
                i += 3
                continue
            if t3 == '"""':
                state = _TDQ
                i += 3
                continue
            t2 = text[i:i + 2]
            if t2 == '//':
                state = _LC
                i += 2
                continue
            if t2 == '/*':
                state = _BC
                i += 2
                continue
            if c == "'":
                state = _SQ
                i += 1
                continue
            if c == '"':
                state = _DQ
                i += 1
                continue
            # Track parenthesis depth
            if c == '(':
                paren_depth += 1
            elif c == ')':
                if paren_depth > 0:
                    paren_depth -= 1
            elif c == '{':
                if paren_depth == 0:
                    return i
            # If we hit a newline and paren_depth is 0 and next meaningful char
            # is not a continuation, this might not be the right brace.
            # However, for declarative Jenkinsfiles this heuristic is sufficient.

        elif state == _SQ:
            if c == '\\':
                i += 2
                continue
            if c == "'":
                state = _NORMAL

        elif state == _DQ:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                state = _NORMAL

        elif state == _TSQ:
            if text[i:i + 3] == "'''":
                state = _NORMAL
                i += 3
                continue

        elif state == _TDQ:
            if text[i:i + 3] == '"""':
                state = _NORMAL
                i += 3
                continue

        elif state == _LC:
            if c == '\n':
                state = _NORMAL

        elif state == _BC:
            if text[i:i + 2] == '*/':
                state = _NORMAL
                i += 2
                continue

        i += 1

    return None


# ---------------------------------------------------------------------------
# Named-block search
# ---------------------------------------------------------------------------

# Regex to extract a quoted string label from ('label') or ("label") form.
# Searched in the text between the directive name and its opening '{'.
_LABEL_RE = re.compile(r'^\s*\(\s*["\']([^"\']*)["\']')


def find_block(
    text: str,
    name: str,
    start: int = 0,
    deadline: float | None = None,
) -> Block | None:
    """Find the first brace block whose directive keyword is *name*.

    Matches ``name {``, ``name('label') {``, ``name("label") {``, and complex
    argument forms such as ``name([...args...]) {``.

    Verifies the directive keyword is in Groovy NORMAL lexical state (not
    inside a string or comment).  Handles complex arguments (nested parens)
    by finding the first '{' at parenthesis depth 0 after the keyword.

    Returns None if no matching block is found.
    """
    name_re = re.compile(r'\b' + re.escape(name) + r'\b')

    for m in name_re.finditer(text, start):
        if _state_at(text, m.start()) != _NORMAL:
            continue

        # Find the opening brace: first '{' at paren depth 0 after the keyword
        brace_pos = _find_block_open_brace(text, m.end(), deadline)
        if brace_pos is None:
            continue

        # Extract optional label from ('label') between keyword and '{'
        between = text[m.end():brace_pos]
        label_m = _LABEL_RE.match(between)
        label = label_m.group(1) if label_m else None

        close_pos = find_matching_brace(text, brace_pos, deadline)
        if close_pos is None:
            continue

        sl, _ = offset_to_line_col(text, m.start())
        el, _ = offset_to_line_col(text, close_pos)

        return Block(
            name=name,
            label=label,
            content=text[brace_pos + 1: close_pos],
            outer_start=m.start(),
            inner_start=brace_pos,
            inner_end=close_pos,
            start_line=sl,
            end_line=el,
        )

    return None


def find_all_blocks(
    text: str,
    name: str,
    start: int = 0,
    deadline: float | None = None,
) -> list[Block]:
    """Find all brace blocks whose directive keyword is *name*.

    Yields blocks in document order, including nested blocks if *name* appears
    at multiple depths.  Each block is found independently; the scanner does
    not skip over previously found blocks (allowing nested extraction).

    See ``find_block`` for matching rules.
    """
    name_re = re.compile(r'\b' + re.escape(name) + r'\b')
    results: list[Block] = []

    for m in name_re.finditer(text, start):
        if _state_at(text, m.start()) != _NORMAL:
            continue

        brace_pos = _find_block_open_brace(text, m.end(), deadline)
        if brace_pos is None:
            continue

        between = text[m.end():brace_pos]
        label_m = _LABEL_RE.match(between)
        label = label_m.group(1) if label_m else None

        close_pos = find_matching_brace(text, brace_pos, deadline)
        if close_pos is None:
            continue

        sl, _ = offset_to_line_col(text, m.start())
        el, _ = offset_to_line_col(text, close_pos)

        results.append(Block(
            name=name,
            label=label,
            content=text[brace_pos + 1: close_pos],
            outer_start=m.start(),
            inner_start=brace_pos,
            inner_end=close_pos,
            start_line=sl,
            end_line=el,
        ))

    return results
