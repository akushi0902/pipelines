"""SLSA-level sanitizer — rejects Level 4 / L4 references from AI narratives.

AC-9: Narratives must reference SLSA Build track L0-L3 only.
      Any output containing SLSA Level 4 is rejected (or sanitized).

The WO constrains SLSA Build track levels to L0 through L3.  Level 4 is a
legacy v0.1 designation that was retired when SLSA 1.0 was published; citing
it in a recommendation would mislead practitioners.
"""
from __future__ import annotations

import re

# Matches SLSA Level 4, SLSA L4, and variant spellings with/without spaces.
_SLSA_L4_RE = re.compile(
    r"\bSLSA\s*(?:Build\s+)?(?:Level\s*4|L4)\b",
    re.IGNORECASE,
)

_REPLACEMENT = "[SLSA Level 4 reference removed — cite L0-L3 only]"


def has_slsa_level_4(text: str) -> bool:
    """Return True when *text* contains a SLSA Level 4 reference."""
    return bool(_SLSA_L4_RE.search(text))


def sanitize_slsa_level_4(text: str) -> str:
    """Replace all SLSA Level 4 / L4 occurrences with a safe placeholder."""
    return _SLSA_L4_RE.sub(_REPLACEMENT, text)


def sanitize_narrative(text: str) -> str:
    """Apply all narrative content sanitizers.

    Currently: SLSA Level 4 removal.
    Safe to call on any free-text field before persistence.
    """
    return sanitize_slsa_level_4(text)
