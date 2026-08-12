"""Pydantic v2 / dataclass models for the deterministic scoring engine.

These are the contracts consumed by:
  - ScoringEngine (produces ScoreResult)
  - Persistence layer (persists ScoreResult to analysis + analysis_category_score)
  - API layer WO-021 (serializes ScoreResult to the response schema)

No FastAPI, SQLAlchemy, or HTTP-client imports are permitted in this module.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Optional


class VerdictEnum(str, enum.Enum):
    """Control evaluation verdict values.

    PRESENT       — control is implemented and satisfied.
    PARTIAL       — control is partially implemented (earns fractional credit).
    MISSING       — control is not implemented.
    NOT_ASSESSABLE — control cannot be evaluated (excluded from denominator).
    """

    PRESENT = "present"
    PARTIAL = "partial"
    MISSING = "missing"
    NOT_ASSESSABLE = "not_assessable"


class ScoringError(Exception):
    """Raised by ScoringEngine for domain-level violations.

    Carries a machine-readable ``code`` so the API layer can map to a
    structured 422 response without string-matching the message.
    """

    def __init__(self, message: str, code: str = "scoring_error") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ControlVerdict:
    """Caller-supplied verdict for one control.

    control_id  — must exist in the active catalogue version.
    category_id — informational; the engine validates this matches the catalogue.
    verdict     — PRESENT | PARTIAL | MISSING | NOT_ASSESSABLE.
    """

    control_id: str
    category_id: str
    verdict: VerdictEnum


@dataclass(frozen=True)
class CategoryScore:
    """Per-category scoring breakdown returned inside ScoreResult.

    earned         — weighted credit earned (Decimal, >= 0).
    possible       — maximum credit possible (denominator for this category,
                     excludes NOT_ASSESSABLE controls).
    excluded_count — number of NOT_ASSESSABLE controls excluded from scoring.
    """

    category_id: str
    earned: Decimal
    possible: Decimal
    excluded_count: int

    @property
    def ratio(self) -> Optional[Decimal]:
        """Category coverage ratio (earned / possible), or None if possible == 0."""
        if self.possible == Decimal("0"):
            return None
        return self.earned / self.possible


@dataclass(frozen=True)
class ScoreResult:
    """Return value of ScoringEngine.score() — the public contract for WO-021.

    total_score    — 0.0–100.0 rounded to one decimal with ROUND_HALF_UP,
                     or None when unscorable (zero denominator).
    letter_grade   — single letter from the catalogue grade bands, or None.
    unscorable     — True when ALL controls are NOT_ASSESSABLE (zero denominator).
    unscorable_reason — human-readable reason when unscorable is True.
    category_scores   — one CategoryScore per enabled category, sorted by category_id.
    catalogue_version — integer version number of the catalogue used.
    analysis_id    — optional UUID of the owning analysis row (set by caller).
    """

    total_score: Optional[Decimal]
    letter_grade: Optional[str]
    unscorable: bool
    unscorable_reason: Optional[str]
    category_scores: tuple[CategoryScore, ...]
    catalogue_version: int
    analysis_id: Optional[uuid.UUID] = None
