"""Data models for the anchor validation gate.

ValidatedFinding is the only persistable finding type — constructed exclusively
by AnchorValidator.validate(). The runtime isinstance guard at the persistence
boundary enforces this.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Any

from pipelineshield.analysis.rule_engine.protocol import EvidenceAnchor


class AnchorValidationConfigurationError(Exception):
    """Raised when RedactedDocument is misconfigured (e.g. not normalized).

    Analysis is failed closed with a 422 rather than silently scoring without
    a valid anchor surface.
    """


class SuppressionReason(str, enum.Enum):
    MISSING_ANCHOR = "missing_anchor"
    OUT_OF_RANGE = "out_of_range"
    UNRESOLVED_FRAGMENT = "unresolved_fragment"
    BLANK_TARGET_LINE = "blank_target_line"
    FINGERPRINT_MISMATCH = "fingerprint_mismatch"
    SNIPPET_CONTAINS_SECRET = "snippet_contains_secret"


@dataclass(frozen=True)
class SuppressionRecord:
    """Single suppression event attached to a SuppressionReport."""

    rule_id: str
    control_id: str
    source: str
    reason: SuppressionReason
    analysis_id: str = ""
    detail: str = ""


@dataclass
class SuppressionReport:
    """Aggregate suppression accounting for one validate() call."""

    suppressions: list[SuppressionRecord] = field(default_factory=list)

    def count_by_reason(self) -> dict[SuppressionReason, int]:
        counts: dict[SuppressionReason, int] = {}
        for s in self.suppressions:
            counts[s.reason] = counts.get(s.reason, 0) + 1
        return counts

    def total(self) -> int:
        return len(self.suppressions)


@dataclass(frozen=True)
class CandidateFinding:
    """Unvalidated finding candidate from the rule engine or LLM pass.

    source must be 'deterministic' or 'ai_advisory'.
    line_fingerprint is the sha256 of the anchored line at generation time;
    omit (leave None) when the generating source did not record one.
    """

    rule_id: str
    control_id: str
    category: str
    source: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any]
    analysis_id: uuid.UUID
    workspace_id: uuid.UUID
    anchor: EvidenceAnchor | None = None
    line_fingerprint: str | None = None
    weight: int = 0
    requires_human_review: bool = True


@dataclass(frozen=True)
class ValidatedFinding:
    """Finding that has passed all anchor validation checks.

    Only AnchorValidator.validate() may produce instances of this type.
    FindingRepository.save_all() enforces this at the persistence boundary
    via a runtime isinstance guard.

    anchor_line / anchor_column are SARIF-compatible (1-based):
      physicalLocation.region.startLine == anchor_line
      physicalLocation.region.startColumn == anchor_column
    """

    rule_id: str
    control_id: str
    category: str
    source: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any]
    analysis_id: uuid.UUID
    workspace_id: uuid.UUID
    anchor_line: int
    anchor_column: int
    snippet: str
    weight: int
    requires_human_review: bool
