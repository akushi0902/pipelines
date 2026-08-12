"""Anchor validation gate for PipelineShield.

The AnchorValidator is the single chokepoint between candidate findings
(from the deterministic rule engine or the LLM advisory pass) and persistence.
ValidatedFinding is the only type accepted by FindingRepository.save_all().
"""
from .models import (
    AnchorValidationConfigurationError,
    CandidateFinding,
    SuppressionReason,
    SuppressionRecord,
    SuppressionReport,
    ValidatedFinding,
)
from .redacted_document import RedactedDocument, build_redacted_document
from .validator import AnchorValidator

__all__ = [
    "AnchorValidationConfigurationError",
    "AnchorValidator",
    "CandidateFinding",
    "RedactedDocument",
    "SuppressionReason",
    "SuppressionRecord",
    "SuppressionReport",
    "ValidatedFinding",
    "build_redacted_document",
]
