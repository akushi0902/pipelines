"""DegradedResult — typed failure container for inference client failures.

Every failure mode (timeout, connection error, HTTP 5xx, schema invalid twice,
circuit open) is represented as a DegradedResult rather than an exception.
Callers check the ``reason`` field to route the response; they never catch
exceptions from the inference path.

The templated ``notice`` strings are sourced from DEGRADED_NOTICES so the
user-facing text is centralised and cannot be fabricated per-failure.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class DegradedReason(str, enum.Enum):
    """Reason an inference call returned a DegradedResult instead of model output."""

    TIMEOUT = "timeout"
    """The model did not respond within the configured wall-clock budget."""

    CONNECTION_ERROR = "connection_error"
    """Transport-level failure: refused connection, DNS failure, TLS error, etc."""

    UPSTREAM_ERROR = "upstream_error"
    """The inference backend returned a non-2xx HTTP status or an oversized response."""

    SCHEMA_INVALID = "schema_invalid"
    """Model output failed Pydantic validation on both the initial attempt and the
    single validation-feedback retry."""

    CIRCUIT_OPEN = "circuit_open"
    """Circuit breaker is open after repeated failures; call was rejected immediately
    without contacting the inference backend."""


# ---------------------------------------------------------------------------
# Templated user-facing notices (BR-02 compliant — no certification language)
# ---------------------------------------------------------------------------

DEGRADED_NOTICES: dict[DegradedReason, str] = {
    DegradedReason.TIMEOUT: (
        "AI-assisted explanations are temporarily unavailable (inference timeout). "
        "The deterministic security findings and score above are unaffected. "
        "Retry the report to attempt AI enrichment."
    ),
    DegradedReason.CONNECTION_ERROR: (
        "AI-assisted explanations are temporarily unavailable (inference unreachable). "
        "The deterministic security findings and score above are unaffected. "
        "Retry the report to attempt AI enrichment."
    ),
    DegradedReason.UPSTREAM_ERROR: (
        "AI-assisted explanations are temporarily unavailable (inference backend error). "
        "The deterministic security findings and score above are unaffected. "
        "Retry the report to attempt AI enrichment."
    ),
    DegradedReason.SCHEMA_INVALID: (
        "AI-assisted explanations could not be validated and have been suppressed. "
        "The deterministic security findings and score above are unaffected. "
        "Retry the report to attempt AI enrichment."
    ),
    DegradedReason.CIRCUIT_OPEN: (
        "AI-assisted explanations are temporarily suspended (repeated inference failures). "
        "The deterministic security findings and score above are unaffected. "
        "Retry the report after the suspension window expires."
    ),
}


@dataclass(frozen=True)
class DegradedResult:
    """Typed failure container returned by InferenceClient when the call cannot
    produce a validated model instance.

    Callers must check ``isinstance(result, DegradedResult)`` and fall back to
    the deterministic report path.  The ``notice`` field is the pre-templated
    user-facing string; callers must propagate it to the report payload as
    ``degraded_coverage_notice``.  The ``error`` field is for internal logging
    only and must never be forwarded to the API response.
    """

    reason: DegradedReason
    """Machine-readable failure reason for metrics and routing."""

    notice: str
    """Human-readable templated notice sourced from DEGRADED_NOTICES."""

    error: str = field(default="")
    """Internal error detail for structured logging.  Never forwarded to callers."""

    latency_ms: float = field(default=0.0)
    """Wall-clock duration of the failed attempt in milliseconds."""

    @classmethod
    def from_reason(
        cls,
        reason: DegradedReason,
        error: str = "",
        latency_ms: float = 0.0,
    ) -> "DegradedResult":
        """Construct with the canonical templated notice for *reason*."""
        return cls(
            reason=reason,
            notice=DEGRADED_NOTICES[reason],
            error=error,
            latency_ms=latency_ms,
        )
