"""InferenceClient protocol — injectable interface for the self-hosted LLM.

The full implementation is provided by WO-023.  This module defines the
protocol so the explanation pass can be tested without a live model, and
provides NullInferenceClient and DegradedResult for use in tests.

The benchmark runner always uses NullInferenceClient — the deterministic
path is the source of truth; the model pass is advisory only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class InferenceResult:
    """Result from a single InferenceClient.complete() call."""

    content: str
    """Raw text produced by the model (may be empty on degraded result)."""

    degraded: bool = False
    """True when the call failed, timed out, or hit the budget ceiling.

    On degradation, the explanation pass falls back to deterministic templated
    remediations and sets a degraded-coverage notice on the analysis response.
    """

    error: str | None = None
    """Human-readable error description when degraded=True."""

    latency_ms: float = 0.0
    """Wall-clock milliseconds for the call (0 when degraded before the call)."""


@runtime_checkable
class InferenceClient(Protocol):
    """Protocol for the self-hosted LLM inference backend.

    The implementation (WO-023) calls the self-hosted model over the internal
    network.  No external egress is permitted; the network segment denies all
    outbound routes except the vLLM endpoint.

    Both reasoning and formatting calls use this same interface; callers control
    the system prompt to select the mode.
    """

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        timeout_s: float = 12.0,
    ) -> InferenceResult:
        """Issue a single completion call to the model.

        Parameters
        ----------
        system_prompt:
            Role and constraint instructions.  Must not contain raw definition
            content (masked IR only, via the redactor).
        user_prompt:
            The task content.  Must contain only redacted text.
        timeout_s:
            Hard wall-clock timeout.  On timeout, the client must return a
            DegradedResult rather than raising an exception so the caller can
            degrade gracefully.

        Returns
        -------
        InferenceResult with degraded=True on any failure.
        """
        ...  # pragma: no cover


class NullInferenceClient:
    """No-op inference client for tests and the benchmark harness.

    Always returns a degraded result so callers fall back to deterministic
    templated remediations without making any network call.
    """

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        timeout_s: float = 12.0,
    ) -> InferenceResult:
        return InferenceResult(
            content="",
            degraded=True,
            error="NullInferenceClient: no model configured",
        )


class FailingInferenceClient:
    """Always-failing client used in tests to assert no LLM calls change results."""

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        timeout_s: float = 12.0,
    ) -> InferenceResult:
        raise RuntimeError(
            "FailingInferenceClient: this client must never be called in the "
            "deterministic analysis path"
        )
