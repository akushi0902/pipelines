"""Resilient inference client package (WO-023).

Exports the key public API:
  HttpInferenceClient  — concrete HTTP client with timeout, retry, circuit breaker
  CircuitBreaker       — reusable in-process circuit breaker
  DegradedResult       — typed failure container (never raises to callers)
  DegradedReason       — reason enum for degradation
  repair_json          — bounded JSON repair utility
  InferenceConfig      — pydantic-settings configuration model
"""
from __future__ import annotations

from .breaker import BreakerState, CircuitBreaker
from .client import HttpInferenceClient
from .degraded import DEGRADED_NOTICES, DegradedReason, DegradedResult
from .json_repair import repair_json

__all__ = [
    "BreakerState",
    "CircuitBreaker",
    "DEGRADED_NOTICES",
    "DegradedReason",
    "DegradedResult",
    "HttpInferenceClient",
    "repair_json",
]
