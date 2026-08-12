"""Observability package — OpenTelemetry spans and Prometheus metrics.

Exports:
  stage_span   — context manager that opens one OTel span and records a
                 Prometheus histogram observation for a named analysis stage.
  METRIC_NAMES — centralised name constants so tests and dashboards reference
                 the same strings.
"""
from .metrics import METRIC_NAMES, get_registry
from .tracing import stage_span

__all__ = ["METRIC_NAMES", "get_registry", "stage_span"]
