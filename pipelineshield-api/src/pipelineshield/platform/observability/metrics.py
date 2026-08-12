"""Prometheus metrics registry for PipelineShield.

All metric names are centralised here as string constants so:
  - Dashboard/alert configurations can import METRIC_NAMES instead of
    using raw strings.
  - Tests assert against the same constants rather than duplicating names.
  - A rename in METRIC_NAMES is the single change required everywhere.

Cardinality guard:
  Only ``format`` and ``stage`` labels are permitted on the duration
  histogram.  No per-analysis, per-user, or per-workspace labels may be
  added — doing so would cause unbounded cardinality in production.

Soft import: ``prometheus_client`` is an optional dependency.  When it is
not installed, ``get_registry()`` returns ``None`` and all helpers become
no-ops so the application starts without observability installed.
"""
from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Centralised name constants
# ---------------------------------------------------------------------------

class METRIC_NAMES:
    """String constants for every Prometheus metric this module registers."""

    ANALYSIS_DURATION_SECONDS = "pipelineshield_analysis_duration_seconds"
    FINDINGS_TOTAL = "pipelineshield_findings_total"
    INFERENCE_DEGRADED_TOTAL = "pipelineshield_inference_degraded_total"
    UNANCHORED_SUPPRESSED_TOTAL = "pipelineshield_unanchored_suppressed_total"
    AUTHZ_DENIED_TOTAL = "pipelineshield_authz_denied_total"
    PURGE_DELETED_TOTAL = "pipelineshield_purge_deleted_total"
    AUDIT_WRITE_FAILURE_TOTAL = "pipelineshield_audit_write_failure_total"


# Duration histogram buckets tuned to stage budgets:
# sub-second buckets for deterministic stages (redact, detect, normalize,
# evaluate, score, validate, persist); up to 15 s for the model pass (infer).
_DURATION_BUCKETS = (
    0.010, 0.025, 0.050, 0.100, 0.250, 0.500,
    1.0, 2.0, 3.0, 5.0, 7.5, 10.0, 15.0, 30.0,
)

# Stage names — the accepted set for the ``stage`` label.
STAGE_NAMES = frozenset({
    "redact",
    "detect",
    "normalize",
    "evaluate",
    "score",
    "infer",
    "validate",
    "persist",
    # Legacy names present in the orchestrator before WO-048
    "yaml_parse",
    "audit",
})

# ---------------------------------------------------------------------------
# Registry singleton
# ---------------------------------------------------------------------------

_registry: Any = None
_histogram: Any = None
_findings_counter: Any = None
_inference_degraded_counter: Any = None
_unanchored_counter: Any = None
_authz_denied_counter: Any = None
_purge_deleted_counter: Any = None
_audit_failure_counter: Any = None


def _build_registry() -> Any:
    """Build and return a prometheus_client CollectorRegistry with all metrics.

    Returns ``None`` when prometheus_client is not installed.
    """
    global _registry, _histogram, _findings_counter
    global _inference_degraded_counter, _unanchored_counter
    global _authz_denied_counter, _purge_deleted_counter, _audit_failure_counter

    try:
        from prometheus_client import CollectorRegistry, Counter, Histogram
    except ImportError:
        return None

    reg = CollectorRegistry()

    _histogram = Histogram(
        METRIC_NAMES.ANALYSIS_DURATION_SECONDS,
        "Duration of each analysis pipeline stage in seconds.",
        labelnames=["format", "stage"],
        buckets=_DURATION_BUCKETS,
        registry=reg,
    )
    _findings_counter = Counter(
        METRIC_NAMES.FINDINGS_TOTAL,
        "Total findings produced by the analysis pipeline.",
        labelnames=["category", "severity", "source"],
        registry=reg,
    )
    _inference_degraded_counter = Counter(
        METRIC_NAMES.INFERENCE_DEGRADED_TOTAL,
        "Total inference calls that returned a degraded result.",
        labelnames=["reason"],
        registry=reg,
    )
    _unanchored_counter = Counter(
        METRIC_NAMES.UNANCHORED_SUPPRESSED_TOTAL,
        "Total findings suppressed due to missing anchor.",
        registry=reg,
    )
    _authz_denied_counter = Counter(
        METRIC_NAMES.AUTHZ_DENIED_TOTAL,
        "Total authorization denials.",
        labelnames=["capability"],
        registry=reg,
    )
    _purge_deleted_counter = Counter(
        METRIC_NAMES.PURGE_DELETED_TOTAL,
        "Total pipeline definitions deleted by the purge worker.",
        registry=reg,
    )
    _audit_failure_counter = Counter(
        METRIC_NAMES.AUDIT_WRITE_FAILURE_TOTAL,
        "Total failures writing to the audit log.",
        registry=reg,
    )

    _registry = reg
    return reg


def get_registry() -> Any:
    """Return the shared Prometheus CollectorRegistry, building it once.

    Returns ``None`` when prometheus_client is not installed.
    """
    global _registry
    if _registry is None:
        _build_registry()
    return _registry


def observe_stage_duration(
    format_label: str,
    stage: str,
    duration_seconds: float,
) -> None:
    """Record one histogram observation for *stage* taking *duration_seconds*.

    No-op when prometheus_client is not installed.
    Silently ignores unknown stages so instrumented code never raises.
    """
    get_registry()
    if _histogram is None:
        return
    try:
        _histogram.labels(format=format_label, stage=stage).observe(duration_seconds)
    except Exception:
        pass


def increment_inference_degraded(reason: str) -> None:
    """Increment pipelineshield_inference_degraded_total for *reason*."""
    get_registry()
    if _inference_degraded_counter is None:
        return
    try:
        _inference_degraded_counter.labels(reason=reason).inc()
    except Exception:
        pass


def increment_findings(category: str, severity: str, source: str) -> None:
    """Increment pipelineshield_findings_total."""
    get_registry()
    if _findings_counter is None:
        return
    try:
        _findings_counter.labels(category=category, severity=severity, source=source).inc()
    except Exception:
        pass


def increment_unanchored_suppressed() -> None:
    """Increment pipelineshield_unanchored_suppressed_total."""
    get_registry()
    if _unanchored_counter is None:
        return
    try:
        _unanchored_counter.inc()
    except Exception:
        pass


def increment_authz_denied(capability: str) -> None:
    """Increment pipelineshield_authz_denied_total."""
    get_registry()
    if _authz_denied_counter is None:
        return
    try:
        _authz_denied_counter.labels(capability=capability).inc()
    except Exception:
        pass


def reset_registry_for_testing() -> None:
    """Reset the singleton so tests can build an isolated registry.

    ONLY call this from test fixtures — never from application code.
    """
    global _registry, _histogram, _findings_counter
    global _inference_degraded_counter, _unanchored_counter
    global _authz_denied_counter, _purge_deleted_counter, _audit_failure_counter

    _registry = None
    _histogram = None
    _findings_counter = None
    _inference_degraded_counter = None
    _unanchored_counter = None
    _authz_denied_counter = None
    _purge_deleted_counter = None
    _audit_failure_counter = None
