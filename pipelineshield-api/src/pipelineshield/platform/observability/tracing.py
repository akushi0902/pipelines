"""OpenTelemetry stage_span context manager.

``stage_span`` is the single instrumentation point for every analysis stage.
It:
  1. Opens an OTel span named ``pipelineshield.stage.<name>``.
  2. Sets ``format`` and ``line_count`` attributes on the span.
  3. On exit, observes the duration into the Prometheus histogram via
     ``observe_stage_duration``.
  4. On exception, marks the span status ERROR and re-raises.

Cardinality guard:
  Only ``format`` and ``stage`` labels are set on metrics.  No analysis id,
  user id, workspace id, or definition content is attached to any span
  attribute or metric label.

Soft import:
  ``opentelemetry`` is optional.  When not installed, span operations are
  no-ops so the application starts without the SDK installed.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Generator

from .metrics import observe_stage_duration

# ---------------------------------------------------------------------------
# OTel soft import
# ---------------------------------------------------------------------------

try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.trace import StatusCode as _StatusCode

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False
    _otel_trace = None  # type: ignore[assignment]
    _StatusCode = None  # type: ignore[assignment]


# Span name prefix — constant so tests assert against the exact same string.
SPAN_NAME_PREFIX = "pipelineshield.stage."


def _get_tracer():  # type: ignore[no-untyped-def]
    """Return an OTel Tracer instance, or ``None`` when OTel is unavailable."""
    if not _OTEL_AVAILABLE:
        return None
    return _otel_trace.get_tracer("pipelineshield")  # type: ignore[union-attr]


@contextmanager
def stage_span(
    name: str,
    *,
    format: str = "unknown",
    line_count: int = 0,
    correlation_id: str | None = None,
) -> Generator[None, None, None]:
    """Context manager that instruments one analysis pipeline stage.

    Parameters
    ----------
    name:
        Stage name — one of the values in ``STAGE_NAMES``
        (e.g. ``"redact"``, ``"detect"``).
    format:
        Pipeline format label (``"github_actions"``, ``"gitlab_ci"``,
        ``"jenkins"``, or ``"unknown"``).  Used as a Prometheus label;
        must not contain definition content.
    line_count:
        Number of lines in the definition being processed.  Written as a
        span attribute only — not used as a metric label (unbounded).
    correlation_id:
        Optional request correlation id, attached as a span attribute for
        distributed-tracing correlation.

    Usage
    -----
    ::

        with stage_span("redact", format="github_actions", line_count=80):
            doc = redact(content)
    """
    tracer = _get_tracer()
    span_name = f"{SPAN_NAME_PREFIX}{name}"

    t_start = time.monotonic()
    span = None

    if tracer is not None:
        span = tracer.start_span(span_name)
        try:
            span.set_attribute("pipelineshield.stage", name)
            span.set_attribute("pipelineshield.format", format)
            span.set_attribute("pipelineshield.line_count", line_count)
            if correlation_id:
                span.set_attribute("pipelineshield.correlation_id", correlation_id)
        except Exception:
            pass

    try:
        yield
    except Exception as exc:
        if span is not None and _StatusCode is not None:
            try:
                span.set_status(_StatusCode.ERROR, str(type(exc).__name__))
            except Exception:
                pass
        raise
    finally:
        duration_s = time.monotonic() - t_start
        observe_stage_duration(format, name, duration_s)
        if span is not None:
            try:
                span.end()
            except Exception:
                pass
