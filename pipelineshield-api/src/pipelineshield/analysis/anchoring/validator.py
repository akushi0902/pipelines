"""AnchorValidator — single chokepoint between candidate findings and persistence.

All candidates (deterministic rule outcomes and LLM-proposed advisory candidates)
must pass through validate() before they reach FindingRepository.save_all().

Validation sequence per candidate:
  1. anchor present                  → missing_anchor
  2. line in bounds (≥ 1, ≤ total)   → out_of_range
  3. fragment not unresolved         → unresolved_fragment
  4. target line not blank           → blank_target_line
  5. fingerprint match (if supplied) → fingerprint_mismatch
  6. snippet extraction
  7. snippet secret-pattern re-scan  → snippet masked to [REDACTED:snippet_scan]

Only step 7 does not suppress: a finding with a masked snippet is still valid.
"""
from __future__ import annotations

import logging
from typing import Sequence

from pipelineshield.analysis.redaction_patterns import ORDERED_PATTERNS
from pipelineshield.analysis.rule_engine.protocol import MetricsEmitter, NullMetricsEmitter

from .models import (
    AnchorValidationConfigurationError,
    CandidateFinding,
    SuppressionReason,
    SuppressionRecord,
    SuppressionReport,
    ValidatedFinding,
)
from .redacted_document import RedactedDocument

_LOG = logging.getLogger(__name__)

_MAX_SNIPPET_CHARS = 200
_DEFAULT_CONTEXT_LINES = 0


def _contains_secret(text: str) -> bool:
    for pattern in ORDERED_PATTERNS:
        if pattern.regex.search(text):
            return True
    return False


class AnchorValidator:
    """Validates candidate findings and produces ValidatedFinding objects.

    Inject a MetricsEmitter to receive:
      findings_validated_total  — labelled: source
      findings_suppressed_total — labelled: source, reason

    A structured WARN log is emitted per suppression with analysis_id, source,
    reason, rule_id, and control_id but no definition content.
    """

    def __init__(
        self,
        metrics: MetricsEmitter | None = None,
        context_lines: int = _DEFAULT_CONTEXT_LINES,
        analysis_id: str = "",
    ) -> None:
        self._metrics = metrics or NullMetricsEmitter()
        self._context_lines = context_lines
        self._analysis_id = analysis_id

    def validate(
        self,
        candidates: Sequence[CandidateFinding],
        redacted_document: RedactedDocument,
    ) -> tuple[list[ValidatedFinding], SuppressionReport]:
        """Validate *candidates* against *redacted_document*.

        Returns:
            (accepted, report) where accepted contains only ValidatedFinding
            instances that passed all checks, and report records every suppression
            with its reason code.

        Raises:
            AnchorValidationConfigurationError if redacted_document.is_normalized
            is False — analysis is failed closed rather than scoring unanchored.
        """
        if not redacted_document.is_normalized:
            raise AnchorValidationConfigurationError(
                "RedactedDocument is not normalized (CRLF not collapsed to LF). "
                "Use build_redacted_document() to construct it."
            )

        accepted: list[ValidatedFinding] = []
        report = SuppressionReport()

        for candidate in candidates:
            result = self._validate_one(candidate, redacted_document, report)
            if result is not None:
                accepted.append(result)
                self._metrics.increment(
                    "findings_validated_total",
                    {"source": candidate.source},
                )

        return accepted, report

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_one(
        self,
        candidate: CandidateFinding,
        doc: RedactedDocument,
        report: SuppressionReport,
    ) -> ValidatedFinding | None:
        def suppress(reason: SuppressionReason, detail: str = "") -> None:
            report.suppressions.append(
                SuppressionRecord(
                    rule_id=candidate.rule_id,
                    control_id=candidate.control_id,
                    source=candidate.source,
                    reason=reason,
                    analysis_id=self._analysis_id,
                    detail=detail,
                )
            )
            self._metrics.increment(
                "findings_suppressed_total",
                {"source": candidate.source, "reason": reason.value},
            )
            _LOG.warning(
                "Finding suppressed by anchor validator",
                extra={
                    "analysis_id": self._analysis_id,
                    "source": candidate.source,
                    "reason": reason.value,
                    "rule_id": candidate.rule_id,
                    "control_id": candidate.control_id,
                },
            )

        # Step 1 — anchor present
        if candidate.anchor is None:
            suppress(SuppressionReason.MISSING_ANCHOR)
            return None

        anchor = candidate.anchor
        line_no = anchor.start_line

        # Step 2 — line within bounds
        if line_no < 1 or line_no > doc.total_lines:
            suppress(
                SuppressionReason.OUT_OF_RANGE,
                f"start_line={line_no} outside [1..{doc.total_lines}]",
            )
            return None

        # Step 3 — fragment not unresolved
        resolution = doc.resolution_status_for_line(line_no)
        if resolution == "unresolved":
            suppress(
                SuppressionReason.UNRESOLVED_FRAGMENT,
                f"line {line_no} is inside an unresolved fragment",
            )
            return None

        # Step 4 — target line not blank
        line = doc.get_line(line_no)
        assert line is not None  # bounds checked above
        if not line.content.strip():
            suppress(SuppressionReason.BLANK_TARGET_LINE, f"line {line_no} is blank")
            return None

        # Step 5 — fingerprint match (only when candidate recorded one)
        if candidate.line_fingerprint is not None:
            if candidate.line_fingerprint != line.fingerprint:
                suppress(
                    SuppressionReason.FINGERPRINT_MISMATCH,
                    f"fingerprint mismatch at line {line_no}",
                )
                return None

        # Step 6 — extract snippet
        snippet = self._extract_snippet(doc, line_no)

        # Step 7 — secret-pattern re-scan (defense-in-depth)
        if _contains_secret(snippet):
            snippet = "[REDACTED:snippet_scan]"

        return ValidatedFinding(
            rule_id=candidate.rule_id,
            control_id=candidate.control_id,
            category=candidate.category,
            source=candidate.source,
            severity=candidate.severity,
            title=candidate.title,
            description=candidate.description,
            evidence=dict(candidate.evidence),
            analysis_id=candidate.analysis_id,
            workspace_id=candidate.workspace_id,
            anchor_line=anchor.start_line,
            anchor_column=anchor.start_column,
            snippet=snippet,
            weight=candidate.weight,
            requires_human_review=candidate.requires_human_review,
        )

    def _extract_snippet(self, doc: RedactedDocument, line_no: int) -> str:
        start = max(1, line_no - self._context_lines)
        end = min(doc.total_lines, line_no + self._context_lines)
        lines: list[str] = []
        for n in range(start, end + 1):
            ln = doc.get_line(n)
            if ln is not None:
                lines.append(ln.content)
        snippet = "\n".join(lines)
        if len(snippet) > _MAX_SNIPPET_CHARS:
            snippet = snippet[:_MAX_SNIPPET_CHARS]
        return snippet
