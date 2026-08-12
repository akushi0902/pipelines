"""Pure CI/CD format detector.

Entry point
-----------
    from pipelineshield.analysis.format_detector import detect, CONFIDENCE_THRESHOLD

    verdict = detect(text, filename=".github/workflows/ci.yml")
    if verdict.confirmation_required:
        # Surface the confirmation UI
        ...

Design
------
Detection is a two-pass weighted score over the SIGNALS registry in
format_signals.py, followed by cross-format penalty adjustment for cases
where one format's signals conflict with another.

Signal weights are calibrated so that a fully-matched definition of any
supported format reaches a raw score of 1.0 from content signals alone;
filename bonuses push the confidence higher when a canonical filename is
present.

A result with best raw score < 0.05 (no meaningful evidence for any format)
is classified as ``"unknown"`` with confidence 0.0 and always requires
confirmation.

No FastAPI, no SQLAlchemy — verified by the import-graph assertion test.
"""
from __future__ import annotations

import time
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, computed_field

from pipelineshield.analysis.format_signals import SIGNALS, FormatSignal

__all__ = ["FormatVerdict", "detect", "CONFIDENCE_THRESHOLD"]

# ---------------------------------------------------------------------------
# Named threshold constant (single definition site reused everywhere)
# ---------------------------------------------------------------------------

#: Confidence score at or above which the platform accepts the detected format
#: without requiring user confirmation.  Fixed at 0.8.
CONFIDENCE_THRESHOLD: float = 0.8

#: Raw-score floor for a "real" detection.  Below this all formats are near-zero
#: and the submission is classified as ``"unknown"``.
_UNKNOWN_FLOOR: float = 0.05


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


class FormatVerdict(BaseModel):
    """Immutable result of one format-detection pass.

    Attributes
    ----------
    format:
        Best-match format string: ``"github_actions"``, ``"gitlab_ci"``,
        ``"jenkins"``, or ``"unknown"`` when no format scores above the
        noise floor.
    confidence:
        Normalised confidence in [0.0, 1.0].  Scores above
        ``CONFIDENCE_THRESHOLD`` (0.8) route directly to the normalizer;
        scores below require user confirmation.
    signals:
        Ordered list of signal names that contributed to the winning score,
        highest-weight first.  Empty for ``"unknown"`` verdicts.
    """

    model_config = ConfigDict(frozen=True)

    format: str
    confidence: float = Field(ge=0.0, le=1.0)
    signals: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confirmation_required(self) -> bool:
        """True when confidence is below CONFIDENCE_THRESHOLD."""
        return self.confidence < CONFIDENCE_THRESHOLD


# ---------------------------------------------------------------------------
# Core detection function
# ---------------------------------------------------------------------------


def detect(text: str, filename: Optional[str] = None) -> FormatVerdict:
    """Classify *text* as a CI/CD pipeline definition format.

    Parameters
    ----------
    text:
        Full text of the pipeline definition. The detector operates on
        masked text produced by the WO-002 redactor.
    filename:
        Optional original filename or path. Filename signals may boost
        or disambiguate the score.

    Returns
    -------
    FormatVerdict
        Immutable result with format, confidence, signals, and
        confirmation_required.
    """
    filename_lower = (filename or "").lower()

    # Kubernetes manifests are not CI/CD pipeline definitions.
    # Their generic YAML structure can otherwise trigger GitLab heuristics.
    kubernetes_manifest = (
        any(
            line.strip().startswith("apiVersion:")
            for line in text.splitlines()
        )
        and any(
            line.strip().startswith("kind:")
            for line in text.splitlines()
        )
    )

    if kubernetes_manifest:
        return FormatVerdict(
            format="unknown",
            confidence=0.0,
            signals=[],
        )

    # ------------------------------------------------------------------
    # Pass 1: accumulate raw scores and matched signal names per format
    # ------------------------------------------------------------------
    scores: dict[str, float] = {
        "github_actions": 0.0,
        "gitlab_ci": 0.0,
        "jenkins": 0.0,
    }

    matched_signals: dict[str, list[FormatSignal]] = {
        "github_actions": [],
        "gitlab_ci": [],
        "jenkins": [],
    }

    for signal in SIGNALS:
        if signal.matches(text, filename_lower):
            scores[signal.format] += signal.weight
            matched_signals[signal.format].append(signal)

    # ------------------------------------------------------------------
    # Pass 2: cross-format penalty adjustments
    # ------------------------------------------------------------------

    # A top-level `jobs:` key is the canonical GHA top-level key;
    # its presence is strong evidence against GitLab CI.
    if any(
        s.name == "gha.jobs_key"
        for s in matched_signals["github_actions"]
    ):
        scores["gitlab_ci"] = max(
            0.0,
            scores["gitlab_ci"] - 0.30,
        )

    # A `pipeline {` block is exclusive to Jenkins declarative;
    # penalise the other two formats.
    if any(
        s.name == "jk.pipeline_block"
        for s in matched_signals["jenkins"]
    ):
        scores["github_actions"] = max(
            0.0,
            scores["github_actions"] - 0.30,
        )
        scores["gitlab_ci"] = max(
            0.0,
            scores["gitlab_ci"] - 0.30,
        )

    # Conflicting filename evidence: if the path says GitLab but content
    # shows strong GHA signals, reduce the GitLab filename bonus.
    if "gl.filename" in {
        s.name for s in matched_signals["gitlab_ci"]
    }:
        gha_content_score = sum(
            s.weight
            for s in matched_signals["github_actions"]
            if s.filename_substring is None
        )

        gl_content_score = sum(
            s.weight
            for s in matched_signals["gitlab_ci"]
            if s.filename_substring is None
        )

        if gha_content_score - gl_content_score > 0.30:
            scores["gitlab_ci"] = max(
                0.0,
                scores["gitlab_ci"] - 0.30,
            )

    # ------------------------------------------------------------------
    # Pass 3: clamp, rank, decide
    # ------------------------------------------------------------------
    for fmt in scores:
        scores[fmt] = min(1.0, scores[fmt])

    best_format = max(scores, key=lambda k: scores[k])
    best_score = scores[best_format]

    if best_score < _UNKNOWN_FLOOR:
        return FormatVerdict(
            format="unknown",
            confidence=0.0,
            signals=[],
        )

    # Build ordered signals list for the winning format.
    winning_signals = sorted(
        matched_signals[best_format],
        key=lambda s: s.weight,
        reverse=True,
    )

    return FormatVerdict(
        format=best_format,
        confidence=min(1.0, best_score),
        signals=[s.name for s in winning_signals],
    )

