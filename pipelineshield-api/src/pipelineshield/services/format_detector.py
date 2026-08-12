"""Pipeline format detector.

Heuristic detection returning (PipelineFormat, confidence) where confidence
is a float in [0.0, 1.0].  The detector is framework-free and may not import
HTTP or database modules.

Format signals
--------------
github_actions : ``on:`` + ``jobs:`` + (``steps:`` or ``uses:``)
gitlab_ci      : ``stages:`` + ``script:`` + no top-level ``jobs:``
jenkins        : ``pipeline {`` + (``agent`` or ``stages {``)
"""
from __future__ import annotations

import re
from typing import Optional

from pipelineshield.api.v1.schemas.analysis import PipelineFormat

__all__ = ["FormatDetector", "FormatDetection"]

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


class FormatDetection:
    __slots__ = ("format", "confidence")

    def __init__(self, format: PipelineFormat, confidence: float) -> None:
        self.format = format
        self.confidence = max(0.0, min(1.0, confidence))


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# GitHub Actions
_GHA_ON = re.compile(r"^\s*on\s*:", re.MULTILINE)
_GHA_JOBS = re.compile(r"^\s*jobs\s*:", re.MULTILINE)
_GHA_STEPS = re.compile(r"^\s*steps\s*:", re.MULTILINE)
_GHA_USES = re.compile(r"^\s*-\s+uses\s*:", re.MULTILINE)
_GHA_RUNS_ON = re.compile(r"runs-on\s*:", re.MULTILINE)

# GitLab CI
_GL_STAGES = re.compile(r"^\s*stages\s*:", re.MULTILINE)
_GL_SCRIPT = re.compile(r"^\s+script\s*:", re.MULTILINE)
_GL_IMAGE = re.compile(r"^\s*image\s*:", re.MULTILINE)
_GL_INCLUDE = re.compile(r"^\s*include\s*:", re.MULTILINE)
_GL_RULES = re.compile(r"^\s+rules\s*:", re.MULTILINE)

# Jenkins Declarative
_JK_PIPELINE = re.compile(r"pipeline\s*\{", re.MULTILINE)
_JK_AGENT = re.compile(r"^\s+agent\s+", re.MULTILINE)
_JK_STAGES = re.compile(r"^\s+stages\s*\{", re.MULTILINE)
_JK_STAGE = re.compile(r"^\s+stage\s*\(", re.MULTILINE)


def _score_gha(text: str) -> float:
    score = 0.0
    if _GHA_ON.search(text):
        score += 0.25
    if _GHA_JOBS.search(text):
        score += 0.35
    if _GHA_STEPS.search(text):
        score += 0.20
    if _GHA_USES.search(text):
        score += 0.15
    if _GHA_RUNS_ON.search(text):
        score += 0.05
    return score


def _score_gitlab(text: str) -> float:
    score = 0.0
    if _GL_STAGES.search(text):
        score += 0.35
    if _GL_SCRIPT.search(text):
        score += 0.30
    if _GL_IMAGE.search(text):
        score += 0.15
    if _GL_INCLUDE.search(text):
        score += 0.10
    if _GL_RULES.search(text):
        score += 0.10
    # Penalise if top-level `jobs:` is present (that's GitHub Actions)
    if _GHA_JOBS.search(text):
        score -= 0.30
    return max(0.0, score)


def _score_jenkins(text: str) -> float:
    score = 0.0
    if _JK_PIPELINE.search(text):
        score += 0.50
    if _JK_AGENT.search(text):
        score += 0.20
    if _JK_STAGES.search(text):
        score += 0.15
    if _JK_STAGE.search(text):
        score += 0.15
    return score


class FormatDetector:
    """Stateless pipeline format heuristic detector."""

    def detect(
        self,
        content: str,
        filename: Optional[str] = None,
    ) -> FormatDetection:
        """Return the best-guess format and confidence.

        *filename* is used as a tie-breaker when scores are close.
        """
        # Filename-based boosts
        filename_lower = (filename or "").lower()

        gha_score = _score_gha(content)
        gl_score = _score_gitlab(content)
        jk_score = _score_jenkins(content)

        # Filename strong signals
        if "github" in filename_lower or ".github" in filename_lower:
            gha_score = min(1.0, gha_score + 0.30)
        if "gitlab" in filename_lower or ".gitlab-ci" in filename_lower:
            gl_score = min(1.0, gl_score + 0.30)
        if "jenkinsfile" in filename_lower:
            jk_score = min(1.0, jk_score + 0.30)

        scores = {
            PipelineFormat.github_actions: gha_score,
            PipelineFormat.gitlab_ci: gl_score,
            PipelineFormat.jenkins: jk_score,
        }

        best_format = max(scores, key=lambda k: scores[k])
        best_score = scores[best_format]

        # Clamp to [0.05, 1.0]; a totally ambiguous file still gets 0.05
        confidence = max(0.05, min(1.0, best_score))

        return FormatDetection(format=best_format, confidence=confidence)
