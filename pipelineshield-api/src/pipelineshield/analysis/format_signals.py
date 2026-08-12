"""Weighted format signal definitions for CI/CD format detection.

Each FormatSignal is an immutable (name, format, weight, predicate) record.
Signals are declared as a top-level constant SIGNALS so callers can iterate,
inspect, and test them independently of the detect() function.

Signal types
------------
content_pattern : compiled regex applied to the full text
filename_substring : case-insensitive substring matched against the filename

A signal fires when its predicate matches. Signals apply only to their
declared format; cross-format penalties are applied separately in detect().

No FastAPI, no SQLAlchemy — verified by the import-graph assertion test.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

__all__ = ["FormatSignal", "SIGNALS"]

# ---------------------------------------------------------------------------
# Compiled patterns — GitHub Actions
# ---------------------------------------------------------------------------

_RE_GHA_ON = re.compile(r"^\s*on\s*:", re.MULTILINE)
_RE_GHA_JOBS = re.compile(r"^\s*jobs\s*:", re.MULTILINE)
_RE_GHA_STEPS = re.compile(r"^\s*steps\s*:", re.MULTILINE)
_RE_GHA_USES = re.compile(r"^\s*-\s+uses\s*:", re.MULTILINE)
_RE_GHA_RUNS_ON = re.compile(r"runs-on\s*:", re.MULTILINE)

# ---------------------------------------------------------------------------
# Compiled patterns — GitLab CI
# ---------------------------------------------------------------------------

_RE_GL_STAGES = re.compile(r"^\s*stages\s*:", re.MULTILINE)
_RE_GL_SCRIPT = re.compile(r"^\s+script\s*:", re.MULTILINE)
# Job-shape: a non-keyword top-level key followed by indented content (job definition)
_RE_GL_JOB_SHAPE = re.compile(
    r"^(?!stages:|image:|include:|workflow:|variables:|default:)[a-zA-Z_][a-zA-Z0-9_\-]*\s*:\s*\n[ \t]+",
    re.MULTILINE,
)
_RE_GL_IMAGE = re.compile(r"^\s*image\s*:", re.MULTILINE)
_RE_GL_INCLUDE = re.compile(r"^\s*include\s*:", re.MULTILINE)
_RE_GL_RULES = re.compile(r"^\s+rules\s*:", re.MULTILINE)

# ---------------------------------------------------------------------------
# Compiled patterns — Jenkins
# ---------------------------------------------------------------------------

_RE_JK_PIPELINE = re.compile(r"\bpipeline\s*\{", re.MULTILINE)
_RE_JK_AGENT = re.compile(r"^\s+agent\s+", re.MULTILINE)
_RE_JK_STAGES = re.compile(r"^\s+stages\s*\{", re.MULTILINE)
_RE_JK_STAGE = re.compile(r"^\s+stage\s*\(", re.MULTILINE)
_RE_JK_NODE = re.compile(r"\bnode\s*[\(\{]", re.MULTILINE)


# ---------------------------------------------------------------------------
# Signal model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FormatSignal:
    """An immutable, weighted predicate for one CI/CD format heuristic.

    Parameters
    ----------
    name:
        Unique dot-separated identifier (e.g. ``gha.jobs_key``).  Matched
        signal names are returned in ``FormatVerdict.signals`` so the scoring
        decision is fully inspectable.
    format:
        Target format string: ``"github_actions"``, ``"gitlab_ci"``, or
        ``"jenkins"``.
    weight:
        Contribution to the raw confidence score when the signal fires.
        Content signals for each format sum to 1.0 so a fully-matched
        definition reaches maximum confidence from content alone.
    content_pattern:
        Pre-compiled ``re.Pattern`` evaluated against the full definition
        text.  Exactly one of ``content_pattern`` or ``filename_substring``
        must be set.
    filename_substring:
        Case-insensitive substring matched against the lowercased filename.
    """

    name: str
    format: str
    weight: float
    content_pattern: Optional[re.Pattern] = field(default=None, compare=False, hash=False)  # type: ignore[type-arg]
    filename_substring: Optional[str] = None

    def matches(self, text: str, filename_lower: str) -> bool:
        """Return True if the signal fires for *text* / *filename_lower*."""
        if self.content_pattern is not None:
            return bool(self.content_pattern.search(text))
        if self.filename_substring is not None:
            return self.filename_substring in filename_lower
        return False  # misconfigured signal — never fires


# ---------------------------------------------------------------------------
# Signal registry
# ---------------------------------------------------------------------------

SIGNALS: tuple[FormatSignal, ...] = (
    # ---- GitHub Actions (content weights sum to 1.0) ---------------------
    FormatSignal("gha.on_key",      "github_actions", 0.25, content_pattern=_RE_GHA_ON),
    FormatSignal("gha.jobs_key",    "github_actions", 0.35, content_pattern=_RE_GHA_JOBS),
    FormatSignal("gha.steps_key",   "github_actions", 0.20, content_pattern=_RE_GHA_STEPS),
    FormatSignal("gha.uses_key",    "github_actions", 0.15, content_pattern=_RE_GHA_USES),
    FormatSignal("gha.runs_on",     "github_actions", 0.05, content_pattern=_RE_GHA_RUNS_ON),
    # Filename bonus — a .github/workflows path strongly implies GHA
    FormatSignal("gha.path",        "github_actions", 0.30, filename_substring=".github"),

    # ---- GitLab CI (content weights sum to 1.0) --------------------------
    FormatSignal("gl.stages_key",   "gitlab_ci", 0.25, content_pattern=_RE_GL_STAGES),
    FormatSignal("gl.script_key",   "gitlab_ci", 0.30, content_pattern=_RE_GL_SCRIPT),
    # Job-shape: top-level non-keyword key followed by indented content
    FormatSignal("gl.job_shape",    "gitlab_ci", 0.20, content_pattern=_RE_GL_JOB_SHAPE),
    FormatSignal("gl.image_key",    "gitlab_ci", 0.10, content_pattern=_RE_GL_IMAGE),
    FormatSignal("gl.include_key",  "gitlab_ci", 0.10, content_pattern=_RE_GL_INCLUDE),
    FormatSignal("gl.rules_key",    "gitlab_ci", 0.05, content_pattern=_RE_GL_RULES),
    # Filename bonus — .gitlab-ci.yml is definitive
    FormatSignal("gl.filename",     "gitlab_ci", 0.30, filename_substring=".gitlab-ci"),

    # ---- Jenkins Declarative (content weights sum to 1.0) ----------------
    FormatSignal("jk.pipeline_block", "jenkins", 0.35, content_pattern=_RE_JK_PIPELINE),
    FormatSignal("jk.agent",          "jenkins", 0.15, content_pattern=_RE_JK_AGENT),
    FormatSignal("jk.stages_block",   "jenkins", 0.10, content_pattern=_RE_JK_STAGES),
    FormatSignal("jk.stage_call",     "jenkins", 0.10, content_pattern=_RE_JK_STAGE),
    # Scripted Jenkins alternative (node { ... }) — scores lower than declarative
    # A scripted Jenkinsfile without pipeline { can reach only ~0.50 from content,
    # requiring confirmation unless named "Jenkinsfile" (+0.30).
    FormatSignal("jk.node_block",     "jenkins", 0.30, content_pattern=_RE_JK_NODE),
    # Filename bonus — "Jenkinsfile" is conventional
    FormatSignal("jk.jenkinsfile",    "jenkins", 0.30, filename_substring="jenkinsfile"),
)
