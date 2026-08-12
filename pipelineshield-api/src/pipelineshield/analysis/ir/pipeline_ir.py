"""Versioned PipelineIR — the single intermediate representation contract.

Design principles:
  - Frozen Pydantic v2 models: once produced, an IR is immutable.
  - Additive-only versioning: new optional fields may be added; existing
    fields are never removed or renamed without a version bump.
  - Rules must read via accessors.py, never raw dict keys.
  - No FastAPI, SQLAlchemy, HTTP, or database imports — pure Python.

IR version history:
  1.0  Initial release (WO-006).
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "IR_VERSION",
    "Anchor",
    "ActionRef",
    "CoverageReport",
    "EffectivePermissions",
    "Job",
    "PipelineIR",
    "SecretRef",
    "Step",
    "UnresolvedFragment",
]

IR_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Source anchor — maps every IR node back to its origin in the raw YAML
# ---------------------------------------------------------------------------


class Anchor(BaseModel):
    """Source-location anchor: 1-based line/column in the original YAML."""

    model_config = ConfigDict(frozen=True)

    start_line: int = Field(ge=1)
    start_column: int = Field(ge=1)
    end_line: int | None = None


# ---------------------------------------------------------------------------
# Coverage reporting
# ---------------------------------------------------------------------------


class UnresolvedFragment(BaseModel):
    """A construct that could not be assessed locally.

    Recorded in CoverageReport.unresolved instead of being silently dropped
    or incorrectly assumed assessable.

    kind values:
      composite_action     — local or remote composite action (uses: ./path or owner/repo)
      reusable_workflow    — external reusable workflow (jobs.<id>.uses: …)
      matrix_dynamic       — matrix with non-enumerable expressions
    """

    model_config = ConfigDict(frozen=True)

    kind: str
    locator: str
    reason: str


class CoverageReport(BaseModel):
    """Per-normalization coverage accounting.

    unresolved:           constructs that were encountered but not assessable locally.
    constructs_handled:   list of construct types the normalizer processed.
    constructs_excluded:  list of construct types present in the source but
                          intentionally excluded from this normalizer version.
    coverage_ratio:       fraction of detected constructs that are assessable
                          (assessable / total_detected).  None when not computed
                          (GitHub Actions, GitLab CI).  0.0 for fully-scripted
                          Jenkins files; 1.0 when no Not Assessable constructs
                          were found.  Used by the scoring engine to exclude
                          Not Assessable content from the denominator (E3).
    """

    model_config = ConfigDict(frozen=True)

    unresolved: list[UnresolvedFragment] = Field(default_factory=list)
    constructs_handled: list[str] = Field(default_factory=list)
    constructs_excluded: list[str] = Field(default_factory=list)
    coverage_ratio: float | None = None


# ---------------------------------------------------------------------------
# Action and secret references
# ---------------------------------------------------------------------------


class ActionRef(BaseModel):
    """A parsed reference to a third-party (or local/docker) action.

    pin_form values:
      sha     — 40-hex immutable commit SHA (most secure)
      tag     — semver or arbitrary tag (mutable pointer)
      branch  — branch name (mutable, HEAD-tracking)
      local   — ./relative-path to a local composite action
      docker  — docker:// image reference
    """

    model_config = ConfigDict(frozen=True)

    name: str
    version_ref: str | None = None
    pin_form: str
    anchor: Anchor | None = None


class SecretRef(BaseModel):
    """A reference to a secret-shaped value within a workflow expression.

    source values:
      secrets    — ${{ secrets.NAME }}
      env        — ${{ env.NAME }} (may carry a secret via env passthrough)
      expression — other ${{ … }} forms (e.g. steps.id.outputs.*)
    """

    model_config = ConfigDict(frozen=True)

    name: str
    source: str
    expression: str | None = None
    anchor: Anchor | None = None


# ---------------------------------------------------------------------------
# Step
# ---------------------------------------------------------------------------


class Step(BaseModel):
    """A single step within a GitHub Actions job."""

    model_config = ConfigDict(frozen=True)

    id: str | None = None
    name: str | None = None
    uses: str | None = None
    run: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    with_inputs: dict[str, str] = Field(default_factory=dict)
    continue_on_error: bool = False
    anchor: Anchor | None = None
    action_ref: ActionRef | None = None
    secret_refs: list[SecretRef] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


class EffectivePermissions(BaseModel):
    """Permissions declaration with explicit semantic state.

    state values:
      absent     — key not present; GitHub applies its default token permissions.
      empty      — permissions: {} or permissions: null; no scopes granted.
      write_all  — permissions: write-all; all scopes writable.
      explicit   — permissions with named scope grants.

    scope values:
      workflow          — declared at the workflow level.
      job               — declared at the job level (overrides workflow for this job).
      workflow_inherited — job inherits from workflow (job had no declaration).
    """

    model_config = ConfigDict(frozen=True)

    scope: str
    state: str
    grants: dict[str, str] = Field(default_factory=dict)
    anchor: Anchor | None = None


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------


class Job(BaseModel):
    """A CI/CD job (GitHub Actions job, GitLab CI job, or Jenkins stage).

    extraction_metadata:  Optional dict carrying normalizer-specific provenance
                          information.  Jenkins sets:
                            {"extraction_method": "heuristic", "confidence": <float>}
                          GitHub Actions and GitLab CI leave this empty.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    name: str | None = None
    runs_on: str | list[str] | None = None
    steps: list[Step] = Field(default_factory=list)
    permissions: EffectivePermissions = Field(
        default_factory=lambda: EffectivePermissions(scope="job", state="absent")
    )
    needs: list[str] = Field(default_factory=list)
    condition: str | None = None
    matrix: dict[str, Any] | None = None
    anchor: Anchor | None = None
    extraction_metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Root PipelineIR
# ---------------------------------------------------------------------------


class PipelineIR(BaseModel):
    """Versioned intermediate representation of a CI/CD pipeline definition.

    Produced by a format-specific normalizer and validated by Pydantic
    before any rule may execute.  Rules read via accessors.py.

    Fields:
      ir_version:       semver string; consumers must assert compatibility.
      source_format:    "github_actions" | "gitlab_ci" | "jenkins".
      triggers:         de-duplicated sorted list of event names.
      trigger_details:  raw trigger configuration keyed by event name.
      permissions:      workflow-level permissions declaration.
      jobs:             ordered list of jobs in document order.
      coverage_report:  unresolved fragments and construct accounting.
      trigger_anchor:   location of the on: key in the source YAML.
    """

    model_config = ConfigDict(frozen=True)

    ir_version: str = IR_VERSION
    source_format: str
    triggers: list[str] = Field(default_factory=list)
    trigger_details: dict[str, Any] = Field(default_factory=dict)
    permissions: EffectivePermissions = Field(
        default_factory=lambda: EffectivePermissions(scope="workflow", state="absent")
    )
    jobs: list[Job] = Field(default_factory=list)
    coverage_report: CoverageReport = Field(default_factory=CoverageReport)
    trigger_anchor: Anchor | None = None
