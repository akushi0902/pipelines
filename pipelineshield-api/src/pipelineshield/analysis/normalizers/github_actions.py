"""GitHub Actions normalizer — converts GHA workflow YAML into PipelineIR.

Design invariants:
  - Never makes outbound HTTP requests.  Composite and reusable workflow
    references that require external resolution are appended to
    coverage_report.unresolved with kind and reason, never guessed.
  - YAML is loaded via yaml_loader.load_yaml() (YAML 1.2 + alias guard).
  - Every Job, Step, ActionRef and EffectivePermissions node carries an
    Anchor so findings can cite exact source lines.
  - Three trigger forms are handled: scalar, list, and mapping.
  - Three permissions states are distinguished: absent, empty, write_all, explicit.
  - Matrix strategies are expanded when statically enumerable; otherwise
    recorded as unresolved/matrix_dynamic.
  - No FastAPI, SQLAlchemy, or HTTP imports — verified by the egress test.
"""
from __future__ import annotations

import re
from typing import Any

from ruamel.yaml.comments import CommentedMap, CommentedSeq  # type: ignore[import-untyped]

from pipelineshield.analysis.ir.pipeline_ir import (
    ActionRef,
    Anchor,
    CoverageReport,
    EffectivePermissions,
    IR_VERSION,
    Job,
    PipelineIR,
    SecretRef,
    Step,
    UnresolvedFragment,
)
from pipelineshield.analysis.yaml_loader import (
    NormalizationError,
    item_anchor,
    key_anchor,
    load_yaml,
    node_anchor,
)
from pipelineshield.services.normalizer_registry import NormalizationResult, Normalizer

__all__ = ["GitHubActionsNormalizer"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# A reusable workflow reference contains /.github/workflows/ in the path part
_REUSABLE_WF_RE = re.compile(r"[^@]+/\.github/workflows/[^@]+@.+")

# 40-character hex SHA (plus longer hashes in the future)
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40,}$")

# semver-ish tag: v1, v1.2, v1.2.3, 1.0.0, 1.0.0-rc.1
_TAG_RE = re.compile(r"^v?\d+(\.\d+)*(-[\w.]+)?$")

# YAML expression: ${{ ... }}
_EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")

# Dynamic matrix expression (contains ${{ ... }} or fromJson)
_DYNAMIC_EXPR_RE = re.compile(r"\$\{\{|fromJson\s*\(", re.IGNORECASE)

# Sentinel for "key not present" (distinct from None value)
_ABSENT = object()

# Constructs this normalizer version handles
_HANDLED_CONSTRUCTS = [
    "triggers",
    "workflow_permissions",
    "jobs",
    "job_permissions",
    "steps",
    "action_refs",
    "secret_refs",
    "matrix_static",
    "needs",
]

_EXCLUDED_CONSTRUCTS: list[str] = [
    "concurrency",
    "environment",
    "outputs",
    "defaults",
    "services",
    "container",
]


# ---------------------------------------------------------------------------
# Public normalizer class
# ---------------------------------------------------------------------------


class GitHubActionsNormalizer(Normalizer):
    """Normalizer for GitHub Actions workflow YAML.

    Registered in NormalizerRegistry for the github_actions format.
    """

    def normalize(self, content: str) -> NormalizationResult:
        """Normalize a GitHub Actions workflow definition.

        Parameters
        ----------
        content:
            Redacted workflow YAML text.

        Returns
        -------
        NormalizationResult
            Contains the validated PipelineIR and a summary coverage report.

        Raises
        ------
        NormalizationError
            On YAML syntax errors or anchor bomb detection.
        """
        doc = load_yaml(content)

        if doc is None:
            # Empty document — return minimal valid IR
            ir = PipelineIR(source_format="github_actions")
            return _make_result(ir, content)

        if not isinstance(doc, (CommentedMap, dict)):
            raise NormalizationError(
                "GitHub Actions workflow must be a YAML mapping at document root.",
                constraint="root_must_be_mapping",
            )

        unresolved: list[UnresolvedFragment] = []

        # ----------------------------------------------------------------
        # 1. Triggers
        # ----------------------------------------------------------------
        triggers, trigger_details, trigger_anchor = _extract_triggers(doc)

        # ----------------------------------------------------------------
        # 2. Workflow-level permissions
        # ----------------------------------------------------------------
        workflow_perms = _extract_permissions(doc, scope="workflow")

        # ----------------------------------------------------------------
        # 3. Jobs
        # ----------------------------------------------------------------
        jobs = _extract_jobs(doc, workflow_perms, unresolved)

        # ----------------------------------------------------------------
        # 4. Assemble IR
        # ----------------------------------------------------------------
        ir = PipelineIR(
            ir_version=IR_VERSION,
            source_format="github_actions",
            triggers=triggers,
            trigger_details=trigger_details,
            permissions=workflow_perms,
            jobs=jobs,
            coverage_report=CoverageReport(
                unresolved=unresolved,
                constructs_handled=list(_HANDLED_CONSTRUCTS),
                constructs_excluded=list(_EXCLUDED_CONSTRUCTS),
            ),
            trigger_anchor=trigger_anchor,
        )

        return _make_result(ir, content)


# ---------------------------------------------------------------------------
# Trigger extraction
# ---------------------------------------------------------------------------


def _extract_triggers(
    doc: CommentedMap,
) -> tuple[list[str], dict[str, Any], Anchor | None]:
    """Extract event triggers from the ``on:`` key.

    Handles three forms:
      scalar:  on: push
      list:    on: [push, pull_request]
      mapping: on:\n  push:\n    branches: [main]
    """
    trigger_anchor = key_anchor(doc, "on")
    on_val = doc.get("on", _ABSENT)

    if on_val is _ABSENT:
        return [], {}, None

    triggers: list[str] = []
    trigger_details: dict[str, Any] = {}

    if isinstance(on_val, str):
        triggers = [on_val]
        trigger_details = {on_val: {}}

    elif isinstance(on_val, (list, CommentedSeq)):
        for item in on_val:
            t = str(item)
            triggers.append(t)
            trigger_details[t] = {}

    elif isinstance(on_val, (dict, CommentedMap)):
        for key in on_val:
            t = str(key)
            triggers.append(t)
            val = on_val[key]
            if val is None:
                trigger_details[t] = {}
            elif isinstance(val, (dict, CommentedMap)):
                trigger_details[t] = _coerce_to_plain(val)
            elif isinstance(val, (list, CommentedSeq)):
                trigger_details[t] = [str(x) for x in val]
            else:
                trigger_details[t] = str(val)

    # Preserve document order; de-duplicate while keeping first occurrence
    seen: set[str] = set()
    deduped: list[str] = []
    for t in triggers:
        if t not in seen:
            seen.add(t)
            deduped.append(t)

    return deduped, trigger_details, trigger_anchor


# ---------------------------------------------------------------------------
# Permissions extraction
# ---------------------------------------------------------------------------


def _extract_permissions(node: Any, scope: str) -> EffectivePermissions:
    """Extract a permissions declaration from *node*.

    Three distinct states (AC-edge-case):
      absent     — key not present at all.
      empty      — permissions: {} or permissions: ~
      write_all  — permissions: write-all
      explicit   — permissions: {contents: read, ...}
    """
    if node is None or not hasattr(node, "get"):
        return EffectivePermissions(scope=scope, state="absent")

    perms_val = node.get("permissions", _ABSENT)

    if perms_val is _ABSENT:
        return EffectivePermissions(scope=scope, state="absent")

    anchor = key_anchor(node, "permissions")

    if perms_val is None or (
        isinstance(perms_val, (dict, CommentedMap)) and len(perms_val) == 0
    ):
        return EffectivePermissions(scope=scope, state="empty", anchor=anchor)

    if isinstance(perms_val, str) and perms_val.lower() == "write-all":
        return EffectivePermissions(scope=scope, state="write_all", anchor=anchor)

    if isinstance(perms_val, (dict, CommentedMap)):
        grants = {str(k): str(v) for k, v in perms_val.items()}
        return EffectivePermissions(
            scope=scope, state="explicit", grants=grants, anchor=anchor
        )

    # Unexpected form — treat as absent to fail-safe
    return EffectivePermissions(scope=scope, state="absent", anchor=anchor)


# ---------------------------------------------------------------------------
# Job extraction
# ---------------------------------------------------------------------------


def _extract_jobs(
    doc: CommentedMap,
    workflow_perms: EffectivePermissions,
    unresolved: list[UnresolvedFragment],
) -> list[Job]:
    jobs_val = doc.get("jobs", _ABSENT)
    if jobs_val is _ABSENT or jobs_val is None:
        return []

    if not isinstance(jobs_val, (dict, CommentedMap)):
        return []

    jobs: list[Job] = []
    for job_id, job_node in jobs_val.items():
        job_id_str = str(job_id)

        if job_node is None or not isinstance(job_node, (dict, CommentedMap)):
            continue

        # Check for reusable workflow call at the job level
        job_uses = job_node.get("uses")
        if job_uses is not None:
            unresolved.append(
                UnresolvedFragment(
                    kind="reusable_workflow",
                    locator=f"jobs.{job_id_str}.uses",
                    reason=(
                        f"Reusable workflow '{job_uses}' cannot be resolved locally; "
                        "marked Not Assessable."
                    ),
                )
            )
            # Still create a minimal job record
            jobs.append(
                Job(
                    id=job_id_str,
                    anchor=node_anchor(job_node),
                    permissions=_extract_permissions(job_node, scope="job"),
                )
            )
            continue

        # Runs-on
        runs_on = _extract_runs_on(job_node)

        # Job-level permissions
        job_perms = _extract_permissions(job_node, scope="job")

        # Needs
        needs = _extract_needs(job_node)

        # Condition
        condition_val = job_node.get("if")
        condition = str(condition_val) if condition_val is not None else None

        # Matrix
        matrix = _extract_matrix(job_node, job_id_str, unresolved)

        # Steps
        steps = _extract_steps(job_node, job_id_str, unresolved)

        jobs.append(
            Job(
                id=job_id_str,
                name=_str_or_none(job_node.get("name")),
                runs_on=runs_on,
                steps=steps,
                permissions=job_perms,
                needs=needs,
                condition=condition,
                matrix=matrix,
                anchor=node_anchor(job_node),
            )
        )

    return jobs


def _extract_runs_on(job_node: CommentedMap) -> str | list[str] | None:
    val = job_node.get("runs-on")
    if val is None:
        return None
    if isinstance(val, (list, CommentedSeq)):
        return [str(x) for x in val]
    return str(val)


def _extract_needs(job_node: CommentedMap) -> list[str]:
    needs_val = job_node.get("needs")
    if needs_val is None:
        return []
    if isinstance(needs_val, str):
        return [needs_val]
    if isinstance(needs_val, (list, CommentedSeq)):
        return [str(x) for x in needs_val]
    return []


def _extract_matrix(
    job_node: CommentedMap,
    job_id: str,
    unresolved: list[UnresolvedFragment],
) -> dict[str, Any] | None:
    strategy = job_node.get("strategy")
    if strategy is None or not isinstance(strategy, (dict, CommentedMap)):
        return None

    matrix = strategy.get("matrix")
    if matrix is None:
        return None

    matrix_str = str(matrix)
    if _DYNAMIC_EXPR_RE.search(matrix_str):
        unresolved.append(
            UnresolvedFragment(
                kind="matrix_dynamic",
                locator=f"jobs.{job_id}.strategy.matrix",
                reason=(
                    "Matrix contains dynamic expressions that cannot be "
                    "statically enumerated; job count is Not Assessable."
                ),
            )
        )
        return None

    if isinstance(matrix, (dict, CommentedMap)):
        return _coerce_to_plain(matrix)

    return None


# ---------------------------------------------------------------------------
# Step extraction
# ---------------------------------------------------------------------------


def _extract_steps(
    job_node: CommentedMap,
    job_id: str,
    unresolved: list[UnresolvedFragment],
) -> list[Step]:
    steps_val = job_node.get("steps")
    if steps_val is None or not isinstance(steps_val, (list, CommentedSeq)):
        return []

    steps: list[Step] = []
    for idx, step_node in enumerate(steps_val):
        if step_node is None or not isinstance(step_node, (dict, CommentedMap)):
            continue

        step_anchor = item_anchor(steps_val, idx) or node_anchor(step_node)
        step_id = _str_or_none(step_node.get("id"))
        step_name = _str_or_none(step_node.get("name"))
        uses_val = _str_or_none(step_node.get("uses"))
        run_val = _str_or_none(step_node.get("run"))
        continue_on_error = bool(step_node.get("continue-on-error", False))

        # env map
        env_map = _extract_str_map(step_node.get("env"))

        # with inputs
        with_map = _extract_str_map(step_node.get("with"))

        # Action reference
        action_ref: ActionRef | None = None
        if uses_val is not None:
            action_ref, maybe_unresolved = _parse_action_ref(
                uses_val, step_anchor, job_id, idx
            )
            if maybe_unresolved is not None:
                unresolved.append(maybe_unresolved)

        # Secret references from env, with, and run
        secret_refs: list[SecretRef] = []
        for val in env_map.values():
            secret_refs.extend(_extract_secret_refs(val, step_anchor))
        for val in with_map.values():
            secret_refs.extend(_extract_secret_refs(val, step_anchor))
        if run_val:
            secret_refs.extend(_extract_secret_refs(run_val, step_anchor))

        steps.append(
            Step(
                id=step_id,
                name=step_name,
                uses=uses_val,
                run=run_val,
                env=env_map,
                with_inputs=with_map,
                continue_on_error=continue_on_error,
                anchor=step_anchor,
                action_ref=action_ref,
                secret_refs=secret_refs,
            )
        )

    return steps


# ---------------------------------------------------------------------------
# Action reference parsing
# ---------------------------------------------------------------------------


def _parse_action_ref(
    uses_str: str,
    anchor: Anchor | None,
    job_id: str,
    step_idx: int,
) -> tuple[ActionRef, UnresolvedFragment | None]:
    """Parse *uses_str* into an ActionRef and optionally an UnresolvedFragment."""
    locator = f"jobs.{job_id}.steps[{step_idx}].uses"

    # Local composite action
    if uses_str.startswith("./") or uses_str.startswith("../"):
        unresolved = UnresolvedFragment(
            kind="composite_action",
            locator=locator,
            reason=(
                f"Local composite action '{uses_str}' cannot be resolved without "
                "filesystem access; marked Not Assessable."
            ),
        )
        return ActionRef(name=uses_str, pin_form="local", anchor=anchor), unresolved

    # Docker image
    if uses_str.startswith("docker://"):
        return ActionRef(name=uses_str, pin_form="docker", anchor=anchor), None

    # Reusable workflow (contains /.github/workflows/)
    if _REUSABLE_WF_RE.match(uses_str):
        # This is a reusable workflow reference at the step level (unusual but valid)
        unresolved = UnresolvedFragment(
            kind="reusable_workflow",
            locator=locator,
            reason=(
                f"Reusable workflow step reference '{uses_str}' cannot be "
                "resolved locally; marked Not Assessable."
            ),
        )
        if "@" in uses_str:
            name, ref = uses_str.rsplit("@", 1)
        else:
            name, ref = uses_str, None
        return (
            ActionRef(
                name=name,
                version_ref=ref,
                pin_form=_classify_pin(ref) if ref else "branch",
                anchor=anchor,
            ),
            unresolved,
        )

    # Remote action: owner/repo@ref
    if "@" not in uses_str:
        # No @ref — HEAD of the default branch (insecure)
        return ActionRef(name=uses_str, pin_form="branch", anchor=anchor), None

    name, ref = uses_str.rsplit("@", 1)
    pin_form = _classify_pin(ref)
    return ActionRef(name=name, version_ref=ref, pin_form=pin_form, anchor=anchor), None


def _classify_pin(ref: str) -> str:
    """Classify a version ref as sha, tag, or branch."""
    if _SHA_RE.match(ref):
        return "sha"
    if _TAG_RE.match(ref):
        return "tag"
    return "branch"


# ---------------------------------------------------------------------------
# Secret reference extraction
# ---------------------------------------------------------------------------


def _extract_secret_refs(text: str, anchor: Anchor | None) -> list[SecretRef]:
    """Extract ${{ secrets.* }} and ${{ env.* }} references from *text*."""
    refs: list[SecretRef] = []
    for match in _EXPR_RE.finditer(str(text)):
        expr = match.group(1).strip()
        if expr.startswith("secrets."):
            name = expr[len("secrets.") :]
            refs.append(
                SecretRef(name=name, source="secrets", expression=expr, anchor=anchor)
            )
        elif expr.startswith("env."):
            name = expr[len("env.") :]
            refs.append(
                SecretRef(name=name, source="env", expression=expr, anchor=anchor)
            )
    return refs


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _str_or_none(val: Any) -> str | None:
    if val is None:
        return None
    return str(val)


def _extract_str_map(val: Any) -> dict[str, str]:
    if val is None or not isinstance(val, (dict, CommentedMap)):
        return {}
    return {str(k): str(v) for k, v in val.items() if v is not None}


def _coerce_to_plain(mapping: Any) -> dict[str, Any]:
    """Recursively convert CommentedMap/CommentedSeq to plain dicts/lists."""
    if isinstance(mapping, (dict, CommentedMap)):
        return {str(k): _coerce_to_plain(v) for k, v in mapping.items()}
    if isinstance(mapping, (list, CommentedSeq)):
        return [_coerce_to_plain(x) for x in mapping]  # type: ignore[return-value]
    return mapping


def _make_result(ir: PipelineIR, original_content: str) -> NormalizationResult:
    """Package the IR into a NormalizationResult."""
    coverage: dict[str, Any] = {
        "ir_version": ir.ir_version,
        "source_format": ir.source_format,
        "unresolved": [u.model_dump() for u in ir.coverage_report.unresolved],
        "constructs_handled": ir.coverage_report.constructs_handled,
        "constructs_excluded": ir.coverage_report.constructs_excluded,
        "job_count": len(ir.jobs),
        "trigger_count": len(ir.triggers),
    }
    return NormalizationResult(
        normalized_content=original_content,
        coverage_report=coverage,
        pipeline_ir=ir,
    )
