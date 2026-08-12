"""GitLab CI normalizer — converts .gitlab-ci.yml into PipelineIR.

Design invariants:
  - Never makes outbound HTTP requests.  Every include that requires a
    network call (remote, project, template, component) is appended to
    coverage_report.unresolved as Not Assessable with kind and reason.
  - YAML is loaded via yaml_loader.load_yaml(), reusing YAML 1.2 mode
    and the alias-bomb guard from WO-006.
  - !reference tags are handled via a module-level ruamel constructor
    registered once at import time; in-document references are resolved in
    a post-load pass; unresolvable references become UnresolvedFragments.
  - Extends chains are resolved by ExtendsMerger (gitlab_extends.py) with
    cycle detection and deep-merge semantics.
  - Hidden jobs (leading dot in the key) are not emitted as executable jobs
    but participate in extends resolution.
  - The IR contract (PipelineIR) is reused unchanged from WO-006; no
    GitLab-specific fields are added.
  - No FastAPI, SQLAlchemy, or HTTP imports.
"""
from __future__ import annotations

import copy
import io
import re
from typing import Any

from ruamel.yaml import YAML  # type: ignore[import-untyped]
from ruamel.yaml.comments import CommentedMap, CommentedSeq  # type: ignore[import-untyped]
from ruamel.yaml.constructor import RoundTripConstructor  # type: ignore[import-untyped]

from pipelineshield.analysis.ir.pipeline_ir import (
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
from pipelineshield.analysis.normalizers.gitlab_extends import ExtendsMerger
from pipelineshield.analysis.yaml_loader import (
    NormalizationError,
    item_anchor,
    key_anchor,
    node_anchor,
    MAX_ALIASES,
)
from pipelineshield.services.normalizer_registry import NormalizationResult, Normalizer

__all__ = ["GitLabCINormalizer"]

# ---------------------------------------------------------------------------
# !reference tag support
# ---------------------------------------------------------------------------


class _ReferenceTag:
    """Placeholder produced when loading a !reference [path...] tag."""

    __slots__ = ("path",)

    def __init__(self, path: list[str]) -> None:
        self.path = path

    def __repr__(self) -> str:
        return f"!reference {self.path}"


def _reference_constructor(loader: Any, node: Any) -> _ReferenceTag:
    seq = loader.construct_sequence(node, deep=True)
    return _ReferenceTag(path=[str(p) for p in seq])


# Register at class level — happens once at module import, affects all
# RoundTripConstructor instances.  The tag '!reference' is non-standard
# so this never conflicts with YAML built-in constructors.
if "!reference" not in RoundTripConstructor.yaml_constructors:
    RoundTripConstructor.add_constructor("!reference", _reference_constructor)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# GitLab default stage list when `stages:` is absent (GitLab docs §stages)
GITLAB_DEFAULT_STAGES: list[str] = [".pre", "build", "test", "deploy", ".post"]

# Top-level keys that are never job definitions
_RESERVED_KEYS: frozenset[str] = frozenset(
    {
        "stages",
        "variables",
        "include",
        "workflow",
        "default",
        "cache",
        "after_script",
        "before_script",
        "image",
        "services",
    }
)

# Constructs this normalizer processes
_HANDLED_CONSTRUCTS: list[str] = [
    "stages",
    "include_local",
    "workflow_rules",
    "job_script",
    "job_before_script",
    "job_after_script",
    "job_image",
    "job_tags",
    "job_variables",
    "job_rules",
    "job_only_except",
    "job_extends",
    "job_reference",
    "global_default_inheritance",
    "hidden_job_templates",
    "job_needs",
]

# Constructs present in GitLab CI but excluded from this normalizer version
_EXCLUDED_CONSTRUCTS: list[str] = [
    "include_remote",
    "include_project",
    "include_template",
    "include_component",
    "trigger",
    "release",
    "artifacts",
    "cache",
    "parallel_matrix",
    "environment",
    "dast_configuration",
]

# Pipeline source names extracted from $CI_PIPELINE_SOURCE expressions
_CI_SOURCE_RE = re.compile(
    r'\$CI_PIPELINE_SOURCE\s*==\s*["\']([^"\']+)["\']'
)

# Secret-shaped GitLab CI variable references in script text
_SECRET_VAR_RE = re.compile(
    r'\$\{?([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|CREDENTIALS?|KEY|'
    r'AUTH|CERT|PRIVATE_KEY|ACCESS_KEY|API_KEY|CI_JOB_TOKEN|'
    r'CI_REGISTRY_PASSWORD|CI_REGISTRY_USER|CI_DEPLOY_TOKEN|'
    r'CI_DEPLOY_PASSWORD))\}?'
)

_ABSENT = object()


# ---------------------------------------------------------------------------
# Public normalizer
# ---------------------------------------------------------------------------


class GitLabCINormalizer(Normalizer):
    """Normalizer for GitLab CI (.gitlab-ci.yml) pipeline definitions."""

    def normalize(self, content: str) -> NormalizationResult:
        """Normalize *content* into a PipelineIR.

        Raises
        ------
        NormalizationError
            On YAML syntax errors or alias-bomb detection.
        """
        doc = _load_gitlab_yaml(content)

        if doc is None:
            ir = PipelineIR(source_format="gitlab_ci")
            return _make_result(ir, content)

        if not isinstance(doc, (CommentedMap, dict)):
            raise NormalizationError(
                "GitLab CI configuration must be a YAML mapping at document root.",
                constraint="root_must_be_mapping",
            )

        unresolved: list[UnresolvedFragment] = []

        # ----------------------------------------------------------------
        # 1. Process includes
        # ----------------------------------------------------------------
        _process_includes(doc, unresolved)

        # ----------------------------------------------------------------
        # 2. Extract stages (with default fallback)
        # ----------------------------------------------------------------
        stages, stages_inferred = _extract_stages(doc)

        # ----------------------------------------------------------------
        # 3. Collect all job nodes (including hidden templates)
        # ----------------------------------------------------------------
        all_jobs = _collect_jobs(doc)

        # ----------------------------------------------------------------
        # 4. Resolve !reference tags in the full document
        # ----------------------------------------------------------------
        _resolve_reference_tags(doc, doc, unresolved)

        # ----------------------------------------------------------------
        # 5. Resolve extends chains
        # ----------------------------------------------------------------
        merged_jobs = ExtendsMerger(all_jobs, unresolved).resolve_all()

        # ----------------------------------------------------------------
        # 6. Apply global default: inheritance
        # ----------------------------------------------------------------
        global_default = _extract_global_default(doc)
        if global_default:
            merged_jobs = _apply_global_default(merged_jobs, global_default)

        # ----------------------------------------------------------------
        # 7. Extract workflow-level triggers
        # ----------------------------------------------------------------
        triggers, trigger_details, trigger_anchor = _extract_triggers(doc)

        # ----------------------------------------------------------------
        # 8. Build Job IR nodes (excluding hidden template jobs)
        # ----------------------------------------------------------------
        jobs: list[Job] = []
        for job_name, job_node in merged_jobs.items():
            if not isinstance(job_node, (dict, CommentedMap)):
                continue
            ir_job = _build_job(job_name, job_node, unresolved)
            if ir_job is not None:
                jobs.append(ir_job)

        # ----------------------------------------------------------------
        # 9. Assemble PipelineIR
        # ----------------------------------------------------------------
        ir = PipelineIR(
            ir_version=IR_VERSION,
            source_format="gitlab_ci",
            triggers=triggers,
            trigger_details=trigger_details,
            permissions=EffectivePermissions(scope="workflow", state="absent"),
            jobs=jobs,
            coverage_report=CoverageReport(
                unresolved=unresolved,
                constructs_handled=list(_HANDLED_CONSTRUCTS),
                constructs_excluded=list(_EXCLUDED_CONSTRUCTS),
            ),
            trigger_anchor=trigger_anchor,
        )

        if stages_inferred:
            # Record as informational fragment
            unresolved_with_stages = list(ir.coverage_report.unresolved) + [
                UnresolvedFragment(
                    kind="stages_inferred",
                    locator="stages",
                    reason=(
                        "No 'stages:' key found; GitLab default stage order "
                        f"({', '.join(GITLAB_DEFAULT_STAGES)}) was inferred. "
                        "Job stage assignments may not reflect intended order."
                    ),
                )
            ]
            ir = ir.model_copy(
                update={
                    "coverage_report": CoverageReport(
                        unresolved=unresolved_with_stages,
                        constructs_handled=ir.coverage_report.constructs_handled,
                        constructs_excluded=ir.coverage_report.constructs_excluded,
                    )
                }
            )

        return _make_result(ir, content)


# ---------------------------------------------------------------------------
# YAML loading with !reference constructor
# ---------------------------------------------------------------------------

_ALIAS_RE = re.compile(r"\*[A-Za-z_][A-Za-z0-9_\-]*")


def _load_gitlab_yaml(text: str) -> Any:
    """Load GitLab CI YAML with !reference support and alias bomb guard."""
    alias_count = len(_ALIAS_RE.findall(text))
    if alias_count > MAX_ALIASES:
        raise NormalizationError(
            f"YAML alias expansion limit exceeded: {alias_count} alias references "
            f"found (limit {MAX_ALIASES}). This may be an anchor bomb.",
            constraint="alias_bomb",
        )

    y = YAML(typ="rt")
    y.version = (1, 2)
    y.preserve_quotes = True
    # !reference constructor is already registered at class level above

    try:
        doc = y.load(io.StringIO(text))
    except Exception as exc:  # noqa: BLE001
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        line: int | None = (mark.line + 1) if mark else None
        col: int | None = (mark.column + 1) if mark else None
        problem: str = getattr(exc, "problem", None) or str(exc)
        raise NormalizationError(
            problem, line=line, column=col, constraint="yaml_syntax"
        ) from exc

    return doc


# ---------------------------------------------------------------------------
# !reference resolution
# ---------------------------------------------------------------------------


def _resolve_reference_tags(
    root: Any,
    node: Any,
    unresolved: list[UnresolvedFragment],
    _depth: int = 0,
) -> Any:
    """Recursively replace all _ReferenceTag objects with their resolved values.

    For sequence elements, if the resolved value is itself a list it is
    flattened in-place (GitLab's expected behaviour).
    """
    if _depth > 50:
        return node

    if isinstance(node, _ReferenceTag):
        return _lookup_reference_path(root, node.path, unresolved)

    if isinstance(node, (dict, CommentedMap)):
        for k in list(node.keys()):
            node[k] = _resolve_reference_tags(root, node[k], unresolved, _depth + 1)
        return node

    if isinstance(node, (list, CommentedSeq)):
        new_items: list[Any] = []
        for item in node:
            resolved = _resolve_reference_tags(root, item, unresolved, _depth + 1)
            if isinstance(resolved, (list, CommentedSeq)):
                # Flatten — GitLab merges referenced script arrays inline
                new_items.extend(resolved)
            else:
                new_items.append(resolved)
        node.clear()
        node.extend(new_items)
        return node

    return node


def _lookup_reference_path(
    root: Any,
    path: list[str],
    unresolved: list[UnresolvedFragment],
) -> Any:
    """Walk *root* following *path*; record failure as unresolved."""
    current: Any = root
    for key in path:
        if not isinstance(current, (dict, CommentedMap)):
            unresolved.append(
                UnresolvedFragment(
                    kind="reference_unresolvable",
                    locator=".".join(path),
                    reason=(
                        f"!reference {path!r} could not be resolved: "
                        f"intermediate key '{key}' is not a mapping — "
                        "marked Not Assessable."
                    ),
                )
            )
            return f"[!reference {path}]"
        val = current.get(key)
        if val is None and key not in current:
            unresolved.append(
                UnresolvedFragment(
                    kind="reference_unresolvable",
                    locator=".".join(path),
                    reason=(
                        f"!reference {path!r} could not be resolved: "
                        f"key '{key}' not found — marked Not Assessable."
                    ),
                )
            )
            return f"[!reference {path}]"
        current = val
    return current


# ---------------------------------------------------------------------------
# Include classification
# ---------------------------------------------------------------------------


def _process_includes(
    doc: CommentedMap,
    unresolved: list[UnresolvedFragment],
) -> None:
    """Classify every include entry; record non-local ones as unresolved."""
    include_val = doc.get("include", _ABSENT)
    if include_val is _ABSENT:
        return

    # Normalise to a list of entries
    if isinstance(include_val, str):
        entries: list[Any] = [include_val]
    elif isinstance(include_val, (list, CommentedSeq)):
        entries = list(include_val)
    elif isinstance(include_val, (dict, CommentedMap)):
        entries = [include_val]
    else:
        entries = [include_val]

    for entry in entries:
        kind, locator = _classify_include(entry)
        if kind != "include_local":
            unresolved.append(
                UnresolvedFragment(
                    kind=kind,
                    locator=locator,
                    reason=_include_reason(kind, locator),
                )
            )
        # include_local: co-submitted resolution is deferred to a future WO;
        # for now it is also Not Assessable when not explicitly co-submitted.
        # Record it as unresolved so the coverage banner shows it.
        else:
            unresolved.append(
                UnresolvedFragment(
                    kind="include_local",
                    locator=locator,
                    reason=(
                        f"Local include '{locator}' is only resolvable when the "
                        "referenced file is co-submitted — marked Not Assessable."
                    ),
                )
            )


def _classify_include(entry: Any) -> tuple[str, str]:
    """Return (kind, locator) for a single include entry."""
    if isinstance(entry, str):
        if entry.startswith(("http://", "https://")):
            return "include_remote", entry
        return "include_local", entry

    if not isinstance(entry, (dict, CommentedMap)):
        return "include_remote", str(entry)

    if "local" in entry:
        return "include_local", str(entry["local"])
    if "remote" in entry:
        return "include_remote", str(entry["remote"])
    if "project" in entry:
        project = str(entry.get("project", ""))
        file_ = str(entry.get("file", ""))
        ref = str(entry.get("ref", "HEAD"))
        return "include_project", f"{project}:{file_}@{ref}"
    if "template" in entry:
        return "include_template", str(entry["template"])
    if "component" in entry:
        return "include_component", str(entry["component"])
    return "include_remote", str(entry)


def _include_reason(kind: str, locator: str) -> str:
    reasons = {
        "include_remote": (
            f"Remote include '{locator}' requires an outbound HTTP request — "
            "never fetched; marked Not Assessable."
        ),
        "include_project": (
            f"Project include '{locator}' requires a GitLab API call — "
            "never fetched; marked Not Assessable."
        ),
        "include_template": (
            f"GitLab CI template include '{locator}' requires access to the "
            "GitLab template library — never fetched; marked Not Assessable."
        ),
        "include_component": (
            f"GitLab CI component include '{locator}' requires a GitLab API call — "
            "never fetched; marked Not Assessable."
        ),
    }
    return reasons.get(kind, f"Include '{locator}' of kind '{kind}' cannot be resolved locally.")


# ---------------------------------------------------------------------------
# Stages extraction
# ---------------------------------------------------------------------------


def _extract_stages(doc: CommentedMap) -> tuple[list[str], bool]:
    """Return (stages, stages_inferred) where stages_inferred=True when
    no 'stages:' key was present and the GitLab default was applied."""
    stages_val = doc.get("stages", _ABSENT)
    if stages_val is _ABSENT or stages_val is None:
        return list(GITLAB_DEFAULT_STAGES), True
    if isinstance(stages_val, (list, CommentedSeq)):
        return [str(s) for s in stages_val], False
    return list(GITLAB_DEFAULT_STAGES), True


# ---------------------------------------------------------------------------
# Job collection (all top-level non-reserved keys)
# ---------------------------------------------------------------------------


def _collect_jobs(doc: CommentedMap) -> dict[str, Any]:
    """Return all job nodes, including hidden dot-prefixed templates."""
    jobs: dict[str, Any] = {}
    for key in doc:
        str_key = str(key)
        if str_key in _RESERVED_KEYS:
            continue
        node = doc[key]
        if isinstance(node, (dict, CommentedMap)):
            jobs[str_key] = node
    return jobs


# ---------------------------------------------------------------------------
# Global default: inheritance
# ---------------------------------------------------------------------------


def _extract_global_default(doc: CommentedMap) -> CommentedMap | None:
    default = doc.get("default", _ABSENT)
    if default is _ABSENT or not isinstance(default, (dict, CommentedMap)):
        return None
    return default  # type: ignore[return-value]


def _apply_global_default(
    jobs: dict[str, Any],
    global_default: CommentedMap,
) -> dict[str, Any]:
    """Merge global *default* into every job that doesn't override each key."""
    result: dict[str, Any] = {}
    for name, node in jobs.items():
        if not isinstance(node, (dict, CommentedMap)):
            result[name] = node
            continue
        merged = CommentedMap()
        # Start with global default
        for k, v in global_default.items():
            merged[k] = copy.deepcopy(v)
        # Job values win
        for k, v in node.items():
            merged[k] = copy.deepcopy(v)
        result[name] = merged
    return result


# ---------------------------------------------------------------------------
# Trigger extraction
# ---------------------------------------------------------------------------

_PIPELINE_SOURCE_LITERALS = {
    "push",
    "web",
    "trigger",
    "schedule",
    "api",
    "external",
    "pipelines",
    "chat",
    "merge_request_event",
    "merge_requests",
    "parent_pipeline",
    "ondemand_dast_scan",
    "ondemand_dast_validation",
}


def _extract_triggers(
    doc: CommentedMap,
) -> tuple[list[str], dict[str, Any], Anchor | None]:
    """Extract pipeline-level triggers from workflow.rules and only/except."""
    triggers: set[str] = set()
    trigger_details: dict[str, Any] = {}

    workflow_val = doc.get("workflow", _ABSENT)
    trigger_anchor = key_anchor(doc, "workflow") if workflow_val is not _ABSENT else None

    # workflow.rules
    if isinstance(workflow_val, (dict, CommentedMap)):
        rules = workflow_val.get("rules")
        if isinstance(rules, (list, CommentedSeq)):
            for rule in rules:
                if not isinstance(rule, (dict, CommentedMap)):
                    continue
                if_expr = rule.get("if")
                if if_expr:
                    for source in _CI_SOURCE_RE.findall(str(if_expr)):
                        triggers.add(source)
                        trigger_details[source] = {"if": str(if_expr)}

    # Scan job-level only/except/rules for event names (informational)
    for key in doc:
        str_key = str(key)
        if str_key in _RESERVED_KEYS:
            continue
        job_node = doc[key]
        if not isinstance(job_node, (dict, CommentedMap)):
            continue

        only = job_node.get("only")
        if isinstance(only, (list, CommentedSeq)):
            for evt in only:
                evt_s = str(evt)
                if evt_s in _PIPELINE_SOURCE_LITERALS:
                    triggers.add(evt_s)
                    trigger_details.setdefault(evt_s, {})

        except_ = job_node.get("except")
        if isinstance(except_, (list, CommentedSeq)):
            for evt in except_:
                evt_s = str(evt)
                if evt_s in _PIPELINE_SOURCE_LITERALS:
                    trigger_details.setdefault(evt_s, {"except": True})

        rules_list = job_node.get("rules")
        if isinstance(rules_list, (list, CommentedSeq)):
            for rule in rules_list:
                if not isinstance(rule, (dict, CommentedMap)):
                    continue
                if_expr = rule.get("if")
                if if_expr:
                    for source in _CI_SOURCE_RE.findall(str(if_expr)):
                        triggers.add(source)
                        trigger_details.setdefault(source, {"if": str(if_expr)})

    # De-duplicate, preserve insertion order where possible
    ordered = sorted(triggers)
    return ordered, trigger_details, trigger_anchor


# ---------------------------------------------------------------------------
# Job building
# ---------------------------------------------------------------------------


def _build_job(
    job_name: str,
    job_node: Any,
    unresolved: list[UnresolvedFragment],
) -> Job | None:
    """Build a PipelineIR.Job from a (possibly merged) GitLab job node."""
    if not isinstance(job_node, (dict, CommentedMap)):
        return None

    anchor = node_anchor(job_node)

    # runs_on: prefer image, fall back to tags
    runs_on = _extract_runs_on(job_node)

    # steps from scripts
    steps = _extract_steps(job_name, job_node, unresolved)

    # needs
    needs = _extract_needs(job_node)

    # condition — first rules.if or only
    condition = _extract_condition(job_node)

    # matrix
    matrix = _extract_matrix(job_name, job_node, unresolved)

    # Hidden jobs are excluded from executable list (but already in merged_jobs)
    # — their IR entry is skipped here; they exist only for extends resolution
    if job_name.startswith("."):
        return None

    return Job(
        id=job_name,
        name=job_name,
        runs_on=runs_on,
        steps=steps,
        permissions=EffectivePermissions(scope="job", state="absent"),
        needs=needs,
        condition=condition,
        matrix=matrix,
        anchor=anchor,
    )


def _extract_runs_on(job_node: Any) -> str | list[str] | None:
    image_val = job_node.get("image")
    if image_val is not None:
        if isinstance(image_val, (dict, CommentedMap)):
            return str(image_val.get("name", "")) or None
        return str(image_val)
    tags_val = job_node.get("tags")
    if isinstance(tags_val, (list, CommentedSeq)):
        return [str(t) for t in tags_val]
    if tags_val is not None:
        return str(tags_val)
    return None


def _extract_needs(job_node: Any) -> list[str]:
    needs_val = job_node.get("needs")
    if needs_val is None:
        return []
    if isinstance(needs_val, (list, CommentedSeq)):
        result = []
        for item in needs_val:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, (dict, CommentedMap)):
                job_ref = item.get("job")
                if job_ref:
                    result.append(str(job_ref))
        return result
    return []


def _extract_condition(job_node: Any) -> str | None:
    rules_val = job_node.get("rules")
    if isinstance(rules_val, (list, CommentedSeq)) and rules_val:
        first_rule = rules_val[0]
        if isinstance(first_rule, (dict, CommentedMap)):
            if_val = first_rule.get("if")
            if if_val:
                return str(if_val)
    only_val = job_node.get("only")
    if isinstance(only_val, (list, CommentedSeq)) and only_val:
        return f"only: {[str(x) for x in only_val]}"
    return None


def _extract_matrix(
    job_name: str,
    job_node: Any,
    unresolved: list[UnresolvedFragment],
) -> dict[str, Any] | None:
    parallel_val = job_node.get("parallel")
    if parallel_val is None:
        return None
    if isinstance(parallel_val, int):
        # parallel: N — numeric parallelism, not a matrix
        return None
    if isinstance(parallel_val, (dict, CommentedMap)):
        matrix_val = parallel_val.get("matrix")
        if matrix_val is None:
            return None
        # Check for dynamic expressions
        matrix_str = str(matrix_val)
        if "${{" in matrix_str or "$CI_" in matrix_str:
            unresolved.append(
                UnresolvedFragment(
                    kind="matrix_dynamic",
                    locator=f"jobs.{job_name}.parallel.matrix",
                    reason=(
                        "Matrix contains dynamic expressions and cannot be "
                        "statically enumerated — marked Not Assessable."
                    ),
                )
            )
            return None
        if isinstance(matrix_val, (list, CommentedSeq)):
            return {"matrix": _coerce_plain(matrix_val)}
        return _coerce_plain(matrix_val)
    return None


# ---------------------------------------------------------------------------
# Step extraction (before_script / script / after_script)
# ---------------------------------------------------------------------------


def _extract_steps(
    job_name: str,
    job_node: Any,
    unresolved: list[UnresolvedFragment],
) -> list[Step]:
    steps: list[Step] = []

    # Job-level variables for env map
    env_map = _extract_variables_map(job_node.get("variables"))

    for phase in ("before_script", "script", "after_script"):
        script_val = job_node.get(phase)
        if script_val is None:
            continue
        run_text = _join_script(script_val)
        anchor = key_anchor(job_node, phase)
        secret_refs = _extract_secret_refs(run_text, env_map, anchor)
        steps.append(
            Step(
                name=phase,
                run=run_text,
                env=env_map if phase == "script" else {},
                anchor=anchor,
                secret_refs=secret_refs,
            )
        )

    return steps


def _join_script(val: Any) -> str:
    if isinstance(val, str):
        return val
    if isinstance(val, (list, CommentedSeq)):
        return "\n".join(str(item) for item in val if item is not None)
    return str(val)


def _extract_variables_map(variables_val: Any) -> dict[str, str]:
    if variables_val is None or not isinstance(variables_val, (dict, CommentedMap)):
        return {}
    result: dict[str, str] = {}
    for k, v in variables_val.items():
        if isinstance(v, (dict, CommentedMap)):
            # value: / masked: form — extract the value field
            inner_val = v.get("value", "")
            result[str(k)] = str(inner_val) if inner_val is not None else ""
        elif v is not None:
            result[str(k)] = str(v)
        else:
            result[str(k)] = ""
    return result


def _extract_secret_refs(
    script_text: str,
    env_map: dict[str, str],
    anchor: Anchor | None,
) -> list[SecretRef]:
    """Extract secret-like variable references from script text and env map."""
    refs: list[SecretRef] = []
    seen: set[str] = set()

    for match in _SECRET_VAR_RE.finditer(script_text):
        name = match.group(1)
        if name not in seen:
            seen.add(name)
            refs.append(
                SecretRef(
                    name=name,
                    source="env",
                    expression=f"${name}",
                    anchor=anchor,
                )
            )

    # Variables declared with secret-like names in the variables block
    for var_name in env_map:
        if _SECRET_VAR_RE.match(f"${var_name}") and var_name not in seen:
            seen.add(var_name)
            refs.append(
                SecretRef(
                    name=var_name,
                    source="env",
                    expression=f"${var_name}",
                    anchor=anchor,
                )
            )

    return refs


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _coerce_plain(obj: Any) -> Any:
    """Recursively convert CommentedMap/CommentedSeq to plain dict/list."""
    if isinstance(obj, (dict, CommentedMap)):
        return {str(k): _coerce_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, CommentedSeq)):
        return [_coerce_plain(item) for item in obj]
    return obj


def _make_result(ir: PipelineIR, original_content: str) -> NormalizationResult:
    """Package PipelineIR into a NormalizationResult."""
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
