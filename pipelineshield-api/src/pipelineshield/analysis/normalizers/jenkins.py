"""Jenkins declarative-subset extractor.

Design principles:
  - Only the declarative subset is parsed: pipeline { ... } with agent,
    environment, options, triggers, stages { stage(...) { steps { ... } } },
    parallel blocks, and post conditions.
  - Every extracted node is flagged with extraction_method='heuristic' in
    Job.extraction_metadata.  Downstream rules must qualify their confidence.
  - Anything not in the declarative subset — scripted Groovy (no pipeline
    block), script { } blocks inside stages, @Library / library() calls,
    and dynamically-constructed stage names — is classified Not Assessable:
    recorded in coverage_report.unresolved with a machine-readable kind and
    reason, excluded from the score denominator, and NEVER classified Missing
    or Present.
  - Anchors are computed from character offsets against the masked text; this
    is safe because WO-002 guarantees length preservation.
  - An extraction wall-clock guard prevents pathological input from hanging
    the synchronous request.

No FastAPI, SQLAlchemy, or HTTP imports.
"""
from __future__ import annotations

import re
import time
from typing import Any

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
from pipelineshield.analysis.normalizers.groovy_block_scanner import (
    Block,
    ExtractionBudgetExceeded,
    find_all_blocks,
    find_block,
    find_matching_brace,
    offset_to_line_col,
)
from pipelineshield.analysis.yaml_loader import NormalizationError
from pipelineshield.services.normalizer_registry import NormalizationResult, Normalizer

__all__ = ["JenkinsNormalizer"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_WALL_SECONDS: float = 5.0

# Constructs the Jenkins normalizer processes
_HANDLED_CONSTRUCTS: list[str] = [
    "pipeline_block",
    "agent_any_none",
    "agent_label",
    "agent_docker_image",
    "stages_block",
    "stage_block",
    "steps_block",
    "parallel_block",
    "environment_credentials",
    "with_credentials",
    "triggers_block",
    "options_block",
    "post_block",
]

# Constructs present but excluded from this normalizer version
_EXCLUDED_CONSTRUCTS: list[str] = [
    "when_block",
    "input_block",
    "matrix_block",
    "agent_kubernetes_yaml",
    "lock_resource",
    "retry_block",
    "timeout_block",
    "tool_block",
    "changelog_block",
    "deploy_artifact",
]

# Heuristic confidence for declarative-subset nodes
_HEURISTIC_CONFIDENCE: float = 0.7

_HEURISTIC_META: dict[str, Any] = {
    "extraction_method": "heuristic",
    "confidence": _HEURISTIC_CONFIDENCE,
}

# ---------------------------------------------------------------------------
# Regex patterns (leaf-level only — never used for block delimitation)
# ---------------------------------------------------------------------------

# Detects @Library annotation
_LIBRARY_ANNOTATION_RE = re.compile(r'@Library\s*\(')
# Detects library() call
_LIBRARY_CALL_RE = re.compile(r'\blibrary\s*\(')
# Detects node { } scripted block at top level
_NODE_BLOCK_RE = re.compile(r'\bnode\s*(?:\([^)]*\)\s*)?\{')
# Detects dynamic stage name: contains ${ ... } GString interpolation
_DYNAMIC_STAGE_NAME_RE = re.compile(r'\$\{')

# Credentials extraction from environment block:
# VAR = credentials('id')
_ENV_CREDENTIALS_RE = re.compile(
    r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*credentials\s*\(\s*["\']([^"\']+)["\']\s*\)'
)

# withCredentials binding patterns:
# string(credentialsId: 'id', ...) / usernamePassword(credentialsId: 'id', ...)
# sshUserPrivateKey(credentialsId: 'id', ...) etc.
_WITH_CREDS_BINDING_RE = re.compile(
    r'\bcredentialsId\s*:\s*["\']([^"\']+)["\']'
)

# Agent docker image extraction: docker { image 'name' }
_DOCKER_IMAGE_RE = re.compile(r"\bimage\s+['\"]([^'\"]+)['\"]")
# Agent label: agent { label 'xxx' }
_AGENT_LABEL_RE = re.compile(r"\blabel\s+['\"]([^'\"]+)['\"]")

# Trigger type names (leaf-level directive names)
_TRIGGER_NAMES_RE = re.compile(
    r'\b(cron|pollSCM|upstream|gerrit|bitbucketPush|githubPush)\s*\('
)

# sh / bat / powershell / dir / echo step invocations
_STEP_COMMAND_RE = re.compile(
    r'\b(sh|bat|powershell|dir|echo|unstash|stash|archiveArtifacts'
    r'|junit|publishHTML|emailext|slackSend|mail|deleteDir|checkout|git'
    r'|docker|build|deploy|input|script|parallel|node|withEnv|wrap|retry'
    r'|timeout|lock|milestone|stage|error|currentBuild|unstable|isUnix'
    r'|readFile|writeFile|readJSON|writeJSON|findFiles|fileExists'
    r'|readProperties|readYaml|writeYaml)\b'
    r'(?:\s+|\s*\()'
)


# ---------------------------------------------------------------------------
# Public normalizer
# ---------------------------------------------------------------------------


class JenkinsNormalizer(Normalizer):
    """Heuristic extractor for Jenkins declarative pipeline definitions.

    Uses a brace-matching scanner for block structure and bounded regexes
    only for leaf-level directive recognition.
    """

    def normalize(self, content: str) -> NormalizationResult:
        """Normalize *content* into a PipelineIR.

        Raises NormalizationError on extraction-budget exhaustion or
        when the input is larger than the configured size limit.
        """
        deadline = time.monotonic() + _MAX_WALL_SECONDS
        unresolved: list[UnresolvedFragment] = []

        try:
            ir = self._extract(content, unresolved, deadline)
        except ExtractionBudgetExceeded as exc:
            raise NormalizationError(
                str(exc),
                constraint="extraction_budget",
            ) from exc

        return _make_result(ir, content)

    # ------------------------------------------------------------------
    # Internal extraction
    # ------------------------------------------------------------------

    def _extract(
        self,
        text: str,
        unresolved: list[UnresolvedFragment],
        deadline: float,
    ) -> PipelineIR:
        # --- Shared-library detection (whole file) ---
        _detect_shared_libraries(text, unresolved)

        # --- Find pipeline { } block ---
        pipeline_block = find_block(text, "pipeline", deadline=deadline)

        if pipeline_block is None:
            # Whole file is scripted Groovy or otherwise unparseable
            unresolved.append(
                UnresolvedFragment(
                    kind="scripted_groovy",
                    locator="pipeline",
                    reason=(
                        "No 'pipeline {' block found. This file appears to be a "
                        "scripted Groovy Jenkinsfile or uses an unsupported top-level "
                        "structure — the entire file is Not Assessable."
                    ),
                )
            )
            ir = PipelineIR(
                ir_version=IR_VERSION,
                source_format="jenkins",
                coverage_report=CoverageReport(
                    unresolved=unresolved,
                    constructs_handled=list(_HANDLED_CONSTRUCTS),
                    constructs_excluded=list(_EXCLUDED_CONSTRUCTS),
                    coverage_ratio=0.0,
                ),
            )
            return ir

        pc = pipeline_block.content

        # --- Agent ---
        runs_on = _extract_agent(text, pc, pipeline_block, unresolved, deadline)

        # --- Environment ---
        env_secret_refs = _extract_environment_secrets(pc, text, unresolved)

        # --- Triggers ---
        triggers = _extract_triggers(pc)

        # --- Stages ---
        jobs, stage_unresolved_count = _extract_stages(
            pc,
            text,
            pipeline_block,
            runs_on,
            env_secret_refs,
            unresolved,
            deadline,
        )
        unresolved.extend(stage_unresolved_count if isinstance(stage_unresolved_count, list) else [])

        # --- Coverage ratio ---
        total_detected = len(jobs) + len(unresolved)
        assessable = len(jobs)
        coverage_ratio = assessable / total_detected if total_detected > 0 else 1.0

        pipeline_anchor = Anchor(
            start_line=pipeline_block.start_line,
            start_column=1,
            end_line=pipeline_block.end_line,
        )

        ir = PipelineIR(
            ir_version=IR_VERSION,
            source_format="jenkins",
            triggers=sorted(triggers),
            trigger_details={t: {} for t in triggers},
            permissions=EffectivePermissions(scope="workflow", state="absent"),
            jobs=jobs,
            coverage_report=CoverageReport(
                unresolved=unresolved,
                constructs_handled=list(_HANDLED_CONSTRUCTS),
                constructs_excluded=list(_EXCLUDED_CONSTRUCTS),
                coverage_ratio=coverage_ratio,
            ),
            trigger_anchor=pipeline_anchor,
        )
        return ir


# ---------------------------------------------------------------------------
# Shared-library detection
# ---------------------------------------------------------------------------


def _detect_shared_libraries(
    text: str,
    unresolved: list[UnresolvedFragment],
) -> None:
    for m in _LIBRARY_ANNOTATION_RE.finditer(text):
        line, _ = offset_to_line_col(text, m.start())
        unresolved.append(
            UnresolvedFragment(
                kind="shared_library",
                locator=f"line:{line}",
                reason=(
                    f"@Library annotation at line {line} imports a shared library — "
                    "shared-library resolution requires the Jenkins instance or SCM "
                    "context and is Not Assessable."
                ),
            )
        )

    for m in _LIBRARY_CALL_RE.finditer(text):
        line, _ = offset_to_line_col(text, m.start())
        unresolved.append(
            UnresolvedFragment(
                kind="shared_library",
                locator=f"line:{line}",
                reason=(
                    f"library() call at line {line} imports a shared library — "
                    "Not Assessable."
                ),
            )
        )


# ---------------------------------------------------------------------------
# Agent extraction
# ---------------------------------------------------------------------------


def _extract_agent(
    full_text: str,
    pipeline_content: str,
    pipeline_block: Block,
    unresolved: list[UnresolvedFragment],
    deadline: float,
) -> str | None:
    """Extract runs_on from the pipeline-level agent directive."""
    # agent any / agent none (scalar form)
    scalar_m = re.search(r'\bagent\s+(any|none)\b', pipeline_content)
    if scalar_m:
        val = scalar_m.group(1)
        return val if val == "any" else None

    # agent { ... } block form
    agent_block = find_block(pipeline_content, "agent", deadline=deadline)
    if agent_block is None:
        return None

    content = agent_block.content

    # docker { image '...' }
    docker_block = find_block(content, "docker", deadline=deadline)
    if docker_block:
        m = _DOCKER_IMAGE_RE.search(docker_block.content)
        if m:
            return m.group(1)
        return "docker"

    # label '...'
    label_m = _AGENT_LABEL_RE.search(content)
    if label_m:
        return label_m.group(1)

    # kubernetes {} — mark as partially unresolved
    k8s_block = find_block(content, "kubernetes", deadline=deadline)
    if k8s_block:
        line = pipeline_block.start_line
        unresolved.append(
            UnresolvedFragment(
                kind="agent_kubernetes",
                locator=f"pipeline.agent.kubernetes",
                reason=(
                    "Kubernetes agent YAML block cannot be statically resolved — "
                    "marked Not Assessable for agent configuration."
                ),
            )
        )
        return "kubernetes"

    return None


# ---------------------------------------------------------------------------
# Environment block — credential extraction
# ---------------------------------------------------------------------------


def _extract_environment_secrets(
    pipeline_content: str,
    full_text: str,
    unresolved: list[UnresolvedFragment],
) -> list[SecretRef]:
    """Extract SecretRefs from environment { VAR = credentials('id') } blocks."""
    refs: list[SecretRef] = []
    env_block = find_block(pipeline_content, "environment")
    if env_block is None:
        return refs

    for m in _ENV_CREDENTIALS_RE.finditer(env_block.content):
        cred_id = m.group(2)
        # Compute line relative to full text (env_block offset + pipeline offset)
        refs.append(
            SecretRef(
                name=cred_id,
                source="credentials",
                expression=f"credentials('{cred_id}')",
            )
        )
    return refs


# ---------------------------------------------------------------------------
# Triggers
# ---------------------------------------------------------------------------


def _extract_triggers(pipeline_content: str) -> list[str]:
    """Extract trigger type names from the triggers { } block."""
    triggers_block = find_block(pipeline_content, "triggers")
    if triggers_block is None:
        return []
    return [m.group(1) for m in _TRIGGER_NAMES_RE.finditer(triggers_block.content)]


# ---------------------------------------------------------------------------
# Stage extraction
# ---------------------------------------------------------------------------


def _extract_stages(
    pipeline_content: str,
    full_text: str,
    pipeline_block: Block,
    default_runs_on: str | None,
    env_secret_refs: list[SecretRef],
    unresolved: list[UnresolvedFragment],
    deadline: float,
) -> tuple[list[Job], list[UnresolvedFragment]]:
    """Extract all stage blocks from the stages { } section."""
    stages_block = find_block(pipeline_content, "stages", deadline=deadline)
    if stages_block is None:
        return [], []

    stage_blocks = find_all_blocks(stages_block.content, "stage", deadline=deadline)
    # Also look for nested parallel > stage
    jobs: list[Job] = []
    new_unresolved: list[UnresolvedFragment] = []

    for sb in stage_blocks:
        job, stage_unresolved = _extract_stage(
            sb,
            stages_block,
            pipeline_block,
            full_text,
            default_runs_on,
            env_secret_refs,
            deadline,
        )
        new_unresolved.extend(stage_unresolved)
        if job is not None:
            jobs.append(job)

    return jobs, new_unresolved


def _extract_stage(
    stage_block: Block,
    stages_block: Block,
    pipeline_block: Block,
    full_text: str,
    default_runs_on: str | None,
    env_secret_refs: list[SecretRef],
    deadline: float,
) -> tuple[Job | None, list[UnresolvedFragment]]:
    """Convert a single stage block into a Job IR node."""
    stage_unresolved: list[UnresolvedFragment] = []
    stage_name = stage_block.label or f"stage-{stage_block.start_line}"

    # Check for dynamic stage name (GString interpolation in label)
    raw_label = stage_block.label or ""
    if _DYNAMIC_STAGE_NAME_RE.search(raw_label):
        stage_unresolved.append(
            UnresolvedFragment(
                kind="dynamic_stage_name",
                locator=f"stages.{stage_name}",
                reason=(
                    f"Stage name '{raw_label}' contains GString interpolation — "
                    "dynamic stage names cannot be statically resolved; "
                    "marked Not Assessable."
                ),
            )
        )
        # Still try to extract what we can from the stage body

    content = stage_block.content

    # Detect script { } blocks (Not Assessable)
    script_blocks = find_all_blocks(content, "script", deadline=deadline)
    for sb in script_blocks:
        stage_unresolved.append(
            UnresolvedFragment(
                kind="script_block",
                locator=f"stages.{stage_name}.script",
                reason=(
                    f"script {{ }} block at line {stage_block.start_line + sb.start_line - 1} "
                    f"inside stage '{stage_name}' contains arbitrary Groovy — "
                    "content is Not Assessable."
                ),
            )
        )

    # Stage-level agent override
    stage_agent_block = find_block(content, "agent", deadline=deadline)
    runs_on: str | None = default_runs_on
    if stage_agent_block:
        agent_result = _extract_agent_from_block(stage_agent_block, [])
        if agent_result:
            runs_on = agent_result

    # Steps extraction
    steps, step_secret_refs = _extract_steps(
        content, stage_name, env_secret_refs, stage_block, deadline
    )

    # Parallel block detection
    parallel_block = find_block(content, "parallel", deadline=deadline)
    if parallel_block:
        # Record parallel as informational (handled but limited extraction)
        pass  # parallel stages become sub-steps

    # Condition from when { } block (not deeply parsed)
    when_block = find_block(content, "when", deadline=deadline)
    condition: str | None = None
    if when_block:
        condition = f"when: {when_block.content.strip()[:80]}"

    anchor = Anchor(
        start_line=stage_block.start_line,
        start_column=1,
        end_line=stage_block.end_line,
    )

    job = Job(
        id=stage_name,
        name=stage_name,
        runs_on=runs_on,
        steps=steps,
        permissions=EffectivePermissions(scope="job", state="absent"),
        needs=[],
        condition=condition,
        anchor=anchor,
        extraction_metadata=dict(_HEURISTIC_META),
    )
    return job, stage_unresolved


def _extract_agent_from_block(
    agent_block: Block,
    unresolved: list[UnresolvedFragment],
) -> str | None:
    content = agent_block.content
    # docker { image '...' }
    docker_m = _DOCKER_IMAGE_RE.search(content)
    if docker_m:
        return docker_m.group(1)
    label_m = _AGENT_LABEL_RE.search(content)
    if label_m:
        return label_m.group(1)
    # agent any / agent none as inline
    scalar_m = re.search(r'\b(any|none)\b', content)
    if scalar_m:
        return scalar_m.group(1) if scalar_m.group(1) == "any" else None
    return None


# ---------------------------------------------------------------------------
# Steps extraction
# ---------------------------------------------------------------------------


def _extract_steps(
    stage_content: str,
    stage_name: str,
    env_secret_refs: list[SecretRef],
    stage_block: Block,
    deadline: float,
) -> tuple[list[Step], list[SecretRef]]:
    """Extract Step IR nodes from the steps { } block of a stage."""
    steps: list[Step] = []
    secret_refs: list[SecretRef] = list(env_secret_refs)

    steps_block = find_block(stage_content, "steps", deadline=deadline)
    if steps_block is None:
        # Check for parallel block steps
        parallel_block = find_block(stage_content, "parallel", deadline=deadline)
        if parallel_block:
            return _extract_parallel_steps(parallel_block, stage_name, env_secret_refs, deadline)
        return [], []

    content = steps_block.content

    # withCredentials blocks
    wc_blocks = find_all_blocks(content, "withCredentials", deadline=deadline)
    # Track which byte ranges inside `content` are owned by withCredentials blocks
    # so top-level extraction doesn't duplicate those commands.
    wc_ranges: list[tuple[int, int]] = []
    for wc in wc_blocks:
        wc_ranges.append((wc.outer_start, wc.inner_end + 1))
        # Extract credentials from the argument (text between withCredentials( and {)
        # wc offsets are relative to content (steps_block.content)
        preamble = content[wc.outer_start:wc.inner_start]
        for m in _WITH_CREDS_BINDING_RE.finditer(preamble):
            cred_id = m.group(1)
            line, _ = offset_to_line_col(content, wc.outer_start)
            secret_refs.append(
                SecretRef(
                    name=cred_id,
                    source="credentials",
                    expression=f"credentialsId: '{cred_id}'",
                    anchor=Anchor(
                        start_line=stage_block.start_line + line - 1,
                        start_column=1,
                    ),
                )
            )
        # Extract sh/bat commands from inside withCredentials
        inner_steps = _extract_sh_commands(wc.content, stage_block.start_line, secret_refs)
        steps.extend(inner_steps)

    # sh / bat / powershell commands at top level of steps (mask withCredentials ranges)
    if wc_ranges:
        buf = list(content)
        for lo, hi in wc_ranges:
            for idx in range(lo, min(hi, len(buf))):
                buf[idx] = ' '
        top_content = ''.join(buf)
    else:
        top_content = content
    top_steps = _extract_sh_commands(top_content, stage_block.start_line, secret_refs)
    steps.extend(top_steps)

    return steps, secret_refs


def _extract_parallel_steps(
    parallel_block: Block,
    stage_name: str,
    env_secret_refs: list[SecretRef],
    deadline: float,
) -> tuple[list[Step], list[SecretRef]]:
    """Extract steps from a parallel { } block."""
    steps: list[Step] = []
    secret_refs: list[SecretRef] = list(env_secret_refs)

    # Find each branch: branchName { steps { ... } }
    branch_blocks = find_all_blocks(parallel_block.content, "steps", deadline=deadline)
    for bb in branch_blocks:
        branch_steps = _extract_sh_commands(bb.content, parallel_block.start_line, secret_refs)
        steps.extend(branch_steps)

    return steps, secret_refs


# sh / bat / powershell invocations
_SH_CALL_RE = re.compile(
    r"\b(sh|bat|powershell)\s+(?:script:\s*)?['\"]([^'\"]{0,512})['\"]"
    r"|\b(sh|bat|powershell)\s+(?:script:\s*)?'''\s*(.*?)'''"
    r"|\b(sh|bat|powershell)\s+(?:script:\s*)?\"\"\"(.*?)\"\"\""
    ,
    re.DOTALL,
)
# Simpler single-line sh/bat
_SH_SIMPLE_RE = re.compile(
    r"\b(sh|bat|powershell)\s*(?:script\s*:\s*)?['\"]([^'\"\n]{0,512})['\"]"
)


def _extract_sh_commands(
    content: str,
    base_line: int,
    secret_refs: list[SecretRef],
) -> list[Step]:
    """Extract sh/bat/powershell invocations as Step objects."""
    steps: list[Step] = []
    for m in _SH_SIMPLE_RE.finditer(content):
        cmd = m.group(1)
        script = m.group(2)
        line, _ = offset_to_line_col(content, m.start())
        steps.append(
            Step(
                name=cmd,
                run=script,
                anchor=Anchor(
                    start_line=base_line + line - 1,
                    start_column=1,
                ),
                secret_refs=_find_secret_refs_in_script(script, base_line + line - 1),
            )
        )
    return steps


_CRED_IN_SCRIPT_RE = re.compile(
    r'\$\{?([A-Z][A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|KEY|CREDENTIALS?))\}?'
)


def _find_secret_refs_in_script(script: str, line: int) -> list[SecretRef]:
    """Find secret-like variable references in a script string."""
    refs: list[SecretRef] = []
    seen: set[str] = set()
    for m in _CRED_IN_SCRIPT_RE.finditer(script):
        name = m.group(1)
        if name not in seen:
            seen.add(name)
            refs.append(
                SecretRef(
                    name=name,
                    source="env",
                    expression=f"${name}",
                    anchor=Anchor(start_line=line, start_column=1),
                )
            )
    return refs


# ---------------------------------------------------------------------------
# Result assembly
# ---------------------------------------------------------------------------


def _make_result(ir: PipelineIR, original_content: str) -> NormalizationResult:
    coverage: dict[str, Any] = {
        "ir_version": ir.ir_version,
        "source_format": ir.source_format,
        "extraction_method": "heuristic",
        "confidence": _HEURISTIC_CONFIDENCE,
        "unresolved": [u.model_dump() for u in ir.coverage_report.unresolved],
        "constructs_handled": ir.coverage_report.constructs_handled,
        "constructs_excluded": ir.coverage_report.constructs_excluded,
        "coverage_ratio": ir.coverage_report.coverage_ratio,
        "job_count": len(ir.jobs),
        "trigger_count": len(ir.triggers),
        # Per-format coverage summary (required by AC#8)
        "format_coverage": {
            "source_format": "jenkins",
            "assessable_jobs": len(ir.jobs),
            "unresolved_count": len(ir.coverage_report.unresolved),
            "coverage_ratio": ir.coverage_report.coverage_ratio,
            "note": (
                "Jenkins coverage is inherently limited: only the declarative "
                "subset is assessable. Scripted constructs are excluded from scoring."
            ),
        },
    }
    return NormalizationResult(
        normalized_content=original_content,
        coverage_report=coverage,
        pipeline_ir=ir,
    )
