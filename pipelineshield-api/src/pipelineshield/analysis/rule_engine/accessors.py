"""Rule-engine-level IR accessor helpers.

Rules MUST use these functions instead of accessing PipelineIR model fields
directly.  This indirection limits the blast radius of future IR field changes
to this file (and analysis/ir/accessors.py for the shared helpers).

All functions are pure: no side effects, no I/O.

These helpers extend (and in some cases wrap) the lower-level accessors in
pipelineshield.analysis.ir.accessors with rule-engine-specific semantics.
"""
from __future__ import annotations

from typing import Iterator

from pipelineshield.analysis.ir.pipeline_ir import (
    ActionRef,
    EffectivePermissions,
    Job,
    PipelineIR,
    SecretRef,
    Step,
    UnresolvedFragment,
)

__all__ = [
    "iter_jobs",
    "iter_steps",
    "iter_triggers",
    "effective_permissions",
    "iter_tool_invocations",
    "iter_action_refs",
    "iter_secret_refs",
    "fragment_resolution_status",
    "count_ir_nodes",
    "is_format_applicable",
]


def iter_jobs(ir: PipelineIR) -> Iterator[Job]:
    """Yield every job in the IR in document order."""
    yield from ir.jobs


def iter_steps(ir: PipelineIR) -> Iterator[tuple[Job, Step]]:
    """Yield (job, step) pairs for every step across all jobs."""
    for job in ir.jobs:
        for step in job.steps:
            yield job, step


def iter_triggers(ir: PipelineIR) -> Iterator[str]:
    """Yield every trigger event name (deduplicated, sorted by IR contract)."""
    yield from ir.triggers


def effective_permissions(ir: PipelineIR, job: Job) -> EffectivePermissions:
    """Return the resolved permissions for *job*, inheriting from workflow if needed.

    If the job has an explicit declaration (state != 'absent'), that wins.
    Otherwise the workflow-level declaration is returned with scope='workflow_inherited'.
    """
    if job.permissions.state != "absent":
        return job.permissions
    return EffectivePermissions(
        scope="workflow_inherited",
        state=ir.permissions.state,
        grants=dict(ir.permissions.grants),
        anchor=ir.permissions.anchor,
    )


def iter_tool_invocations(ir: PipelineIR) -> Iterator[tuple[Job, Step, ActionRef]]:
    """Yield (job, step, action_ref) for every step that invokes an external tool/action."""
    for job in ir.jobs:
        for step in job.steps:
            if step.action_ref is not None:
                yield job, step, step.action_ref


def iter_action_refs(ir: PipelineIR) -> Iterator[tuple[Job, Step, ActionRef]]:
    """Yield (job, step, action_ref) for every step that uses an action (alias for iter_tool_invocations)."""
    yield from iter_tool_invocations(ir)


def iter_secret_refs(ir: PipelineIR) -> Iterator[tuple[Job, Step, SecretRef]]:
    """Yield (job, step, secret_ref) for every secret reference across all steps."""
    for job in ir.jobs:
        for step in job.steps:
            for ref in step.secret_refs:
                yield job, step, ref


def fragment_resolution_status(ir: PipelineIR) -> dict[str, list[UnresolvedFragment]]:
    """Return unresolved fragments grouped by kind.

    Returns a dict mapping fragment kind → list of UnresolvedFragment objects.
    An empty dict means all constructs are fully resolved (assessable).
    """
    result: dict[str, list[UnresolvedFragment]] = {}
    for fragment in ir.coverage_report.unresolved:
        result.setdefault(fragment.kind, []).append(fragment)
    return result


def count_ir_nodes(ir: PipelineIR) -> int:
    """Count the total number of IR nodes (jobs + steps).

    Used by the engine's node-budget guard.
    """
    return sum(1 + len(job.steps) for job in ir.jobs)


def is_format_applicable(ir: PipelineIR, applicable_formats: set[str]) -> bool:
    """Return True if the IR's source_format is in *applicable_formats*."""
    return ir.source_format in applicable_formats
