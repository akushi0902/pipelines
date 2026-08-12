"""Accessor helpers for PipelineIR.

Rules MUST use these functions instead of accessing IR model fields directly.
This indirection limits the blast radius of future field changes to this file.

All functions are pure: no side effects, no I/O.
"""
from __future__ import annotations

from typing import Iterator

from .pipeline_ir import (
    ActionRef,
    EffectivePermissions,
    Job,
    PipelineIR,
    SecretRef,
    Step,
    UnresolvedFragment,
)

__all__ = [
    "get_triggers",
    "has_trigger",
    "has_dangerous_triggers",
    "get_jobs",
    "get_steps",
    "get_action_refs",
    "get_secret_refs",
    "get_effective_permissions",
    "iter_all_secret_refs",
    "iter_all_action_refs",
    "get_unresolved",
    "is_schema_valid",
]

# ---------------------------------------------------------------------------
# Trigger accessors
# ---------------------------------------------------------------------------


def get_triggers(ir: PipelineIR) -> list[str]:
    """Return the list of event triggers for this pipeline."""
    return list(ir.triggers)


def has_trigger(ir: PipelineIR, event: str) -> bool:
    """Return True if the pipeline is triggered by *event*."""
    return event in ir.triggers


def has_dangerous_triggers(ir: PipelineIR) -> bool:
    """Return True if any high-severity trigger is present.

    pull_request_target and workflow_run are considered high-severity because
    they execute with write permissions even for untrusted fork PRs.
    """
    return has_trigger(ir, "pull_request_target") or has_trigger(ir, "workflow_run")


# ---------------------------------------------------------------------------
# Job/step accessors
# ---------------------------------------------------------------------------


def get_jobs(ir: PipelineIR) -> list[Job]:
    """Return all jobs in document order."""
    return list(ir.jobs)


def get_steps(job: Job) -> list[Step]:
    """Return all steps for *job*."""
    return list(job.steps)


def get_action_refs(step: Step) -> list[ActionRef]:
    """Return the action ref for *step*, or an empty list if it has none."""
    if step.action_ref is not None:
        return [step.action_ref]
    return []


def get_secret_refs(step: Step) -> list[SecretRef]:
    """Return all secret references found in *step*."""
    return list(step.secret_refs)


# ---------------------------------------------------------------------------
# Iterator helpers for rule-wide scans
# ---------------------------------------------------------------------------


def iter_all_action_refs(ir: PipelineIR) -> Iterator[tuple[str, str, ActionRef]]:
    """Yield (job_id, step_index, action_ref) for every step with an action ref."""
    for job in ir.jobs:
        for idx, step in enumerate(job.steps):
            if step.action_ref is not None:
                yield job.id, str(idx), step.action_ref


def iter_all_secret_refs(ir: PipelineIR) -> Iterator[tuple[str, str, SecretRef]]:
    """Yield (job_id, step_index, secret_ref) for every secret reference."""
    for job in ir.jobs:
        for idx, step in enumerate(job.steps):
            for ref in step.secret_refs:
                yield job.id, str(idx), ref


# ---------------------------------------------------------------------------
# Permissions accessor
# ---------------------------------------------------------------------------


def get_effective_permissions(ir: PipelineIR, job: Job) -> EffectivePermissions:
    """Return the effective permissions for *job*.

    If the job has an explicit declaration (state != 'absent'), that wins.
    Otherwise the workflow-level declaration is returned with
    scope='workflow_inherited'.
    """
    if job.permissions.state != "absent":
        return job.permissions
    # Inherit from workflow
    return EffectivePermissions(
        scope="workflow_inherited",
        state=ir.permissions.state,
        grants=dict(ir.permissions.grants),
        anchor=ir.permissions.anchor,
    )


# ---------------------------------------------------------------------------
# Coverage accessors
# ---------------------------------------------------------------------------


def get_unresolved(ir: PipelineIR) -> list[UnresolvedFragment]:
    """Return all unresolved fragments from the coverage report."""
    return list(ir.coverage_report.unresolved)


# ---------------------------------------------------------------------------
# Validation gate helper
# ---------------------------------------------------------------------------


def is_schema_valid(ir: PipelineIR) -> bool:
    """Return True if *ir* is a valid PipelineIR instance.

    Pydantic validates on construction so this will always return True for
    objects that were successfully constructed.  It exists as a named gate
    point so tests and the orchestrator can call it explicitly.
    """
    return isinstance(ir, PipelineIR)
