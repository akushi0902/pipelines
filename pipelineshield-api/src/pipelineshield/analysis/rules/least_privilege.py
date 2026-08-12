"""Least-privilege identity rules (lp-001).

Detects missing or overly broad permissions on GitHub Actions workflows.

Permission-precedence semantics:
  Job-level permissions block overrides workflow-level for that job.
  Absence of both is reported once at workflow scope.

Violations flagged:
  1. No permissions block at all (absent at workflow level and all jobs)
     — GitHub default grants write to all scopes for classic PAT scenarios.
  2. Workflow-level write-all — explicitly grants write to every scope.
  3. Job-level write-all — explicitly grants write to every scope for a job.

Satisfied condition:
  At least one explicit permissions block is present at workflow or job level
  with non-write-all state.

Note: GitLab CI and Jenkins do not use the GitHub permissions: key, so this
rule is GitHub Actions only.  GitLab token scope restriction cannot be
detected from IR alone (it requires project-level configuration).
"""
from __future__ import annotations

from typing import Any, Iterator

from pipelineshield.analysis.ir.pipeline_ir import PipelineIR
from pipelineshield.analysis.rule_engine.protocol import (
    EvidenceAnchor,
    RuleOutcome,
    RuleOutcomeVerdict,
)

__all__ = ["LeastPrivilegeRule"]


def _anchor_from(obj: Any, default_line: int = 1) -> EvidenceAnchor:
    if obj is not None and hasattr(obj, "anchor") and obj.anchor is not None:
        return EvidenceAnchor(
            start_line=obj.anchor.start_line,
            start_column=obj.anchor.start_column,
        )
    return EvidenceAnchor(start_line=default_line, start_column=1)


class LeastPrivilegeRule:
    """Detects absent or write-all permissions on GitHub Actions workflows."""

    rule_id = "least-privilege-permissions"
    control_id = "lp-001"
    category = "least_privilege"
    applicable_formats = frozenset({"github_actions"})
    severity_key = "severity"
    evidence_kind = "permissions_declaration"

    def anchor_extractor(self, ir: Any, node: Any) -> Iterator[EvidenceAnchor]:
        if hasattr(node, "anchor") and node.anchor is not None:
            yield EvidenceAnchor(
                start_line=node.anchor.start_line,
                start_column=node.anchor.start_column,
            )

    def evaluate(self, ir: PipelineIR, catalogue_snapshot: Any) -> Iterator[RuleOutcome]:
        """Check workflow and per-job permissions for absent or write-all state."""
        wf_perms = ir.permissions
        wf_state = wf_perms.state  # "absent" | "empty" | "write_all" | "explicit"

        # Track whether any explicit (non-absent, non-write_all) declaration exists
        any_explicit = False

        # Workflow-level violations
        if wf_state == "write_all":
            anchor = _anchor_from(wf_perms)
            yield self._violated(anchor, "workflow-level write-all permissions")
            return

        if wf_state == "explicit":
            any_explicit = True

        # Per-job checks
        for job in ir.jobs:
            job_perms = job.permissions
            job_state = job_perms.state

            if job_state == "write_all":
                anchor = _anchor_from(job_perms, job.anchor.start_line if job.anchor else 1)
                yield self._violated(anchor, f"job {job.id!r} write-all permissions")
                return

            if job_state == "explicit":
                any_explicit = True

        # If no explicit permission block found anywhere
        if not any_explicit and wf_state == "absent":
            # Report at workflow scope (trigger_anchor or line 1)
            if ir.trigger_anchor is not None:
                anchor = EvidenceAnchor(
                    start_line=ir.trigger_anchor.start_line,
                    start_column=ir.trigger_anchor.start_column,
                )
            else:
                anchor = EvidenceAnchor(start_line=1, start_column=1)
            yield self._violated(anchor, "no permissions block defined")
            return

        # Permissions are explicitly declared and not write-all → satisfied
        best_anchor: EvidenceAnchor | None = None
        if wf_state == "explicit" and wf_perms.anchor is not None:
            best_anchor = EvidenceAnchor(
                start_line=wf_perms.anchor.start_line,
                start_column=wf_perms.anchor.start_column,
            )
        if best_anchor is None:
            best_anchor = EvidenceAnchor(start_line=1, start_column=1)

        fp = RuleOutcome.compute_fingerprint(self.rule_id, self.control_id, (best_anchor,))
        yield RuleOutcome(
            control_id=self.control_id,
            rule_id=self.rule_id,
            verdict=RuleOutcomeVerdict.SATISFIED,
            anchors=(best_anchor,),
            evidence_kind=self.evidence_kind,
            fingerprint=fp,
        )

    def _violated(self, anchor: EvidenceAnchor, label: str) -> RuleOutcome:
        fp = RuleOutcome.compute_fingerprint(self.rule_id, self.control_id, (anchor,))
        return RuleOutcome(
            control_id=self.control_id,
            rule_id=self.rule_id,
            verdict=RuleOutcomeVerdict.VIOLATED,
            anchors=(anchor,),
            evidence_kind=self.evidence_kind,
            fingerprint=fp,
        )
