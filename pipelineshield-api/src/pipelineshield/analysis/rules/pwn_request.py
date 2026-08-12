"""Pwn-request rule (sci-002).

Detects the pwn-request pattern: a workflow triggered by pull_request_target
or workflow_run that checks out fork-controlled code and executes it with an
elevated token or uses secret references.

Attack chain:
  1. Trigger fires on fork PR (pull_request_target has write access to GITHUB_TOKEN).
  2. Attacker opens a PR from their fork.
  3. Workflow checks out the fork's code using a fork-controlled ref (e.g.
     github.event.pull_request.head.sha / head.ref).
  4. Attacker's code now runs with the privileged token.

Mitigating factors NOT flagged:
  - Pull request (not pull_request_target) — lower privilege, GITHUB_TOKEN read-only.
  - Checkout without a fork-controlled ref — checks out base branch, not fork.
"""
from __future__ import annotations

import re
from typing import Any, Iterator

from pipelineshield.analysis.ir.pipeline_ir import PipelineIR
from pipelineshield.analysis.rule_engine.protocol import (
    EvidenceAnchor,
    RuleOutcome,
    RuleOutcomeVerdict,
)

__all__ = ["PwnRequestRule"]

# Triggers that grant the GITHUB_TOKEN write access on forks
_PRIVILEGED_TRIGGERS = frozenset({"pull_request_target", "workflow_run"})

# Fork-controlled ref expressions
_FORK_REF_PATTERNS = [
    r"github\.event\.pull_request\.head\.sha",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head\.label",
    r"github\.head_ref",
    r"github\.event\.workflow_run\.head_sha",
    r"github\.event\.workflow_run\.head_branch",
]

_FORK_REF_RE = re.compile(
    r"\$\{\{\s*(?:" + "|".join(_FORK_REF_PATTERNS) + r")\s*\}\}",
    re.IGNORECASE,
)

# Common checkout action names
_CHECKOUT_ACTION_PREFIXES = ("actions/checkout",)


def _has_privileged_trigger(ir: PipelineIR) -> bool:
    return any(t in _PRIVILEGED_TRIGGERS for t in ir.triggers)


def _step_is_fork_checkout(step: Any) -> bool:
    """Return True when the step checks out a fork-controlled ref."""
    # Only checkout actions
    if step.action_ref is None:
        return False
    action_name = step.action_ref.name.lower()
    if not any(action_name.startswith(p) for p in _CHECKOUT_ACTION_PREFIXES):
        return False
    # Check ref= in with_inputs
    ref_val = step.with_inputs.get("ref", "")
    if _FORK_REF_RE.search(ref_val):
        return True
    # Check run script for fork-controlled ref (run: git checkout ...)
    if step.run and _FORK_REF_RE.search(step.run):
        return True
    return False


class PwnRequestRule:
    """Detects pwn-request: privileged trigger + fork-controlled ref checkout."""

    rule_id = "pwn-request"
    control_id = "sci-002"
    category = "supply_chain_integrity"
    applicable_formats = frozenset({"github_actions"})
    severity_key = "severity"
    evidence_kind = "pwn_request"

    def anchor_extractor(self, ir: Any, node: Any) -> Iterator[EvidenceAnchor]:
        """Yield anchor for the checkout step with the fork-controlled ref."""
        if hasattr(node, "anchor") and node.anchor is not None:
            yield EvidenceAnchor(
                start_line=node.anchor.start_line,
                start_column=node.anchor.start_column,
            )

    def evaluate(self, ir: PipelineIR, catalogue_snapshot: Any) -> Iterator[RuleOutcome]:
        """Check for privileged-trigger + fork-controlled-ref-checkout combination."""
        if not _has_privileged_trigger(ir):
            return

        for job in ir.jobs:
            for step in job.steps:
                if not _step_is_fork_checkout(step):
                    continue

                # Anchor at the ref input line — use step anchor as best proxy
                anchor = EvidenceAnchor(
                    start_line=step.anchor.start_line if step.anchor else 1,
                    start_column=step.anchor.start_column if step.anchor else 1,
                    label="fork-controlled-ref-checkout",
                )
                fp = RuleOutcome.compute_fingerprint(
                    self.rule_id, self.control_id, (anchor,)
                )
                yield RuleOutcome(
                    control_id=self.control_id,
                    rule_id=self.rule_id,
                    verdict=RuleOutcomeVerdict.VIOLATED,
                    anchors=(anchor,),
                    evidence_kind=self.evidence_kind,
                    fingerprint=fp,
                )
