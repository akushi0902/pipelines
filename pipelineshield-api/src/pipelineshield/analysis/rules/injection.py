"""Expression injection rule (sci-002).

Detects direct interpolation of untrusted GitHub Actions context values into
shell run blocks.  If the value flows through an env-var first, it is treated
as mitigated and NOT flagged.

Untrusted contexts:
  github.event.issue.title / body
  github.event.pull_request.title / body / head.ref / head.label
  github.event.comment.body
  github.event.review.body / review_comment.body
  github.head_ref
  github.event.workflow_run.head_branch / head_commit.message

Safe pattern (env-var indirection):
  env:
    TITLE: ${{ github.event.issue.title }}  # env assignment is safe
  run: echo "$TITLE"                         # shell uses env var, not direct expr
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

__all__ = ["ExpressionInjectionRule"]

# Untrusted context expressions — these should never appear directly in run:
_UNTRUSTED_CONTEXTS = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.head_ref",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
]

# Pattern matching ${{ <context> }} with optional whitespace
_EXPR_TEMPLATE_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.DOTALL)


def _is_mitigated_by_env(context_expr: str, step_env: dict[str, str]) -> bool:
    """Return True when the context expression is assigned to a step env-var.

    If the step has `env: { MY_VAR: "${{ github.event.issue.title }}" }`, then
    uses of $MY_VAR in the run script are safe (not a direct injection path).
    """
    for env_value in step_env.values():
        # Check if the env var value contains this context expression
        for m in _EXPR_TEMPLATE_RE.finditer(env_value):
            if m.group(1).strip() == context_expr:
                return True
    return False


class ExpressionInjectionRule:
    """Flags direct interpolation of untrusted contexts into shell run blocks.

    Only applicable to github_actions format — GitLab CI and Jenkins do not
    use the ${{ context }} expression syntax.
    """

    rule_id = "expression-injection"
    control_id = "sci-002"
    category = "supply_chain_integrity"
    applicable_formats = frozenset({"github_actions"})
    severity_key = "severity"
    evidence_kind = "expression_injection"

    def anchor_extractor(self, ir: Any, node: Any) -> Iterator[EvidenceAnchor]:
        """Yield anchors for lines with direct context interpolation."""
        if hasattr(node, "anchor") and node.anchor is not None:
            yield EvidenceAnchor(
                start_line=node.anchor.start_line,
                start_column=node.anchor.start_column,
            )

    def evaluate(self, ir: PipelineIR, catalogue_snapshot: Any) -> Iterator[RuleOutcome]:
        """Scan run blocks for direct untrusted context interpolation."""
        for job in ir.jobs:
            for step in job.steps:
                if step.run is None:
                    continue
                yield from self._check_step(step)

    def _check_step(self, step: Any) -> Iterator[RuleOutcome]:
        run_text = step.run
        if not run_text:
            return

        base_line = step.anchor.start_line if step.anchor is not None else 1

        for line_offset, line in enumerate(run_text.splitlines()):
            for m in _EXPR_TEMPLATE_RE.finditer(line):
                context_expr = m.group(1).strip()
                if context_expr not in _UNTRUSTED_CONTEXTS:
                    continue
                # Check env-var indirection mitigation
                if _is_mitigated_by_env(context_expr, step.env):
                    continue
                anchor = EvidenceAnchor(
                    start_line=base_line + line_offset,
                    start_column=m.start() + 1,
                    label=f"untrusted-context:{context_expr}",
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
