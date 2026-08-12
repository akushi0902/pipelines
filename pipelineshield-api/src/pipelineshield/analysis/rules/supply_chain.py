"""Supply-chain integrity rules.

UnpinnedActionRule (sci-001):
  Third-party actions must be pinned to a 40-hex commit SHA.  Mutable
  tag or branch references are flagged as violated.

  Local actions (./path) and docker:// references are excluded — they
  do not have the same supply-chain pin semantics.
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

__all__ = ["UnpinnedActionRule"]

# Pin forms that are immutable (only sha is secure)
_MUTABLE_PIN_FORMS = frozenset({"tag", "branch"})

# GitHub's known first-party action namespace — pinning SHA is still best
# practice even here, but the rule applies to all third-party AND first-party
# references equally (the WO says "third-party actions and container images")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40,}$")


class UnpinnedActionRule:
    """Flags action uses: values pinned to a mutable tag or branch."""

    rule_id = "unpinned-action-ref"
    control_id = "sci-001"
    category = "supply_chain_integrity"
    applicable_formats = frozenset({"github_actions"})
    severity_key = "severity"
    evidence_kind = "action_ref"

    def anchor_extractor(self, ir: Any, node: Any) -> Iterator[EvidenceAnchor]:
        """Yield anchor for the uses: line of a mutable action reference."""
        if hasattr(node, "anchor") and node.anchor is not None:
            yield EvidenceAnchor(
                start_line=node.anchor.start_line,
                start_column=node.anchor.start_column,
            )

    def evaluate(self, ir: PipelineIR, catalogue_snapshot: Any) -> Iterator[RuleOutcome]:
        """Scan all action_refs for mutable pin forms."""
        for job in ir.jobs:
            for step in job.steps:
                if step.action_ref is None:
                    continue
                ref = step.action_ref
                # Skip local and docker references
                if ref.pin_form in ("local", "docker"):
                    continue
                if ref.pin_form not in _MUTABLE_PIN_FORMS:
                    continue

                # Use the action_ref anchor, falling back to the step anchor
                raw_anchor = ref.anchor or step.anchor
                anchor = EvidenceAnchor(
                    start_line=raw_anchor.start_line if raw_anchor else 1,
                    start_column=raw_anchor.start_column if raw_anchor else 1,
                    label=f"mutable-pin:{ref.version_ref or '?'}",
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
