"""Generic presence detector for all nine control categories.

A presence rule checks whether an IR contains evidence of a specific security
tool invocation.  Adding coverage for a new tool requires only a JSON edit to
data/tool_signatures.json — no rule code changes.

Outcome semantics:
  satisfied     — at least one matching tool invocation was found
  violated      — no matching invocation found; the control is missing
  not_assessable — the IR has unresolved fragments that may hide the tool,
                   OR the format is not supported for this category
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from pipelineshield.analysis.ir.pipeline_ir import Anchor, PipelineIR
from pipelineshield.analysis.rule_engine.protocol import (
    EvidenceAnchor,
    RuleOutcome,
    RuleOutcomeVerdict,
)

__all__ = [
    "PresenceRule",
    "load_tool_signatures",
    "SignatureLoadError",
]

_SIGNATURES_PATH = Path(__file__).parent / "data" / "tool_signatures.json"

_ALL_FORMATS = frozenset({"github_actions", "gitlab_ci", "jenkins"})


class SignatureLoadError(RuntimeError):
    """Raised when the tool signature file is missing or malformed."""


def load_tool_signatures() -> dict[str, Any]:
    """Load and return the tool signature map from disk.

    Raises SignatureLoadError if the file cannot be read or parsed.
    """
    try:
        raw = _SIGNATURES_PATH.read_text(encoding="utf-8")
        return json.loads(raw)
    except FileNotFoundError as exc:
        raise SignatureLoadError(
            f"Tool signatures file not found at {_SIGNATURES_PATH}. "
            "This file is required for presence detection."
        ) from exc
    except json.JSONDecodeError as exc:
        raise SignatureLoadError(
            f"Tool signatures file at {_SIGNATURES_PATH} is not valid JSON: {exc}"
        ) from exc


def _extract_anchor(anchor: Anchor | None) -> EvidenceAnchor:
    """Convert a PipelineIR Anchor to an EvidenceAnchor, defaulting to 1:1."""
    if anchor is not None:
        return EvidenceAnchor(
            start_line=anchor.start_line,
            start_column=anchor.start_column,
            end_line=anchor.end_line,
        )
    return EvidenceAnchor(start_line=1, start_column=1)


def _nominal_anchor(ir: PipelineIR) -> EvidenceAnchor:
    """Return a nominal document-level anchor for 'whole IR' violations."""
    if ir.trigger_anchor is not None:
        return _extract_anchor(ir.trigger_anchor)
    for job in ir.jobs:
        if job.anchor is not None:
            return _extract_anchor(job.anchor)
    return EvidenceAnchor(start_line=1, start_column=1)


def _action_name_matches(action_name: str, patterns: list[str]) -> bool:
    """Return True if the action name starts with any of the given prefixes."""
    a = action_name.lower()
    for pat in patterns:
        if a.startswith(pat.lower()):
            return True
    return False


def _run_contains_token(run_text: str, tokens: list[str]) -> bool:
    """Return True if any shell token appears in the run text (case-insensitive)."""
    lower = run_text.lower()
    for tok in tokens:
        if tok.lower() in lower:
            return True
    return False


def _image_matches(image_name: str, patterns: list[str]) -> bool:
    """Return True if the image name contains any pattern (case-insensitive)."""
    lower = image_name.lower()
    for pat in patterns:
        if pat.lower() in lower:
            return True
    return False


class PresenceRule:
    """Generic presence detector parameterized by category and signature set.

    One instance covers one control ID.  Extend detection coverage by editing
    data/tool_signatures.json; no code changes required.
    """

    def __init__(
        self,
        rule_id: str,
        control_id: str,
        category: str,
        action_patterns: list[str],
        image_patterns: list[str],
        shell_tokens: list[str],
        applicable_formats: frozenset[str] | None = None,
    ) -> None:
        self.rule_id = rule_id
        self.control_id = control_id
        self.category = category
        self.applicable_formats: frozenset[str] = applicable_formats or _ALL_FORMATS
        self.severity_key = "severity"
        self.evidence_kind = "tool_presence"
        # Sorted for determinism
        self._action_patterns: list[str] = sorted(action_patterns)
        self._image_patterns: list[str] = sorted(image_patterns)
        self._shell_tokens: list[str] = sorted(shell_tokens)

    def anchor_extractor(self, ir: Any, node: Any) -> Iterator[EvidenceAnchor]:
        """Yield an anchor for a matched tool invocation step."""
        if hasattr(node, "anchor") and node.anchor is not None:
            yield _extract_anchor(node.anchor)

    def evaluate(self, ir: PipelineIR, catalogue_snapshot: Any) -> Iterator[RuleOutcome]:
        """Check whether any step invokes a matching tool.

        Returns:
          satisfied   — matching tool found
          violated    — no tool found; yields single outcome with nominal anchor
          not_assessable — IR has unresolved fragments that may hide the tool
        """
        # Check for unresolved fragments — they may contain tool invocations
        has_unresolved = bool(ir.coverage_report.unresolved)

        found_anchor: EvidenceAnchor | None = None

        for job in ir.jobs:
            # Check image/runs_on for tool presence
            runs_on = job.runs_on
            if runs_on and isinstance(runs_on, str):
                if _image_matches(runs_on, self._image_patterns):
                    anchor = _extract_anchor(job.anchor)
                    found_anchor = anchor
                    break

            for step in job.steps:
                # Check action reference names
                if step.action_ref is not None:
                    if _action_name_matches(step.action_ref.name, self._action_patterns):
                        a = step.action_ref.anchor or step.anchor
                        found_anchor = _extract_anchor(a)
                        break

                # Check shell run scripts for tool invocations
                if step.run is not None:
                    if _run_contains_token(step.run, self._shell_tokens):
                        found_anchor = _extract_anchor(step.anchor)
                        break

            if found_anchor is not None:
                break

        if found_anchor is not None:
            fp = RuleOutcome.compute_fingerprint(self.rule_id, self.control_id, (found_anchor,))
            yield RuleOutcome(
                control_id=self.control_id,
                rule_id=self.rule_id,
                verdict=RuleOutcomeVerdict.SATISFIED,
                anchors=(found_anchor,),
                evidence_kind=self.evidence_kind,
                fingerprint=fp,
            )
            return

        if has_unresolved:
            # Cannot confirm absence — unresolved fragments may contain the tool
            fp = RuleOutcome.compute_fingerprint(self.rule_id, self.control_id, ())
            yield RuleOutcome(
                control_id=self.control_id,
                rule_id=self.rule_id,
                verdict=RuleOutcomeVerdict.NOT_ASSESSABLE,
                anchors=(),
                evidence_kind=self.evidence_kind,
                fingerprint=fp,
            )
            return

        # Tool not found — violated with nominal anchor
        nominal = _nominal_anchor(ir)
        fp = RuleOutcome.compute_fingerprint(self.rule_id, self.control_id, (nominal,))
        yield RuleOutcome(
            control_id=self.control_id,
            rule_id=self.rule_id,
            verdict=RuleOutcomeVerdict.VIOLATED,
            anchors=(nominal,),
            evidence_kind=self.evidence_kind,
            fingerprint=fp,
        )


def build_presence_rules(signatures: dict[str, Any]) -> list[PresenceRule]:
    """Construct one PresenceRule per category entry in the signatures dict.

    The list is sorted by rule_id for determinism.
    """
    rules: list[PresenceRule] = []
    for category_key, entry in sorted(signatures.items()):
        control_id = entry["control_id"]
        rule_id = f"presence-{category_key.replace('_', '-')}"

        # Approval gates: only Jenkins supports IR-level detection
        if category_key == "approval_gates":
            applicable_formats: frozenset[str] = frozenset({"jenkins"})
        else:
            applicable_formats = _ALL_FORMATS

        rules.append(
            PresenceRule(
                rule_id=rule_id,
                control_id=control_id,
                category=category_key,
                action_patterns=entry.get("action_patterns", []),
                image_patterns=entry.get("image_patterns", []),
                shell_tokens=entry.get("shell_tokens", []),
                applicable_formats=applicable_formats,
            )
        )
    return rules
