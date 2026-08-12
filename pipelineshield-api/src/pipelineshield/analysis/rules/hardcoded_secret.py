"""Hardcoded-secret rule (sh-001).

Detects credential-shaped literal values committed directly in pipeline
definitions — in step env-var assignments and in shell run scripts.

SECURITY: findings must never echo the secret value.  Outcomes carry only
the source line anchor.  The rule must not include secret content in any
field of RuleOutcome (control_id, rule_id, evidence_kind, fingerprint, or
label fields on EvidenceAnchor).
"""
from __future__ import annotations

import re
from typing import Any, Iterator

from pipelineshield.analysis.ir.pipeline_ir import Anchor, PipelineIR
from pipelineshield.analysis.rule_engine.protocol import (
    EvidenceAnchor,
    RuleOutcome,
    RuleOutcomeVerdict,
)

__all__ = ["HardcodedSecretRule"]

# Keys that suggest a credential-shaped assignment
_CREDENTIAL_KEY_RE = re.compile(
    r"(?i)(secret|token|password|passwd|api_key|apikey|private_key|"
    r"auth|credential|cred|access_key|signing_key|encryption_key)",
)

# Template expressions are safe — they pull from secrets context
_TEMPLATE_EXPR_RE = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)

# Minimum value length to flag as a credential candidate
_MIN_CREDENTIAL_LEN = 8

# High-entropy string patterns that indicate a real credential value
_CREDENTIAL_VALUE_RE = re.compile(
    r"""(?x)
    # GitHub PAT / fine-grained PAT
    (?:ghp_|gho_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}
    |
    # AWS access key
    (?:A3T|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
    |
    # Generic long hex/base64 token (at least 32 chars, no whitespace)
    [A-Za-z0-9+/]{32,}={0,2}
    |
    # Generic high-entropy hex
    [0-9a-fA-F]{32,}
    """,
    re.VERBOSE,
)

# Assignment in shell: VAR=value or export VAR=value (not templates)
_SHELL_ASSIGN_RE = re.compile(
    r"(?i)(?:export\s+)?([A-Z_][A-Z0-9_]*)=([^\s\n\r]{8,})",
)


def _is_template(value: str) -> bool:
    """Return True if the value is purely a template expression."""
    stripped = value.strip()
    return bool(_TEMPLATE_EXPR_RE.fullmatch(stripped) or stripped.startswith("${{"))


def _looks_like_credential(value: str) -> bool:
    """Return True when the value pattern matches a known credential format."""
    if _is_template(value):
        return False
    return bool(_CREDENTIAL_VALUE_RE.search(value))


def _env_anchor(step_anchor: Anchor | None) -> EvidenceAnchor:
    if step_anchor is not None:
        return EvidenceAnchor(
            start_line=step_anchor.start_line,
            start_column=step_anchor.start_column,
        )
    return EvidenceAnchor(start_line=1, start_column=1)


def _run_line_anchor(step_anchor: Anchor | None, line_offset: int) -> EvidenceAnchor:
    base = step_anchor.start_line if step_anchor is not None else 1
    return EvidenceAnchor(start_line=base + line_offset, start_column=1)


class HardcodedSecretRule:
    """Detects credential-shaped literals in step env-vars and shell scripts.

    Outcomes carry only the line anchor — never the secret value.
    """

    rule_id = "hardcoded-secret"
    control_id = "sh-001"
    category = "secrets_hygiene"
    applicable_formats = frozenset({"github_actions", "gitlab_ci", "jenkins"})
    severity_key = "severity"
    evidence_kind = "hardcoded_credential"

    def anchor_extractor(self, ir: Any, node: Any) -> Iterator[EvidenceAnchor]:
        """Yield anchor for a step with a credential-shaped env-var value."""
        if hasattr(node, "anchor") and node.anchor is not None:
            yield EvidenceAnchor(
                start_line=node.anchor.start_line,
                start_column=node.anchor.start_column,
            )

    def evaluate(self, ir: PipelineIR, catalogue_snapshot: Any) -> Iterator[RuleOutcome]:
        """Scan all steps for hardcoded credential-shaped values."""
        for job in ir.jobs:
            for step in job.steps:
                yield from self._check_step(step)

    def _check_step(self, step: Any) -> Iterator[RuleOutcome]:
        # Check env-var dict values
        for key, value in sorted(step.env.items()):
            if _CREDENTIAL_KEY_RE.search(key) and _looks_like_credential(str(value)):
                anchor = _env_anchor(step.anchor)
                fp = RuleOutcome.compute_fingerprint(
                    self.rule_id, self.control_id, (anchor,)
                )
                yield RuleOutcome(
                    control_id=self.control_id,
                    rule_id=self.rule_id,
                    verdict=RuleOutcomeVerdict.VIOLATED,
                    # Anchor cites the line; secret value is NOT included
                    anchors=(anchor,),
                    evidence_kind=self.evidence_kind,
                    fingerprint=fp,
                )
                return  # one finding per step

        # Check run script lines
        if step.run is not None:
            for line_offset, line in enumerate(step.run.splitlines()):
                m = _SHELL_ASSIGN_RE.search(line)
                if m:
                    var_name = m.group(1)
                    var_value = m.group(2)
                    if _CREDENTIAL_KEY_RE.search(var_name) and _looks_like_credential(var_value):
                        anchor = _run_line_anchor(step.anchor, line_offset)
                        fp = RuleOutcome.compute_fingerprint(
                            self.rule_id, self.control_id, (anchor,)
                        )
                        yield RuleOutcome(
                            control_id=self.control_id,
                            rule_id=self.rule_id,
                            verdict=RuleOutcomeVerdict.VIOLATED,
                            # Anchor cites the line only; value is NOT included
                            anchors=(anchor,),
                            evidence_kind=self.evidence_kind,
                            fingerprint=fp,
                        )
                        return  # one finding per step
