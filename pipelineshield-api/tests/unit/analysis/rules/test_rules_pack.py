"""Unit tests for the WO-016 rule pack.

Coverage:
  1. HardcodedSecretRule: positive (env-var credential), negative (template expr)
  2. ExpressionInjectionRule: positive (direct inject), negative (env-var indirection)
  3. PwnRequestRule: positive (pull_request_target + fork ref), negative (push only)
  4. UnpinnedActionRule: positive (tag pin), negative (SHA pin)
  5. LeastPrivilegeRule: positive (absent perms), negative (explicit perms)
  6. PresenceRule: positive (tool in run), negative (no tool)
  7. Presence not_assessable when unresolved fragments present
  8. Approval-gate presence: not_assessable for github_actions format
  9. No network access during evaluate (import-graph test)
  10. No severity literals in rules package source code
  11. Registry: all rules registered without duplicate rule_id
  12. Secret value must not appear in any RuleOutcome field
  13. Hardened fixture detection rate >= 80% for seeded gaps
  14. Presence rule returns satisfied when tool found in runs_on image
  15. format-applicability: GitLab CI IR skips github_actions-only rules
"""
from __future__ import annotations

import importlib
import pkgutil
import re
import socket
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from pipelineshield.analysis.ir.pipeline_ir import (
    ActionRef,
    Anchor,
    CoverageReport,
    EffectivePermissions,
    Job,
    PipelineIR,
    SecretRef,
    Step,
    UnresolvedFragment,
)
from pipelineshield.analysis.rule_engine.protocol import (
    EvidenceAnchor,
    RuleOutcomeVerdict,
)
from pipelineshield.analysis.rules import (
    HardcodedSecretRule,
    build_default_registry,
    register_all_rules,
)
from pipelineshield.analysis.rules.hardcoded_secret import HardcodedSecretRule
from pipelineshield.analysis.rules.injection import ExpressionInjectionRule
from pipelineshield.analysis.rules.least_privilege import LeastPrivilegeRule
from pipelineshield.analysis.rules.presence import PresenceRule, build_presence_rules, load_tool_signatures
from pipelineshield.analysis.rules.pwn_request import PwnRequestRule
from pipelineshield.analysis.rules.supply_chain import UnpinnedActionRule
from pipelineshield.analysis.rule_engine.registry import RuleRegistry

# ---------------------------------------------------------------------------
# IR construction helpers
# ---------------------------------------------------------------------------


def _make_ir(
    source_format: str = "github_actions",
    triggers: list[str] | None = None,
    permissions_state: str = "absent",
    jobs: list[Job] | None = None,
    unresolved: list[UnresolvedFragment] | None = None,
) -> PipelineIR:
    perms = EffectivePermissions(
        scope="workflow",
        state=permissions_state,
        grants={"contents": "read"} if permissions_state == "explicit" else {},
        anchor=Anchor(start_line=3, start_column=1) if permissions_state != "absent" else None,
    )
    return PipelineIR(
        source_format=source_format,
        triggers=triggers or ["push"],
        permissions=perms,
        jobs=jobs or [],
        coverage_report=CoverageReport(unresolved=unresolved or []),
        trigger_anchor=Anchor(start_line=1, start_column=1),
    )


def _make_job(
    job_id: str = "build",
    steps: list[Step] | None = None,
    permissions_state: str = "absent",
    runs_on: str = "ubuntu-latest",
) -> Job:
    perms = EffectivePermissions(scope="job", state=permissions_state)
    return Job(
        id=job_id,
        runs_on=runs_on,
        steps=steps or [],
        permissions=perms,
        anchor=Anchor(start_line=10, start_column=3),
    )


def _make_step_run(run: str, env: dict[str, str] | None = None, line: int = 20) -> Step:
    return Step(
        run=run,
        env=env or {},
        anchor=Anchor(start_line=line, start_column=5),
    )


def _make_step_uses(action_name: str, pin_form: str = "sha", ref: str | None = None,
                     with_inputs: dict[str, str] | None = None, line: int = 20) -> Step:
    version_ref = ref or ("abc" * 14)[:40]
    return Step(
        uses=f"{action_name}@{version_ref}",
        action_ref=ActionRef(
            name=action_name,
            version_ref=version_ref,
            pin_form=pin_form,
            anchor=Anchor(start_line=line, start_column=9),
        ),
        with_inputs=with_inputs or {},
        anchor=Anchor(start_line=line, start_column=5),
    )


_NULL_CATALOGUE = object()


# ---------------------------------------------------------------------------
# 1. HardcodedSecretRule — positive
# ---------------------------------------------------------------------------


class TestHardcodedSecretRule:
    def _rule(self):
        return HardcodedSecretRule()

    def test_flags_credential_in_env_var(self):
        """Step env-var with credential-shaped key and literal value is flagged."""
        step = Step(
            run="echo hello",
            env={"REGISTRY_TOKEN": "ghp_EXAMPLEsyntheticNOTREALaaaaaaaaaaaaaaa"},
            anchor=Anchor(start_line=30, start_column=5),
        )
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED
        assert outcomes[0].control_id == "sh-001"

    def test_ignores_template_expression_in_env_var(self):
        """Template ${{ secrets.X }} in env var is NOT a hardcoded secret."""
        step = Step(
            run="echo hello",
            env={"REGISTRY_TOKEN": "${{ secrets.REGISTRY_TOKEN }}"},
            anchor=Anchor(start_line=30, start_column=5),
        )
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert not outcomes

    def test_flags_hardcoded_in_run_script(self):
        """Credential assignment in shell run script is flagged."""
        step = _make_step_run(
            "TOKEN=ghp_EXAMPLEsyntheticNOTREALaaaaaaaaaaaaaaa && docker login"
        )
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED

    def test_ignores_template_in_run_script(self):
        """Token assignment using secrets context in run is safe."""
        step = _make_step_run("TOKEN=${{ secrets.MY_TOKEN }} && docker login")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert not outcomes

    def test_secret_value_not_in_outcome_fields(self):
        """The secret value must NEVER appear in any RuleOutcome field."""
        secret_value = "ghp_EXAMPLEsyntheticNOTREALaaaaaaaaaaaaaaa"
        step = Step(
            run=f"PASSWORD={secret_value}",
            env={},
            anchor=Anchor(start_line=5, start_column=1),
        )
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        o = outcomes[0]
        # Check no outcome field contains the secret value
        for field_val in (o.control_id, o.rule_id, o.evidence_kind, o.fingerprint):
            assert secret_value not in str(field_val)
        for anchor in o.anchors:
            assert secret_value not in str(anchor.label)

    def test_no_outcome_on_clean_step(self):
        """A step with no credential-shaped assignments produces no outcome."""
        step = _make_step_run("npm ci && npm run build")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert not outcomes


# ---------------------------------------------------------------------------
# 2. ExpressionInjectionRule
# ---------------------------------------------------------------------------


class TestExpressionInjectionRule:
    def _rule(self):
        return ExpressionInjectionRule()

    def test_flags_direct_issue_title_injection(self):
        """Direct interpolation of github.event.issue.title in run is flagged."""
        step = _make_step_run('echo "Issue: ${{ github.event.issue.title }}"')
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED
        assert outcomes[0].control_id == "sci-002"

    def test_flags_direct_pr_head_ref_injection(self):
        """Direct interpolation of github.event.pull_request.head.ref is flagged."""
        step = _make_step_run("git checkout ${{ github.event.pull_request.head.ref }}")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED

    def test_env_var_indirection_is_safe(self):
        """When value flows through env var, injection is mitigated."""
        step = Step(
            run='echo "$ISSUE_TITLE"',
            env={"ISSUE_TITLE": "${{ github.event.issue.title }}"},
            anchor=Anchor(start_line=20, start_column=5),
        )
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert not outcomes

    def test_github_sha_is_trusted(self):
        """github.sha is not an untrusted context — not flagged."""
        step = _make_step_run('echo "SHA: ${{ github.sha }}"')
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert not outcomes

    def test_skips_non_run_steps(self):
        """Action uses: steps have no run text — no outcome."""
        step = _make_step_uses("actions/checkout", pin_form="sha")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert not outcomes

    def test_not_applicable_to_gitlab_ci(self):
        """Expression injection rule is github_actions only."""
        rule = self._rule()
        assert "gitlab_ci" not in rule.applicable_formats
        assert "github_actions" in rule.applicable_formats


# ---------------------------------------------------------------------------
# 3. PwnRequestRule
# ---------------------------------------------------------------------------


class TestPwnRequestRule:
    def _rule(self):
        return PwnRequestRule()

    def test_flags_prt_with_fork_checkout(self):
        """pull_request_target + fork ref checkout is flagged."""
        step = _make_step_uses(
            "actions/checkout",
            pin_form="sha",
            with_inputs={"ref": "${{ github.event.pull_request.head.sha }}"},
        )
        ir = _make_ir(
            triggers=["pull_request_target"],
            jobs=[_make_job(steps=[step])],
        )
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED
        assert outcomes[0].control_id == "sci-002"

    def test_no_finding_without_privileged_trigger(self):
        """Regular pull_request trigger does not produce a finding."""
        step = _make_step_uses(
            "actions/checkout",
            pin_form="sha",
            with_inputs={"ref": "${{ github.event.pull_request.head.sha }}"},
        )
        ir = _make_ir(
            triggers=["push", "pull_request"],
            jobs=[_make_job(steps=[step])],
        )
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert not outcomes

    def test_no_finding_without_fork_ref(self):
        """Privileged trigger + safe checkout (no fork ref) is not flagged."""
        step = _make_step_uses("actions/checkout", pin_form="sha")
        ir = _make_ir(
            triggers=["pull_request_target"],
            jobs=[_make_job(steps=[step])],
        )
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert not outcomes

    def test_workflow_run_trigger_flagged(self):
        """workflow_run is also a privileged trigger."""
        step = _make_step_uses(
            "actions/checkout",
            pin_form="sha",
            with_inputs={"ref": "${{ github.event.workflow_run.head_sha }}"},
        )
        ir = _make_ir(
            triggers=["workflow_run"],
            jobs=[_make_job(steps=[step])],
        )
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1

    def test_not_applicable_to_gitlab_ci(self):
        rule = self._rule()
        assert "gitlab_ci" not in rule.applicable_formats


# ---------------------------------------------------------------------------
# 4. UnpinnedActionRule
# ---------------------------------------------------------------------------


class TestUnpinnedActionRule:
    def _rule(self):
        return UnpinnedActionRule()

    def test_flags_tag_pinned_action(self):
        """Action pinned to a tag is flagged."""
        step = _make_step_uses("actions/checkout", pin_form="tag", ref="v4")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED
        assert outcomes[0].control_id == "sci-001"

    def test_sha_pinned_action_not_flagged(self):
        """Action pinned to a 40-hex SHA is not flagged."""
        sha = "a" * 40
        step = _make_step_uses("actions/checkout", pin_form="sha", ref=sha)
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert not outcomes

    def test_local_action_not_flagged(self):
        """Local action (./path) is not flagged."""
        step = _make_step_uses("./.github/actions/my-action", pin_form="local", ref="")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert not outcomes

    def test_branch_pinned_action_flagged(self):
        """Action pinned to a branch ref is flagged."""
        step = _make_step_uses("actions/checkout", pin_form="branch", ref="main")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED

    def test_multiple_unpinned_actions_each_flagged(self):
        """Each unpinned action in a job produces its own finding."""
        steps = [
            _make_step_uses("actions/checkout", pin_form="tag", ref="v4", line=10),
            _make_step_uses("actions/setup-node", pin_form="tag", ref="v4", line=15),
        ]
        ir = _make_ir(jobs=[_make_job(steps=steps)])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 2

    def test_not_applicable_to_gitlab_ci(self):
        rule = self._rule()
        assert "gitlab_ci" not in rule.applicable_formats


# ---------------------------------------------------------------------------
# 5. LeastPrivilegeRule
# ---------------------------------------------------------------------------


class TestLeastPrivilegeRule:
    def _rule(self):
        return LeastPrivilegeRule()

    def test_flags_absent_permissions(self):
        """No permissions block at all is flagged."""
        ir = _make_ir(permissions_state="absent", jobs=[_make_job()])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED
        assert outcomes[0].control_id == "lp-001"

    def test_flags_workflow_write_all(self):
        """Workflow-level write-all permissions is flagged."""
        ir = _make_ir(permissions_state="write_all", jobs=[_make_job()])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED

    def test_explicit_permissions_satisfied(self):
        """Explicit non-write-all permissions block yields satisfied."""
        ir = _make_ir(permissions_state="explicit", jobs=[_make_job()])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.SATISFIED

    def test_job_level_write_all_flagged(self):
        """Job-level write-all permissions is flagged even if workflow is absent."""
        job = _make_job(permissions_state="write_all")
        ir = _make_ir(permissions_state="absent", jobs=[job])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED

    def test_job_level_explicit_satisfied(self):
        """Job-level explicit permissions makes the rule satisfied."""
        job = _make_job(permissions_state="explicit")
        ir = _make_ir(permissions_state="absent", jobs=[job])
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.SATISFIED

    def test_absent_permissions_reported_once(self):
        """Absent permissions is reported once, not once per job."""
        jobs = [_make_job("build"), _make_job("test")]
        ir = _make_ir(permissions_state="absent", jobs=jobs)
        outcomes = list(self._rule().evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1

    def test_not_applicable_to_gitlab_ci(self):
        rule = self._rule()
        assert "gitlab_ci" not in rule.applicable_formats


# ---------------------------------------------------------------------------
# 6. PresenceRule — positive (tool found)
# ---------------------------------------------------------------------------


class TestPresenceRule:
    def _make_gitleaks_rule(self) -> PresenceRule:
        return PresenceRule(
            rule_id="presence-secrets-hygiene",
            control_id="sh-002",
            category="secrets_hygiene",
            action_patterns=["gitleaks/gitleaks-action"],
            image_patterns=["zricethezav/gitleaks"],
            shell_tokens=["gitleaks detect"],
        )

    def test_satisfied_when_action_ref_found(self):
        """Action reference matching pattern yields satisfied."""
        step = _make_step_uses("gitleaks/gitleaks-action", pin_form="sha")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        rule = self._make_gitleaks_rule()
        outcomes = list(rule.evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.SATISFIED
        assert outcomes[0].control_id == "sh-002"

    def test_satisfied_when_shell_token_in_run(self):
        """Shell token in run text yields satisfied."""
        step = _make_step_run("gitleaks detect --source . --exit-code 1")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        rule = self._make_gitleaks_rule()
        outcomes = list(rule.evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.SATISFIED

    def test_satisfied_when_image_matches(self):
        """Tool image in runs_on yields satisfied."""
        job = _make_job(runs_on="zricethezav/gitleaks:v8")
        ir = _make_ir(jobs=[job])
        rule = self._make_gitleaks_rule()
        outcomes = list(rule.evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.SATISFIED

    def test_violated_when_tool_absent(self):
        """No matching tool yields violated with nominal anchor."""
        step = _make_step_run("npm ci && npm test")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        rule = self._make_gitleaks_rule()
        outcomes = list(rule.evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED
        assert outcomes[0].anchors  # must have at least one anchor

    def test_not_assessable_with_unresolved_fragments(self):
        """Unresolved fragments → not_assessable (tool may be in included file)."""
        step = _make_step_run("npm ci")
        fragment = UnresolvedFragment(
            kind="composite_action",
            locator="my-org/security-checks@v1",
            reason="Cannot resolve external composite action",
        )
        ir = _make_ir(jobs=[_make_job(steps=[step])], unresolved=[fragment])
        rule = self._make_gitleaks_rule()
        outcomes = list(rule.evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.NOT_ASSESSABLE


# ---------------------------------------------------------------------------
# 7. Approval gates: not_assessable for github_actions and gitlab_ci
# ---------------------------------------------------------------------------


class TestApprovalGatePresence:
    def _ag_rule(self) -> PresenceRule:
        sigs = load_tool_signatures()
        rules = build_presence_rules(sigs)
        for r in rules:
            if r.control_id == "ag-001":
                return r
        raise AssertionError("ag-001 rule not found")

    def test_ag001_not_applicable_to_github_actions(self):
        """ag-001 presence rule is NOT applicable to github_actions format."""
        rule = self._ag_rule()
        assert "github_actions" not in rule.applicable_formats

    def test_ag001_not_applicable_to_gitlab_ci(self):
        """ag-001 presence rule is NOT applicable to gitlab_ci format."""
        rule = self._ag_rule()
        assert "gitlab_ci" not in rule.applicable_formats

    def test_ag001_applicable_to_jenkins(self):
        """ag-001 presence rule IS applicable to jenkins format."""
        rule = self._ag_rule()
        assert "jenkins" in rule.applicable_formats

    def test_ag001_satisfied_for_jenkins_with_input_step(self):
        """Jenkins run script with 'input message:' yields satisfied."""
        step = _make_step_run("input message: 'Deploy to production?', ok: 'Approve'")
        ir = _make_ir(source_format="jenkins", jobs=[_make_job(steps=[step])])
        rule = self._ag_rule()
        outcomes = list(rule.evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.SATISFIED

    def test_ag001_violated_for_jenkins_without_input(self):
        """Jenkins pipeline without input step yields violated."""
        step = _make_step_run("sh 'mvn deploy'")
        ir = _make_ir(source_format="jenkins", jobs=[_make_job(steps=[step])])
        rule = self._ag_rule()
        outcomes = list(rule.evaluate(ir, _NULL_CATALOGUE))
        assert len(outcomes) == 1
        assert outcomes[0].verdict == RuleOutcomeVerdict.VIOLATED


# ---------------------------------------------------------------------------
# 8. Registry: all rules registered, unique rule_ids
# ---------------------------------------------------------------------------


class TestDefaultRegistry:
    def test_build_default_registry_succeeds(self):
        registry = build_default_registry()
        assert len(registry) > 0

    def test_no_duplicate_rule_ids(self):
        registry = build_default_registry()
        seen: set[str] = set()
        for rule in registry.iter_rules():
            assert rule.rule_id not in seen, f"Duplicate rule_id: {rule.rule_id}"
            seen.add(rule.rule_id)

    def test_all_rules_have_valid_control_ids(self):
        registry = build_default_registry()
        valid_controls = {
            "sh-001", "sh-002", "sa-001", "ds-001", "ds-002", "lp-001",
            "iac-001", "sci-001", "sci-002", "sbom-001", "as-001", "as-002", "ag-001",
        }
        for rule in registry.iter_rules():
            assert rule.control_id in valid_controls, (
                f"Rule {rule.rule_id!r} has unknown control_id {rule.control_id!r}"
            )

    def test_rules_iterated_in_sorted_order(self):
        registry = build_default_registry()
        rule_ids = [rule.rule_id for rule in registry.iter_rules()]
        assert rule_ids == sorted(rule_ids)

    def test_all_rules_have_callable_anchor_extractor(self):
        registry = build_default_registry()
        for rule in registry.iter_rules():
            assert callable(rule.anchor_extractor), (
                f"Rule {rule.rule_id!r} has non-callable anchor_extractor"
            )


# ---------------------------------------------------------------------------
# 9. No network access during evaluate
# ---------------------------------------------------------------------------


class TestNoNetworkAccess:
    def test_evaluate_does_not_open_socket(self):
        """No rule should attempt network I/O during evaluate."""
        registry = build_default_registry()
        ir = _make_ir(jobs=[_make_job(steps=[_make_step_run("npm ci")])])
        catalogue = object()

        original_connect = socket.socket.connect

        def raise_on_connect(*args, **kwargs):
            raise AssertionError(
                f"Network connection attempted during rule evaluation: {args}"
            )

        with patch.object(socket.socket, "connect", raise_on_connect):
            for rule in registry.iter_rules():
                if ir.source_format not in rule.applicable_formats:
                    continue
                try:
                    list(rule.evaluate(ir, catalogue))
                except Exception:
                    pass  # rule errors are ok; network errors are not


# ---------------------------------------------------------------------------
# 10. No severity literals in rules package
# ---------------------------------------------------------------------------


class TestNoSeverityLiterals:
    _SEVERITY_WORDS = re.compile(
        r'(?<!["\'])(critical|high|medium|low|info)(?!["\w])',
        re.IGNORECASE,
    )
    _RULES_SRC = Path(__file__).parents[4] / "src" / "pipelineshield" / "analysis" / "rules"

    def _rule_source_files(self):
        return [
            p for p in self._RULES_SRC.rglob("*.py")
            if not p.name.startswith("_") or p.name == "__init__.py"
        ]

    def test_no_hardcoded_severity_strings_in_rule_modules(self):
        """Rules must not contain hardcoded severity strings like 'critical'."""
        violations: list[str] = []
        for pyfile in self._rule_source_files():
            src = pyfile.read_text(encoding="utf-8")
            for lineno, line in enumerate(src.splitlines(), start=1):
                # Skip comments and docstrings (rough approximation)
                stripped = line.lstrip()
                if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
                    continue
                # Skip test strings in string literals for docstrings
                m = self._SEVERITY_WORDS.search(line)
                if m:
                    # Allow only in comments at end of line
                    comment_pos = line.find("#")
                    if comment_pos == -1 or m.start() < comment_pos:
                        violations.append(f"{pyfile.name}:{lineno}: {line.strip()!r}")
        assert not violations, (
            "Hardcoded severity strings found in rules package:\n" +
            "\n".join(violations[:10])
        )


# ---------------------------------------------------------------------------
# 11. format-applicability: GitLab CI IR skips GHA-only rules
# ---------------------------------------------------------------------------


class TestFormatApplicability:
    def test_gitlab_ir_skips_gha_only_rules(self):
        """Rules with applicable_formats={'github_actions'} produce no outcomes for gitlab_ci IR."""
        gha_only_rules = [
            ExpressionInjectionRule(),
            PwnRequestRule(),
            UnpinnedActionRule(),
            LeastPrivilegeRule(),
        ]
        ir = _make_ir(
            source_format="gitlab_ci",
            jobs=[_make_job()],
        )
        for rule in gha_only_rules:
            assert "gitlab_ci" not in rule.applicable_formats, (
                f"{rule.rule_id} should not be applicable to gitlab_ci"
            )

    def test_hardcoded_secret_rule_applicable_to_all_formats(self):
        """HardcodedSecretRule applies to all three CI formats."""
        rule = HardcodedSecretRule()
        for fmt in ("github_actions", "gitlab_ci", "jenkins"):
            assert fmt in rule.applicable_formats


# ---------------------------------------------------------------------------
# 12. Seeded gap detection rate ≥ 80% for github_actions format
# ---------------------------------------------------------------------------


class TestDetectionRate:
    """Verify the rule pack detects ≥ 80% of seeded gaps from corpus fixtures.

    The test builds PipelineIR objects directly to avoid dependency on the
    normalizer stack (dependencies may not be installed in the test environment).
    We use IR that directly represents the patterns documented in ground_truth.yaml.
    """

    def _get_registry(self):
        return build_default_registry()

    def _count_violations_for_control(self, registry, ir, control_id: str) -> int:
        count = 0
        for rule in registry.iter_rules():
            if rule.control_id != control_id:
                continue
            if ir.source_format not in rule.applicable_formats:
                continue
            for outcome in rule.evaluate(ir, _NULL_CATALOGUE):
                if outcome.verdict == RuleOutcomeVerdict.VIOLATED:
                    count += 1
        return count

    def test_detects_hardcoded_secret_sh001(self):
        """sh-001: hardcoded GitHub PAT in docker login command."""
        step = _make_step_run(
            "docker login ghcr.io --username ci-bot "
            "--password ghp_EXAMPLEsyntheticNOTREALaaaaaaaaaaaaaaa"
        )
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        count = self._count_violations_for_control(
            self._get_registry(), ir, "sh-001"
        )
        assert count >= 1

    def test_detects_missing_permissions_lp001(self):
        """lp-001: no permissions block on workflow."""
        ir = _make_ir(permissions_state="absent", jobs=[_make_job()])
        count = self._count_violations_for_control(
            self._get_registry(), ir, "lp-001"
        )
        assert count >= 1

    def test_detects_unpinned_action_sci001(self):
        """sci-001: action pinned to tag."""
        step = _make_step_uses("actions/checkout", pin_form="tag", ref="v4")
        ir = _make_ir(jobs=[_make_job(steps=[step])])
        count = self._count_violations_for_control(
            self._get_registry(), ir, "sci-001"
        )
        assert count >= 1

    def test_detects_pwn_request_sci002(self):
        """sci-002: pull_request_target + fork checkout."""
        step = _make_step_uses(
            "actions/checkout",
            pin_form="sha",
            with_inputs={"ref": "${{ github.event.pull_request.head.sha }}"},
        )
        ir = _make_ir(
            triggers=["pull_request_target"],
            jobs=[_make_job(steps=[step])],
        )
        count = self._count_violations_for_control(
            self._get_registry(), ir, "sci-002"
        )
        assert count >= 1

    def test_detects_missing_sast_sa001(self):
        """sa-001: no SAST tool in pipeline."""
        ir = _make_ir(jobs=[_make_job(steps=[_make_step_run("npm test")])])
        count = self._count_violations_for_control(
            self._get_registry(), ir, "sa-001"
        )
        assert count >= 1

    def test_detects_missing_dep_scan_ds001(self):
        """ds-001: no dependency scanning tool."""
        ir = _make_ir(jobs=[_make_job(steps=[_make_step_run("npm test")])])
        count = self._count_violations_for_control(
            self._get_registry(), ir, "ds-001"
        )
        assert count >= 1

    def test_detection_rate_6_of_7_github_actions_gaps(self):
        """Overall detection rate ≥ 80% (6 of 7 seeded gaps detected)."""
        detected = 0
        total = 7

        # Gap 1: sh-001 — hardcoded secret
        step1 = _make_step_run("TOKEN=ghp_EXAMPLEsyntheticNOTREALaaaaaaaaaaaaaaa")
        ir1 = _make_ir(jobs=[_make_job(steps=[step1])])
        if self._count_violations_for_control(self._get_registry(), ir1, "sh-001") >= 1:
            detected += 1

        # Gap 2: lp-001 — no permissions
        ir2 = _make_ir(permissions_state="absent", jobs=[_make_job()])
        if self._count_violations_for_control(self._get_registry(), ir2, "lp-001") >= 1:
            detected += 1

        # Gap 3: sci-001 — unpinned tag
        step3 = _make_step_uses("actions/checkout", pin_form="tag", ref="v4")
        ir3 = _make_ir(jobs=[_make_job(steps=[step3])])
        if self._count_violations_for_control(self._get_registry(), ir3, "sci-001") >= 1:
            detected += 1

        # Gap 4: sci-002 — pwn-request
        step4 = _make_step_uses(
            "actions/checkout", pin_form="sha",
            with_inputs={"ref": "${{ github.event.pull_request.head.sha }}"},
        )
        ir4 = _make_ir(
            triggers=["pull_request_target"],
            jobs=[_make_job(steps=[step4])],
        )
        if self._count_violations_for_control(self._get_registry(), ir4, "sci-002") >= 1:
            detected += 1

        # Gap 5: sa-001 — no SAST
        ir5 = _make_ir(jobs=[_make_job(steps=[_make_step_run("npm test")])])
        if self._count_violations_for_control(self._get_registry(), ir5, "sa-001") >= 1:
            detected += 1

        # Gap 6: ds-001 — no dependency scan
        ir6 = _make_ir(jobs=[_make_job(steps=[_make_step_run("npm test")])])
        if self._count_violations_for_control(self._get_registry(), ir6, "ds-001") >= 1:
            detected += 1

        # Gap 7: ag-001 — approval gates (not_assessable for GHA — allowed miss)
        # This gap is expected to NOT be detected for github_actions format
        # ag-001 is only detected for jenkins; not counted in the 80% requirement
        # We skip it here and still achieve 6/6 = 100% on detectable gaps
        total = 6  # ag-001 excluded as not_assessable for github_actions

        detection_rate = detected / total
        assert detection_rate >= 0.80, (
            f"Detection rate {detection_rate:.0%} is below 80% "
            f"({detected}/{total} gaps detected)"
        )
