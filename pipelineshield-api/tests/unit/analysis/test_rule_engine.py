"""Unit tests for the rule engine core.

Coverage targets:
  - Rule protocol validation at registration
  - RuleRegistry ordering (always sorted by rule_id regardless of insertion)
  - RuleEngine.evaluate() determinism (shuffled registration → identical result)
  - Error isolation (raising rule → not_assessable, others still run)
  - Dedup by fingerprint (two outcomes with same fingerprint → one retained)
  - Node-count budget guard
  - Wall-clock budget guard
  - Accessor helpers
  - Import-graph guard (no framework/network imports)
  - Log scrubbing (no content leakage in logs)
  - Empty IR (no crash)
  - Violated outcome with empty anchors → rule_error
"""
from __future__ import annotations

import importlib
import json
import logging
import random
import socket
import time
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import MagicMock, patch

import pytest

from pipelineshield.analysis.ir.pipeline_ir import (
    Anchor,
    Job,
    PipelineIR,
    Step,
)
from pipelineshield.analysis.rule_engine.accessors import (
    count_ir_nodes,
    effective_permissions,
    fragment_resolution_status,
    is_format_applicable,
    iter_action_refs,
    iter_jobs,
    iter_secret_refs,
    iter_steps,
    iter_triggers,
    iter_tool_invocations,
)
from pipelineshield.analysis.rule_engine.engine import (
    AnalysisEvaluationError,
    RuleEngine,
)
from pipelineshield.analysis.rule_engine.protocol import (
    EvaluationContext,
    EvaluationResult,
    EvidenceAnchor,
    NullMetricsEmitter,
    RuleOutcome,
    RuleOutcomeVerdict,
)
from pipelineshield.analysis.rule_engine.registry import (
    DuplicateRuleError,
    InvalidRuleError,
    RuleRegistry,
)

# ---------------------------------------------------------------------------
# Fixtures directory
# ---------------------------------------------------------------------------

FIXTURE_DIR = Path(__file__).parent.parent.parent / "fixtures" / "ir"


def load_ir(name: str) -> PipelineIR:
    path = FIXTURE_DIR / f"{name}.json"
    return PipelineIR.model_validate(json.loads(path.read_text()))


# ---------------------------------------------------------------------------
# Helpers to build minimal IR objects
# ---------------------------------------------------------------------------


def _make_ir(
    source_format: str = "github_actions",
    num_jobs: int = 1,
    steps_per_job: int = 1,
) -> PipelineIR:
    jobs = []
    for i in range(num_jobs):
        steps = [
            Step(
                id=f"step-{i}-{j}",
                run=f"echo {i}-{j}",
                anchor=Anchor(start_line=i * 10 + j + 1, start_column=1),
            )
            for j in range(steps_per_job)
        ]
        jobs.append(Job(id=f"job-{i}", steps=steps))
    return PipelineIR(source_format=source_format, jobs=jobs)


# ---------------------------------------------------------------------------
# Minimal rule factories
# ---------------------------------------------------------------------------


def _make_rule(
    rule_id: str = "test-rule",
    control_id: str = "sh-001",
    category: str = "secrets_hygiene",
    applicable_formats: set | None = None,
    severity_key: str = "high",
    evidence_kind: str = "step",
    outcomes: list | None = None,
    raise_exc: Exception | None = None,
):
    if applicable_formats is None:
        applicable_formats = {"github_actions", "gitlab_ci", "jenkins"}

    def anchor_extractor(ir, node):
        yield from []

    class _Rule:
        pass

    r = _Rule()
    r.rule_id = rule_id
    r.control_id = control_id
    r.category = category
    r.applicable_formats = applicable_formats
    r.severity_key = severity_key
    r.evidence_kind = evidence_kind
    r.anchor_extractor = anchor_extractor

    _outcomes = outcomes or []
    _raise = raise_exc

    def evaluate(ir, catalogue_snapshot):
        if _raise is not None:
            raise _raise
        yield from _outcomes

    r.evaluate = evaluate
    return r


def _satisfied_outcome(rule_id: str = "test-rule", control_id: str = "sh-001") -> RuleOutcome:
    return RuleOutcome(
        control_id=control_id,
        rule_id=rule_id,
        verdict=RuleOutcomeVerdict.SATISFIED,
        anchors=(),
        evidence_kind="step",
        fingerprint=RuleOutcome.compute_fingerprint(rule_id, control_id, ()),
    )


def _violated_outcome(
    rule_id: str = "test-rule",
    control_id: str = "sh-001",
    line: int = 1,
    col: int = 1,
) -> RuleOutcome:
    anchors = (EvidenceAnchor(start_line=line, start_column=col),)
    return RuleOutcome(
        control_id=control_id,
        rule_id=rule_id,
        verdict=RuleOutcomeVerdict.VIOLATED,
        anchors=anchors,
        evidence_kind="step",
        fingerprint=RuleOutcome.compute_fingerprint(rule_id, control_id, anchors),
    )


# ---------------------------------------------------------------------------
# Test: Registry
# ---------------------------------------------------------------------------


class TestRuleRegistry:
    def test_register_and_iterate(self):
        reg = RuleRegistry()
        r = _make_rule("zz-rule", "sh-002")
        reg.register(r)
        assert list(reg.iter_rules()) == [r]

    def test_iteration_sorted_by_rule_id(self):
        reg = RuleRegistry()
        reg.register(_make_rule("z-rule"))
        reg.register(_make_rule("a-rule", "sh-002"))
        reg.register(_make_rule("m-rule", "sh-003"))
        ids = [r.rule_id for r in reg.iter_rules()]
        assert ids == sorted(ids)

    def test_duplicate_rule_id_raises(self):
        reg = RuleRegistry()
        reg.register(_make_rule("dup"))
        with pytest.raises(DuplicateRuleError):
            reg.register(_make_rule("dup", "sh-002"))

    def test_missing_anchor_extractor_raises(self):
        reg = RuleRegistry()
        r = _make_rule("no-anchor")
        del r.anchor_extractor
        with pytest.raises(InvalidRuleError, match="anchor_extractor"):
            reg.register(r)

    def test_non_callable_anchor_extractor_raises(self):
        reg = RuleRegistry()
        r = _make_rule("bad-anchor")
        r.anchor_extractor = "not-callable"
        with pytest.raises(InvalidRuleError, match="anchor_extractor"):
            reg.register(r)

    def test_missing_rule_id_raises(self):
        reg = RuleRegistry()
        r = _make_rule("")
        r.rule_id = ""
        with pytest.raises(InvalidRuleError):
            reg.register(r)

    def test_empty_applicable_formats_raises(self):
        reg = RuleRegistry()
        r = _make_rule("fmt-rule")
        r.applicable_formats = set()
        with pytest.raises(InvalidRuleError, match="applicable_formats"):
            reg.register(r)

    def test_len_and_contains(self):
        reg = RuleRegistry()
        reg.register(_make_rule("r1"))
        assert len(reg) == 1
        assert "r1" in reg
        assert "missing" not in reg

    def test_decorator_registers(self):
        reg = RuleRegistry()

        @reg.rule()
        class MyRule:
            rule_id = "my-rule"
            control_id = "sh-001"
            category = "secrets_hygiene"
            applicable_formats = {"github_actions"}
            severity_key = "high"
            evidence_kind = "step"

            def anchor_extractor(self, ir, node):
                yield from []

            def evaluate(self, ir, catalogue_snapshot):
                yield from []

        assert "my-rule" in reg


# ---------------------------------------------------------------------------
# Test: Protocol validation
# ---------------------------------------------------------------------------


class TestProtocolValidation:
    def test_rule_outcome_fingerprint_deterministic(self):
        anchors = (EvidenceAnchor(start_line=5, start_column=3),)
        fp1 = RuleOutcome.compute_fingerprint("rule-a", "ctrl-1", anchors)
        fp2 = RuleOutcome.compute_fingerprint("rule-a", "ctrl-1", anchors)
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA-256 hex

    def test_rule_outcome_fingerprint_differs_by_content(self):
        anchors1 = (EvidenceAnchor(start_line=5, start_column=3),)
        anchors2 = (EvidenceAnchor(start_line=6, start_column=3),)
        assert RuleOutcome.compute_fingerprint("r", "c", anchors1) != RuleOutcome.compute_fingerprint("r", "c", anchors2)

    def test_evidence_anchor_sort_key(self):
        a1 = EvidenceAnchor(start_line=10, start_column=1)
        a2 = EvidenceAnchor(start_line=5, start_column=3)
        assert sorted([a1, a2], key=lambda a: a.sort_key()) == [a2, a1]

    def test_rule_outcome_sort_key_ordering(self):
        o1 = _violated_outcome("b-rule", "sh-002", line=5, col=1)
        o2 = _violated_outcome("a-rule", "sh-001", line=5, col=1)
        o3 = _violated_outcome("a-rule", "sh-001", line=3, col=1)
        sorted_outcomes = sorted([o1, o2, o3], key=lambda o: o.sort_key())
        # sh-001/a-rule/line3 < sh-001/a-rule/line5 < sh-002/b-rule/line5
        assert sorted_outcomes[0].control_id == "sh-001"
        assert sorted_outcomes[0].anchors[0].start_line == 3
        assert sorted_outcomes[-1].control_id == "sh-002"


# ---------------------------------------------------------------------------
# Test: Engine determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def _make_multi_rule_registry(self, shuffled: bool = False) -> RuleRegistry:
        reg = RuleRegistry()
        rules = [
            _make_rule("rule-a", "sh-001", outcomes=[_satisfied_outcome("rule-a", "sh-001")]),
            _make_rule("rule-b", "sh-002", outcomes=[_violated_outcome("rule-b", "sh-002", line=3)]),
            _make_rule("rule-c", "sh-003", outcomes=[_satisfied_outcome("rule-c", "sh-003")]),
        ]
        if shuffled:
            rules = list(rules)
            random.shuffle(rules)
        for r in rules:
            reg.register(r)
        return reg

    def _serialize_outcomes(self, result: EvaluationResult) -> list[dict]:
        return [
            {
                "control_id": o.control_id,
                "rule_id": o.rule_id,
                "verdict": o.verdict.value,
                "fingerprint": o.fingerprint,
            }
            for o in result.outcomes
        ]

    def test_same_ir_same_result(self):
        ir = load_ir("github_actions_minimal")
        catalogue = MagicMock()
        reg = self._make_multi_rule_registry()
        engine = RuleEngine(registry=reg)
        r1 = engine.evaluate(ir, catalogue)
        r2 = engine.evaluate(ir, catalogue)
        assert self._serialize_outcomes(r1) == self._serialize_outcomes(r2)

    def test_shuffled_registration_same_result(self):
        ir = load_ir("github_actions_minimal")
        catalogue = MagicMock()

        results = []
        for _ in range(5):
            reg = self._make_multi_rule_registry(shuffled=True)
            engine = RuleEngine(registry=reg)
            r = engine.evaluate(ir, catalogue)
            results.append(self._serialize_outcomes(r))

        # All must be identical
        assert all(r == results[0] for r in results)

    def test_determinism_across_formats(self):
        catalogue = MagicMock()
        for fixture in ("github_actions_minimal", "gitlab_ci_minimal", "jenkins_declarative"):
            ir = load_ir(fixture)
            reg = self._make_multi_rule_registry()
            engine = RuleEngine(registry=reg)
            r1 = engine.evaluate(ir, catalogue)
            r2 = engine.evaluate(ir, catalogue)
            assert self._serialize_outcomes(r1) == self._serialize_outcomes(r2), f"Failed for {fixture}"


# ---------------------------------------------------------------------------
# Test: Error isolation
# ---------------------------------------------------------------------------


class TestErrorIsolation:
    def test_raising_rule_produces_rule_error(self):
        ir = _make_ir()
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule("bad-rule", "sh-001", raise_exc=ValueError("boom")))
        reg.register(_make_rule("good-rule", "sh-002", outcomes=[_satisfied_outcome("good-rule", "sh-002")]))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        assert len(result.rule_errors) == 1
        err = result.rule_errors[0]
        assert err.rule_id == "bad-rule"
        assert err.control_id == "sh-001"
        assert err.exc_type == "ValueError"

    def test_raising_rule_downgrades_to_not_assessable(self):
        ir = _make_ir()
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule("bad-rule", "sh-001", raise_exc=RuntimeError("fail")))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        na_outcomes = [o for o in result.outcomes if o.verdict == RuleOutcomeVerdict.NOT_ASSESSABLE]
        assert any(o.rule_id == "bad-rule" for o in na_outcomes)

    def test_other_rules_still_run_after_error(self):
        ir = _make_ir()
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule("bad-rule", "sh-001", raise_exc=ValueError("fail")))
        reg.register(_make_rule("ok-rule", "sh-002", outcomes=[_satisfied_outcome("ok-rule", "sh-002")]))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        assert result.total_rules_evaluated == 2
        ok_outcomes = [o for o in result.outcomes if o.rule_id == "ok-rule"]
        assert len(ok_outcomes) == 1
        assert ok_outcomes[0].verdict == RuleOutcomeVerdict.SATISFIED

    def test_raising_rule_logged_with_context(self, caplog):
        ir = _make_ir()
        catalogue = MagicMock()
        ctx = EvaluationContext(correlation_id="corr-123")
        reg = RuleRegistry()
        reg.register(_make_rule("err-rule", "sh-001", raise_exc=RuntimeError("test error")))
        engine = RuleEngine(registry=reg)

        with caplog.at_level(logging.WARNING, logger="pipelineshield.analysis.rule_engine.engine"):
            engine.evaluate(ir, catalogue, context=ctx)

        assert any("err-rule" in r.message for r in caplog.records)
        assert any("corr-123" in r.message for r in caplog.records)

    def test_violated_outcome_without_anchors_is_rule_error(self):
        ir = _make_ir()
        catalogue = MagicMock()
        reg = RuleRegistry()
        bad_outcome = RuleOutcome(
            control_id="sh-001",
            rule_id="anchor-less",
            verdict=RuleOutcomeVerdict.VIOLATED,
            anchors=(),
            evidence_kind="step",
            fingerprint=RuleOutcome.compute_fingerprint("anchor-less", "sh-001", ()),
        )
        reg.register(_make_rule("anchor-less", "sh-001", outcomes=[bad_outcome]))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        assert len(result.rule_errors) == 1
        assert result.rule_errors[0].exc_type == "MissingAnchorsError"


# ---------------------------------------------------------------------------
# Test: Budget guards
# ---------------------------------------------------------------------------


class TestBudgetGuards:
    def test_node_budget_exceeded_returns_budget_exceeded(self):
        ir = load_ir("large_ir")
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule("r1"))
        engine = RuleEngine(registry=reg, max_ir_nodes=100)

        result = engine.evaluate(ir, catalogue)

        assert result.budget_exceeded is True
        assert "node" in result.budget_detail.lower()

    def test_node_budget_does_not_raise(self):
        ir = load_ir("large_ir")
        catalogue = MagicMock()
        reg = RuleRegistry()
        engine = RuleEngine(registry=reg, max_ir_nodes=1)

        result = engine.evaluate(ir, catalogue)
        assert isinstance(result, EvaluationResult)

    def test_wall_clock_budget_exceeded(self):
        ir = _make_ir()
        catalogue = MagicMock()
        reg = RuleRegistry()

        call_count = [0]
        original_time = time.monotonic

        def slow_clock():
            call_count[0] += 1
            # Return 0 on first call (wall_start), then 10000 ms later
            if call_count[0] == 1:
                return 0.0
            return 10.0  # 10 seconds = well over 2500 ms budget

        reg.register(_make_rule("slow-rule", "sh-001"))
        reg.register(_make_rule("other-rule", "sh-002"))
        engine = RuleEngine(registry=reg, max_wall_clock_ms=100.0, clock=slow_clock)

        result = engine.evaluate(ir, catalogue)

        assert result.budget_exceeded is True
        assert "wall" in result.budget_detail.lower() or "budget" in result.budget_detail.lower()

    def test_wall_clock_budget_does_not_raise(self):
        ir = _make_ir()
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule("r1"))

        clock_calls = [0]

        def instant_exceeded_clock():
            clock_calls[0] += 1
            return float(clock_calls[0]) * 100.0  # Each call adds 100 seconds

        engine = RuleEngine(registry=reg, max_wall_clock_ms=0.0, clock=instant_exceeded_clock)
        result = engine.evaluate(ir, catalogue)
        assert isinstance(result, EvaluationResult)


# ---------------------------------------------------------------------------
# Test: Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_same_fingerprint_deduplicated(self):
        ir = _make_ir()
        catalogue = MagicMock()
        reg = RuleRegistry()

        # Two outcomes with identical content → same fingerprint
        outcome = _violated_outcome("dup-rule", "sh-001", line=5, col=1)
        reg.register(_make_rule("dup-rule", "sh-001", outcomes=[outcome, outcome]))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        matching = [o for o in result.outcomes if o.rule_id == "dup-rule" and o.verdict == RuleOutcomeVerdict.VIOLATED]
        assert len(matching) == 1

    def test_different_anchors_not_deduplicated(self):
        ir = _make_ir()
        catalogue = MagicMock()
        reg = RuleRegistry()

        o1 = _violated_outcome("multi-rule", "sh-001", line=5, col=1)
        o2 = _violated_outcome("multi-rule", "sh-001", line=10, col=1)
        assert o1.fingerprint != o2.fingerprint
        reg.register(_make_rule("multi-rule", "sh-001", outcomes=[o1, o2]))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        matching = [o for o in result.outcomes if o.rule_id == "multi-rule"]
        assert len(matching) == 2


# ---------------------------------------------------------------------------
# Test: Format filtering
# ---------------------------------------------------------------------------


class TestFormatFiltering:
    def test_rule_not_applicable_to_format_is_skipped(self):
        ir = _make_ir(source_format="github_actions")
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule(
            "gitlab-only-rule",
            "sh-001",
            applicable_formats={"gitlab_ci"},
            outcomes=[_satisfied_outcome("gitlab-only-rule", "sh-001")],
        ))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        assert result.total_rules_skipped == 1
        assert result.total_rules_evaluated == 0
        assert len(result.outcomes) == 0

    def test_applicable_rule_runs(self):
        ir = _make_ir(source_format="github_actions")
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule(
            "gha-rule",
            "sh-001",
            applicable_formats={"github_actions"},
            outcomes=[_satisfied_outcome("gha-rule", "sh-001")],
        ))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        assert result.total_rules_evaluated == 1
        assert result.total_rules_skipped == 0


# ---------------------------------------------------------------------------
# Test: Empty IR
# ---------------------------------------------------------------------------


class TestEmptyIR:
    def test_empty_ir_no_crash(self):
        ir = load_ir("empty_ir")
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule("r1"))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        assert isinstance(result, EvaluationResult)
        assert not result.budget_exceeded
        assert result.rule_errors == []

    def test_empty_ir_no_violated_findings(self):
        ir = PipelineIR(source_format="github_actions")
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule("r1", outcomes=[_satisfied_outcome()]))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        violated = [o for o in result.outcomes if o.verdict == RuleOutcomeVerdict.VIOLATED]
        assert violated == []


# ---------------------------------------------------------------------------
# Test: AnalysisEvaluationError
# ---------------------------------------------------------------------------


class TestEngineErrors:
    def test_invalid_ir_type_raises(self):
        reg = RuleRegistry()
        engine = RuleEngine(registry=reg)
        with pytest.raises(AnalysisEvaluationError, match="PipelineIR"):
            engine.evaluate({"not": "a_pipeline_ir"}, MagicMock())

    def test_none_catalogue_raises(self):
        reg = RuleRegistry()
        engine = RuleEngine(registry=reg)
        with pytest.raises(AnalysisEvaluationError, match="catalogue_snapshot"):
            engine.evaluate(_make_ir(), None)


# ---------------------------------------------------------------------------
# Test: Accessor helpers
# ---------------------------------------------------------------------------


class TestAccessors:
    def test_iter_jobs(self):
        ir = _make_ir(num_jobs=3)
        assert len(list(iter_jobs(ir))) == 3

    def test_iter_steps(self):
        ir = _make_ir(num_jobs=2, steps_per_job=3)
        pairs = list(iter_steps(ir))
        assert len(pairs) == 6

    def test_iter_triggers(self):
        ir = load_ir("github_actions_minimal")
        triggers = list(iter_triggers(ir))
        assert "push" in triggers
        assert "pull_request" in triggers

    def test_effective_permissions_inherits_workflow(self):
        ir = load_ir("github_actions_minimal")
        job = ir.jobs[0]
        perms = effective_permissions(ir, job)
        assert perms.scope in ("workflow_inherited", "job")

    def test_fragment_resolution_status_empty(self):
        ir = _make_ir()
        status = fragment_resolution_status(ir)
        assert status == {}

    def test_count_ir_nodes(self):
        ir = _make_ir(num_jobs=2, steps_per_job=3)
        # 2 jobs + 2*3 steps = 8
        assert count_ir_nodes(ir) == 8

    def test_is_format_applicable_true(self):
        ir = _make_ir(source_format="github_actions")
        assert is_format_applicable(ir, {"github_actions", "gitlab_ci"}) is True

    def test_is_format_applicable_false(self):
        ir = _make_ir(source_format="jenkins")
        assert is_format_applicable(ir, {"github_actions"}) is False

    def test_iter_action_refs_empty(self):
        ir = _make_ir()
        refs = list(iter_action_refs(ir))
        assert refs == []

    def test_iter_action_refs_from_fixture(self):
        ir = load_ir("github_actions_minimal")
        refs = list(iter_action_refs(ir))
        assert len(refs) == 1
        _, _, ref = refs[0]
        assert ref.pin_form == "sha"

    def test_iter_secret_refs_empty(self):
        ir = _make_ir()
        refs = list(iter_secret_refs(ir))
        assert refs == []

    def test_iter_tool_invocations(self):
        ir = load_ir("github_actions_minimal")
        invocations = list(iter_tool_invocations(ir))
        assert len(invocations) == 1


# ---------------------------------------------------------------------------
# Test: Log scrubbing
# ---------------------------------------------------------------------------


class TestLogScrubbing:
    def test_logs_do_not_contain_definition_content(self, caplog):
        secret_run_cmd = "echo 'SUPER_SECRET_TOKEN=abc123xyz'"
        step = Step(id="secret-step", run=secret_run_cmd)
        job = Job(id="secret-job", steps=[step])
        ir = PipelineIR(source_format="github_actions", jobs=[job])
        catalogue = MagicMock()
        ctx = EvaluationContext(correlation_id="log-test-corr")
        reg = RuleRegistry()
        reg.register(_make_rule("log-test-rule"))
        engine = RuleEngine(registry=reg)

        with caplog.at_level(logging.DEBUG, logger="pipelineshield.analysis.rule_engine.engine"):
            engine.evaluate(ir, catalogue, context=ctx)

        all_log_text = " ".join(r.message for r in caplog.records)
        assert "SUPER_SECRET_TOKEN" not in all_log_text
        assert "abc123xyz" not in all_log_text

    def test_logs_contain_required_context_fields(self, caplog):
        ir = _make_ir()
        catalogue = MagicMock()
        ctx = EvaluationContext(
            correlation_id="ctx-corr-id",
            source_format="github_actions",
            catalogue_version="v1.0",
        )
        reg = RuleRegistry()
        engine = RuleEngine(registry=reg)

        with caplog.at_level(logging.INFO, logger="pipelineshield.analysis.rule_engine.engine"):
            engine.evaluate(ir, catalogue, context=ctx)

        all_log_text = " ".join(r.message for r in caplog.records)
        assert "ctx-corr-id" in all_log_text


# ---------------------------------------------------------------------------
# Test: Import graph (no framework or network imports)
# ---------------------------------------------------------------------------


class TestImportGraph:
    FORBIDDEN_IMPORTS = [
        "fastapi",
        "sqlalchemy",
        "httpx",
        "requests",
        "anthropic",
        "openai",
    ]

    RULE_ENGINE_MODULES = [
        "pipelineshield.analysis.rule_engine.engine",
        "pipelineshield.analysis.rule_engine.protocol",
        "pipelineshield.analysis.rule_engine.registry",
        "pipelineshield.analysis.rule_engine.accessors",
    ]

    def test_no_forbidden_imports_in_rule_engine(self):
        for module_name in self.RULE_ENGINE_MODULES:
            module = importlib.import_module(module_name)
            source_file = getattr(module, "__file__", None)
            if source_file is None:
                continue
            source = Path(source_file).read_text()
            for forbidden in self.FORBIDDEN_IMPORTS:
                assert forbidden not in source, (
                    f"{module_name} contains forbidden import {forbidden!r}. "
                    "The rule engine must be framework-free."
                )

    def test_no_socket_open_in_evaluate(self):
        ir = _make_ir()
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule("net-check-rule"))
        engine = RuleEngine(registry=reg)

        original_socket_connect = socket.socket.connect

        connection_attempts = []

        def spy_connect(self, address):
            connection_attempts.append(address)
            return original_socket_connect(self, address)

        with patch.object(socket.socket, "connect", spy_connect):
            engine.evaluate(ir, catalogue)

        assert connection_attempts == [], (
            f"RuleEngine opened {len(connection_attempts)} socket connection(s): "
            f"{connection_attempts}. The engine must perform zero I/O."
        )


# ---------------------------------------------------------------------------
# Test: Telemetry
# ---------------------------------------------------------------------------


class TestTelemetry:
    def test_telemetry_populated(self):
        ir = _make_ir()
        catalogue = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule("tel-rule", "sh-001", outcomes=[_satisfied_outcome("tel-rule", "sh-001")]))
        engine = RuleEngine(registry=reg)

        result = engine.evaluate(ir, catalogue)

        assert result.total_rules_evaluated == 1
        assert len(result.rule_telemetry) == 1
        t = result.rule_telemetry[0]
        assert t.rule_id == "tel-rule"
        assert t.duration_ms >= 0

    def test_metrics_emitter_called(self):
        ir = _make_ir()
        catalogue = MagicMock()
        emitter = MagicMock()
        emitter.observe_duration = MagicMock()
        emitter.increment = MagicMock()
        reg = RuleRegistry()
        reg.register(_make_rule("met-rule", outcomes=[_satisfied_outcome("met-rule")]))
        engine = RuleEngine(registry=reg, metrics=emitter)

        engine.evaluate(ir, catalogue)

        assert emitter.observe_duration.called
        assert emitter.increment.called


# ---------------------------------------------------------------------------
# Test: Fixtures loadable
# ---------------------------------------------------------------------------


class TestFixturesLoadable:
    @pytest.mark.parametrize("fixture_name", [
        "github_actions_minimal",
        "gitlab_ci_minimal",
        "jenkins_declarative",
        "empty_ir",
        "large_ir",
    ])
    def test_fixture_loads_as_pipeline_ir(self, fixture_name):
        ir = load_ir(fixture_name)
        assert isinstance(ir, PipelineIR)
        assert ir.ir_version == "1.0"

    def test_github_actions_fixture_has_jobs(self):
        ir = load_ir("github_actions_minimal")
        assert len(ir.jobs) >= 1

    def test_large_ir_has_many_nodes(self):
        ir = load_ir("large_ir")
        assert count_ir_nodes(ir) > 5000


# ---------------------------------------------------------------------------
# Test: NullMetricsEmitter
# ---------------------------------------------------------------------------


class TestNullMetricsEmitter:
    def test_null_emitter_does_not_raise(self):
        emitter = NullMetricsEmitter()
        emitter.observe_duration("test", 1.0, {"key": "val"})
        emitter.increment("test", {"key": "val"})
