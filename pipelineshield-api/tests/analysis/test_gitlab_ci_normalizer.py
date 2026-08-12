"""Tests for the GitLab CI normalizer (WO-007).

Test strategy:
  - Golden-file tests: normalizer output (anchors stripped) vs expected/*.json
    Set REGEN_GOLDEN=1 to regenerate golden files from current normalizer output.
  - Unit tests: extends resolution, !reference, default stages, hidden job exclusion,
    triggers, coverage report unresolved count.
  - Schema gate: PipelineIR validates against its own JSON schema.
  - No-HTTP-egress guard: the normalizer module imports no HTTP libraries.
  - Registry wiring: create_default_registry() includes gitlab_ci.
  - Integration test: normalizer produces valid IR end-to-end.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from pipelineshield.analysis.ir.pipeline_ir import IR_VERSION, PipelineIR
from pipelineshield.analysis.normalizers.gitlab_ci import (
    GITLAB_DEFAULT_STAGES,
    GitLabCINormalizer,
)
from pipelineshield.analysis.yaml_loader import NormalizationError
from pipelineshield.services.normalizer_registry import PipelineFormat

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_FIXTURE_DIR = (
    Path(__file__).parent.parent / "fixtures" / "normalizers" / "gitlab_ci"
)
_EXPECTED_DIR = _FIXTURE_DIR / "expected"
_REGEN = os.environ.get("REGEN_GOLDEN", "0").lower() in {"1", "true", "yes"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_anchors(obj: Any) -> Any:
    """Recursively set every 'anchor' key to None for stable golden comparisons."""
    if isinstance(obj, dict):
        return {
            k: (None if k == "anchor" else _strip_anchors(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_strip_anchors(item) for item in obj]
    return obj


def _normalize_fixture(name: str) -> PipelineIR:
    text = (_FIXTURE_DIR / name).read_text()
    result = GitLabCINormalizer().normalize(text)
    assert result.pipeline_ir is not None, f"pipeline_ir must not be None for {name}"
    return result.pipeline_ir


def _actual_stripped(ir: PipelineIR) -> dict[str, Any]:
    return _strip_anchors(ir.model_dump())


def _assert_golden(fixture_name: str, ir: PipelineIR) -> None:
    stem = Path(fixture_name).stem
    expected_path = _EXPECTED_DIR / f"{stem}.json"
    actual = _actual_stripped(ir)

    if _REGEN or not expected_path.exists():
        _EXPECTED_DIR.mkdir(parents=True, exist_ok=True)
        expected_path.write_text(
            json.dumps(actual, indent=2, ensure_ascii=False) + "\n"
        )
        return

    expected = json.loads(expected_path.read_text())
    assert actual == expected, (
        f"Golden file mismatch for {fixture_name}.\n"
        f"Run with REGEN_GOLDEN=1 to update.\n"
        f"Actual unresolved: {[u['kind'] for u in actual.get('coverage_report', {}).get('unresolved', [])]}\n"
        f"Expected unresolved: {[u['kind'] for u in expected.get('coverage_report', {}).get('unresolved', [])]}"
    )


# ---------------------------------------------------------------------------
# Golden-file tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture_name",
    [
        "minimal.yml",
        "no_explicit_stages.yml",
        "deep_extends.yml",
        "multiple_parent_extends.yml",
        "reference_tag.yml",
        "remote_include.yml",
        "project_include.yml",
        "hidden_job_templates.yml",
    ],
)
def test_golden(fixture_name: str) -> None:
    ir = _normalize_fixture(fixture_name)
    _assert_golden(fixture_name, ir)


# ---------------------------------------------------------------------------
# Unit: source_format
# ---------------------------------------------------------------------------


def test_source_format_is_gitlab_ci() -> None:
    ir = _normalize_fixture("minimal.yml")
    assert ir.source_format == "gitlab_ci"


def test_ir_version() -> None:
    ir = _normalize_fixture("minimal.yml")
    assert ir.ir_version == IR_VERSION


# ---------------------------------------------------------------------------
# Unit: default stages when stages: absent
# ---------------------------------------------------------------------------


def test_default_stages_recorded_as_unresolved() -> None:
    ir = _normalize_fixture("no_explicit_stages.yml")
    kinds = [u.kind for u in ir.coverage_report.unresolved]
    assert "stages_inferred" in kinds


def test_default_stages_constant() -> None:
    assert GITLAB_DEFAULT_STAGES == [".pre", "build", "test", "deploy", ".post"]


# ---------------------------------------------------------------------------
# Unit: hidden jobs excluded from executable list
# ---------------------------------------------------------------------------


def test_hidden_jobs_excluded() -> None:
    ir = _normalize_fixture("hidden_job_templates.yml")
    job_ids = [j.id for j in ir.jobs]
    assert not any(jid.startswith(".") for jid in job_ids), (
        f"Hidden jobs found in IR jobs: {[j for j in job_ids if j.startswith('.')]}"
    )


def test_hidden_jobs_count() -> None:
    ir = _normalize_fixture("hidden_job_templates.yml")
    assert len(ir.jobs) == 3, (
        f"Expected 3 concrete jobs, got {len(ir.jobs)}: {[j.id for j in ir.jobs]}"
    )


# ---------------------------------------------------------------------------
# Unit: extends resolution
# ---------------------------------------------------------------------------


def test_deep_extends_image_inheritance() -> None:
    ir = _normalize_fixture("deep_extends.yml")
    test_deep = next(j for j in ir.jobs if j.id == "test-deep")
    assert test_deep.runs_on == "ubuntu:22.04"


def test_deep_extends_before_script_override() -> None:
    ir = _normalize_fixture("deep_extends.yml")
    test_deep = next(j for j in ir.jobs if j.id == "test-deep")
    before = next((s for s in test_deep.steps if s.name == "before_script"), None)
    assert before is not None
    assert "middle" in before.run


def test_deep_extends_variable_inheritance() -> None:
    ir = _normalize_fixture("deep_extends.yml")
    test_deep = next(j for j in ir.jobs if j.id == "test-deep")
    script_step = next(s for s in test_deep.steps if s.name == "script")
    assert script_step.env.get("TIMEOUT") == "30"


def test_multiple_parent_extends_last_parent_image() -> None:
    ir = _normalize_fixture("multiple_parent_extends.yml")
    build = next(j for j in ir.jobs if j.id == "build-image")
    assert build.runs_on == "docker:24"


def test_multiple_parent_extends_child_var_wins() -> None:
    ir = _normalize_fixture("multiple_parent_extends.yml")
    prod = next(j for j in ir.jobs if j.id == "production-deploy")
    script_step = next(s for s in prod.steps if s.name == "script")
    assert script_step.env.get("ENVIRONMENT") == "production"


def test_extends_cycle_recorded_as_unresolved() -> None:
    cyclic = """
stages: [test]
.job-a:
  extends: .job-b
  script: [echo a]
.job-b:
  extends: .job-a
  script: [echo b]
real-job:
  extends: .job-a
  stage: test
  script: [echo real]
"""
    ir = GitLabCINormalizer().normalize(cyclic).pipeline_ir
    assert ir is not None
    kinds = [u.kind for u in ir.coverage_report.unresolved]
    assert "extends_cycle" in kinds


# ---------------------------------------------------------------------------
# Unit: !reference tag resolution
# ---------------------------------------------------------------------------


def test_reference_tag_successful_resolution() -> None:
    ir = _normalize_fixture("reference_tag.yml")
    unit = next(j for j in ir.jobs if j.id == "unit-tests")
    before = next(s for s in unit.steps if s.name == "before_script")
    assert "pip install" in before.run


def test_reference_tag_unresolvable_recorded() -> None:
    ir = _normalize_fixture("reference_tag.yml")
    kinds = [u.kind for u in ir.coverage_report.unresolved]
    assert "reference_unresolvable" in kinds


def test_reference_tag_unresolvable_locator() -> None:
    ir = _normalize_fixture("reference_tag.yml")
    unresolved = [u for u in ir.coverage_report.unresolved if u.kind == "reference_unresolvable"]
    assert len(unresolved) == 1
    assert ".nonexistent-job" in unresolved[0].locator


# ---------------------------------------------------------------------------
# Unit: trigger extraction
# ---------------------------------------------------------------------------


def test_pipeline_source_trigger_from_rules() -> None:
    ir = _normalize_fixture("remote_include.yml")
    assert "push" in ir.triggers


def test_trigger_from_only() -> None:
    ir = _normalize_fixture("project_include.yml")
    assert "merge_requests" in ir.triggers


def test_branch_name_in_only_not_a_trigger() -> None:
    ir = _normalize_fixture("no_explicit_stages.yml")
    assert "main" not in ir.triggers
    assert ir.triggers == []


# ---------------------------------------------------------------------------
# Unit: remote/project/template include → exactly 3 unresolved
# ---------------------------------------------------------------------------


def test_remote_include_exactly_three_unresolved() -> None:
    ir = _normalize_fixture("remote_include.yml")
    assert len(ir.coverage_report.unresolved) == 3


def test_remote_include_kinds() -> None:
    ir = _normalize_fixture("remote_include.yml")
    kinds = {u.kind for u in ir.coverage_report.unresolved}
    assert kinds == {"include_remote", "include_project", "include_template"}


def test_include_unresolved_never_counts_as_present() -> None:
    ir = _normalize_fixture("remote_include.yml")
    for u in ir.coverage_report.unresolved:
        assert "Not Assessable" in u.reason or "not" in u.reason.lower()


# ---------------------------------------------------------------------------
# Unit: global default: inheritance
# ---------------------------------------------------------------------------


def test_global_default_image_applied() -> None:
    ir = _normalize_fixture("no_explicit_stages.yml")
    for job in ir.jobs:
        assert job.runs_on == "python:3.11", (
            f"Job '{job.id}' should inherit global default image"
        )


# ---------------------------------------------------------------------------
# Unit: coverage report fields
# ---------------------------------------------------------------------------


def test_coverage_report_constructs_handled() -> None:
    ir = _normalize_fixture("minimal.yml")
    assert "job_script" in ir.coverage_report.constructs_handled
    assert "global_default_inheritance" in ir.coverage_report.constructs_handled
    assert "hidden_job_templates" in ir.coverage_report.constructs_handled


def test_coverage_report_constructs_excluded() -> None:
    ir = _normalize_fixture("minimal.yml")
    assert "include_remote" in ir.coverage_report.constructs_excluded
    assert "trigger" in ir.coverage_report.constructs_excluded


# ---------------------------------------------------------------------------
# Unit: permissions always absent for GitLab CI
# ---------------------------------------------------------------------------


def test_workflow_permissions_absent() -> None:
    ir = _normalize_fixture("minimal.yml")
    assert ir.permissions.state == "absent"


def test_job_permissions_absent() -> None:
    ir = _normalize_fixture("minimal.yml")
    for job in ir.jobs:
        assert job.permissions.state == "absent"


# ---------------------------------------------------------------------------
# Schema gate: PipelineIR validates its own model
# ---------------------------------------------------------------------------


def test_schema_gate() -> None:
    ir = _normalize_fixture("remote_include.yml")
    dumped = ir.model_dump()
    assert dumped["ir_version"] == IR_VERSION
    assert dumped["source_format"] == "gitlab_ci"
    reimported = PipelineIR.model_validate(dumped)
    assert reimported.ir_version == IR_VERSION


# ---------------------------------------------------------------------------
# No-HTTP-egress guard
# ---------------------------------------------------------------------------


def test_no_http_egress_in_normalizer_module() -> None:
    banned = {"requests", "httpx", "urllib3", "aiohttp", "http.client"}
    mod = importlib.import_module("pipelineshield.analysis.normalizers.gitlab_ci")
    loaded = set(sys.modules.keys())
    violations = banned & loaded
    assert not violations, (
        f"HTTP-capable modules loaded by the normalizer: {violations}"
    )


def test_no_http_egress_in_extends_module() -> None:
    banned = {"requests", "httpx", "urllib3", "aiohttp", "http.client"}
    importlib.import_module("pipelineshield.analysis.normalizers.gitlab_extends")
    loaded = set(sys.modules.keys())
    violations = banned & loaded
    assert not violations, (
        f"HTTP-capable modules loaded by extends module: {violations}"
    )


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


def test_registry_includes_gitlab_ci() -> None:
    from pipelineshield.services.normalizer_registry import create_default_registry
    registry = create_default_registry()
    normalizer = registry.get_normalizer(PipelineFormat.gitlab_ci)
    assert normalizer is not None
    assert isinstance(normalizer, GitLabCINormalizer)


def test_registry_gitlab_ci_produces_ir() -> None:
    from pipelineshield.services.normalizer_registry import create_default_registry
    registry = create_default_registry()
    normalizer = registry.get_normalizer(PipelineFormat.gitlab_ci)
    assert normalizer is not None
    content = (_FIXTURE_DIR / "minimal.yml").read_text()
    result = normalizer.normalize(content)
    assert result.pipeline_ir is not None
    assert result.pipeline_ir.source_format == "gitlab_ci"


# ---------------------------------------------------------------------------
# Integration test: end-to-end via normalizer
# ---------------------------------------------------------------------------


def test_integration_full_pipeline() -> None:
    content = (_FIXTURE_DIR / "hidden_job_templates.yml").read_text()
    result = GitLabCINormalizer().normalize(content)
    assert result.pipeline_ir is not None
    ir = result.pipeline_ir
    assert ir.source_format == "gitlab_ci"
    assert len(ir.jobs) == 3
    job_ids = {j.id for j in ir.jobs}
    assert "unit-test" in job_ids
    assert "staging-deploy" in job_ids
    assert "production-deploy" in job_ids
    assert not any(jid.startswith(".") for jid in job_ids)
    assert "push" in ir.triggers
    assert result.coverage_report["job_count"] == 3


def test_integration_empty_document() -> None:
    result = GitLabCINormalizer().normalize("")
    assert result.pipeline_ir is not None
    assert result.pipeline_ir.source_format == "gitlab_ci"
    assert result.pipeline_ir.jobs == []
