"""Tests for the GitHub Actions normalizer (WO-006).

Test strategy:
  - Golden-file tests: normalizer output (anchors stripped) vs expected/*.json
    Set REGEN_GOLDEN=1 to regenerate golden files from current normalizer output.
  - Unit tests: specific behaviour (trigger forms, permissions states, pin forms).
  - Schema gate: PipelineIR validates against its own JSON schema.
  - No-HTTP-egress guard: the normalizer module imports no HTTP libraries.
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
from pipelineshield.analysis.normalizers.github_actions import GitHubActionsNormalizer
from pipelineshield.analysis.yaml_loader import NormalizationError

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_FIXTURE_DIR = (
    Path(__file__).parent.parent / "fixtures" / "normalizers" / "github_actions"
)
_EXPECTED_DIR = _FIXTURE_DIR / "expected"
_REGEN = os.environ.get("REGEN_GOLDEN", "0").lower() in {"1", "true", "yes"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_anchors(obj: Any) -> Any:
    """Recursively set every 'anchor' key to None.

    Golden-file comparisons strip anchors so that reformatting fixture YAML
    (which shifts line numbers) does not require regenerating golden files.
    """
    if isinstance(obj, dict):
        return {
            k: (None if k == "anchor" else _strip_anchors(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_strip_anchors(item) for item in obj]
    return obj


def _normalize_fixture(name: str) -> PipelineIR:
    """Load a fixture YAML file and normalize it, returning the PipelineIR."""
    text = (_FIXTURE_DIR / name).read_text()
    result = GitHubActionsNormalizer().normalize(text)
    assert result.pipeline_ir is not None, f"pipeline_ir must not be None for {name}"
    return result.pipeline_ir


def _actual_stripped(ir: PipelineIR) -> dict[str, Any]:
    return _strip_anchors(ir.model_dump())


def _assert_golden(fixture_name: str, ir: PipelineIR) -> None:
    """Compare *ir* (anchors stripped) to its golden file.

    If REGEN_GOLDEN=1 is set or the golden file is absent, write the golden file.
    """
    stem = Path(fixture_name).stem
    expected_path = _EXPECTED_DIR / f"{stem}.json"
    actual = _actual_stripped(ir)

    if _REGEN or not expected_path.exists():
        _EXPECTED_DIR.mkdir(parents=True, exist_ok=True)
        expected_path.write_text(json.dumps(actual, indent=2, ensure_ascii=False) + "\n")
        return

    expected = json.loads(expected_path.read_text())
    assert actual == expected, (
        f"Golden file mismatch for {fixture_name}.\n"
        f"Run with REGEN_GOLDEN=1 to update: pytest tests/analysis/test_github_actions_normalizer.py\n"
        f"Diff:\n  actual  keys={set(actual.keys())}\n  expected keys={set(expected.keys())}"
    )


# ---------------------------------------------------------------------------
# Golden-file tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture_name",
    [
        "minimal.yml",
        "matrix_static.yml",
        "reusable_workflow_caller.yml",
        "composite_action_user.yml",
        "pull_request_target.yml",
        "unpinned_actions.yml",
        "yaml_1_1_traps.yml",
    ],
)
def test_golden(fixture_name: str) -> None:
    ir = _normalize_fixture(fixture_name)
    _assert_golden(fixture_name, ir)


# ---------------------------------------------------------------------------
# Unit: anchor-bomb guard
# ---------------------------------------------------------------------------


def test_anchor_bomb_raises() -> None:
    text = (_FIXTURE_DIR / "anchor_bomb.yml").read_text()
    with pytest.raises(NormalizationError) as exc_info:
        GitHubActionsNormalizer().normalize(text)
    assert exc_info.value.constraint == "alias_bomb"


# ---------------------------------------------------------------------------
# Unit: YAML 1.1 boolean traps are neutralised
# ---------------------------------------------------------------------------


def test_yaml_1_1_on_key_is_trigger_not_bool() -> None:
    """on: push must produce trigger 'push', not fail due to on → True."""
    ir = _normalize_fixture("yaml_1_1_traps.yml")
    assert "push" in ir.triggers
    assert len(ir.triggers) == 1


def test_yaml_1_1_env_values_remain_strings() -> None:
    """NO/Yes/off/y/n must stay as string values, not coerce to booleans."""
    # This is validated indirectly — if YAML 1.1 mode were active, the job-level
    # env map would raise a validation error (dict[str,str] can't hold bools).
    ir = _normalize_fixture("yaml_1_1_traps.yml")
    assert ir.ir_version == IR_VERSION


# ---------------------------------------------------------------------------
# Unit: trigger forms
# ---------------------------------------------------------------------------


def test_scalar_trigger() -> None:
    ir = _normalize_fixture("minimal.yml")
    assert ir.triggers == ["push"]
    assert ir.trigger_details == {"push": {}}


def test_list_trigger() -> None:
    ir = _normalize_fixture("matrix_static.yml")
    assert set(ir.triggers) == {"push", "pull_request"}


def test_mapping_trigger_with_details() -> None:
    ir = _normalize_fixture("pull_request_target.yml")
    assert "pull_request_target" in ir.triggers
    assert "workflow_run" in ir.triggers
    assert ir.trigger_details["pull_request_target"]["types"] == ["opened", "synchronize"]


# ---------------------------------------------------------------------------
# Unit: dangerous trigger detection (accessor helper)
# ---------------------------------------------------------------------------


def test_has_dangerous_triggers() -> None:
    from pipelineshield.analysis.ir.accessors import has_dangerous_triggers

    ir = _normalize_fixture("pull_request_target.yml")
    assert has_dangerous_triggers(ir) is True


def test_no_dangerous_triggers() -> None:
    from pipelineshield.analysis.ir.accessors import has_dangerous_triggers

    ir = _normalize_fixture("minimal.yml")
    assert has_dangerous_triggers(ir) is False


# ---------------------------------------------------------------------------
# Unit: permissions states
# ---------------------------------------------------------------------------


def test_permissions_absent() -> None:
    ir = _normalize_fixture("minimal.yml")
    assert ir.permissions.state == "absent"


def test_permissions_explicit_workflow() -> None:
    ir = _normalize_fixture("pull_request_target.yml")
    assert ir.permissions.state == "explicit"
    assert ir.permissions.grants["contents"] == "read"
    assert ir.permissions.grants["pull-requests"] == "write"


def test_permissions_explicit_job() -> None:
    ir = _normalize_fixture("pull_request_target.yml")
    job = ir.jobs[0]
    assert job.permissions.state == "explicit"
    assert job.permissions.grants["pull-requests"] == "write"


def test_permissions_absent_job_inherits_via_accessor() -> None:
    from pipelineshield.analysis.ir.accessors import get_effective_permissions

    ir = _normalize_fixture("minimal.yml")
    job = ir.jobs[0]
    assert job.permissions.state == "absent"
    effective = get_effective_permissions(ir, job)
    assert effective.scope == "workflow_inherited"
    assert effective.state == "absent"


# ---------------------------------------------------------------------------
# Unit: action pin forms
# ---------------------------------------------------------------------------


def test_sha_pin() -> None:
    ir = _normalize_fixture("minimal.yml")
    ref = ir.jobs[0].steps[0].action_ref
    assert ref is not None
    assert ref.pin_form == "sha"
    assert len(ref.version_ref or "") == 40


def test_tag_pin() -> None:
    ir = _normalize_fixture("unpinned_actions.yml")
    checkout_ref = ir.jobs[0].steps[0].action_ref
    assert checkout_ref is not None
    assert checkout_ref.pin_form == "tag"
    assert checkout_ref.version_ref == "v4"


def test_branch_pin() -> None:
    ir = _normalize_fixture("unpinned_actions.yml")
    setup_node_ref = ir.jobs[0].steps[1].action_ref
    assert setup_node_ref is not None
    assert setup_node_ref.pin_form == "branch"
    assert setup_node_ref.version_ref == "main"


def test_local_pin_is_unresolved() -> None:
    ir = _normalize_fixture("composite_action_user.yml")
    step = ir.jobs[0].steps[1]
    assert step.action_ref is not None
    assert step.action_ref.pin_form == "local"

    unresolved_kinds = [u.kind for u in ir.coverage_report.unresolved]
    assert "composite_action" in unresolved_kinds


# ---------------------------------------------------------------------------
# Unit: secret references
# ---------------------------------------------------------------------------


def test_secret_ref_from_secrets_context() -> None:
    ir = _normalize_fixture("unpinned_actions.yml")
    deploy_step = ir.jobs[0].steps[2]
    secrets_refs = [r for r in deploy_step.secret_refs if r.source == "secrets"]
    assert len(secrets_refs) == 1
    assert secrets_refs[0].name == "DEPLOY_API_KEY"


def test_secret_ref_from_env_context() -> None:
    ir = _normalize_fixture("unpinned_actions.yml")
    deploy_step = ir.jobs[0].steps[2]
    env_refs = [r for r in deploy_step.secret_refs if r.source == "env"]
    assert len(env_refs) == 1
    assert env_refs[0].name == "CI_TOKEN"


def test_secret_ref_in_with_inputs() -> None:
    ir = _normalize_fixture("pull_request_target.yml")
    step = ir.jobs[0].steps[0]
    refs = [r for r in step.secret_refs if r.source == "secrets"]
    assert any(r.name == "GITHUB_TOKEN" for r in refs)


# ---------------------------------------------------------------------------
# Unit: reusable workflow is marked unresolved
# ---------------------------------------------------------------------------


def test_reusable_workflow_unresolved() -> None:
    ir = _normalize_fixture("reusable_workflow_caller.yml")
    unresolved = ir.coverage_report.unresolved
    assert len(unresolved) == 1
    assert unresolved[0].kind == "reusable_workflow"
    assert "call-workflow" in unresolved[0].locator


# ---------------------------------------------------------------------------
# Unit: static matrix extraction
# ---------------------------------------------------------------------------


def test_static_matrix_extracted() -> None:
    ir = _normalize_fixture("matrix_static.yml")
    job = ir.jobs[0]
    assert job.matrix is not None
    assert "python-version" in job.matrix
    assert job.matrix["python-version"] == ["3.11", "3.12"]


# ---------------------------------------------------------------------------
# Schema gate: PipelineIR validates against its own JSON schema
# ---------------------------------------------------------------------------


def test_ir_validates_against_own_schema() -> None:
    from pipelineshield.analysis.ir.accessors import is_schema_valid

    ir = _normalize_fixture("pull_request_target.yml")
    assert is_schema_valid(ir)

    # Verify the schema is producible (contract/ file may not exist yet in CI)
    schema = PipelineIR.model_json_schema()
    assert schema["title"] == "PipelineIR"
    assert "properties" in schema


# ---------------------------------------------------------------------------
# No-HTTP-egress: the normalizer imports no HTTP or I/O libraries
# ---------------------------------------------------------------------------


_BANNED_HTTP_MODULES = {
    "httpx", "aiohttp", "requests", "urllib3",
    "fastapi", "starlette",
    "sqlalchemy",
    "boto3", "botocore",
}


def test_no_http_egress_in_normalizer() -> None:
    """Verify that importing the normalizer does not pull in HTTP libraries."""
    # Force a clean re-import to check its dependency closure
    mod_name = "pipelineshield.analysis.normalizers.github_actions"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    importlib.import_module(mod_name)

    loaded = set(sys.modules.keys())
    banned_found = _BANNED_HTTP_MODULES & loaded
    assert not banned_found, (
        f"Normalizer pulled in banned HTTP/ORM modules: {banned_found}. "
        "Normalizers must never make outbound HTTP requests."
    )


# ---------------------------------------------------------------------------
# NormalizationResult has pipeline_ir set
# ---------------------------------------------------------------------------


def test_normalization_result_has_pipeline_ir() -> None:
    text = (_FIXTURE_DIR / "minimal.yml").read_text()
    result = GitHubActionsNormalizer().normalize(text)
    assert result.pipeline_ir is not None
    assert isinstance(result.pipeline_ir, PipelineIR)
    assert result.pipeline_ir.ir_version == IR_VERSION


# ---------------------------------------------------------------------------
# create_default_registry wires up github_actions
# ---------------------------------------------------------------------------


def test_create_default_registry_registers_github_actions() -> None:
    from pipelineshield.api.v1.schemas.analysis import PipelineFormat
    from pipelineshield.services.normalizer_registry import (
        PassthroughNormalizer,
        create_default_registry,
    )

    registry = create_default_registry()
    normalizer = registry.get_normalizer(PipelineFormat.github_actions)
    assert not isinstance(normalizer, PassthroughNormalizer), (
        "github_actions format must be handled by GitHubActionsNormalizer, not passthrough"
    )
