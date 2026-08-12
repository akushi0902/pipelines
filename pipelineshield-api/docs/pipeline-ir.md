# PipelineIR — Pipeline Intermediate Representation

**Version:** 1.0  
**File:** `pipelineshield/analysis/ir/pipeline_ir.py`  
**Schema:** `contracts/pipeline-ir.schema.json`

## Overview

PipelineIR is the single, versioned intermediate representation produced by
format-specific normalizers (GitHub Actions, GitLab CI, Jenkins). Security
rules consume the IR via `accessors.py` and never access raw pipeline YAML.

All models are **frozen Pydantic v2** — once produced, an IR is immutable.

---

## Versioning

| Version | Changes |
|---------|---------|
| 1.0 | Initial release (WO-006) |

Versioning is **additive-only**: new optional fields may be added in minor
versions. Existing fields are never removed or renamed without a major version
bump. Consumers should assert `ir.ir_version.startswith("1.")`.

---

## Root: `PipelineIR`

| Field | Type | Description |
|-------|------|-------------|
| `ir_version` | `str` | Schema version string (default `"1.0"`) |
| `source_format` | `str` | `"github_actions"` \| `"gitlab_ci"` \| `"jenkins"` |
| `triggers` | `list[str]` | De-duplicated event names in document order |
| `trigger_details` | `dict[str, Any]` | Raw trigger config keyed by event name |
| `permissions` | `EffectivePermissions` | Workflow-level permissions declaration |
| `jobs` | `list[Job]` | Jobs in document order |
| `coverage_report` | `CoverageReport` | Unresolved constructs and coverage accounting |
| `trigger_anchor` | `Anchor \| None` | Source location of the `on:` key |

---

## `Anchor`

Maps every IR node back to its origin in the raw YAML (1-based).

| Field | Type | Description |
|-------|------|-------------|
| `start_line` | `int ≥ 1` | Line number in the source file |
| `start_column` | `int ≥ 1` | Column number in the source file |
| `end_line` | `int \| None` | End line (optional; may be absent for scalars) |

---

## `EffectivePermissions`

Represents a permissions declaration with an explicit semantic state.

| Field | Type | Description |
|-------|------|-------------|
| `scope` | `str` | `"workflow"` \| `"job"` \| `"workflow_inherited"` |
| `state` | `str` | See states below |
| `grants` | `dict[str, str]` | Scope → level (e.g. `{"contents": "read"}`) |
| `anchor` | `Anchor \| None` | Source location of the `permissions:` key |

### `state` values

| Value | Meaning |
|-------|---------|
| `absent` | `permissions:` key not present; GitHub applies default token permissions |
| `empty` | `permissions: {}` or `permissions: null`; no scopes granted |
| `write_all` | `permissions: write-all`; all scopes have write access |
| `explicit` | `permissions:` with named scope grants |

---

## `Job`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Job key from `jobs.<id>` |
| `name` | `str \| None` | Human-readable name |
| `runs_on` | `str \| list[str] \| None` | Runner label(s) |
| `steps` | `list[Step]` | Steps in document order |
| `permissions` | `EffectivePermissions` | Job-level permissions (state=absent if not declared) |
| `needs` | `list[str]` | Job IDs this job depends on |
| `condition` | `str \| None` | The `if:` condition expression |
| `matrix` | `dict[str, Any] \| None` | Statically-enumerable matrix; `None` if dynamic/absent |
| `anchor` | `Anchor \| None` | Source location of the job node |

---

## `Step`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str \| None` | Step `id:` value |
| `name` | `str \| None` | Step `name:` value |
| `uses` | `str \| None` | Raw `uses:` string |
| `run` | `str \| None` | Shell script content |
| `env` | `dict[str, str]` | Step-level `env:` map |
| `with_inputs` | `dict[str, str]` | Step `with:` inputs |
| `continue_on_error` | `bool` | `continue-on-error:` flag |
| `anchor` | `Anchor \| None` | Source location |
| `action_ref` | `ActionRef \| None` | Parsed action reference (set when `uses` is present) |
| `secret_refs` | `list[SecretRef]` | Secret references found in env/with/run |

---

## `ActionRef`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Action name (without version ref) |
| `version_ref` | `str \| None` | The ref after `@` |
| `pin_form` | `str` | See pin forms below |
| `anchor` | `Anchor \| None` | Source location |

### `pin_form` values

| Value | Example | Security implication |
|-------|---------|---------------------|
| `sha` | `actions/checkout@abc123...` | Immutable — most secure |
| `tag` | `actions/checkout@v4` | Mutable tag pointer |
| `branch` | `actions/setup-node@main` | Mutable, HEAD-tracking — least secure |
| `local` | `./path/to/action` | Composite action; marked Not Assessable |
| `docker` | `docker://ubuntu:22.04` | Docker image reference |

---

## `SecretRef`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Variable name extracted from the expression |
| `source` | `str` | `"secrets"` \| `"env"` \| `"expression"` |
| `expression` | `str \| None` | Full inner expression text |
| `anchor` | `Anchor \| None` | Source location |

---

## `UnresolvedFragment`

Records constructs that require external resolution and cannot be statically assessed.

| Field | Type | Description |
|-------|------|-------------|
| `kind` | `str` | `"composite_action"` \| `"reusable_workflow"` \| `"matrix_dynamic"` |
| `locator` | `str` | Dot-path to the construct (e.g. `jobs.build.steps[1].uses`) |
| `reason` | `str` | Human-readable explanation |

---

## `CoverageReport`

| Field | Type | Description |
|-------|------|-------------|
| `unresolved` | `list[UnresolvedFragment]` | Constructs that could not be assessed |
| `constructs_handled` | `list[str]` | Construct types this normalizer processed |
| `constructs_excluded` | `list[str]` | Construct types present but intentionally excluded |

---

## Accessor API

Rules must use `pipelineshield.analysis.ir.accessors` instead of accessing
model fields directly. Key functions:

```python
from pipelineshield.analysis.ir.accessors import (
    get_triggers,          # list[str]
    has_trigger,           # bool
    has_dangerous_triggers, # bool — pull_request_target or workflow_run
    get_jobs,              # list[Job]
    get_steps,             # list[Step]
    get_action_refs,       # list[ActionRef]
    get_secret_refs,       # list[SecretRef]
    get_effective_permissions,  # EffectivePermissions (with inheritance)
    iter_all_action_refs,  # Iterator[(job_id, step_idx, ActionRef)]
    iter_all_secret_refs,  # Iterator[(job_id, step_idx, SecretRef)]
    get_unresolved,        # list[UnresolvedFragment]
    is_schema_valid,       # bool
)
```

---

## YAML 1.2 Mode

The loader (`yaml_loader.py`) uses `ruamel.yaml` in round-trip mode with
`y.version = (1, 2)`. This prevents YAML 1.1 boolean coercions:

| Source text | YAML 1.1 | YAML 1.2 (used here) |
|-------------|----------|----------------------|
| `on:` key | `True` | `"on"` |
| `NO` value | `False` | `"NO"` |
| `Yes` value | `True` | `"Yes"` |
| `off` value | `False` | `"off"` |

Without YAML 1.2, GitHub Actions `on:` trigger blocks would corrupt trigger
analysis by becoming boolean `True`.

---

## Anchor Bomb Guard

The loader rejects documents with more than `MAX_ALIASES = 100` alias
references (`*identifier`), guarding against exponential memory expansion
from deeply nested YAML anchors.
