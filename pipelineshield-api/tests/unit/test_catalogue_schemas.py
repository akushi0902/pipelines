"""Unit tests for CatalogueSnapshot Pydantic v2 validators and checksum helpers.

Covers:
- Valid v1 fixture loads without error.
- Weight total validation (99, 100, 101).
- Duplicate category and control IDs rejected.
- Unknown severity enum value rejected.
- Grade band gap and overlap rejected.
- Checksum determinism across different key insertion orders.
- CatalogueValidationError carries field and value attributes.
- GradeBand with min > max rejected.
- Snapshot with zero enabled categories rejected.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from pipelineshield.catalogue import (
    CatalogueSnapshot,
    CatalogueValidationError,
    ControlCategory,
    ControlDefinition,
    GradeBand,
    Severity,
    canonical_json,
    compute_checksum,
)

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _minimal_snapshot(weight: int = 100) -> dict:
    """Minimal valid snapshot with a single category.

    The default control uses severity=high with a reference_tool to satisfy
    the WO-015 constraint that Critical/High controls must name at least one tool.
    """
    return {
        "categories": [
            {
                "id": "cat_a",
                "name": "Category A",
                "weight": weight,
                "enabled": True,
                "description": "",
                "controls": [
                    {
                        "id": "ctrl-001",
                        "category_id": "cat_a",
                        "severity": "high",
                        "enabled": True,
                        "reference_tools": ["TestTool"],
                        "remediation_template_ref": None,
                    }
                ],
            }
        ],
        "grade_bands": [
            {"grade": "F", "min_score": 0, "max_score": 59},
            {"grade": "D", "min_score": 60, "max_score": 69},
            {"grade": "C", "min_score": 70, "max_score": 79},
            {"grade": "B", "min_score": 80, "max_score": 89},
            {"grade": "A", "min_score": 90, "max_score": 100},
        ],
    }


# ---------------------------------------------------------------------------
# Valid fixture
# ---------------------------------------------------------------------------


def test_v1_fixture_loads_without_error():
    raw = _load("catalogue_v1.json")
    snapshot = CatalogueSnapshot.model_validate(raw)
    assert len(snapshot.categories) == 9
    total = sum(c.weight for c in snapshot.categories if c.enabled)
    assert total == 100


def test_v1_fixture_has_correct_grade_bands():
    raw = _load("catalogue_v1.json")
    snapshot = CatalogueSnapshot.model_validate(raw)
    grades = {gb.grade for gb in snapshot.grade_bands}
    assert grades == {"A", "B", "C", "D", "F"}


def test_v1_fixture_all_controls_have_valid_severity():
    raw = _load("catalogue_v1.json")
    snapshot = CatalogueSnapshot.model_validate(raw)
    valid_severities = {s.value for s in Severity}
    for cat in snapshot.categories:
        for ctrl in cat.controls:
            assert ctrl.severity.value in valid_severities


# ---------------------------------------------------------------------------
# Weight total validation
# ---------------------------------------------------------------------------


def test_weight_total_99_rejected():
    data = _minimal_snapshot(weight=99)
    with pytest.raises(ValidationError, match="100"):
        CatalogueSnapshot.model_validate(data)


def test_weight_total_100_accepted():
    data = _minimal_snapshot(weight=100)
    snap = CatalogueSnapshot.model_validate(data)
    assert snap.categories[0].weight == 100


def test_weight_total_101_rejected():
    data = _minimal_snapshot(weight=101)
    with pytest.raises(ValidationError):
        CatalogueSnapshot.model_validate(data)


def test_invalid_weight_fixture_rejected():
    raw = _load("catalogue_invalid_weight.json")
    with pytest.raises(ValidationError, match="101"):
        CatalogueSnapshot.model_validate(raw)


def test_disabled_category_weight_excluded_from_total():
    """Disabled category's weight is excluded from the 100-total check."""
    data = {
        "categories": [
            {
                "id": "cat_enabled",
                "name": "Enabled",
                "weight": 100,
                "enabled": True,
                "description": "",
                "controls": [],
            },
            {
                "id": "cat_disabled",
                "name": "Disabled",
                "weight": 50,
                "enabled": False,  # excluded from total
                "description": "",
                "controls": [],
            },
        ],
        "grade_bands": [
            {"grade": "F", "min_score": 0, "max_score": 59},
            {"grade": "D", "min_score": 60, "max_score": 69},
            {"grade": "C", "min_score": 70, "max_score": 79},
            {"grade": "B", "min_score": 80, "max_score": 89},
            {"grade": "A", "min_score": 90, "max_score": 100},
        ],
    }
    snap = CatalogueSnapshot.model_validate(data)
    assert not snap.categories[1].enabled


# ---------------------------------------------------------------------------
# Duplicate ID validation
# ---------------------------------------------------------------------------


def test_duplicate_category_id_rejected():
    raw = _load("catalogue_invalid_duplicate_id.json")
    with pytest.raises(ValidationError, match="[Dd]uplicate"):
        CatalogueSnapshot.model_validate(raw)


def test_duplicate_control_id_rejected():
    data = {
        "categories": [
            {
                "id": "cat_a",
                "name": "Cat A",
                "weight": 60,
                "enabled": True,
                "description": "",
                "controls": [
                    {
                        "id": "ctrl-001",
                        "category_id": "cat_a",
                        "severity": "high",
                        "enabled": True,
                        "reference_tools": ["ToolA"],
                        "remediation_template_ref": None,
                    },
                    {
                        "id": "ctrl-001",  # duplicate!
                        "category_id": "cat_a",
                        "severity": "medium",
                        "enabled": True,
                        "reference_tools": [],
                        "remediation_template_ref": None,
                    },
                ],
            },
            {
                "id": "cat_b",
                "name": "Cat B",
                "weight": 40,
                "enabled": True,
                "description": "",
                "controls": [],
            },
        ],
        "grade_bands": [
            {"grade": "F", "min_score": 0, "max_score": 59},
            {"grade": "D", "min_score": 60, "max_score": 69},
            {"grade": "C", "min_score": 70, "max_score": 79},
            {"grade": "B", "min_score": 80, "max_score": 89},
            {"grade": "A", "min_score": 90, "max_score": 100},
        ],
    }
    with pytest.raises(ValidationError, match="[Dd]uplicate"):
        CatalogueSnapshot.model_validate(data)


# ---------------------------------------------------------------------------
# Severity enum validation
# ---------------------------------------------------------------------------


def test_unknown_severity_rejected():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["severity"] = "UNKNOWN"
    with pytest.raises(ValidationError):
        CatalogueSnapshot.model_validate(data)


def test_all_severity_values_accepted():
    for sev in ("critical", "high", "medium", "low", "info"):
        data = _minimal_snapshot()
        data["categories"][0]["controls"][0]["severity"] = sev
        # Critical/High need at least one reference_tool (WO-015 constraint)
        if sev in ("critical", "high"):
            data["categories"][0]["controls"][0]["reference_tools"] = ["TestTool"]
        else:
            data["categories"][0]["controls"][0]["reference_tools"] = []
        snap = CatalogueSnapshot.model_validate(data)
        assert snap.categories[0].controls[0].severity.value == sev


# ---------------------------------------------------------------------------
# Grade band coverage validation
# ---------------------------------------------------------------------------


def test_invalid_grade_gap_fixture_rejected():
    raw = _load("catalogue_invalid_grade_gap.json")
    with pytest.raises(ValidationError, match="[Gg]ap|[Oo]verlap|expected"):
        CatalogueSnapshot.model_validate(raw)


def test_grade_bands_not_starting_at_zero_rejected():
    data = _minimal_snapshot()
    data["grade_bands"] = [{"grade": "A", "min_score": 1, "max_score": 100}]
    with pytest.raises(ValidationError, match="0"):
        CatalogueSnapshot.model_validate(data)


def test_grade_bands_not_ending_at_100_rejected():
    data = _minimal_snapshot()
    data["grade_bands"] = [{"grade": "A", "min_score": 0, "max_score": 99}]
    with pytest.raises(ValidationError, match="100"):
        CatalogueSnapshot.model_validate(data)


def test_overlapping_grade_bands_rejected():
    data = _minimal_snapshot()
    # C ends at 80, B starts at 80 — overlap at 80.
    data["grade_bands"] = [
        {"grade": "F", "min_score": 0, "max_score": 59},
        {"grade": "D", "min_score": 60, "max_score": 69},
        {"grade": "C", "min_score": 70, "max_score": 80},
        {"grade": "B", "min_score": 80, "max_score": 89},
        {"grade": "A", "min_score": 90, "max_score": 100},
    ]
    with pytest.raises(ValidationError):
        CatalogueSnapshot.model_validate(data)


# ---------------------------------------------------------------------------
# GradeBand min > max
# ---------------------------------------------------------------------------


def test_grade_band_min_greater_than_max_rejected():
    with pytest.raises(ValidationError):
        GradeBand(grade="X", min_score=80, max_score=70)


# ---------------------------------------------------------------------------
# Zero enabled categories
# ---------------------------------------------------------------------------


def test_zero_enabled_categories_rejected():
    data = _minimal_snapshot()
    data["categories"][0]["enabled"] = False
    with pytest.raises(ValidationError, match="[Ee]nabled|disabled"):
        CatalogueSnapshot.model_validate(data)


# ---------------------------------------------------------------------------
# Checksum determinism
# ---------------------------------------------------------------------------


def test_canonical_json_sorts_keys():
    a = canonical_json({"z": 1, "a": 2})
    b = canonical_json({"a": 2, "z": 1})
    assert a == b
    assert a == '{"a":2,"z":1}'


def test_checksum_same_for_different_key_orders():
    snapshot_a = {"categories": [], "grade_bands": [], "meta": {"version": 1}}
    snapshot_b = {"meta": {"version": 1}, "grade_bands": [], "categories": []}
    assert compute_checksum(snapshot_a) == compute_checksum(snapshot_b)


def test_checksum_is_64_char_hex():
    digest = compute_checksum({"x": 1})
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_v1_fixture_checksum_stable():
    """Checksum of catalogue_v1.json must not change across runs."""
    raw = _load("catalogue_v1.json")
    snap = CatalogueSnapshot.model_validate(raw)
    checksum1 = compute_checksum(snap.model_dump())
    checksum2 = compute_checksum(snap.model_dump())
    assert checksum1 == checksum2
    assert len(checksum1) == 64


def test_different_snapshots_have_different_checksums():
    a = compute_checksum({"value": 1})
    b = compute_checksum({"value": 2})
    assert a != b


# ---------------------------------------------------------------------------
# CatalogueValidationError
# ---------------------------------------------------------------------------


def test_catalogue_validation_error_has_field_and_value():
    err = CatalogueValidationError("bad field", field="weight", value=99)
    assert err.field == "weight"
    assert err.value == 99
    assert "bad field" in str(err)


def test_catalogue_validation_error_defaults():
    err = CatalogueValidationError("plain error")
    assert err.field == ""
    assert err.value is None


# ---------------------------------------------------------------------------
# ControlSource enum (WO-015)
# ---------------------------------------------------------------------------


def test_control_source_deterministic_is_default():
    from pipelineshield.catalogue import ControlSource
    data = _minimal_snapshot()
    snap = CatalogueSnapshot.model_validate(data)
    ctrl = snap.categories[0].controls[0]
    assert ctrl.source == ControlSource.DETERMINISTIC


def test_control_source_ai_advisory_accepted():
    from pipelineshield.catalogue import ControlSource
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["source"] = "ai_advisory"
    # weight_contribution must be 0 for ai_advisory (default is 0.0)
    snap = CatalogueSnapshot.model_validate(data)
    assert snap.categories[0].controls[0].source == ControlSource.AI_ADVISORY


def test_control_source_invalid_value_rejected():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["source"] = "nonexistent_source"
    with pytest.raises(ValidationError):
        CatalogueSnapshot.model_validate(data)


# ---------------------------------------------------------------------------
# AI-advisory zero-weight constraint (WO-015)
# ---------------------------------------------------------------------------


def test_ai_advisory_control_with_nonzero_weight_rejected():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["source"] = "ai_advisory"
    data["categories"][0]["controls"][0]["weight_contribution"] = 5.0
    with pytest.raises(ValidationError, match="[Aa][Ii]|ai_advisory|weight"):
        CatalogueSnapshot.model_validate(data)


def test_ai_advisory_control_with_zero_weight_accepted():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["source"] = "ai_advisory"
    data["categories"][0]["controls"][0]["weight_contribution"] = 0.0
    snap = CatalogueSnapshot.model_validate(data)
    assert snap.categories[0].controls[0].weight_contribution == 0.0


def test_deterministic_control_with_positive_weight_accepted():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["source"] = "deterministic"
    data["categories"][0]["controls"][0]["weight_contribution"] = 5.0
    snap = CatalogueSnapshot.model_validate(data)
    assert snap.categories[0].controls[0].weight_contribution == 5.0


# ---------------------------------------------------------------------------
# Critical/High controls must have reference_tools (WO-015)
# ---------------------------------------------------------------------------


def test_critical_control_without_reference_tools_rejected():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["severity"] = "critical"
    data["categories"][0]["controls"][0]["reference_tools"] = []
    with pytest.raises(ValidationError, match="[Rr]eference|tool"):
        CatalogueSnapshot.model_validate(data)


def test_high_control_without_reference_tools_rejected():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["severity"] = "high"
    data["categories"][0]["controls"][0]["reference_tools"] = []
    with pytest.raises(ValidationError, match="[Rr]eference|tool"):
        CatalogueSnapshot.model_validate(data)


def test_critical_control_with_reference_tools_accepted():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["severity"] = "critical"
    data["categories"][0]["controls"][0]["reference_tools"] = ["Gitleaks"]
    snap = CatalogueSnapshot.model_validate(data)
    assert snap.categories[0].controls[0].reference_tools == ["Gitleaks"]


def test_medium_control_without_reference_tools_accepted():
    """Medium severity controls are not required to specify reference_tools."""
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["severity"] = "medium"
    data["categories"][0]["controls"][0]["reference_tools"] = []
    snap = CatalogueSnapshot.model_validate(data)
    assert snap.categories[0].controls[0].reference_tools == []


def test_low_control_without_reference_tools_accepted():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["severity"] = "low"
    data["categories"][0]["controls"][0]["reference_tools"] = []
    snap = CatalogueSnapshot.model_validate(data)
    assert snap.categories[0].controls[0].reference_tools == []


def test_v1_fixture_passes_reference_tools_validation():
    """Updated v1 fixture must pass the new reference_tools constraint."""
    raw = _load("catalogue_v1.json")
    snap = CatalogueSnapshot.model_validate(raw)
    from pipelineshield.catalogue.schemas import Severity
    high_sev = {Severity.CRITICAL, Severity.HIGH}
    for cat in snap.categories:
        for ctrl in cat.controls:
            if ctrl.severity in high_sev:
                assert ctrl.reference_tools, (
                    f"{ctrl.id} has {ctrl.severity.value} severity but empty reference_tools"
                )


# ---------------------------------------------------------------------------
# weight_contribution field (WO-015)
# ---------------------------------------------------------------------------


def test_weight_contribution_defaults_to_zero():
    data = _minimal_snapshot()
    snap = CatalogueSnapshot.model_validate(data)
    assert snap.categories[0].controls[0].weight_contribution == 0.0


def test_weight_contribution_accepts_positive_float():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["weight_contribution"] = 12.5
    snap = CatalogueSnapshot.model_validate(data)
    assert snap.categories[0].controls[0].weight_contribution == 12.5


def test_weight_contribution_negative_rejected():
    data = _minimal_snapshot()
    data["categories"][0]["controls"][0]["weight_contribution"] = -1.0
    with pytest.raises(ValidationError):
        CatalogueSnapshot.model_validate(data)
