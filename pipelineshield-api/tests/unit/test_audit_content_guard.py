"""Unit tests for the audit content guard (reject mode).

Verifies:
- Each secret pattern triggers AuditContentViolation with the correct pattern_id
- Safe change_detail passes without error
- Oversized change_detail is truncated (not rejected) with _truncated marker
- High-entropy strings are rejected
- Nested dict/list structures are scanned recursively
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pipelineshield.platform.content_guard import (
    AuditContentViolation,
    guard_change_detail,
)

_FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "change_detail_with_secrets.json"


class TestContentGuardRejectMode:
    def test_safe_payload_passes(self) -> None:
        detail = {
            "version": 2,
            "diff_count": 3,
            "category": "secrets_hygiene",
        }
        result = guard_change_detail(detail)
        assert result["version"] == 2

    def test_github_pat_rejected(self) -> None:
        with pytest.raises(AuditContentViolation) as exc_info:
            guard_change_detail({"token": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
        assert exc_info.value.pattern_id == "github_pat"

    def test_aws_key_rejected(self) -> None:
        with pytest.raises(AuditContentViolation) as exc_info:
            guard_change_detail({"key": "AKIAIOSFODNN7EXAMPLE"})
        assert exc_info.value.pattern_id == "aws_access_key_id"

    def test_jwt_rejected(self) -> None:
        with pytest.raises(AuditContentViolation) as exc_info:
            guard_change_detail({
                "auth": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.dummysig"
            })
        assert exc_info.value.pattern_id == "jwt"

    def test_pem_block_rejected(self) -> None:
        with pytest.raises(AuditContentViolation) as exc_info:
            guard_change_detail({"key_material": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."})
        assert exc_info.value.pattern_id == "pem_block"

    def test_secret_key_name_rejected(self) -> None:
        with pytest.raises(AuditContentViolation) as exc_info:
            guard_change_detail({"database_password": "super$ecretPa55w0rd!"})
        assert exc_info.value.pattern_id == "key_name_value"

    def test_nested_dict_scanned(self) -> None:
        with pytest.raises(AuditContentViolation) as exc_info:
            guard_change_detail({
                "outer": {
                    "inner": {"token": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
                }
            })
        assert "inner.token" in exc_info.value.field_path

    def test_list_values_scanned(self) -> None:
        with pytest.raises(AuditContentViolation):
            guard_change_detail({
                "tokens": ["ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
            })

    def test_error_message_never_includes_value(self) -> None:
        secret_value = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        with pytest.raises(AuditContentViolation) as exc_info:
            guard_change_detail({"token": secret_value})
        assert secret_value not in str(exc_info.value)

    def test_high_entropy_string_rejected(self) -> None:
        # A 64-char random-looking string with high entropy
        high_entropy = "aB3xKq9mN2wP5vR7yT1uZ6eC8jH0iL4oS" + "qWeDrFtGyHuJkIlM"
        with pytest.raises(AuditContentViolation) as exc_info:
            guard_change_detail({"entropy_test": high_entropy})
        assert exc_info.value.pattern_id == "high_entropy"

    def test_low_entropy_string_passes(self) -> None:
        # Repetitive string — low entropy
        guard_change_detail({"text": "aaaa" * 20})

    def test_fixture_cases_all_rejected(self) -> None:
        fixture = json.loads(_FIXTURE_PATH.read_text())
        for case in fixture["cases"]:
            with pytest.raises(AuditContentViolation) as exc_info:
                guard_change_detail(case["change_detail"])
            assert exc_info.value.pattern_id == case["expected_pattern"], (
                f"Case {case['name']!r}: expected pattern {case['expected_pattern']!r} "
                f"but got {exc_info.value.pattern_id!r}"
            )


class TestContentGuardSizeLimit:
    def test_oversized_payload_truncated(self) -> None:
        big_detail = {"data": "x" * 70_000}
        result = guard_change_detail(big_detail)
        assert result.get("_truncated") is True
        assert "reason" in result or "_reason" in result

    def test_truncation_marker_present(self) -> None:
        big_detail = {"big": "y" * 70_000}
        result = guard_change_detail(big_detail)
        assert result["_truncated"] is True

    def test_within_limit_not_truncated(self) -> None:
        small_detail = {"version": 1, "action": "catalogue.version_created"}
        result = guard_change_detail(small_detail)
        assert "_truncated" not in result

    def test_truncation_preferred_over_rejection(self) -> None:
        # A safe but oversized payload should be truncated, not raise
        safe_big = {"data": "hello " * 15_000}
        result = guard_change_detail(safe_big)
        assert result.get("_truncated") is True
