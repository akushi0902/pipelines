"""Content-safety assertions for the committed audit fixture corpus (AC-8, AC-11).

Verifies:
- Every change_detail entry in the 'corpus' array passes the content guard
  (no secret-shaped values, no pipeline definition content).
- Every entry in 'content_safety_negative_cases' is rejected by the guard
  with a non-null pattern_id.
- No entry in the corpus contains a raw pipeline definition YAML excerpt.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipelineshield.platform.content_guard import AuditContentViolation, guard_change_detail

_FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "audit_corpus.json"

_DEFINITION_INDICATORS = (
    "steps:",
    "jobs:",
    "stages:",
    "pipeline {",
    "agent {",
    "uses: actions/",
    "script:",
    "runs-on:",
)


@pytest.fixture(scope="module")
def audit_corpus():
    return json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))


class TestAuditCorpusContentSafety:
    def test_all_corpus_entries_pass_content_guard(self, audit_corpus) -> None:
        """Every committed audit event change_detail must pass the content guard."""
        for entry in audit_corpus["corpus"]:
            action = entry["action"]
            detail = entry["change_detail"]
            try:
                guard_change_detail(detail)
            except AuditContentViolation as exc:
                pytest.fail(
                    f"Corpus entry {action!r} failed content guard: "
                    f"pattern={exc.pattern_id!r} field={exc.field_path!r}"
                )

    def test_corpus_entries_contain_no_definition_excerpts(self, audit_corpus) -> None:
        """No corpus change_detail should contain raw pipeline definition content."""
        for entry in audit_corpus["corpus"]:
            detail_str = json.dumps(entry["change_detail"])
            for indicator in _DEFINITION_INDICATORS:
                assert indicator not in detail_str, (
                    f"Corpus entry {entry['action']!r} contains a definition excerpt "
                    f"({indicator!r}). Audit records must hold metadata only."
                )

    def test_negative_cases_are_rejected_by_content_guard(self, audit_corpus) -> None:
        """Entries in content_safety_negative_cases must trigger AuditContentViolation."""
        for case in audit_corpus["content_safety_negative_cases"]:
            detail = case["change_detail"]
            with pytest.raises(AuditContentViolation, match=""):
                guard_change_detail(detail)

    def test_fixture_file_has_required_sections(self, audit_corpus) -> None:
        assert "corpus" in audit_corpus, "audit_corpus.json must have a 'corpus' key"
        assert "content_safety_negative_cases" in audit_corpus
        assert len(audit_corpus["corpus"]) >= 5, "Corpus must cover at least 5 action types"

    def test_corpus_covers_key_action_types(self, audit_corpus) -> None:
        actions = {entry["action"] for entry in audit_corpus["corpus"]}
        required = {
            "catalogue.version_created",
            "analysis.ingestion_accepted",
            "auth.login_success",
            "auth.login_failure",
            "auth.logout",
        }
        missing = required - actions
        assert not missing, f"Audit corpus is missing action types: {missing}"

    def test_corpus_entries_have_non_empty_change_detail(self, audit_corpus) -> None:
        for entry in audit_corpus["corpus"]:
            assert entry["change_detail"], (
                f"Corpus entry {entry['action']!r} has an empty change_detail"
            )
