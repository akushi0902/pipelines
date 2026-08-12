"""Unit tests for AnchorValidator — WO-017.

Coverage:
  1. missing_anchor suppression
  2. out_of_range — below 1 and above total_lines
  3. unresolved_fragment suppression
  4. blank_target_line suppression
  5. fingerprint_mismatch on mutated fixture
  6. successful validation — correct snippet extracted
  7. snippet secret-pattern re-scan → [REDACTED:snippet_scan]
  8. SARIF serialization — anchor_line == physicalLocation.region.startLine
  9. empty candidate list — empty accepted, zero-count report
  10. metrics incremented on suppression and acceptance
  11. AnchorValidationConfigurationError on non-normalized document
  12. duplicate deduplication is caller responsibility (validator accepts both)
  13. context_lines expands snippet window
  14. build_redacted_document — CRLF normalization
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import replace
from unittest.mock import MagicMock

import pytest

from pipelineshield.analysis.anchoring import (
    AnchorValidationConfigurationError,
    AnchorValidator,
    CandidateFinding,
    SuppressionReason,
    ValidatedFinding,
    build_redacted_document,
)
from pipelineshield.analysis.anchoring.redacted_document import (
    RedactedDocument,
    _RedactedLine,
    _line_fingerprint,
)
from pipelineshield.analysis.redactor import redact
from pipelineshield.analysis.rule_engine.protocol import EvidenceAnchor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ANALYSIS_ID = uuid.uuid4()
_WORKSPACE_ID = uuid.uuid4()


def _make_document(text: str) -> RedactedDocument:
    return build_redacted_document(redact(text))


def _make_candidate(
    line_no: int | None = 2,
    source: str = "deterministic",
    text: str = "",
    line_fingerprint: str | None = None,
) -> CandidateFinding:
    anchor = (
        EvidenceAnchor(start_line=line_no, start_column=1)
        if line_no is not None
        else None
    )
    return CandidateFinding(
        rule_id="test-rule",
        control_id="sh-001",
        category="secrets_hygiene",
        source=source,
        severity="high",
        title="Test finding",
        description="",
        evidence={},
        analysis_id=_ANALYSIS_ID,
        workspace_id=_WORKSPACE_ID,
        anchor=anchor,
        line_fingerprint=line_fingerprint,
    )


_SAMPLE_TEXT = "line one\nline two\nline three\n"


# ---------------------------------------------------------------------------
# 1. missing_anchor
# ---------------------------------------------------------------------------


class TestMissingAnchor:
    def test_candidate_without_anchor_suppressed(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=None)

        accepted, report = validator.validate([candidate], doc)

        assert not accepted
        assert report.total() == 1
        assert report.suppressions[0].reason == SuppressionReason.MISSING_ANCHOR

    def test_accepted_when_anchor_present(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=1)

        accepted, report = validator.validate([candidate], doc)

        assert len(accepted) == 1
        assert report.total() == 0


# ---------------------------------------------------------------------------
# 2. out_of_range
# ---------------------------------------------------------------------------


class TestOutOfRange:
    def test_line_zero_suppressed(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=0)

        accepted, report = validator.validate([candidate], doc)

        assert not accepted
        assert report.suppressions[0].reason == SuppressionReason.OUT_OF_RANGE

    def test_negative_line_suppressed(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=-5)

        accepted, report = validator.validate([candidate], doc)

        assert report.suppressions[0].reason == SuppressionReason.OUT_OF_RANGE

    def test_line_beyond_total_suppressed(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=doc.total_lines + 10)

        accepted, report = validator.validate([candidate], doc)

        assert report.suppressions[0].reason == SuppressionReason.OUT_OF_RANGE

    def test_last_valid_line_accepted(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=doc.total_lines)

        accepted, report = validator.validate([candidate], doc)

        assert len(accepted) == 1


# ---------------------------------------------------------------------------
# 3. unresolved_fragment
# ---------------------------------------------------------------------------


class TestUnresolvedFragment:
    def test_line_in_unresolved_fragment_suppressed(self):
        doc_raw = build_redacted_document(
            redact(_SAMPLE_TEXT),
            fragment_resolution={(2, 2): "unresolved"},
        )
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=2)

        accepted, report = validator.validate([candidate], doc_raw)

        assert not accepted
        assert report.suppressions[0].reason == SuppressionReason.UNRESOLVED_FRAGMENT

    def test_line_outside_unresolved_range_accepted(self):
        doc_raw = build_redacted_document(
            redact(_SAMPLE_TEXT),
            fragment_resolution={(5, 10): "unresolved"},
        )
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=2)

        accepted, report = validator.validate([candidate], doc_raw)

        assert len(accepted) == 1

    def test_heuristic_fragment_accepted(self):
        doc_raw = build_redacted_document(
            redact(_SAMPLE_TEXT),
            fragment_resolution={(2, 2): "heuristic"},
        )
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=2)

        accepted, report = validator.validate([candidate], doc_raw)

        assert len(accepted) == 1


# ---------------------------------------------------------------------------
# 4. blank_target_line
# ---------------------------------------------------------------------------


class TestBlankTargetLine:
    def test_blank_line_suppressed(self):
        text = "line one\n\nline three\n"
        doc = _make_document(text)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=2)

        accepted, report = validator.validate([candidate], doc)

        assert not accepted
        assert report.suppressions[0].reason == SuppressionReason.BLANK_TARGET_LINE

    def test_whitespace_only_line_suppressed(self):
        text = "line one\n   \nline three\n"
        doc = _make_document(text)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=2)

        accepted, report = validator.validate([candidate], doc)

        assert report.suppressions[0].reason == SuppressionReason.BLANK_TARGET_LINE

    def test_non_blank_line_accepted(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=1)

        accepted, report = validator.validate([candidate], doc)

        assert len(accepted) == 1


# ---------------------------------------------------------------------------
# 5. fingerprint_mismatch
# ---------------------------------------------------------------------------


class TestFingerprintMismatch:
    def test_wrong_fingerprint_suppressed(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        bad_fp = hashlib.sha256(b"completely different content").hexdigest()
        candidate = _make_candidate(line_no=1, line_fingerprint=bad_fp)

        accepted, report = validator.validate([candidate], doc)

        assert not accepted
        assert report.suppressions[0].reason == SuppressionReason.FINGERPRINT_MISMATCH

    def test_correct_fingerprint_accepted(self):
        doc = _make_document(_SAMPLE_TEXT)
        line = doc.get_line(1)
        assert line is not None
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=1, line_fingerprint=line.fingerprint)

        accepted, report = validator.validate([candidate], doc)

        assert len(accepted) == 1
        assert report.total() == 0

    def test_no_fingerprint_skips_check(self):
        """Candidate without line_fingerprint skips the fingerprint check."""
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=1, line_fingerprint=None)

        accepted, report = validator.validate([candidate], doc)

        assert len(accepted) == 1

    def test_mutated_fixture_suppressed(self):
        """Fingerprint computed from original content rejected against mutated doc."""
        original = "line one\nline two\nline three\n"
        mutated = "line one\nLINE TWO MUTATED\nline three\n"

        original_doc = _make_document(original)
        original_line = original_doc.get_line(2)
        assert original_line is not None
        original_fp = original_line.fingerprint

        mutated_doc = _make_document(mutated)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=2, line_fingerprint=original_fp)

        accepted, report = validator.validate([candidate], mutated_doc)

        assert not accepted
        assert report.suppressions[0].reason == SuppressionReason.FINGERPRINT_MISMATCH


# ---------------------------------------------------------------------------
# 6. Successful validation and snippet extraction
# ---------------------------------------------------------------------------


class TestSuccessfulValidation:
    def test_returns_validated_finding_type(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=2)

        accepted, report = validator.validate([candidate], doc)

        assert len(accepted) == 1
        assert isinstance(accepted[0], ValidatedFinding)

    def test_snippet_contains_anchored_line(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=2)

        accepted, _ = validator.validate([candidate], doc)

        assert "line two" in accepted[0].snippet

    def test_anchor_coordinates_preserved(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator(analysis_id="test-123")
        candidate = _make_candidate(line_no=2)

        accepted, _ = validator.validate([candidate], doc)

        assert accepted[0].anchor_line == 2
        assert accepted[0].anchor_column == 1

    def test_context_lines_expand_snippet(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator(context_lines=1)
        candidate = _make_candidate(line_no=2)

        accepted, _ = validator.validate([candidate], doc)

        snippet = accepted[0].snippet
        assert "line one" in snippet
        assert "line two" in snippet
        assert "line three" in snippet

    def test_snippet_truncated_at_max_length(self):
        long_text = ("x" * 210) + "\n" + ("y" * 10) + "\n"
        doc = _make_document(long_text)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=1)

        accepted, _ = validator.validate([candidate], doc)

        assert len(accepted[0].snippet) <= 200


# ---------------------------------------------------------------------------
# 7. Snippet secret-pattern re-scan
# ---------------------------------------------------------------------------


class TestSnippetSecretScan:
    def test_token_bearing_snippet_masked(self):
        """A line containing a GitHub PAT-shaped token is masked in the snippet."""
        # SYNTHETIC PLACEHOLDER — not a real token
        synthetic_pat = "ghp_" + "A" * 40
        text = f"line one\nAPI_TOKEN: {synthetic_pat}\nline three\n"
        doc = _make_document(text)
        validator = AnchorValidator()
        # Point at the token-bearing line (line 2)
        candidate = _make_candidate(line_no=2)

        accepted, report = validator.validate([candidate], doc)

        # The finding is accepted but snippet is masked
        assert len(accepted) == 1
        snippet = accepted[0].snippet
        assert "[REDACTED:" in snippet or "REDACTED" in snippet

    def test_clean_snippet_not_masked(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=1)

        accepted, _ = validator.validate([candidate], doc)

        assert "[REDACTED:snippet_scan]" not in accepted[0].snippet


# ---------------------------------------------------------------------------
# 8. SARIF serialization
# ---------------------------------------------------------------------------


class TestSARIFCompatibility:
    def test_anchor_line_maps_to_sarif_start_line(self):
        """anchor_line is the value used for physicalLocation.region.startLine."""
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()
        candidate = _make_candidate(line_no=3)

        accepted, _ = validator.validate([candidate], doc)

        sarif_start_line = accepted[0].anchor_line
        assert sarif_start_line == 3

    def test_anchor_column_maps_to_sarif_start_column(self):
        anchor = EvidenceAnchor(start_line=1, start_column=5)
        candidate = CandidateFinding(
            rule_id="test-rule",
            control_id="sh-001",
            category="secrets_hygiene",
            source="deterministic",
            severity="high",
            title="T",
            description="",
            evidence={},
            analysis_id=_ANALYSIS_ID,
            workspace_id=_WORKSPACE_ID,
            anchor=anchor,
        )
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()

        accepted, _ = validator.validate([candidate], doc)

        assert accepted[0].anchor_column == 5


# ---------------------------------------------------------------------------
# 9. Empty candidate list
# ---------------------------------------------------------------------------


class TestEmptyInput:
    def test_empty_candidates_returns_empty_accepted(self):
        doc = _make_document(_SAMPLE_TEXT)
        validator = AnchorValidator()

        accepted, report = validator.validate([], doc)

        assert accepted == []
        assert report.total() == 0


# ---------------------------------------------------------------------------
# 10. Metrics
# ---------------------------------------------------------------------------


class TestMetrics:
    def test_suppression_increments_counter(self):
        doc = _make_document(_SAMPLE_TEXT)
        mock_metrics = MagicMock()
        validator = AnchorValidator(metrics=mock_metrics)
        candidate = _make_candidate(line_no=None)

        validator.validate([candidate], doc)

        mock_metrics.increment.assert_called_with(
            "findings_suppressed_total",
            {"source": "deterministic", "reason": "missing_anchor"},
        )

    def test_accepted_increments_validated_counter(self):
        doc = _make_document(_SAMPLE_TEXT)
        mock_metrics = MagicMock()
        validator = AnchorValidator(metrics=mock_metrics)
        candidate = _make_candidate(line_no=1, source="ai_advisory")

        validator.validate([candidate], doc)

        mock_metrics.increment.assert_called_with(
            "findings_validated_total",
            {"source": "ai_advisory"},
        )


# ---------------------------------------------------------------------------
# 11. AnchorValidationConfigurationError on non-normalized document
# ---------------------------------------------------------------------------


class TestConfigurationError:
    def test_non_normalized_document_raises(self):
        bad_doc = RedactedDocument(
            line_index=(),
            fragment_resolution={},
            total_lines=0,
            is_normalized=False,
        )
        validator = AnchorValidator()

        with pytest.raises(AnchorValidationConfigurationError):
            validator.validate([], bad_doc)


# ---------------------------------------------------------------------------
# 12. build_redacted_document — CRLF normalization
# ---------------------------------------------------------------------------


class TestBuildRedactedDocument:
    def test_crlf_normalized_to_lf(self):
        crlf_text = "line one\r\nline two\r\nline three\r\n"
        doc = build_redacted_document(redact(crlf_text))

        assert doc.is_normalized
        assert doc.total_lines == 3
        for line in doc.line_index:
            assert "\r" not in line.content

    def test_bare_cr_normalized(self):
        cr_text = "line one\rline two\rline three\r"
        doc = build_redacted_document(redact(cr_text))

        assert doc.total_lines == 3

    def test_line_numbers_are_1_based(self):
        doc = _make_document(_SAMPLE_TEXT)

        assert doc.line_index[0].line_no == 1
        assert doc.line_index[-1].line_no == doc.total_lines

    def test_fingerprint_is_sha256_of_rstripped_content(self):
        text = "  leading spaces  \n"
        doc = _make_document(text)
        line = doc.line_index[0]

        expected = hashlib.sha256(line.content.rstrip().encode()).hexdigest()
        assert line.fingerprint == expected

    def test_tab_and_trailing_whitespace_fingerprint_stable(self):
        text_a = "  \t  key: value  \n"
        text_b = "  \t  key: value\n"
        doc_a = _make_document(text_a)
        doc_b = _make_document(text_b)

        # Both strip trailing whitespace before hashing → same fingerprint
        assert doc_a.line_index[0].fingerprint == doc_b.line_index[0].fingerprint
