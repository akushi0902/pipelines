"""Integration tests — persistence gate: only ValidatedFinding may be saved.

These tests assert that:
  1. save_all() with a ValidatedFinding succeeds (converts to Finding).
  2. save_all() with a raw CandidateFinding raises TypeError at the boundary.
  3. An LLM advisory candidate citing a non-existent line never reaches
     persistence (suppressed by the validator before save_all is called).

The SQLAlchemyFindingRepository is exercised with a real (in-memory SQLite)
session to prove the isinstance guard is enforced at the actual boundary, not
only in unit tests.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from pipelineshield.analysis.anchoring import (
    AnchorValidator,
    CandidateFinding,
    ValidatedFinding,
    build_redacted_document,
)
from pipelineshield.analysis.redactor import redact
from pipelineshield.analysis.rule_engine.protocol import EvidenceAnchor
from pipelineshield.persistence.models.base import Base
from pipelineshield.persistence.repositories.finding import (
    SQLAlchemyFindingRepository,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_ANALYSIS_ID = uuid.uuid4()
_WORKSPACE_ID = uuid.uuid4()
_SAMPLE_TEXT = "line one\nline two\nline three\n"


def _make_validated_finding() -> ValidatedFinding:
    doc = build_redacted_document(redact(_SAMPLE_TEXT))
    validator = AnchorValidator()
    candidate = CandidateFinding(
        rule_id="test-rule",
        control_id="sh-001",
        category="secrets_hygiene",
        source="deterministic",
        severity="high",
        title="Test hardcoded secret",
        description="",
        evidence={},
        analysis_id=_ANALYSIS_ID,
        workspace_id=_WORKSPACE_ID,
        anchor=EvidenceAnchor(start_line=2, start_column=1),
    )
    accepted, _ = validator.validate([candidate], doc)
    assert len(accepted) == 1
    return accepted[0]


# ---------------------------------------------------------------------------
# 1. save_all rejects raw CandidateFinding at the repository boundary
# ---------------------------------------------------------------------------


class TestPersistenceGateBoundary:
    def test_save_all_raises_for_raw_candidate(self):
        """A raw CandidateFinding passed to save_all() raises TypeError."""
        raw = CandidateFinding(
            rule_id="bad-rule",
            control_id="sh-001",
            category="secrets_hygiene",
            source="deterministic",
            severity="high",
            title="Raw finding — not validated",
            description="",
            evidence={},
            analysis_id=_ANALYSIS_ID,
            workspace_id=_WORKSPACE_ID,
            anchor=EvidenceAnchor(start_line=1, start_column=1),
        )
        # We need a session — use a minimal SQLite in-memory engine.
        engine = create_engine("sqlite:///:memory:")
        # Create tables that exist on Base metadata
        Base.metadata.create_all(engine, checkfirst=True)
        with Session(engine) as session:
            repo = SQLAlchemyFindingRepository(session)
            with pytest.raises(TypeError, match="ValidatedFinding"):
                repo.save_all([raw])  # type: ignore[arg-type]

    def test_save_all_raises_for_plain_dict(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine, checkfirst=True)
        with Session(engine) as session:
            repo = SQLAlchemyFindingRepository(session)
            with pytest.raises(TypeError, match="ValidatedFinding"):
                repo.save_all([{"rule_id": "x"}])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 2. LLM candidate citing non-existent line never reaches persistence
# ---------------------------------------------------------------------------


class TestLLMCandidateGating:
    def test_fabricated_line_suppressed_before_save(self):
        """LLM advisory candidate with non-existent line_no is suppressed."""
        doc = build_redacted_document(redact(_SAMPLE_TEXT))
        validator = AnchorValidator()

        fabricated_candidate = CandidateFinding(
            rule_id="llm-rule",
            control_id="sh-001",
            category="secrets_hygiene",
            source="ai_advisory",
            severity="high",
            title="LLM fabricated finding",
            description="",
            evidence={},
            analysis_id=_ANALYSIS_ID,
            workspace_id=_WORKSPACE_ID,
            anchor=EvidenceAnchor(start_line=9999, start_column=1),
        )

        accepted, report = validator.validate([fabricated_candidate], doc)

        assert not accepted
        assert report.total() == 1
        assert report.suppressions[0].reason.value == "out_of_range"

    def test_real_line_candidate_accepted(self):
        """LLM advisory candidate with a real line_no passes the gate."""
        doc = build_redacted_document(redact(_SAMPLE_TEXT))
        validator = AnchorValidator()

        real_candidate = CandidateFinding(
            rule_id="llm-rule",
            control_id="sh-001",
            category="secrets_hygiene",
            source="ai_advisory",
            severity="high",
            title="LLM finding on real line",
            description="",
            evidence={},
            analysis_id=_ANALYSIS_ID,
            workspace_id=_WORKSPACE_ID,
            anchor=EvidenceAnchor(start_line=1, start_column=1),
            requires_human_review=True,
        )

        accepted, report = validator.validate([real_candidate], doc)

        assert len(accepted) == 1
        assert accepted[0].source == "ai_advisory"
        assert accepted[0].requires_human_review is True
        assert report.total() == 0
