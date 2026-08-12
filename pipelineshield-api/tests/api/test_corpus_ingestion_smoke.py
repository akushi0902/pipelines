"""Smoke integration test: run every corpus file through redaction.

Asserts:
- Zero unhandled exceptions for any corpus file
- Redaction produces a RedactedDoc (never raises) for all formats
- Files seeded with sh-001 (hardcoded credential) produce >= 1 redaction hit
- Not-assessable files (unresolvable includes, scripted blocks) process without error
"""
from __future__ import annotations

import pytest


class TestCorpusIngestionSmoke:
    def test_all_corpus_files_redact_without_exception(self) -> None:
        """Every corpus file must pass through the redactor without unhandled error."""
        from pipelineshield.analysis.redactor import redact
        from tests.fixtures import iter_corpus_files

        errors: list[str] = []
        for corpus_file, raw_bytes in iter_corpus_files():
            text = raw_bytes.decode("utf-8", errors="replace")
            try:
                redact(text)
            except Exception as exc:
                errors.append(f"{corpus_file.path}: {type(exc).__name__}: {exc}")

        assert not errors, (
            "Corpus files raised unhandled exceptions during redaction:\n"
            + "\n".join(errors)
        )

    def test_sh001_files_produce_redaction_hits(self) -> None:
        """Files seeded with sh-001 (hardcoded credential) must yield >= 1 redaction."""
        from pipelineshield.analysis.redactor import redact
        from tests.fixtures import load_ground_truth, load_corpus

        manifest = load_ground_truth()
        corpus = load_corpus()

        seeded_paths = {
            f.path
            for f in manifest.files
            for gap in f.seeded_gaps
            if gap.control_id == "sh-001"
        }
        no_hits: list[str] = []
        for path in seeded_paths:
            raw = corpus[path]
            text = raw.decode("utf-8", errors="replace")
            doc = redact(text)
            if sum(doc.pattern_counts.values()) == 0:
                no_hits.append(path)

        assert not no_hits, (
            "sh-001 seeded files produced zero redaction hits — "
            "synthetic placeholders may not trip the redactor:\n" + "\n".join(no_hits)
        )

    def test_not_assessable_files_process_without_exception(self) -> None:
        """NOT ASSESSABLE corpus files must process without unhandled error."""
        from pipelineshield.analysis.redactor import redact
        from tests.fixtures import load_ground_truth, load_corpus

        manifest = load_ground_truth()
        corpus = load_corpus()

        na_paths = {f.path for f in manifest.files if f.not_assessable}
        errors: list[str] = []
        for path in na_paths:
            raw = corpus[path]
            text = raw.decode("utf-8", errors="replace")
            try:
                redact(text)
            except Exception as exc:
                errors.append(f"{path}: {type(exc).__name__}: {exc}")

        assert not errors, (
            "Not-assessable corpus files raised unhandled exceptions:\n"
            + "\n".join(errors)
        )

    def test_hardened_files_produce_zero_redaction_hits(self) -> None:
        """Hardened files (no seeded gaps) must contain no real secret patterns."""
        from pipelineshield.analysis.redactor import redact
        from tests.fixtures import load_ground_truth, load_corpus

        manifest = load_ground_truth()
        corpus = load_corpus()

        hardened_paths = {
            f.path
            for f in manifest.files
            if not f.seeded_gaps and not f.not_assessable
        }
        with_hits: list[str] = []
        for path in hardened_paths:
            raw = corpus[path]
            text = raw.decode("utf-8", errors="replace")
            doc = redact(text)
            total_hits = sum(doc.pattern_counts.values())
            if total_hits > 0:
                with_hits.append(f"{path}: {total_hits} hit(s): {dict(doc.pattern_counts)}")

        assert not with_hits, (
            "Hardened corpus files produced unexpected redaction hits "
            "(may contain real-looking credentials):\n" + "\n".join(with_hits)
        )
