"""Unit tests for the benchmark corpus and ground-truth manifest.

Tests:
- Manifest loads and validates without error
- All control_ids reference the ratified catalogue
- No duplicate file paths in manifest
- No duplicate SeededGap entries per file
- Every file on disk is referenced in the manifest (no orphans)
- Every manifest path exists on disk (no missing files)
- Every corpus file is under 500 lines
- manifest.line_count matches actual file line count
- Negative expectations count >= 20
- At least 1 gap in each of 9 control categories
- At least 3 not_assessable entries across corpus
- Synthetic secret placeholders trip the redactor pattern set
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

_CORPUS_DIR = Path(__file__).parent.parent / "fixtures" / "corpus"
_VALID_CONTROL_IDS = frozenset({
    "sh-001", "sh-002",
    "as-001", "as-002",
    "sa-001",
    "ds-001", "ds-002",
    "lp-001", "lp-002",
    "iac-001",
    "sci-001", "sci-002",
    "sbom-001",
    "ag-001",
})
_NINE_CATEGORIES = frozenset({
    "secrets_hygiene", "static_analysis", "dependency_scanning",
    "iac_misconfiguration", "sbom", "artifact_signing",
    "least_privilege", "supply_chain_integrity", "approval_gates",
})

# Redactor pattern for GitHub PAT (matches the analysis module pattern)
_GITHUB_PAT_RE = re.compile(r"(?:ghp|github_pat|gho|ghs|ghr)_[A-Za-z0-9]{36,255}", re.I)


class TestManifestLoads:
    def test_manifest_parses_without_error(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        assert manifest is not None
        assert manifest.corpus_version
        assert manifest.catalogue_version >= 1

    def test_manifest_has_minimum_15_files(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        assert len(manifest.files) >= 15, f"Expected >=15 files, got {len(manifest.files)}"

    def test_manifest_has_min_6_github_actions(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        count = sum(1 for f in manifest.files if f.format.value == "github_actions")
        assert count >= 6, f"Expected >=6 github_actions files, got {count}"

    def test_manifest_has_min_5_gitlab_ci(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        count = sum(1 for f in manifest.files if f.format.value == "gitlab_ci")
        assert count >= 5, f"Expected >=5 gitlab_ci files, got {count}"

    def test_manifest_has_min_4_jenkins(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        count = sum(1 for f in manifest.files if f.format.value == "jenkins")
        assert count >= 4, f"Expected >=4 jenkins files, got {count}"


class TestControlIdReferentialIntegrity:
    def test_all_seeded_gap_control_ids_are_valid(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        invalid: list[str] = []
        for corpus_file in manifest.files:
            for gap in corpus_file.seeded_gaps:
                if gap.control_id not in _VALID_CONTROL_IDS:
                    invalid.append(f"{corpus_file.path}: {gap.control_id}")
        assert not invalid, f"Invalid control_ids in seeded_gaps: {invalid}"

    def test_all_negative_expectation_control_ids_are_valid(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        invalid: list[str] = []
        for corpus_file in manifest.files:
            for neg in corpus_file.negative_expectations:
                if neg.control_id not in _VALID_CONTROL_IDS:
                    invalid.append(f"{corpus_file.path}: {neg.control_id}")
        assert not invalid, f"Invalid control_ids in negative_expectations: {invalid}"

    def test_no_duplicate_file_paths(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        paths = [f.path for f in manifest.files]
        dupes = [p for p, cnt in Counter(paths).items() if cnt > 1]
        assert not dupes, f"Duplicate file paths: {dupes}"

    def test_no_duplicate_seeded_gaps_per_file(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        for corpus_file in manifest.files:
            keys = [(g.control_id, g.expected_anchor_line) for g in corpus_file.seeded_gaps]
            dupes = [k for k, cnt in Counter(keys).items() if cnt > 1]
            assert not dupes, (
                f"Duplicate SeededGap entries in {corpus_file.path!r}: {dupes}"
            )


class TestFilesOnDisk:
    def test_every_manifest_path_exists(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        missing: list[str] = []
        for corpus_file in manifest.files:
            abs_path = _CORPUS_DIR / corpus_file.path
            if not abs_path.exists():
                missing.append(corpus_file.path)
        assert not missing, f"Files in manifest but missing on disk: {missing}"

    def test_every_disk_file_is_in_manifest(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        manifest_paths = {f.path for f in manifest.files}
        extensions = {".yml", ".yaml", ".jenkinsfile"}
        orphans: list[str] = []
        for sub in ("github_actions", "gitlab_ci", "jenkins"):
            sub_dir = _CORPUS_DIR / sub
            if not sub_dir.exists():
                continue
            for disk_file in sub_dir.iterdir():
                if disk_file.suffix.lower() in extensions:
                    rel = f"{sub}/{disk_file.name}"
                    if rel not in manifest_paths:
                        orphans.append(rel)
        assert not orphans, f"Files on disk but not in manifest: {orphans}"

    def test_line_counts_match_actual_files(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        mismatches: list[str] = []
        for corpus_file in manifest.files:
            abs_path = _CORPUS_DIR / corpus_file.path
            if not abs_path.exists():
                continue
            actual = len(abs_path.read_text(encoding="utf-8").splitlines())
            if actual != corpus_file.line_count:
                mismatches.append(
                    f"{corpus_file.path}: manifest={corpus_file.line_count} actual={actual}"
                )
        assert not mismatches, f"Line count mismatches: {mismatches}"

    def test_all_files_under_500_lines(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        over_limit: list[str] = []
        for corpus_file in manifest.files:
            abs_path = _CORPUS_DIR / corpus_file.path
            if not abs_path.exists():
                continue
            actual = len(abs_path.read_text(encoding="utf-8").splitlines())
            if actual > 500:
                over_limit.append(f"{corpus_file.path}: {actual} lines")
        assert not over_limit, f"Files exceeding 500-line envelope: {over_limit}"


class TestCoverageRequirements:
    def test_at_least_one_gap_per_control_category(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        categories_with_gaps: set[str] = set()
        for corpus_file in manifest.files:
            for gap in corpus_file.seeded_gaps:
                categories_with_gaps.add(gap.category)
        missing = _NINE_CATEGORIES - categories_with_gaps
        assert not missing, (
            f"Control categories with no seeded gap: {sorted(missing)}"
        )

    def test_negative_expectations_total_at_least_20(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        total = sum(len(f.negative_expectations) for f in manifest.files)
        assert total >= 20, f"Expected >=20 negative expectations, got {total}"

    def test_at_least_3_not_assessable_constructs(self) -> None:
        from tests.fixtures import load_ground_truth
        manifest = load_ground_truth()
        total = sum(len(f.not_assessable) for f in manifest.files)
        assert total >= 3, (
            f"Expected >=3 not_assessable entries, got {total}"
        )


class TestSyntheticSecretAssertion:
    def test_synthetic_placeholders_trip_github_pat_pattern(self) -> None:
        """Every corpus file containing a synthetic GitHub PAT trips the redactor."""
        from tests.fixtures import load_ground_truth, load_corpus
        manifest = load_ground_truth()
        corpus = load_corpus()

        # Files seeded with sh-001 (hardcoded credential) must match the PAT pattern
        seeded_sh001_paths = {
            f.path
            for f in manifest.files
            for gap in f.seeded_gaps
            if gap.control_id == "sh-001"
        }
        for path in seeded_sh001_paths:
            content = corpus[path].decode("utf-8", errors="replace")
            assert _GITHUB_PAT_RE.search(content), (
                f"{path} is seeded with sh-001 but synthetic PAT placeholder "
                "does not match GitHub PAT redactor pattern"
            )

    def test_no_non_synthetic_credentials_committed(self) -> None:
        """Asserts every credential-like match is documented as a synthetic placeholder.

        A match is acceptable only if the file also has a SYNTHETIC PLACEHOLDER or EXAMPLE
        comment annotation on or near the matching line.
        """
        _SYNTHETIC_MARKERS = ("SYNTHETIC", "EXAMPLE", "NOT_REAL", "placeholder", "synthetic")
        from tests.fixtures import load_corpus
        corpus = load_corpus()
        violations: list[str] = []
        for rel_path, raw_bytes in corpus.items():
            content = raw_bytes.decode("utf-8", errors="replace")
            lines = content.splitlines()
            for match in _GITHUB_PAT_RE.finditer(content):
                line_no = content[: match.start()].count("\n")
                # Check the surrounding 5 lines for a synthetic marker
                context_start = max(0, line_no - 2)
                context_end = min(len(lines), line_no + 3)
                context = "\n".join(lines[context_start:context_end]).upper()
                if not any(m.upper() in context for m in _SYNTHETIC_MARKERS):
                    violations.append(
                        f"{rel_path}:{line_no + 1} — credential match without synthetic annotation"
                    )
        assert not violations, (
            "Real-looking credentials found without synthetic placeholder annotation:\n"
            + "\n".join(violations)
        )

    def test_corpus_load_helper_returns_bytes_for_all_files(self) -> None:
        from tests.fixtures import load_corpus, load_ground_truth
        corpus = load_corpus()
        manifest = load_ground_truth()
        assert len(corpus) == len(manifest.files)
        for path, raw in corpus.items():
            assert isinstance(raw, bytes), f"Expected bytes for {path}"
            assert len(raw) > 0, f"Corpus file {path} is empty"

    def test_iter_corpus_files_yields_all_entries(self) -> None:
        from tests.fixtures import iter_corpus_files, load_ground_truth
        manifest = load_ground_truth()
        pairs = list(iter_corpus_files())
        assert len(pairs) == len(manifest.files)
        for corpus_file, raw in pairs:
            assert isinstance(raw, bytes)
