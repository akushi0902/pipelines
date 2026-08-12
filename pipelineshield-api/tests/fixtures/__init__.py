# Test fixtures
"""Fixture loaders for the benchmark corpus and ground-truth manifest."""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Iterator

import yaml

from pipelineshield.benchmark.ground_truth import CorpusFile, GroundTruthManifest

_CORPUS_DIR = Path(__file__).parent / "corpus"
_MANIFEST_PATH = _CORPUS_DIR / "ground_truth.yaml"


@functools.lru_cache(maxsize=1)
def load_ground_truth() -> GroundTruthManifest:
    """Parse and validate the ground-truth manifest, cached after first load."""
    raw = yaml.safe_load(_MANIFEST_PATH.read_text(encoding="utf-8"))
    return GroundTruthManifest.model_validate(raw)


@functools.lru_cache(maxsize=1)
def load_corpus() -> dict[str, bytes]:
    """Return a mapping of manifest-relative path -> raw bytes for every corpus file.

    Paths are relative to tests/fixtures/corpus/, matching CorpusFile.path values.
    """
    manifest = load_ground_truth()
    result: dict[str, bytes] = {}
    for corpus_file in manifest.files:
        abs_path = _CORPUS_DIR / corpus_file.path
        result[corpus_file.path] = abs_path.read_bytes()
    return result


def iter_corpus_files() -> Iterator[tuple[CorpusFile, bytes]]:
    """Yield (CorpusFile, raw_bytes) for every file referenced in the manifest."""
    corpus = load_corpus()
    manifest = load_ground_truth()
    for corpus_file in manifest.files:
        yield corpus_file, corpus[corpus_file.path]
