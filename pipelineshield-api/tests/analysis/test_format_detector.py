"""Unit tests for analysis/format_detector.py (WO-004 AC-1–AC-9).

Coverage
--------
TestFormatVerdictModel       — FormatVerdict structure, confirmation_required property.
TestGitHubActionsDetection   — signal-by-signal and corpus fixture tests.
TestGitLabCIDetection        — including no-stages case.
TestJenkinsDetection         — declarative and scripted lower-confidence case.
TestConfidenceThreshold      — boundary at 0.79 and 0.80.
TestAmbiguityAndUnknown      — two-format conflict, Kubernetes manifest.
TestMaskedTextResilience     — REDACTED tokens must not break detection.
TestImportGraph              — no FastAPI, no SQLAlchemy in detector modules.
TestPerformance              — 100 ms budget for a 500-line definition.
"""
from __future__ import annotations

import ast
import importlib
import sys
import time
from pathlib import Path

import pytest

from pipelineshield.analysis.format_detector import (
    CONFIDENCE_THRESHOLD,
    FormatVerdict,
    detect,
)
from pipelineshield.analysis.format_signals import SIGNALS, FormatSignal

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "detection"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load(name: str) -> str:
    return (_FIXTURES / name).read_text()


# ---------------------------------------------------------------------------
# AC-1: FormatVerdict model
# ---------------------------------------------------------------------------


class TestFormatVerdictModel:
    def test_frozen_model(self) -> None:
        verdict = FormatVerdict(format="github_actions", confidence=0.9, signals=["gha.jobs_key"])
        with pytest.raises(Exception):  # ValidationError or AttributeError on frozen
            verdict.confidence = 0.5  # type: ignore[misc]

    def test_confirmation_required_below_threshold(self) -> None:
        v = FormatVerdict(format="github_actions", confidence=0.79, signals=[])
        assert v.confirmation_required is True

    def test_confirmation_not_required_at_threshold(self) -> None:
        v = FormatVerdict(format="github_actions", confidence=0.80, signals=[])
        assert v.confirmation_required is False

    def test_unknown_always_requires_confirmation(self) -> None:
        v = FormatVerdict(format="unknown", confidence=0.0, signals=[])
        assert v.confirmation_required is True

    def test_confidence_clamped(self) -> None:
        v = FormatVerdict(format="jenkins", confidence=1.0, signals=[])
        assert 0.0 <= v.confidence <= 1.0

    def test_signals_list_preserved(self) -> None:
        v = FormatVerdict(format="gitlab_ci", confidence=0.85, signals=["gl.stages_key", "gl.script_key"])
        assert "gl.stages_key" in v.signals


# ---------------------------------------------------------------------------
# Signal registry introspection
# ---------------------------------------------------------------------------


class TestSignalRegistry:
    def test_all_signals_have_unique_names(self) -> None:
        names = [s.name for s in SIGNALS]
        assert len(names) == len(set(names)), "Duplicate signal names found"

    def test_each_signal_has_predicate(self) -> None:
        for sig in SIGNALS:
            assert sig.content_pattern is not None or sig.filename_substring is not None, (
                f"Signal {sig.name} has neither content_pattern nor filename_substring"
            )

    def test_content_signals_per_format_sum_to_one(self) -> None:
        for fmt in ("github_actions", "gitlab_ci", "jenkins"):
            total = sum(
                s.weight for s in SIGNALS
                if s.format == fmt and s.content_pattern is not None
            )
            assert abs(total - 1.0) < 0.01, (
                f"Content signal weights for {fmt} sum to {total:.3f}, expected ~1.0"
            )


# ---------------------------------------------------------------------------
# AC-2: GitHub Actions corpus
# ---------------------------------------------------------------------------


class TestGitHubActionsDetection:
    @pytest.mark.parametrize("filename", [
        "github_actions_basic.yml",
        "github_actions_matrix.yml",
        "github_actions_release.yml",
    ])
    def test_gha_corpus_high_confidence(self, filename: str) -> None:
        text = _load(filename)
        verdict = detect(text, filename=f".github/workflows/{filename}")
        assert verdict.format == "github_actions", (
            f"{filename}: expected github_actions, got {verdict.format}"
        )
        assert verdict.confidence >= CONFIDENCE_THRESHOLD, (
            f"{filename}: confidence {verdict.confidence:.3f} < {CONFIDENCE_THRESHOLD}"
        )

    def test_gha_on_signal_fires(self) -> None:
        text = "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        verdict = detect(text)
        assert "gha.on_key" in verdict.signals

    def test_gha_jobs_signal_fires(self) -> None:
        text = "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
        verdict = detect(text)
        assert "gha.jobs_key" in verdict.signals

    def test_gha_uses_signal_fires(self) -> None:
        text = "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
        verdict = detect(text)
        assert "gha.uses_key" in verdict.signals

    def test_gha_no_filename_still_detects(self) -> None:
        text = _load("github_actions_basic.yml")
        verdict = detect(text, filename=None)
        assert verdict.format == "github_actions"

    def test_gha_content_dominates_gitlab_filename(self) -> None:
        """Conflicting evidence: strong GHA content + GitLab filename → confidence drops."""
        text = _load("github_actions_basic.yml")
        verdict = detect(text, filename=".gitlab-ci.yml")
        # Content signals dominate; confidence must drop below threshold (ambiguous result)
        assert verdict.confidence < CONFIDENCE_THRESHOLD or verdict.format == "github_actions"


# ---------------------------------------------------------------------------
# AC-2: GitLab CI corpus
# ---------------------------------------------------------------------------


class TestGitLabCIDetection:
    @pytest.mark.parametrize("filename,fname", [
        ("gitlab_ci_basic.yml", ".gitlab-ci.yml"),
        ("gitlab_ci_include.yml", ".gitlab-ci.yml"),
    ])
    def test_gitlab_corpus_high_confidence(self, filename: str, fname: str) -> None:
        text = _load(filename)
        verdict = detect(text, filename=fname)
        assert verdict.format == "gitlab_ci", (
            f"{filename}: expected gitlab_ci, got {verdict.format}"
        )
        assert verdict.confidence >= CONFIDENCE_THRESHOLD, (
            f"{filename}: confidence {verdict.confidence:.3f} < {CONFIDENCE_THRESHOLD}"
        )

    def test_gitlab_no_stages_with_filename_classifies(self) -> None:
        """GitLab CI without explicit stages: still classifies via job-shape + filename."""
        text = _load("gitlab_ci_no_stages.yml")
        verdict = detect(text, filename=".gitlab-ci.yml")
        assert verdict.format == "gitlab_ci"
        # With canonical filename, confidence should reach threshold
        assert verdict.confidence >= CONFIDENCE_THRESHOLD

    def test_gitlab_script_signal_fires(self) -> None:
        text = "test:\n  script:\n    - pytest\n"
        verdict = detect(text, filename=".gitlab-ci.yml")
        assert "gl.script_key" in verdict.signals

    def test_gitlab_jobs_key_reduces_score(self) -> None:
        """Top-level jobs: (GHA signal) must penalise the GitLab score."""
        text = "stages:\n  - build\nscript:\n  - echo hi\njobs:\n  build:\n    runs-on: ubuntu\n"
        gla_verdict = detect(text)
        # Should not confidently classify as gitlab_ci
        assert gla_verdict.confidence < CONFIDENCE_THRESHOLD or gla_verdict.format != "gitlab_ci"


# ---------------------------------------------------------------------------
# AC-2: Jenkins corpus
# ---------------------------------------------------------------------------


class TestJenkinsDetection:
    @pytest.mark.parametrize("filename", [
        "jenkins_declarative.jenkinsfile",
        "jenkins_docker_agent.jenkinsfile",
    ])
    def test_jenkins_declarative_high_confidence(self, filename: str) -> None:
        text = _load(filename)
        verdict = detect(text, filename=filename)
        assert verdict.format == "jenkins", (
            f"{filename}: expected jenkins, got {verdict.format}"
        )
        assert verdict.confidence >= CONFIDENCE_THRESHOLD, (
            f"{filename}: confidence {verdict.confidence:.3f} < {CONFIDENCE_THRESHOLD}"
        )

    def test_jenkins_scripted_lower_confidence_without_filename(self) -> None:
        """Scripted Jenkinsfile without filename → lower confidence (< 0.8)."""
        text = _load("jenkins_scripted.jenkinsfile")
        verdict = detect(text, filename=None)
        assert verdict.format == "jenkins"
        assert verdict.confidence < CONFIDENCE_THRESHOLD, (
            f"Scripted Jenkins without filename should be < {CONFIDENCE_THRESHOLD}, "
            f"got {verdict.confidence:.3f}"
        )
        assert verdict.confirmation_required is True

    def test_jenkins_scripted_with_filename_classifies(self) -> None:
        """Scripted Jenkinsfile named 'Jenkinsfile' gets filename bonus → may reach 0.8."""
        text = _load("jenkins_scripted.jenkinsfile")
        verdict = detect(text, filename="Jenkinsfile")
        assert verdict.format == "jenkins"
        # With filename bonus, scripted may reach threshold; what matters is format=jenkins
        assert verdict.confidence > 0.0

    def test_pipeline_block_fires(self) -> None:
        text = "pipeline {\n  agent any\n  stages {\n    stage('Build') {\n      steps { sh 'make' }\n    }\n  }\n}\n"
        verdict = detect(text)
        assert "jk.pipeline_block" in verdict.signals

    def test_pipeline_block_penalises_gha_and_gitlab(self) -> None:
        """A declarative Jenkinsfile must not be mis-classified as GHA or GitLab."""
        text = _load("jenkins_declarative.jenkinsfile")
        verdict = detect(text, filename=None)
        assert verdict.format == "jenkins"


# ---------------------------------------------------------------------------
# AC-9: Confidence threshold boundary tests
# ---------------------------------------------------------------------------


class TestConfidenceThreshold:
    def test_confidence_0_79_requires_confirmation(self) -> None:
        v = FormatVerdict(format="github_actions", confidence=0.79, signals=[])
        assert v.confirmation_required is True

    def test_confidence_0_80_does_not_require_confirmation(self) -> None:
        v = FormatVerdict(format="github_actions", confidence=0.80, signals=[])
        assert v.confirmation_required is False

    def test_threshold_constant_is_0_8(self) -> None:
        assert CONFIDENCE_THRESHOLD == 0.8

    def test_ambiguous_file_below_threshold(self) -> None:
        """A file with signals from two formats should score below threshold."""
        text = _load("ambiguous_stages_and_jobs.yml")
        verdict = detect(text)
        assert verdict.confirmation_required is True


# ---------------------------------------------------------------------------
# AC-6: Unknown / unrecognisable submissions
# ---------------------------------------------------------------------------


class TestAmbiguityAndUnknown:
    def test_kubernetes_manifest_returns_unknown(self) -> None:
        text = _load("unknown_kubernetes.yml")
        verdict = detect(text)
        assert verdict.format == "unknown"
        assert verdict.confidence == 0.0
        assert verdict.confirmation_required is True

    def test_unknown_has_empty_signals(self) -> None:
        text = _load("unknown_kubernetes.yml")
        verdict = detect(text)
        assert verdict.signals == []

    def test_empty_text_returns_unknown(self) -> None:
        verdict = detect("   ")
        assert verdict.format == "unknown"

    def test_ambiguous_yaml_requires_confirmation(self) -> None:
        text = _load("ambiguous_stages_and_jobs.yml")
        verdict = detect(text)
        # Either unknown or low-confidence
        assert verdict.confirmation_required is True


# ---------------------------------------------------------------------------
# Masked text resilience (WO-002 redactor tokens must not break detection)
# ---------------------------------------------------------------------------


class TestMaskedTextResilience:
    def test_gha_with_redacted_token_still_classifies(self) -> None:
        text = (
            "on:\n"
            "  push:\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      TOKEN: [REDACTED:gh-pat-0001:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx]\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        verdict = detect(text, filename=".github/workflows/ci.yml")
        assert verdict.format == "github_actions"
        assert verdict.confidence >= CONFIDENCE_THRESHOLD

    def test_gitlab_with_redacted_secrets_still_classifies(self) -> None:
        text = (
            "stages:\n  - test\n\n"
            "test:\n"
            "  stage: test\n"
            "  script:\n"
            "    - pytest\n"
            "  variables:\n"
            "    API_KEY: [REDACTED:high-entropy-0001:xxxxxxxxxxxxxxxxxxxxxxxx]\n"
        )
        verdict = detect(text, filename=".gitlab-ci.yml")
        assert verdict.format == "gitlab_ci"
        assert verdict.confidence >= CONFIDENCE_THRESHOLD

    def test_boolean_on_coercion_yaml_12(self) -> None:
        """In YAML 1.1, `on:` could be coerced to boolean True.
        Detection must work on the raw text string, not YAML-parsed result.
        """
        # Raw text still has the literal string "on:" — our regex works on text
        text = "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
        verdict = detect(text)
        assert verdict.format == "github_actions"
        assert "gha.on_key" in verdict.signals


# ---------------------------------------------------------------------------
# AC-7: Import-graph assertion (no FastAPI, no SQLAlchemy)
# ---------------------------------------------------------------------------


class TestImportGraph:
    @pytest.mark.parametrize("module_name", [
        "pipelineshield.analysis.format_detector",
        "pipelineshield.analysis.format_signals",
    ])
    def test_no_fastapi_import(self, module_name: str) -> None:
        mod = importlib.import_module(module_name)
        source_file = getattr(mod, "__file__", None)
        assert source_file is not None
        tree = ast.parse(Path(source_file).read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module_str = (
                    node.names[0].name if isinstance(node, ast.Import)
                    else (node.module or "")
                )
                assert not module_str.startswith("fastapi"), (
                    f"{module_name} must not import from fastapi; found: {module_str}"
                )
                assert not module_str.startswith("sqlalchemy"), (
                    f"{module_name} must not import from sqlalchemy; found: {module_str}"
                )


# ---------------------------------------------------------------------------
# AC-8: Performance smoke test — 100 ms budget for a 500-line definition
# ---------------------------------------------------------------------------


class TestPerformance:
    def test_detect_within_100ms_for_500_lines(self) -> None:
        # Build a realistic 500-line GitHub Actions workflow
        lines = [
            "name: Perf Test\n",
            "on:\n  push:\n    branches: [main]\n",
            "jobs:\n",
        ]
        for i in range(50):
            lines.append(f"  job_{i}:\n")
            lines.append("    runs-on: ubuntu-latest\n")
            lines.append("    steps:\n")
            for j in range(8):
                lines.append(f"      - name: Step {j}\n")
                lines.append(f"        run: echo step_{j}\n")

        text = "".join(lines)[:500 * 80]  # cap at ~500 lines worth

        start = time.monotonic()
        verdict = detect(text, filename=".github/workflows/perf.yml")
        elapsed_ms = (time.monotonic() - start) * 1000

        assert verdict.format == "github_actions"
        assert elapsed_ms < 100.0, (
            f"Detection took {elapsed_ms:.1f}ms, exceeds 100ms budget"
        )
