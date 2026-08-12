"""NormalizerRegistry — pluggable format-specific normalisation interface.

WO-05, WO-06, WO-07 will register concrete normalizers here.
Until those WOs land, a PassthroughNormalizer is used for all formats,
returning the redacted content verbatim with an empty coverage report.

The registry must never import HTTP or database modules.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pipelineshield.api.v1.schemas.analysis import PipelineFormat

if TYPE_CHECKING:
    from pipelineshield.analysis.ir.pipeline_ir import PipelineIR

__all__ = [
    "NormalizationResult",
    "Normalizer",
    "PassthroughNormalizer",
    "NormalizerRegistry",
    "create_default_registry",
]


@dataclass
class NormalizationResult:
    """Result of a single normalisation pass."""
    normalized_content: str
    coverage_report: dict[str, Any] = field(default_factory=dict)
    pipeline_ir: PipelineIR | None = None


class Normalizer(ABC):
    """Abstract normalizer interface.  Concrete implementations register via
    ``NormalizerRegistry.register()``."""

    @abstractmethod
    def normalize(self, content: str) -> NormalizationResult:
        """Normalize *content* and return a ``NormalizationResult``."""


class PassthroughNormalizer(Normalizer):
    """Stub normalizer that returns content unchanged with an empty report.

    Used until format-specific normalizers are registered by WO-05/06/07.
    """

    def normalize(self, content: str) -> NormalizationResult:
        return NormalizationResult(
            normalized_content=content,
            coverage_report={
                "fragments": [],
                "not_assessable": [],
                "note": "Normalizer not yet implemented for this format",
            },
        )


class NormalizerRegistry:
    """Registry mapping PipelineFormat values to Normalizer implementations.

    Falls back to PassthroughNormalizer for any unregistered format.
    """

    def __init__(self) -> None:
        self._registry: dict[PipelineFormat, Normalizer] = {}

    def register(self, fmt: PipelineFormat, normalizer: Normalizer) -> None:
        """Register a normalizer for *fmt*.  Replaces any existing entry."""
        self._registry[fmt] = normalizer

    def get_normalizer(self, fmt: PipelineFormat) -> Normalizer:
        """Return the registered normalizer for *fmt*, or a passthrough stub."""
        return self._registry.get(fmt, PassthroughNormalizer())

    def normalize(self, content: str, fmt: PipelineFormat) -> NormalizationResult:
        """Convenience: look up the normalizer for *fmt* and run it."""
        return self.get_normalizer(fmt).normalize(content)


def create_default_registry() -> NormalizerRegistry:
    """Return a NormalizerRegistry pre-loaded with all built-in normalizers.

    Importing happens here (not at module top-level) to prevent circular
    import chains when only NormalizationResult or Normalizer are needed.
    """
    # Imports are deferred intentionally — see module docstring
    from pipelineshield.analysis.normalizers.github_actions import (  # noqa: PLC0415
        GitHubActionsNormalizer,
    )
    from pipelineshield.analysis.normalizers.gitlab_ci import (  # noqa: PLC0415
        GitLabCINormalizer,
    )
    from pipelineshield.analysis.normalizers.jenkins import (  # noqa: PLC0415
        JenkinsNormalizer,
    )

    registry = NormalizerRegistry()
    registry.register(PipelineFormat.github_actions, GitHubActionsNormalizer())
    registry.register(PipelineFormat.gitlab_ci, GitLabCINormalizer())
    registry.register(PipelineFormat.jenkins, JenkinsNormalizer())
    return registry
