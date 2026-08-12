"""Pydantic v2 schema for the benchmark corpus ground-truth manifest.

Models:
SeededGap           — a deliberately injected control weakness
NegativeExpectation — a control that must evaluate as Present (FP guard)
NotAssessableEntry  — construct that cannot be statically assessed
CorpusFile          — per-file manifest entry
GroundTruthManifest — top-level versioned manifest
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ControlStatus(str, Enum):
    missing = "missing"
    partial = "partial"
    present = "present"
    not_assessable = "not_assessable"


class PipelineFormat(str, Enum):
    github_actions = "github_actions"
    gitlab_ci = "gitlab_ci"
    jenkins = "jenkins"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


# ---------------------------------------------------------------------------
# Ground-truth sub-models
# ---------------------------------------------------------------------------


class SeededGap(BaseModel, frozen=True, extra="forbid"):
    control_id: str
    category: str
    severity: Severity
    expected_status: ControlStatus
    expected_anchor_line: Optional[int] = None
    rationale: str


class NegativeExpectation(BaseModel, frozen=True, extra="forbid"):
    control_id: str
    category: str
    rationale: str


class NotAssessableEntry(BaseModel, frozen=True, extra="forbid"):
    # Pydantic BaseModel already has a `construct` attribute/method.
    # Use a safe Python attribute name while preserving `construct`
    # as the external serialized/validation field name.
    construct_name: str = Field(alias="construct")
    first_line: int
    rationale: str

    model_config = {
        "populate_by_name": True,
    }


class CorpusFile(BaseModel, frozen=True, extra="forbid"):
    path: str
    format: PipelineFormat
    line_count: int
    seeded_gaps: list[SeededGap] = []
    negative_expectations: list[NegativeExpectation] = []
    not_assessable: list[NotAssessableEntry] = []

    @field_validator("line_count")
    @classmethod
    def _line_count_within_envelope(cls, v: int) -> int:
        if v > 500:
            raise ValueError(
                f"Corpus file exceeds 500-line envelope: {v}"
            )
        return v

    @model_validator(mode="after")
    def _no_duplicate_seeded_gap(self) -> "CorpusFile":
        seen: set[tuple[str, int | None]] = set()

        for gap in self.seeded_gaps:
            key = (
                gap.control_id,
                gap.expected_anchor_line,
            )

            if key in seen:
                raise ValueError(
                    f"Duplicate SeededGap for control_id="
                    f"{gap.control_id!r} "
                    f"at line {gap.expected_anchor_line} "
                    f"in {self.path!r}"
                )

            seen.add(key)

        return self


class GroundTruthManifest(
    BaseModel,
    frozen=True,
    extra="forbid",
):
    corpus_version: str
    catalogue_version: int
    files: list[CorpusFile]

    @model_validator(mode="after")
    def _validate_control_ids(self) -> "GroundTruthManifest":
        valid_ids = _VALID_CONTROL_IDS

        for corpus_file in self.files:
            for gap in corpus_file.seeded_gaps:
                if gap.control_id not in valid_ids:
                    raise ValueError(
                        f"Unknown control_id {gap.control_id!r} "
                        f"in {corpus_file.path!r}. "
                        f"Valid IDs: {sorted(valid_ids)}"
                    )

            for neg in corpus_file.negative_expectations:
                if neg.control_id not in valid_ids:
                    raise ValueError(
                        f"Unknown control_id {neg.control_id!r} "
                        f"(negative expectation) "
                        f"in {corpus_file.path!r}"
                    )

        return self

    @model_validator(mode="after")
    def _no_duplicate_file_paths(self) -> "GroundTruthManifest":
        paths = [f.path for f in self.files]

        if len(paths) != len(set(paths)):
            dupes = {
                p
                for p in paths
                if paths.count(p) > 1
            }

            raise ValueError(
                f"Duplicate file paths in manifest: {dupes}"
            )

        return self


# ---------------------------------------------------------------------------
# Ratified control ID set
# (must match catalogue_v1.json categories/controls)
# ---------------------------------------------------------------------------


_VALID_CONTROL_IDS: frozenset[str] = frozenset(
    {
        "sh-001",
        "sh-002",       # secrets_hygiene

        "as-001",
        "as-002",       # artifact_signing

        "sa-001",       # static_analysis

        "ds-001",
        "ds-002",       # dependency_scanning

        "lp-001",
        "lp-002",       # least_privilege

        "iac-001",      # iac_misconfiguration

        "sci-001",
        "sci-002",      # supply_chain_integrity

        "sbom-001",     # sbom

        "ag-001",       # approval_gates
    }
)