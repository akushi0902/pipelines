"""Versioned stage-taxonomy for the architecture recommender.

This module defines the lifecycle stage model as data, not code branches.
The CONTROL_STAGE_MAP maps every known control_id to a lifecycle stage_id.
Adding a new control means adding one entry here; no conditional logic changes.

Startup validation (called by ArchitectureService) asserts:
  - Every enabled control in the active catalogue has a stage mapping.
  - Every Critical/High control has at least one reference tool (enforced by
    CatalogueSnapshot validators already; re-checked here for defence-in-depth).

Stage ordering mirrors a typical CI/CD pipeline lifecycle:
  source → build → static_analysis → dependency_scanning → iac_scanning →
  sbom → signing_provenance → deployment_approval → post_deploy
"""
from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Stage definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StageDefinition:
    """A single lifecycle stage in the secure-pipeline blueprint."""

    stage_id: str
    display_name: str
    order: int


# ---------------------------------------------------------------------------
# Ordered stage taxonomy
# ---------------------------------------------------------------------------

STAGE_DEFINITIONS: tuple[StageDefinition, ...] = (
    StageDefinition("source", "Source Controls", 1),
    StageDefinition("build", "Build Pipeline Integrity", 2),
    StageDefinition("static_analysis", "Static Analysis", 3),
    StageDefinition("dependency_scanning", "Dependency and Container Scanning", 4),
    StageDefinition("iac_scanning", "IaC Misconfiguration Scanning", 5),
    StageDefinition("sbom", "Software Bill of Materials", 6),
    StageDefinition("signing_provenance", "Artifact Signing and Provenance", 7),
    StageDefinition("deployment_approval", "Deployment Approval Gates", 8),
    StageDefinition("post_deploy", "Post-Deploy Verification", 9),
)

#: Index for fast lookup: stage_id → StageDefinition
STAGE_INDEX: dict[str, StageDefinition] = {s.stage_id: s for s in STAGE_DEFINITIONS}

#: Approved reference tool names (union of WO-022 ReferenceTool enum values).
APPROVED_REFERENCE_TOOLS: frozenset[str] = frozenset({
    "Gitleaks",
    "TruffleHog",
    "Semgrep",
    "SonarQube",
    "CodeQL",
    "Trivy",
    "Grype",
    "Checkov",
    "tfsec",
    "Syft",
    "CycloneDX",
    "Cosign",
    "Sigstore",
    "in-toto",
    "StepSecurity/harden-runner",
    "GitHub Actions permissions key",
    "CODEOWNERS",
    "GitHub Environments protection rules",
    "GitLab Protected Environments",
    "Cosign with Rekor",
})

# ---------------------------------------------------------------------------
# Control → stage mapping
# Keyed by control_id from catalogue_v1.json.  Unknown controls default to
# the "build" stage so the recommender never silently drops a control.
# ---------------------------------------------------------------------------

CONTROL_STAGE_MAP: dict[str, str] = {
    # secrets_hygiene category
    "sh-001": "source",
    "sh-002": "source",
    # static_analysis category
    "sa-001": "static_analysis",
    # dependency_scanning category
    "ds-001": "dependency_scanning",
    "ds-002": "dependency_scanning",
    # least_privilege category — enforced at the build/run level
    "lp-001": "build",
    "lp-002": "build",
    # iac_misconfiguration category
    "iac-001": "iac_scanning",
    # supply_chain_integrity category — pipeline action pinning / runner hardening
    "sci-001": "build",
    "sci-002": "build",
    # sbom category
    "sbom-001": "sbom",
    # artifact_signing category
    "as-001": "signing_provenance",
    "as-002": "signing_provenance",
    # approval_gates category
    "ag-001": "deployment_approval",
}

# Fallback stage for controls not in CONTROL_STAGE_MAP
_DEFAULT_STAGE = "build"

# Per-category default reference tools when a control's reference_tools list is empty
# and status is missing/partial.
_CATEGORY_FALLBACK_TOOLS: dict[str, str] = {
    "secrets_hygiene": "Gitleaks",
    "artifact_signing": "Cosign",
    "static_analysis": "Semgrep",
    "dependency_scanning": "Trivy",
    "least_privilege": "Semgrep",
    "iac_misconfiguration": "Checkov",
    "supply_chain_integrity": "StepSecurity/harden-runner",
    "sbom": "Syft",
    "approval_gates": "Semgrep",
}


def stage_for_control(control_id: str) -> str:
    """Return the stage_id for *control_id*, defaulting to 'build'."""
    return CONTROL_STAGE_MAP.get(control_id, _DEFAULT_STAGE)


def fallback_tool_for_category(category_id: str) -> str:
    """Return the fallback reference tool name for *category_id*."""
    return _CATEGORY_FALLBACK_TOOLS.get(category_id, "Semgrep")
