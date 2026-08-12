"""Reference-tool allow-list and deterministic fallback remediations.

AC-7: Every Critical and High finding must name at least one approved tool.
      If the model omits or uses an invalid tool name, the deterministic
      fallback for the control category is substituted.
"""
from __future__ import annotations

import enum


class ReferenceTool(str, enum.Enum):
    """Approved tool names for reference in remediations.

    Only these names may appear in FindingExplanation.reference_tools and
    RemediationDetail.tool.  Any other name is considered invalid and replaced
    by the deterministic fallback for the control category.
    """

    GITLEAKS = "Gitleaks"
    SEMGREP = "Semgrep"
    TRIVY = "Trivy"
    GRYPE = "Grype"
    CHECKOV = "Checkov"
    TFSEC = "tfsec"
    SYFT = "Syft"
    COSIGN_REKOR = "Cosign with Rekor"


_VALID_TOOL_NAMES: frozenset[str] = frozenset(t.value for t in ReferenceTool)


def is_valid_tool(name: str) -> bool:
    """Return True if *name* is an approved reference tool."""
    return name in _VALID_TOOL_NAMES


# ---------------------------------------------------------------------------
# Deterministic fallback remediations per control category
# ---------------------------------------------------------------------------
# These are applied when the model omits a tool or cites an invalid one.
# Keyed by the nine-category short-names used across the catalogue.

_FALLBACK_REMEDIATIONS: dict[str, dict[str, str]] = {
    "secrets_hygiene": {
        "tool": ReferenceTool.GITLEAKS.value,
        "change_summary": (
            "Run Gitleaks as a pre-commit hook and in CI to detect hardcoded "
            "secrets. Remove any detected secrets from the pipeline definition "
            "and rotate the affected credentials immediately."
        ),
    },
    "access_secrets": {
        "tool": ReferenceTool.GITLEAKS.value,
        "change_summary": (
            "Store secrets in the CI/CD platform's encrypted secret store and "
            "reference them via environment variable expressions, not inline values. "
            "Audit existing jobs with Gitleaks."
        ),
    },
    "sast": {
        "tool": ReferenceTool.SEMGREP.value,
        "change_summary": (
            "Integrate Semgrep into the CI pipeline to scan for common vulnerability "
            "patterns. Run in --strict mode and fail the build on new findings."
        ),
    },
    "supply_chain_integrity": {
        "tool": ReferenceTool.COSIGN_REKOR.value,
        "change_summary": (
            "Sign build artefacts with Cosign and publish attestations to Rekor "
            "to establish a verifiable audit trail of artefact provenance."
        ),
    },
    "dependency_container": {
        "tool": ReferenceTool.TRIVY.value,
        "change_summary": (
            "Scan container images and dependency manifests with Trivy in the CI "
            "pipeline. Configure CRITICAL/HIGH severity gates to fail the build."
        ),
    },
    "least_privilege": {
        "tool": ReferenceTool.SEMGREP.value,
        "change_summary": (
            "Review pipeline job permissions to follow the principle of least "
            "privilege. Use Semgrep rules targeting CI/CD misconfigurations to "
            "detect over-privileged job configurations."
        ),
    },
    "iac": {
        "tool": ReferenceTool.CHECKOV.value,
        "change_summary": (
            "Scan IaC definitions (Terraform, CloudFormation, Helm) with Checkov "
            "to detect misconfigurations before deployment."
        ),
    },
    "sbom": {
        "tool": ReferenceTool.SYFT.value,
        "change_summary": (
            "Generate a Software Bill of Materials with Syft at build time and "
            "attach it to the release artefact to enable downstream consumers to "
            "audit the dependency tree."
        ),
    },
    "approval_gates": {
        "tool": ReferenceTool.SEMGREP.value,
        "change_summary": (
            "Add required reviewer rules and protected-branch policies in your "
            "SCM. Use Semgrep to detect pipeline definitions that bypass approval "
            "gates via force-push or unprotected merge paths."
        ),
    },
}

# Default fallback for unknown / unmapped categories
_DEFAULT_FALLBACK: dict[str, str] = {
    "tool": ReferenceTool.SEMGREP.value,
    "change_summary": (
        "Review the pipeline configuration against the PipelineShield control "
        "catalogue and remediate identified gaps. Integrate Semgrep with "
        "CI-specific rule packs for automated detection."
    ),
}


def get_fallback_remediation(category: str) -> dict[str, str]:
    """Return the deterministic fallback tool and change_summary for *category*."""
    return _FALLBACK_REMEDIATIONS.get(category, _DEFAULT_FALLBACK)


def filter_valid_tools(tools: list[str]) -> list[str]:
    """Return only the approved tool names from *tools*, preserving order."""
    return [t for t in tools if is_valid_tool(t)]
