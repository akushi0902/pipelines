"""Baseline schema — all twelve PipelineShield tables.

Revision ID: 0001
Revises: (none — this is the first revision)
Create Date: 2026-08-11

This single migration provisions the complete PostgreSQL 16 schema,
including:
- All twelve tables with UUID primary keys and timestamptz created_at.
- workspace_id foreign keys on every tenant-scoped table.
- COMMENT ON TABLE statements carrying data classification and retention.
- The AI zero-weight CHECK constraint on the finding table.
- The pipelineshield_app role with least-privilege grants:
    INSERT + SELECT on all tables,
    but NO UPDATE, DELETE on audit_event,
    and NO DDL privileges anywhere.

IMPORTANT: migrations run under a separate migration role (pipelineshield_migrate)
that holds CREATE/ALTER/DROP.  The application role (pipelineshield_app) never
holds DDL privileges.

Downgrade note: dropping tables in a non-production environment.  Do NOT
run the downgrade on a production database containing audit_event rows.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ---------------------------------------------------------------------------
# Data classification and retention annotations
# Sourced from the architecture data-classification table.
# Format: "Classification: <level> | Retention: <period>"
# ---------------------------------------------------------------------------
_TABLE_COMMENTS = {
    "workspace": (
        "Classification: Internal | Retention: indefinite | "
        "Top-level tenant container.  All tenant-scoped tables reference "
        "workspace_id for row-level scoping."
    ),
    "app_user": (
        "Classification: Internal | Retention: indefinite | "
        "Application user account mapped from the enterprise IdP."
    ),
    "role_binding": (
        "Classification: Internal | Retention: indefinite | "
        "Maps an AppUser to a persona within a workspace."
    ),
    "analysis": (
        "Classification: Confidential | Retention: 90 days | "
        "Pipeline security analysis result.  Hard-delete only — "
        "no soft-delete columns permitted."
    ),
    "pipeline_definition": (
        "Classification: Confidential | Retention: 90 days | "
        "Application-level envelope-encrypted masked pipeline definition.  "
        "masked_content column holds AES-256-GCM ciphertext.  "
        "Hard-delete only — no soft-delete columns permitted."
    ),
    "finding": (
        "Classification: Confidential | Retention: 90 days | "
        "Security finding from the deterministic rule engine (source=deterministic) "
        "or the AI advisory pass (source=ai, weight=0, requires_human_review=true).  "
        "Hard-delete only — no soft-delete columns permitted."
    ),
    "remediation": (
        "Classification: Confidential | Retention: 90 days | "
        "Recommended remediation action for a security finding.  "
        "Recommendation only — never executed automatically.  "
        "Hard-delete only — no soft-delete columns permitted."
    ),
    "generated_draft": (
        "Classification: Confidential | Retention: 90 days | "
        "AI-generated hardened pipeline configuration draft.  "
        "Always requires human review.  Hard-delete only."
    ),
    "audit_event": (
        "Classification: Restricted | Retention: 1 year | "
        "Append-only audit log.  pipelineshield_app holds INSERT+SELECT only — "
        "no UPDATE or DELETE.  change_detail MUST NOT contain definition content "
        "or secret values."
    ),
    "purge_receipt": (
        "Classification: Internal | Retention: indefinite | "
        "Record of a completed hard-delete purge batch.  Retained as "
        "SOC 2 evidence.  Not purged."
    ),
    "control_catalogue_version": (
        "Classification: Internal | Retention: indefinite | "
        "Versioned snapshot of the security control catalogue.  "
        "Every analysis records the catalogue_version it was scored against."
    ),
    "sample_pipeline": (
        "Classification: Internal | Retention: indefinite | "
        "Bundled demo pipeline configurations seeded for offline development.  "
        "Contains no Confidential user-uploaded content."
    ),
}

# Tables on which pipelineshield_app receives full INSERT+SELECT
_APP_ROLE_FULL_TABLES = [
    "workspace",
    "app_user",
    "role_binding",
    "analysis",
    "pipeline_definition",
    "finding",
    "remediation",
    "generated_draft",
    "purge_receipt",
    "control_catalogue_version",
    "sample_pipeline",
]

# audit_event gets only INSERT+SELECT (NOT UPDATE or DELETE)
_AUDIT_TABLE = "audit_event"
_APP_ROLE = "pipelineshield_app"


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. workspace
    # ------------------------------------------------------------------
    op.create_table(
        "workspace",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — workspace identifier.",
        ),
        sa.Column(
            "name",
            sa.String(255),
            nullable=False,
            comment="Human-readable workspace name.",
        ),
        sa.Column(
            "slug",
            sa.String(63),
            nullable=False,
            comment="URL-safe slug; unique across the platform.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.UniqueConstraint("slug", name="uq_workspace_slug"),
        sa.PrimaryKeyConstraint("id", name="pk_workspace"),
    )

    # ------------------------------------------------------------------
    # 2. app_user
    # ------------------------------------------------------------------
    op.create_table(
        "app_user",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — user identifier.",
        ),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Owning workspace — tenant scope.",
        ),
        sa.Column(
            "sub_claim",
            sa.String(255),
            nullable=False,
            comment="IdP subject claim (opaque); stable user identifier.",
        ),
        sa.Column(
            "email",
            sa.String(320),
            nullable=False,
            comment="Email address from IdP claims.",
        ),
        sa.Column(
            "display_name",
            sa.String(255),
            nullable=False,
            comment="Display name from IdP claims.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name="fk_app_user_workspace_id_workspace",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_app_user"),
    )
    op.create_index("ix_app_user_workspace_id", "app_user", ["workspace_id"])

    # ------------------------------------------------------------------
    # 3. role_binding
    # ------------------------------------------------------------------
    op.create_table(
        "role_binding",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — role binding identifier.",
        ),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Workspace this binding belongs to.",
        ),
        sa.Column(
            "app_user_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="User being granted the persona.",
        ),
        sa.Column(
            "persona",
            sa.String(64),
            nullable=False,
            comment=(
                "Persona label — one of: app_developer, devops_engineer, "
                "devsecops_engineer, appsec_lead, engineering_manager."
            ),
        ),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Timestamp when the binding was created (UTC).",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name="fk_role_binding_workspace_id_workspace",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["app_user_id"],
            ["app_user.id"],
            name="fk_role_binding_app_user_id_app_user",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "app_user_id",
            name="uq_role_binding_workspace_user",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_role_binding"),
    )
    op.create_index("ix_role_binding_workspace_id", "role_binding", ["workspace_id"])
    op.create_index("ix_role_binding_app_user_id", "role_binding", ["app_user_id"])

    # ------------------------------------------------------------------
    # 4. control_catalogue_version
    # ------------------------------------------------------------------
    op.create_table(
        "control_catalogue_version",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — catalogue version identifier.",
        ),
        sa.Column(
            "version_number",
            sa.Integer,
            nullable=False,
            comment="Monotonically increasing version counter.",
        ),
        sa.Column(
            "description",
            sa.Text,
            nullable=False,
            server_default=sa.text("''"),
            comment="Human-readable change notes for this catalogue version.",
        ),
        sa.Column(
            "controls",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            comment="Full catalogue snapshot as JSONB.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.UniqueConstraint(
            "version_number", name="uq_control_catalogue_version_version_number"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_control_catalogue_version"),
    )

    # ------------------------------------------------------------------
    # 5. analysis
    # ------------------------------------------------------------------
    op.create_table(
        "analysis",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — analysis identifier.",
        ),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Owning workspace — tenant scope.",
        ),
        sa.Column(
            "owner_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="User who initiated the analysis.",
        ),
        sa.Column(
            "catalogue_version_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Catalogue version used for scoring.",
        ),
        sa.Column(
            "pipeline_format",
            sa.String(64),
            nullable=False,
            comment=(
                "Detected pipeline format: github_actions, gitlab_ci, "
                "jenkins_declarative."
            ),
        ),
        sa.Column(
            "format_confidence",
            sa.Numeric(4, 3),
            nullable=False,
            comment="Format detection confidence score (0.000–1.000).",
        ),
        sa.Column(
            "score",
            sa.Integer,
            nullable=False,
            comment="Security posture score (0–100).",
        ),
        sa.Column(
            "grade",
            sa.String(2),
            nullable=False,
            comment="Letter grade derived from score (A, B, C, D, F).",
        ),
        sa.Column(
            "coverage_report",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
            comment=(
                "Coverage report listing unresolved fragments and "
                "Not Assessable categories."
            ),
        ),
        sa.Column(
            "status",
            sa.String(32),
            nullable=False,
            server_default=sa.text("'completed'"),
            comment=(
                "Analysis lifecycle status: completed, degraded "
                "(model timeout), failed."
            ),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name="fk_analysis_workspace_id_workspace",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["owner_id"],
            ["app_user.id"],
            name="fk_analysis_owner_id_app_user",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["catalogue_version_id"],
            ["control_catalogue_version.id"],
            name="fk_analysis_catalogue_version_id_control_catalogue_version",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_analysis"),
    )
    op.create_index("ix_analysis_workspace_id", "analysis", ["workspace_id"])
    op.create_index("ix_analysis_owner_id", "analysis", ["owner_id"])

    # ------------------------------------------------------------------
    # 6. pipeline_definition
    # ------------------------------------------------------------------
    op.create_table(
        "pipeline_definition",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — pipeline definition identifier.",
        ),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Owning workspace — tenant scope.",
        ),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="One-to-one link to the parent analysis.",
        ),
        sa.Column(
            "masked_content",
            sa.Text,
            nullable=False,
            comment=(
                "Application-level envelope-encrypted ciphertext of the "
                "masked pipeline definition.  Contains no plaintext secrets "
                "or definition text.  Classification: Confidential."
            ),
        ),
        sa.Column(
            "key_id",
            sa.String(128),
            nullable=False,
            comment=(
                "Identifier of the encryption key version used to produce "
                "masked_content.  Never stores the key value itself."
            ),
        ),
        sa.Column(
            "original_filename",
            sa.String(255),
            nullable=True,
            comment="Original filename supplied by the user (optional).",
        ),
        sa.Column(
            "line_count",
            sa.Integer,
            nullable=False,
            comment="Number of lines in the original masked definition.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name="fk_pipeline_definition_workspace_id_workspace",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["analysis_id"],
            ["analysis.id"],
            name="fk_pipeline_definition_analysis_id_analysis",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "analysis_id", name="uq_pipeline_definition_analysis_id"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_pipeline_definition"),
    )
    op.create_index(
        "ix_pipeline_definition_workspace_id",
        "pipeline_definition",
        ["workspace_id"],
    )

    # ------------------------------------------------------------------
    # 7. finding
    # ------------------------------------------------------------------
    op.create_table(
        "finding",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — finding identifier.",
        ),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Owning workspace — tenant scope.",
        ),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Parent analysis this finding belongs to.",
        ),
        sa.Column(
            "source",
            sa.String(16),
            nullable=False,
            comment=(
                "Origin of this finding: 'deterministic' (rule engine, "
                "authoritative) or 'ai' (model pass, advisory only)."
            ),
        ),
        sa.Column(
            "requires_human_review",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
            comment=(
                "True when a human must review this finding before acting on it.  "
                "Always True for AI-sourced findings."
            ),
        ),
        sa.Column(
            "control_category",
            sa.String(64),
            nullable=False,
            comment="One of the nine control categories (e.g. secrets, signing).",
        ),
        sa.Column(
            "rule_id",
            sa.String(128),
            nullable=False,
            comment="Stable rule identifier for deduplication and tracking.",
        ),
        sa.Column(
            "severity",
            sa.String(16),
            nullable=False,
            comment="Severity level: critical, high, medium, low, info.",
        ),
        sa.Column(
            "weight",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
            comment=(
                "Score contribution of this finding.  MUST be 0 when "
                "source = 'ai' (enforced by CHECK constraint "
                "ck_finding_ai_source_zero_weight)."
            ),
        ),
        sa.Column(
            "title",
            sa.String(255),
            nullable=False,
            comment="Short, human-readable finding title.",
        ),
        sa.Column(
            "description",
            sa.Text,
            nullable=False,
            server_default=sa.text("''"),
            comment="Full finding description.  Never contains secret values.",
        ),
        sa.Column(
            "anchor_line",
            sa.Integer,
            nullable=True,
            comment="1-indexed source line where the issue was detected.",
        ),
        sa.Column(
            "anchor_column",
            sa.Integer,
            nullable=True,
            comment="1-indexed source column where the issue was detected.",
        ),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
            comment="Structured evidence supporting the finding.  No secret values.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.CheckConstraint(
            "NOT (source = 'ai' AND weight != 0)",
            name="ai_source_zero_weight",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name="fk_finding_workspace_id_workspace",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["analysis_id"],
            ["analysis.id"],
            name="fk_finding_analysis_id_analysis",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_finding"),
    )
    op.create_index("ix_finding_workspace_id", "finding", ["workspace_id"])
    op.create_index("ix_finding_analysis_id", "finding", ["analysis_id"])

    # ------------------------------------------------------------------
    # 8. remediation
    # ------------------------------------------------------------------
    op.create_table(
        "remediation",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — remediation identifier.",
        ),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Owning workspace — tenant scope.",
        ),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Parent finding this remediation addresses.",
        ),
        sa.Column(
            "tool_name",
            sa.String(128),
            nullable=False,
            comment=(
                "Name of the recommended tool (e.g. Gitleaks, Semgrep, "
                "Trivy, Checkov, Syft, Cosign)."
            ),
        ),
        sa.Column(
            "guidance",
            sa.Text,
            nullable=False,
            comment=(
                "Plain-language remediation guidance.  "
                "Recommendation only — never executed."
            ),
        ),
        sa.Column(
            "reference_url",
            sa.String(2048),
            nullable=True,
            comment="Optional reference URL for further reading.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name="fk_remediation_workspace_id_workspace",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["finding.id"],
            name="fk_remediation_finding_id_finding",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_remediation"),
    )
    op.create_index("ix_remediation_workspace_id", "remediation", ["workspace_id"])
    op.create_index("ix_remediation_finding_id", "remediation", ["finding_id"])

    # ------------------------------------------------------------------
    # 9. generated_draft
    # ------------------------------------------------------------------
    op.create_table(
        "generated_draft",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — generated draft identifier.",
        ),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Owning workspace — tenant scope.",
        ),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Parent analysis that produced this draft.",
        ),
        sa.Column(
            "draft_type",
            sa.String(64),
            nullable=False,
            comment=(
                "Type of draft: secure_pipeline_architecture or "
                "hardened_configuration."
            ),
        ),
        sa.Column(
            "content",
            sa.Text,
            nullable=False,
            comment=(
                "Draft content.  Always advisory — never applied "
                "automatically.  Classification: Confidential."
            ),
        ),
        sa.Column(
            "model_id",
            sa.String(128),
            nullable=False,
            comment="Identifier of the model that produced this draft.",
        ),
        sa.Column(
            "requires_human_review",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("true"),
            comment="Always True — AI-generated drafts require human review.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name="fk_generated_draft_workspace_id_workspace",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["analysis_id"],
            ["analysis.id"],
            name="fk_generated_draft_analysis_id_analysis",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_generated_draft"),
    )
    op.create_index(
        "ix_generated_draft_workspace_id", "generated_draft", ["workspace_id"]
    )
    op.create_index(
        "ix_generated_draft_analysis_id", "generated_draft", ["analysis_id"]
    )

    # ------------------------------------------------------------------
    # 10. audit_event  (append-only)
    # ------------------------------------------------------------------
    op.create_table(
        "audit_event",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — audit event identifier.",
        ),
        sa.Column(
            "actor_id",
            sa.String(255),
            nullable=False,
            comment="Identifier of the user or service account performing the action.",
        ),
        sa.Column(
            "actor_persona",
            sa.String(64),
            nullable=True,
            comment=(
                "Persona label at the time of the action "
                "(null for system events)."
            ),
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Wall-clock timestamp of the event (UTC).  Immutable once written.",
        ),
        sa.Column(
            "resource_type",
            sa.String(64),
            nullable=False,
            comment=(
                "Type of resource affected "
                "(e.g. 'analysis', 'workspace', 'auth')."
            ),
        ),
        sa.Column(
            "resource_id",
            sa.String(255),
            nullable=True,
            comment="UUID or other identifier of the affected resource.",
        ),
        sa.Column(
            "action",
            sa.String(64),
            nullable=False,
            comment=(
                "Action label "
                "(e.g. 'create', 'delete', 'auth_login_success')."
            ),
        ),
        sa.Column(
            "change_detail",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
            comment=(
                "Structured event detail as JSONB.  "
                "INVARIANT: MUST NOT contain definition content or secret values."
            ),
        ),
        sa.Column(
            "correlation_id",
            sa.String(128),
            nullable=True,
            comment="Optional request correlation ID for distributed tracing.",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_event"),
    )
    op.create_index(
        "ix_audit_event_occurred_at", "audit_event", ["occurred_at"]
    )

    # ------------------------------------------------------------------
    # 11. purge_receipt
    # ------------------------------------------------------------------
    op.create_table(
        "purge_receipt",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — purge receipt identifier.",
        ),
        sa.Column(
            "batch_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment=(
                "Unique batch identifier for this purge run.  "
                "Stable across retries of the same purge job."
            ),
        ),
        sa.Column(
            "executed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Timestamp when the purge batch completed (UTC).",
        ),
        sa.Column(
            "deleted_counts",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            comment=(
                "JSONB map of table name → row count deleted "
                "(e.g. {\"analysis\": 42, \"finding\": 310})."
            ),
        ),
        sa.Column(
            "verification_digest",
            sa.String(128),
            nullable=False,
            comment=(
                "Cryptographic digest of the batch manifest used to verify "
                "the purge was complete (e.g. SHA-256 hex)."
            ),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.UniqueConstraint("batch_id", name="uq_purge_receipt_batch_id"),
        sa.PrimaryKeyConstraint("id", name="pk_purge_receipt"),
    )

    # ------------------------------------------------------------------
    # 12. sample_pipeline
    # ------------------------------------------------------------------
    op.create_table(
        "sample_pipeline",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            comment="Primary key — sample pipeline identifier.",
        ),
        sa.Column(
            "workspace_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            comment="Owning workspace — tenant scope.",
        ),
        sa.Column(
            "name",
            sa.String(255),
            nullable=False,
            comment="Human-readable name for this sample pipeline.",
        ),
        sa.Column(
            "pipeline_format",
            sa.String(64),
            nullable=False,
            comment=(
                "Pipeline format: github_actions, gitlab_ci, "
                "jenkins_declarative."
            ),
        ),
        sa.Column(
            "description",
            sa.Text,
            nullable=False,
            server_default=sa.text("''"),
            comment="Description of what this sample demonstrates.",
        ),
        sa.Column(
            "content",
            sa.Text,
            nullable=False,
            comment=(
                "Plain-text pipeline content.  Contains no secrets or "
                "Confidential data — classification: Internal."
            ),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
            comment="Row creation timestamp (UTC).",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspace.id"],
            name="fk_sample_pipeline_workspace_id_workspace",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_sample_pipeline"),
    )
    op.create_index(
        "ix_sample_pipeline_workspace_id", "sample_pipeline", ["workspace_id"]
    )

    # ------------------------------------------------------------------
    # COMMENT ON TABLE statements — data classification and retention
    # ------------------------------------------------------------------
    for table, comment in _TABLE_COMMENTS.items():
        op.execute(
            sa.text(f"COMMENT ON TABLE {table} IS :comment").bindparams(
                comment=comment
            )
        )

    # ------------------------------------------------------------------
    # Role and privilege setup — pipelineshield_app (least privilege)
    #
    # The application role may NOT hold DDL privileges and may NOT UPDATE
    # or DELETE from audit_event.  Migrations run under a separate role
    # (pipelineshield_migrate) that is not created here.
    #
    # IF NOT EXISTS is used so that re-running GRANT statements after a
    # failed migration does not raise an error (idempotency requirement).
    # ------------------------------------------------------------------
    op.execute(sa.text(
        "DO $$ BEGIN "
        "  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role) THEN "
        "    CREATE ROLE pipelineshield_app NOLOGIN; "
        "  END IF; "
        "END $$"
    ).bindparams(role=_APP_ROLE))

    # Grant INSERT + SELECT on all non-audit tables.
    for table in _APP_ROLE_FULL_TABLES:
        op.execute(sa.text(
            f"GRANT INSERT, SELECT ON TABLE {table} TO {_APP_ROLE}"
        ))

    # Grant INSERT + SELECT ONLY on audit_event — NO UPDATE, NO DELETE.
    op.execute(sa.text(
        f"GRANT INSERT, SELECT ON TABLE {_AUDIT_TABLE} TO {_APP_ROLE}"
    ))

    # Explicitly revoke UPDATE and DELETE on audit_event (belt-and-suspenders).
    op.execute(sa.text(
        f"REVOKE UPDATE, DELETE ON TABLE {_AUDIT_TABLE} FROM {_APP_ROLE}"
    ))

    # Revoke UPDATE and DELETE on all other application tables from public
    # and the app role to enforce the principle of least privilege.
    # (These are not granted above, but explicit REVOKE provides defence-in-depth.)
    for table in _APP_ROLE_FULL_TABLES:
        op.execute(sa.text(
            f"REVOKE UPDATE, DELETE ON TABLE {table} FROM {_APP_ROLE}"
        ))


def downgrade() -> None:
    """Drop all tables created by the baseline migration.

    WARNING: This operation is DESTRUCTIVE and is only permitted in
    non-production environments.  All data including audit_event rows
    will be permanently lost.
    """
    # Revoke privileges before dropping objects.
    op.execute(sa.text(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {_APP_ROLE}"))
    op.execute(sa.text(
        "DO $$ BEGIN "
        "  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role) THEN "
        "    DROP ROLE pipelineshield_app; "
        "  END IF; "
        "END $$"
    ).bindparams(role=_APP_ROLE))

    # Drop tables in reverse dependency order.
    op.drop_table("sample_pipeline")
    op.drop_table("purge_receipt")
    op.drop_table("audit_event")
    op.drop_table("generated_draft")
    op.drop_table("remediation")
    op.drop_table("finding")
    op.drop_table("pipeline_definition")
    op.drop_table("analysis")
    op.drop_table("control_catalogue_version")
    op.drop_table("role_binding")
    op.drop_table("app_user")
    op.drop_table("workspace")
