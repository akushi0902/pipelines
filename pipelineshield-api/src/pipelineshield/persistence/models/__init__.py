"""SQLAlchemy 2.0 declarative models for PipelineShield.

All models use Mapped[] annotations and UUID primary keys.
Tenant-scoped tables carry a workspace_id foreign key.
Confidential entities use hard-delete only — no soft-delete columns.
"""
from __future__ import annotations

from sqlalchemy import MetaData

from .base import Base, metadata
from .workspace import Workspace
from .app_user import AppUser
from .role_binding import RoleBinding
from .group_persona_mapping import GroupPersonaMapping
from .analysis import Analysis
from .pipeline_definition import PipelineDefinition
from .finding import Finding
from .remediation import Remediation
from .generated_draft import GeneratedDraft
from .audit_event import AuditEvent
from .purge_receipt import PurgeReceipt
from .control_catalogue_version import ControlCatalogueVersion
from .sample_pipeline import SamplePipeline
from .workspace_score_rollup import WorkspaceScoreRollup
from .category_gap_rollup import CategoryGapRollup
from .retention_policy import RetentionPolicy
from .analysis_category_score import AnalysisCategoryScore
from .coverage_limitation import CoverageLimitation

__all__ = [
    "Base",
    "metadata",
    "Workspace",
    "AppUser",
    "RoleBinding",
    "GroupPersonaMapping",
    "Analysis",
    "PipelineDefinition",
    "Finding",
    "Remediation",
    "GeneratedDraft",
    "AuditEvent",
    "PurgeReceipt",
    "ControlCatalogueVersion",
    "SamplePipeline",
    "WorkspaceScoreRollup",
    "CategoryGapRollup",
    "RetentionPolicy",
    "AnalysisCategoryScore",
    "CoverageLimitation",
]
