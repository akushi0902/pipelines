"""Pydantic v2 response/request models for governance console endpoints.

All response_model declarations use these so undeclared fields cannot leak.
Schema-level strict validation (extra='forbid') prevents silent field additions
from being exposed through the API.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Common
# ---------------------------------------------------------------------------


class GovernanceErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    title: str
    status: int
    detail: str
    correlation_id: str | None = None
    errors: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Classification inventory
# ---------------------------------------------------------------------------


class ClassificationEntityItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Entity / table name in the data model")
    tier: str = Field(description="Classification tier: Confidential, Restricted, Internal, Public")
    retention: str = Field(description="Retention policy summary")
    encryption: str = Field(description="Encryption approach")
    masking_rule: str = Field(description="Masking / redaction rule applied before storage")
    access_rule: str = Field(description="Minimum capability required to access this entity")


class ClassificationInventoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entities: list[ClassificationEntityItem]


# ---------------------------------------------------------------------------
# Governance audit events
# ---------------------------------------------------------------------------


class GovernanceAuditEventItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    occurred_at: datetime
    actor_id: str
    actor_display: str | None = None
    actor_persona: str | None = None
    workspace_id: uuid.UUID | None = None
    action: str
    resource_type: str
    resource_id: str | None = None
    change_detail: dict[str, Any] = Field(default_factory=dict)


class GovernanceAuditEventsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[GovernanceAuditEventItem]
    next_cursor: str | None = None
    has_more: bool


# ---------------------------------------------------------------------------
# Retention policy
# ---------------------------------------------------------------------------


class RetentionPolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    retention_days: int
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    last_run_status: str | None = None
    purge_sla_breaches: int
    updated_by: str | None = None
    updated_at: datetime | None = None


class RetentionPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    retention_days: int = Field(ge=1, le=90)

    @field_validator("retention_days")
    @classmethod
    def validate_max_policy(cls, v: int) -> int:
        if v > 90:
            raise ValueError(
                "retention_days cannot exceed 90 — Confidential entity maximum per policy."
            )
        return v


# ---------------------------------------------------------------------------
# Purge receipts
# ---------------------------------------------------------------------------


class PurgeReceiptItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    batch_id: uuid.UUID
    executed_at: datetime
    entity_counts: dict[str, int]
    verification_digest: str
    status: str
    error_detail: str | None = None
    trigger: str = "scheduled"
    subject_user_id: uuid.UUID | None = None


class PurgeReceiptsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[PurgeReceiptItem]
    next_cursor: str | None = None
    has_more: bool


# ---------------------------------------------------------------------------
# Export history
# ---------------------------------------------------------------------------


class ExportHistoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    occurred_at: datetime
    actor_id: str
    resource_type: str
    resource_id: str | None = None
    format: str | None = None


class ExportHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ExportHistoryItem]
    next_cursor: str | None = None
    has_more: bool
