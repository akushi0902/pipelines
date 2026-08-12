"""Pydantic v2 schemas for /api/v1/audit-events.

Response items expose only metadata — no secret values, no pipeline
definition content.  The actor reference is always the masked form.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuditEventItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    occurred_at: datetime
    actor_id: str = Field(description="Actor identifier (may be masked for unauthenticated events)")
    actor_reference: str | None = Field(default=None, description="Masked actor reference")
    actor_persona: str | None = None
    workspace_id: uuid.UUID | None = None
    action: str
    resource_type: str
    resource_id: str | None = None
    change_detail: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = None


class AuditEventsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[AuditEventItem]
    next_cursor: str | None = None
    total_returned: int


class AuditErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = "https://pipelineshield.internal/errors/audit"
    title: str
    status: int
    detail: str
    correlation_id: str = ""
