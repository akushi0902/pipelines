"""Pydantic schemas for the admin role-binding API.

All identities are represented via masked email and display name.
Full email addresses are never returned.  Snake_case field names throughout.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, field_validator

from pipelineshield.persistence.models.role_binding import VALID_PERSONAS


class ErrorResponse(BaseModel):
    type: str
    title: str
    status: int
    detail: str
    correlation_id: str | None = None
    errors: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Role binding schemas
# ---------------------------------------------------------------------------


class RoleBindingItem(BaseModel):
    id: uuid.UUID
    app_user_id: uuid.UUID
    masked_email: str
    display_name: str
    persona: str
    granted_by_id: uuid.UUID | None
    granted_at: datetime
    revoked_at: datetime | None

    model_config = {"from_attributes": True}


class RoleBindingListResponse(BaseModel):
    items: list[RoleBindingItem]
    total: int


class GrantBindingRequest(BaseModel):
    user_id: uuid.UUID
    persona: str

    @field_validator("persona")
    @classmethod
    def persona_must_be_valid(cls, v: str) -> str:
        if v not in VALID_PERSONAS:
            raise ValueError(
                f"{v!r} is not a valid persona. Choose from: {VALID_PERSONAS!r}."
            )
        return v


class GrantBindingResponse(BaseModel):
    id: uuid.UUID
    app_user_id: uuid.UUID
    masked_email: str
    display_name: str
    persona: str
    granted_by_id: uuid.UUID | None
    granted_at: datetime
    revoked_at: datetime | None

    model_config = {"from_attributes": True}


class ChangeBindingRequest(BaseModel):
    persona: str

    @field_validator("persona")
    @classmethod
    def persona_must_be_valid(cls, v: str) -> str:
        if v not in VALID_PERSONAS:
            raise ValueError(
                f"{v!r} is not a valid persona. Choose from: {VALID_PERSONAS!r}."
            )
        return v


# ---------------------------------------------------------------------------
# Group persona mapping schemas
# ---------------------------------------------------------------------------


class GroupPersonaMappingItem(BaseModel):
    id: uuid.UUID
    idp_group: str
    workspace_id: uuid.UUID
    persona: str
    precedence: int
    created_at: datetime

    model_config = {"from_attributes": True}


class GroupPersonaMappingListResponse(BaseModel):
    items: list[GroupPersonaMappingItem]
    total: int


class GroupPersonaMappingUpsertItem(BaseModel):
    idp_group: str
    workspace_id: uuid.UUID
    persona: str
    precedence: int = 100

    @field_validator("persona")
    @classmethod
    def persona_must_be_valid(cls, v: str) -> str:
        if v not in VALID_PERSONAS:
            raise ValueError(
                f"{v!r} is not a valid persona. Choose from: {VALID_PERSONAS!r}."
            )
        return v


class GroupPersonaMappingUpsertRequest(BaseModel):
    items: list[GroupPersonaMappingUpsertItem]
