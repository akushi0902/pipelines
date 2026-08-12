"""Pydantic v2 request and response models for /api/v1/auth endpoints.

All error bodies follow RFC 7807 style with snake_case fields.
No token, code, verifier, or cookie value appears in any response body.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CallbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., min_length=1, max_length=512, description="Authorization code from IdP")
    state: str = Field(..., min_length=1, max_length=512, description="CSRF state parameter")
    code_verifier: str = Field(
        ...,
        min_length=43,
        max_length=128,
        description="PKCE code verifier (43–128 chars, base64url)",
    )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class UserIdentityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: uuid.UUID
    email: str = Field(description="Email address (may be partially masked)")
    display_name: str
    persona: str
    workspace_id: uuid.UUID


class SessionStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: uuid.UUID
    persona: str
    workspace_id: uuid.UUID
    remaining_idle_seconds: int = Field(ge=0)
    absolute_expires_at: datetime


class AuthErrorResponse(BaseModel):
    """RFC 7807-style error body."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(default="https://pipelineshield.internal/errors/auth")
    title: str
    status: int
    detail: str
    correlation_id: str = ""
