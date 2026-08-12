"""Auth router — thin delegation layer for /api/v1/auth.

Endpoints:
  GET  /login    — begin OIDC PKCE flow, return 302 to IdP
  POST /callback — complete code exchange, set session cookie, return user info
  GET  /session  — return session status (remaining idle time, absolute expiry)
  POST /logout   — revoke session, clear cookie, return 204

The router contains no business logic. All decisions are delegated to
AuthModule. Errors from AuthModule are mapped to structured HTTP responses.

Cookie attributes:
  httpOnly=True, secure=True, samesite="lax", path="/api"
  No token, id_token, access_token, or refresh_token ever appears in the
  cookie or in any response body.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from pipelineshield.api.v1.schemas.auth import (
    AuthErrorResponse,
    CallbackRequest,
    SessionStatusResponse,
    UserIdentityResponse,
)
from pipelineshield.platform.auth_module import (
    AccessNotGrantedError,
    AuthError,
    AuthModule,
    ServiceUnavailableError,
)
from pipelineshield.platform.session_store import SessionData

_LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_COOKIE_NAME = "pipelineshield_session"
_COOKIE_PATH = "/api"


# ---------------------------------------------------------------------------
# Dependencies (overridden in tests via app.dependency_overrides)
# ---------------------------------------------------------------------------


def get_auth_module() -> AuthModule:  # pragma: no cover
    raise NotImplementedError("get_auth_module must be overridden before use")


def get_db() -> Session:  # pragma: no cover
    raise NotImplementedError("get_db must be overridden before use")


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------


def _set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key=_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        path=_COOKIE_PATH,
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=_COOKIE_NAME, path=_COOKIE_PATH)


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------


def _auth_error_response(
    status_code: int,
    title: str,
    detail: str,
    correlation_id: str = "",
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=AuthErrorResponse(
            title=title,
            status=status_code,
            detail=detail,
            correlation_id=correlation_id or secrets.token_hex(8),
        ).model_dump(),
    )


# ---------------------------------------------------------------------------
# GET /api/v1/auth/login
# ---------------------------------------------------------------------------


@router.get(
    "/login",
    summary="Begin OIDC PKCE login flow",
    response_class=RedirectResponse,
    status_code=302,
    responses={
        400: {"model": AuthErrorResponse},
        503: {"model": AuthErrorResponse},
    },
)
def begin_login(
    code_challenge: Annotated[str, Query(description="S256 PKCE challenge from the browser")],
    redirect: Annotated[str | None, Query(description="Post-login relative path")] = None,
    auth_module: AuthModule = Depends(get_auth_module),
) -> RedirectResponse:
    try:
        idp_url = auth_module.begin_login(code_challenge, redirect)
    except AuthError as exc:
        raise _auth_error_response(400, "Bad Request", exc.detail, exc.correlation_id)
    except ServiceUnavailableError as exc:
        raise _auth_error_response(503, "Service Unavailable", exc.detail)
    return RedirectResponse(url=idp_url, status_code=302)


# ---------------------------------------------------------------------------
# POST /api/v1/auth/callback
# ---------------------------------------------------------------------------


@router.post(
    "/callback",
    response_model=UserIdentityResponse,
    summary="Complete OIDC callback and establish session",
    responses={
        401: {"model": AuthErrorResponse},
        403: {"model": AuthErrorResponse},
        503: {"model": AuthErrorResponse},
    },
)
def complete_callback(
    request_body: CallbackRequest,
    response: Response,
    db: Session = Depends(get_db),
    auth_module: AuthModule = Depends(get_auth_module),
) -> UserIdentityResponse:
    correlation_id = secrets.token_hex(8)
    try:
        session_id, identity = auth_module.complete_callback(
            code=request_body.code,
            state=request_body.state,
            code_verifier=request_body.code_verifier,
            db_session=db,
            correlation_id=correlation_id,
        )
    except AccessNotGrantedError as exc:
        raise _auth_error_response(403, "Access Not Granted", exc.detail, correlation_id)
    except AuthError as exc:
        raise _auth_error_response(401, "Authentication Failed", exc.detail, exc.correlation_id)
    except ServiceUnavailableError as exc:
        raise _auth_error_response(503, "Service Unavailable", exc.detail, correlation_id)

    _set_session_cookie(response, session_id)
    return UserIdentityResponse(
        user_id=identity.user_id,
        email=identity.email,
        display_name=identity.display_name,
        persona=identity.persona,
        workspace_id=identity.workspace_id,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/auth/session
# ---------------------------------------------------------------------------


@router.get(
    "/session",
    response_model=SessionStatusResponse,
    summary="Get current session status",
    responses={
        401: {"model": AuthErrorResponse},
        503: {"model": AuthErrorResponse},
    },
)
def get_session(
    request: Request,
    auth_module: AuthModule = Depends(get_auth_module),
) -> SessionStatusResponse:
    session_id: str = request.cookies.get(_COOKIE_NAME, "")
    if not session_id:
        raise _auth_error_response(401, "Not Authenticated", "No session cookie.")

    try:
        data: SessionData | None = auth_module.resolve_session(session_id)
    except ServiceUnavailableError as exc:
        raise _auth_error_response(503, "Service Unavailable", exc.detail)

    if data is None:
        raise _auth_error_response(401, "Session Expired", "Session has expired or was revoked.")

    now = datetime.now(tz=data.absolute_expires_at.tzinfo)
    remaining = max(0, int((data.absolute_expires_at - now).total_seconds()))
    return SessionStatusResponse(
        user_id=data.user_id,
        persona=data.persona,
        workspace_id=data.workspace_id,
        remaining_idle_seconds=remaining,
        absolute_expires_at=data.absolute_expires_at,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/auth/logout
# ---------------------------------------------------------------------------


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Terminate session and clear cookie",
    responses={
        503: {"model": AuthErrorResponse},
    },
)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    auth_module: AuthModule = Depends(get_auth_module),
) -> None:
    session_id: str = request.cookies.get(_COOKIE_NAME, "")

    session_data: SessionData | None = None
    if session_id:
        try:
            session_data = auth_module.resolve_session(session_id)
        except ServiceUnavailableError as exc:
            raise _auth_error_response(503, "Service Unavailable", exc.detail)
        try:
            auth_module.terminate_session(session_id)
        except ServiceUnavailableError as exc:
            raise _auth_error_response(503, "Service Unavailable", exc.detail)

    if session_data is not None:
        auth_module.write_logout_event(
            db,
            str(session_data.user_id),
            session_data.persona,
        )

    _clear_session_cookie(response)
