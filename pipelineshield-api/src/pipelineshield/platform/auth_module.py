"""AuthModule — OIDC PKCE authentication lifecycle.

Responsibilities:
  begin_login        — generate state/nonce/PKCE params, redirect URL
  complete_callback  — code exchange, id_token verify, JIT user upsert, session create
  resolve_session    — look up and TTL-refresh active session
  terminate_session  — delete session (idempotent)

Security invariants:
  - SSRF prevention: IdP endpoints come only from the cached discovery document,
    never from user-supplied URLs.
  - No token material, code, verifier, or cookie value is ever logged.
  - Sessions are opaque and server-side revocable; no JWT in the session cookie.
  - Fail closed: IdP or Redis unavailability raises ServiceUnavailableError → 503.
  - No password column or credential handling is introduced here.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import jwt as pyjwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from pipelineshield.config import AuthConfig
from pipelineshield.persistence.models.app_user import AppUser
from pipelineshield.persistence.models.audit_event import AuditEvent
from pipelineshield.persistence.models.role_binding import RoleBinding
from pipelineshield.persistence.models.workspace import Workspace
from pipelineshield.platform.session_store import (
    LoginState,
    LoginStateStore,
    SessionData,
    SessionStore,
)

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AuthError(Exception):
    """Authentication failure — maps to HTTP 401."""

    def __init__(self, error_code: str, detail: str, correlation_id: str = "") -> None:
        super().__init__(detail)
        self.error_code = error_code
        self.detail = detail
        self.correlation_id = correlation_id or secrets.token_hex(8)


class AccessNotGrantedError(Exception):
    """IdP authentication succeeded but the user has no persona binding — 403."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class ServiceUnavailableError(Exception):
    """IdP or Redis outage — maps to HTTP 503."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------


def _validate_pkce_challenge_format(code_challenge: str) -> None:
    """Verify code_challenge is valid base64url (43 chars for S256)."""
    if not code_challenge:
        raise AuthError("invalid_request", "code_challenge is required.")
    # S256 SHA-256 digest → 32 bytes → base64url = 43 chars (no padding)
    if len(code_challenge) != 43:
        raise AuthError(
            "invalid_request",
            "code_challenge must be 43 characters (S256 base64url of SHA-256).",
        )
    _B64URL_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if not all(c in _B64URL_CHARS for c in code_challenge):
        raise AuthError("invalid_request", "code_challenge must be base64url encoded.")


def _validate_pkce_verifier_matches_challenge(
    code_verifier: str, code_challenge: str
) -> None:
    """Verify S256: base64url(sha256(verifier)) == challenge."""
    if not code_verifier:
        raise AuthError("invalid_request", "code_verifier is required.")
    if len(code_verifier) < 43 or len(code_verifier) > 128:
        raise AuthError(
            "invalid_request",
            "code_verifier must be 43–128 characters.",
        )
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if not secrets.compare_digest(computed, code_challenge):
        raise AuthError("invalid_pkce_verifier", "PKCE code_verifier does not match code_challenge.")


def _validate_redirect_path(path: str | None, allowed: list[str]) -> str:
    """Return a safe redirect path or raise AuthError for open-redirect attempts."""
    if not path:
        return "/"
    if "://" in path or not path.startswith("/"):
        raise AuthError("invalid_redirect", "Redirect target must be a relative path.")
    if path not in allowed:
        _LOG.warning("authz_denied_redirect", extra={"path": "[REDACTED]"})
        return "/"
    return path


# ---------------------------------------------------------------------------
# AuthModule
# ---------------------------------------------------------------------------


@dataclass
class UserIdentity:
    user_id: uuid.UUID
    idp_subject: str
    email: str
    display_name: str
    persona: str
    workspace_id: uuid.UUID


class AuthModule:
    """Orchestrates the OIDC PKCE authentication lifecycle."""

    def __init__(
        self,
        config: AuthConfig,
        session_store: SessionStore,
        login_state_store: LoginStateStore,
        http_client: Any | None = None,
    ) -> None:
        self._config = config
        self._sessions = session_store
        self._login_states = login_state_store
        self._http = http_client
        self._oidc_config: dict[str, Any] | None = None
        self._jwks_cache: dict[str, Any] | None = None
        self._jwks_cached_at: float = 0.0

    # -----------------------------------------------------------------------
    # OIDC discovery + JWKS
    # -----------------------------------------------------------------------

    def _get_oidc_config(self) -> dict[str, Any]:
        if self._oidc_config is not None:
            return self._oidc_config
        if self._http is None:
            raise ServiceUnavailableError("HTTP client not configured.")
        discovery_url = f"{self._config.oidc_issuer}/.well-known/openid-configuration"
        try:
            resp = self._http.get(discovery_url)
            resp.raise_for_status()
            self._oidc_config = resp.json()
            return self._oidc_config
        except Exception as exc:
            raise ServiceUnavailableError(
                "IdP discovery document unavailable. Retry later."
            ) from exc

    def _get_jwks(self) -> dict[str, Any]:
        now = time.monotonic()
        refresh_needed = (
            self._jwks_cache is None
            or (now - self._jwks_cached_at) > self._config.oidc_jwks_ttl_seconds
        )
        if not refresh_needed:
            return self._jwks_cache  # type: ignore[return-value]

        oidc_cfg = self._get_oidc_config()
        jwks_uri = oidc_cfg.get("jwks_uri", "")
        if not jwks_uri:
            raise ServiceUnavailableError("IdP discovery document missing jwks_uri.")

        try:
            resp = self._http.get(jwks_uri)  # type: ignore[union-attr]
            resp.raise_for_status()
            self._jwks_cache = resp.json()
            self._jwks_cached_at = now
            return self._jwks_cache  # type: ignore[return-value]
        except Exception as exc:
            if self._jwks_cache is not None:
                _LOG.warning("jwks_refresh_failed_serving_stale")
                return self._jwks_cache
            raise ServiceUnavailableError("JWKS unavailable. Retry later.") from exc

    # -----------------------------------------------------------------------
    # begin_login
    # -----------------------------------------------------------------------

    def begin_login(
        self,
        code_challenge: str,
        redirect_path: str | None = None,
    ) -> str:
        """Store PKCE state and return the IdP authorization URL (302 target)."""
        _validate_pkce_challenge_format(code_challenge)
        safe_redirect = _validate_redirect_path(
            redirect_path, self._config.session_allowed_redirect_paths
        )

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        try:
            self._login_states.store(
                state,
                LoginState(
                    nonce=nonce,
                    code_challenge=code_challenge,
                    redirect_path=safe_redirect,
                ),
                ttl_seconds=300,
            )
        except Exception as exc:
            raise ServiceUnavailableError(
                "Session store unavailable. Retry later."
            ) from exc

        oidc_cfg = self._get_oidc_config()
        auth_endpoint = oidc_cfg.get("authorization_endpoint", "")
        if not auth_endpoint:
            raise ServiceUnavailableError(
                "IdP discovery document missing authorization_endpoint."
            )

        params = {
            "client_id": self._config.oidc_client_id,
            "redirect_uri": self._config.oidc_redirect_uri,
            "response_type": "code",
            "scope": self._config.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{auth_endpoint}?{urlencode(params)}"

    # -----------------------------------------------------------------------
    # complete_callback
    # -----------------------------------------------------------------------

    def complete_callback(
        self,
        code: str,
        state: str,
        code_verifier: str,
        db_session: Session,
        correlation_id: str = "",
    ) -> tuple[str, UserIdentity]:
        """Exchange code for tokens, verify id_token, upsert user, create session.

        Returns (session_id, UserIdentity).
        Raises AuthError for any authentication failure.
        Raises ServiceUnavailableError for IdP/Redis outages.
        """
        corr = correlation_id or secrets.token_hex(8)

        # 1. Pop login state — atomic, prevents state replay
        try:
            login_state = self._login_states.pop(state)
        except Exception as exc:
            raise ServiceUnavailableError("Session store unavailable. Retry later.") from exc

        if login_state is None:
            self._write_login_failure(db_session, corr, "invalid_state")
            raise AuthError("invalid_state", "Unknown or expired state.", corr)

        # 2. Server-side PKCE verification
        try:
            _validate_pkce_verifier_matches_challenge(code_verifier, login_state.code_challenge)
        except AuthError:
            self._write_login_failure(db_session, corr, "invalid_pkce")
            raise

        # 3. Exchange code for tokens
        token_response = self._exchange_code(code, code_verifier, corr)
        id_token = token_response.get("id_token", "")
        if not id_token:
            self._write_login_failure(db_session, corr, "missing_id_token")
            raise AuthError("invalid_token", "IdP did not return an id_token.", corr)

        # 4. Verify id_token
        try:
            claims = self._verify_id_token(id_token, login_state.nonce, corr)
        except AuthError:
            self._write_login_failure(db_session, corr, "id_token_invalid")
            raise

        # 5. JIT upsert AppUser
        user = self._upsert_user(db_session, claims)

        # 6. Resolve persona from role_binding
        rb_row = db_session.execute(
            select(RoleBinding).where(RoleBinding.app_user_id == user.id)
        ).scalar_one_or_none()

        if rb_row is None:
            self._write_login_failure(db_session, corr, "no_persona_binding")
            raise AccessNotGrantedError(
                "Authentication succeeded but this account has no workspace access. "
                "Contact your administrator to request access."
            )

        # 7. Create Redis session
        now = datetime.now(tz=timezone.utc)
        session_id = secrets.token_urlsafe(32)
        session_data = SessionData(
            session_id=session_id,
            user_id=user.id,
            idp_subject=claims["sub"],
            persona=rb_row.persona,
            workspace_id=rb_row.workspace_id,
            absolute_expires_at=now + timedelta(
                seconds=self._config.session_absolute_lifetime_seconds
            ),
            last_seen_at=now,
        )
        try:
            self._sessions.create(session_data, self._config.session_idle_ttl_seconds)
        except Exception as exc:
            raise ServiceUnavailableError("Session store unavailable. Retry later.") from exc

        # 8. Emit audit event
        self._write_login_success(db_session, user, rb_row.persona, corr)

        identity = UserIdentity(
            user_id=user.id,
            idp_subject=claims["sub"],
            email=user.email,
            display_name=user.display_name,
            persona=rb_row.persona,
            workspace_id=rb_row.workspace_id,
        )
        return session_id, identity

    # -----------------------------------------------------------------------
    # resolve_session / terminate_session
    # -----------------------------------------------------------------------

    def resolve_session(self, session_id: str) -> SessionData | None:
        """Return session data with sliding TTL refresh, or None if expired/missing."""
        try:
            return self._sessions.read(
                session_id, self._config.session_idle_ttl_seconds
            )
        except Exception as exc:
            raise ServiceUnavailableError("Session store unavailable. Retry later.") from exc

    def terminate_session(self, session_id: str) -> None:
        """Delete the session. Idempotent — unknown session IDs are not an error."""
        try:
            self._sessions.delete(session_id)
        except Exception as exc:
            raise ServiceUnavailableError("Session store unavailable. Retry later.") from exc

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _exchange_code(
        self, code: str, code_verifier: str, correlation_id: str
    ) -> dict[str, Any]:
        oidc_cfg = self._get_oidc_config()
        token_endpoint = oidc_cfg.get("token_endpoint", "")
        if not token_endpoint:
            raise ServiceUnavailableError(
                "IdP discovery document missing token_endpoint."
            )
        try:
            resp = self._http.post(  # type: ignore[union-attr]
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self._config.oidc_redirect_uri,
                    "client_id": self._config.oidc_client_id,
                    "client_secret": self._config.oidc_client_secret,
                    "code_verifier": code_verifier,
                },
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            raise ServiceUnavailableError(
                "Token endpoint unavailable. Retry later."
            ) from exc

    def _verify_id_token(
        self, id_token: str, expected_nonce: str, correlation_id: str
    ) -> dict[str, Any]:
        """Verify the id_token signature, claims, and nonce."""
        jwks = self._get_jwks()
        try:
            jwks_obj = pyjwt.PyJWKSet.from_dict(jwks)
            # Get the signing key from the JWKS matching the token's kid header
            header = pyjwt.get_unverified_header(id_token)
            kid = header.get("kid")
            signing_key = None
            for key in jwks_obj.keys:
                if not kid or key.key_id == kid:
                    signing_key = key
                    break
            if signing_key is None:
                raise AuthError("invalid_token", "No matching key in JWKS.", correlation_id)

            claims = pyjwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self._config.oidc_client_id,
                issuer=self._config.oidc_issuer,
                leeway=self._config.oidc_clock_skew_seconds,
                options={"require": ["sub", "iat", "exp", "nonce"]},
            )
        except pyjwt.ExpiredSignatureError as exc:
            raise AuthError("token_expired", "id_token has expired.", correlation_id) from exc
        except pyjwt.InvalidAudienceError as exc:
            raise AuthError("invalid_audience", "id_token audience mismatch.", correlation_id) from exc
        except pyjwt.InvalidIssuerError as exc:
            raise AuthError("invalid_issuer", "id_token issuer mismatch.", correlation_id) from exc
        except (pyjwt.InvalidTokenError, Exception) as exc:
            raise AuthError("invalid_token", "id_token validation failed.", correlation_id) from exc

        if not secrets.compare_digest(claims.get("nonce", ""), expected_nonce):
            raise AuthError("invalid_nonce", "id_token nonce mismatch.", correlation_id)

        return claims

    def _upsert_user(self, db_session: Session, claims: dict[str, Any]) -> AppUser:
        """Insert or update AppUser keyed on idp_subject."""
        idp_subject = claims["sub"]
        now = datetime.now(tz=timezone.utc)

        user = db_session.execute(
            select(AppUser).where(AppUser.idp_subject == idp_subject)
        ).scalar_one_or_none()

        if user is None:
            # Try matching by legacy sub_claim for migrated users
            user = db_session.execute(
                select(AppUser).where(AppUser.sub_claim == idp_subject)
            ).scalar_one_or_none()

        if user is None:
            # New user — find the workspace from the first available workspace
            ws = db_session.execute(select(Workspace).limit(1)).scalar_one_or_none()
            workspace_id = ws.id if ws else uuid.uuid4()
            user = AppUser(
                workspace_id=workspace_id,
                sub_claim=idp_subject,
                idp_subject=idp_subject,
                email=claims.get("email", ""),
                display_name=claims.get("name", claims.get("email", idp_subject)),
                last_login_at=now,
            )
            db_session.add(user)
        else:
            user.idp_subject = idp_subject
            user.last_login_at = now

        db_session.flush()
        return user

    def _write_login_success(
        self,
        db_session: Session,
        user: AppUser,
        persona: str,
        correlation_id: str,
    ) -> None:
        event = AuditEvent(
            actor_id=str(user.id),
            actor_persona=persona,
            resource_type="auth",
            resource_id=str(user.id),
            action="auth.login_success",
            change_detail={
                "persona": persona,
                "workspace_id": str(user.workspace_id),
            },
            correlation_id=correlation_id,
        )
        db_session.add(event)

    def _write_login_failure(
        self,
        db_session: Session,
        correlation_id: str,
        reason: str,
    ) -> None:
        event = AuditEvent(
            actor_id="anonymous",
            actor_persona=None,
            resource_type="auth",
            resource_id=None,
            action="auth.login_failure",
            change_detail={"reason": reason},
            correlation_id=correlation_id,
        )
        db_session.add(event)

    def write_logout_event(
        self,
        db_session: Session,
        user_id: str,
        persona: str | None,
        correlation_id: str = "",
    ) -> None:
        event = AuditEvent(
            actor_id=user_id,
            actor_persona=persona,
            resource_type="auth",
            resource_id=user_id,
            action="auth.logout",
            change_detail={},
            correlation_id=correlation_id or secrets.token_hex(8),
        )
        db_session.add(event)
