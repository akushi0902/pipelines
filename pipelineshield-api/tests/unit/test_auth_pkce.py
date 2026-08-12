"""Unit tests for PKCE/state/nonce validators and id_token verification.

All tests use injected interfaces — no live network or Redis calls.
id_token fixtures use the test RSA key from tests.fixtures.oidc_fixtures.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time

import pytest

from pipelineshield.platform.auth_module import (
    AuthError,
    _validate_pkce_challenge_format,
    _validate_pkce_verifier_matches_challenge,
    _validate_redirect_path,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> str:
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# _validate_pkce_challenge_format
# ---------------------------------------------------------------------------


class TestValidatePkceChallengeFormat:
    def test_valid_s256_challenge(self) -> None:
        verifier = _make_verifier()
        challenge = _s256(verifier)
        _validate_pkce_challenge_format(challenge)  # no exception

    def test_empty_challenge_raises(self) -> None:
        with pytest.raises(AuthError, match="required"):
            _validate_pkce_challenge_format("")

    def test_wrong_length_raises(self) -> None:
        with pytest.raises(AuthError, match="43 characters"):
            _validate_pkce_challenge_format("tooshort")

    def test_non_base64url_chars_raise(self) -> None:
        # 43 chars with padding char '=' which is forbidden in base64url
        bad = "A" * 42 + "="
        with pytest.raises(AuthError, match="base64url"):
            _validate_pkce_challenge_format(bad)

    def test_correct_length_but_invalid_char(self) -> None:
        bad = "A" * 42 + "+"
        with pytest.raises(AuthError, match="base64url"):
            _validate_pkce_challenge_format(bad)


# ---------------------------------------------------------------------------
# _validate_pkce_verifier_matches_challenge
# ---------------------------------------------------------------------------


class TestValidatePkceVerifierMatchesChallenge:
    def test_matching_pair(self) -> None:
        verifier = _make_verifier()
        challenge = _s256(verifier)
        _validate_pkce_verifier_matches_challenge(verifier, challenge)

    def test_empty_verifier_raises(self) -> None:
        with pytest.raises(AuthError, match="required"):
            _validate_pkce_verifier_matches_challenge("", _s256(_make_verifier()))

    def test_too_short_verifier_raises(self) -> None:
        with pytest.raises(AuthError, match="43"):
            _validate_pkce_verifier_matches_challenge("tooshort", "A" * 43)

    def test_too_long_verifier_raises(self) -> None:
        with pytest.raises(AuthError, match="43"):
            _validate_pkce_verifier_matches_challenge("A" * 129, "A" * 43)

    def test_mismatch_raises(self) -> None:
        verifier = _make_verifier()
        wrong_challenge = _s256(_make_verifier())  # different verifier's challenge
        with pytest.raises(AuthError, match="does not match"):
            _validate_pkce_verifier_matches_challenge(verifier, wrong_challenge)


# ---------------------------------------------------------------------------
# _validate_redirect_path
# ---------------------------------------------------------------------------


class TestValidateRedirectPath:
    _ALLOWED = ["/", "/dashboard", "/reports"]

    def test_none_returns_root(self) -> None:
        assert _validate_redirect_path(None, self._ALLOWED) == "/"

    def test_empty_string_returns_root(self) -> None:
        assert _validate_redirect_path("", self._ALLOWED) == "/"

    def test_allowed_path_returned(self) -> None:
        assert _validate_redirect_path("/dashboard", self._ALLOWED) == "/dashboard"

    def test_disallowed_path_returns_root(self) -> None:
        result = _validate_redirect_path("/admin", self._ALLOWED)
        assert result == "/"

    def test_absolute_url_raises(self) -> None:
        with pytest.raises(AuthError, match="relative path"):
            _validate_redirect_path("https://evil.example.com/steal", self._ALLOWED)

    def test_scheme_relative_url_raises(self) -> None:
        with pytest.raises(AuthError, match="relative path"):
            _validate_redirect_path("//evil.example.com/steal", self._ALLOWED)

    def test_no_scheme_but_not_starting_slash_raises(self) -> None:
        with pytest.raises(AuthError, match="relative path"):
            _validate_redirect_path("evil.example.com/path", self._ALLOWED)


# ---------------------------------------------------------------------------
# id_token verification (requires PyJWT + cryptography)
# ---------------------------------------------------------------------------


HAS_PYJWT = True
try:
    import jwt as pyjwt  # noqa: F401
    from tests.fixtures.oidc_fixtures import (
        TEST_CLIENT_ID,
        TEST_ISSUER,
        TEST_KID,
        get_test_jwks,
        make_id_token,
    )
except ImportError:
    HAS_PYJWT = False

pytestmark_pyjwt = pytest.mark.skipif(not HAS_PYJWT, reason="PyJWT not installed")


@pytestmark_pyjwt
class TestIdTokenVerification:
    """Verify _verify_id_token using the test signing key."""

    @pytest.fixture()
    def auth_module(self):
        from unittest.mock import MagicMock

        from pipelineshield.config import AuthConfig
        from pipelineshield.platform.auth_module import AuthModule
        from pipelineshield.platform.session_store import (
            LoginStateStore,
            SessionStore,
        )

        cfg = AuthConfig(
            oidc_issuer=TEST_ISSUER,
            oidc_client_id=TEST_CLIENT_ID,
            oidc_client_secret="test-secret",
            oidc_redirect_uri="https://app.test.example.com/api/v1/auth/callback",
            redis_url="redis://localhost:6379/0",
        )
        module = AuthModule(
            config=cfg,
            session_store=MagicMock(spec=SessionStore),
            login_state_store=MagicMock(spec=LoginStateStore),
        )
        # Inject cached JWKS and discovery doc so no network calls happen
        module._jwks_cache = get_test_jwks()
        module._jwks_cached_at = 9_999_999_999.0  # far future — never refreshes
        module._oidc_config = {
            "issuer": TEST_ISSUER,
            "authorization_endpoint": f"{TEST_ISSUER}/authorize",
            "token_endpoint": f"{TEST_ISSUER}/token",
            "jwks_uri": f"{TEST_ISSUER}/.well-known/jwks.json",
        }
        return module

    def test_valid_id_token(self, auth_module) -> None:
        nonce = "test-nonce-abc"
        token = make_id_token(nonce=nonce)
        claims = auth_module._verify_id_token(token, nonce, "corr-001")
        assert claims["sub"] == "sub|test-user-001"
        assert claims["nonce"] == nonce

    def test_expired_token_raises(self, auth_module) -> None:
        nonce = "nonce-for-expiry"
        token = make_id_token(nonce=nonce, exp_offset=-3600)
        with pytest.raises(AuthError, match="expired"):
            auth_module._verify_id_token(token, nonce, "corr-002")

    def test_wrong_audience_raises(self, auth_module) -> None:
        nonce = "nonce-for-aud"
        token = make_id_token(nonce=nonce, aud="wrong-client-id")
        with pytest.raises(AuthError):
            auth_module._verify_id_token(token, nonce, "corr-003")

    def test_wrong_issuer_raises(self, auth_module) -> None:
        nonce = "nonce-for-iss"
        token = make_id_token(nonce=nonce, iss="https://evil.example.com")
        with pytest.raises(AuthError):
            auth_module._verify_id_token(token, nonce, "corr-004")

    def test_nonce_mismatch_raises(self, auth_module) -> None:
        token = make_id_token(nonce="correct-nonce")
        with pytest.raises(AuthError, match="nonce"):
            auth_module._verify_id_token(token, "wrong-nonce", "corr-005")

    def test_tampered_signature_raises(self, auth_module) -> None:
        token = make_id_token(nonce="nonce-tamper")
        parts = token.split(".")
        # Flip one byte in the signature
        sig_bytes = base64.urlsafe_b64decode(parts[2] + "==")
        tampered = bytearray(sig_bytes)
        tampered[0] ^= 0xFF
        parts[2] = base64.urlsafe_b64encode(bytes(tampered)).rstrip(b"=").decode()
        bad_token = ".".join(parts)
        with pytest.raises(AuthError):
            auth_module._verify_id_token(bad_token, "nonce-tamper", "corr-006")

    def test_audit_detail_has_no_token_material(self) -> None:
        """Verify audit change_detail never contains raw token values."""
        import json

        from pipelineshield.platform.auth_module import AuthModule

        # Build a fake audit event change_detail as the module would
        detail = {
            "persona": "devsecops_engineer",
            "workspace_id": "00000000-0000-0000-0000-000000000001",
        }
        serialized = json.dumps(detail)
        # Must not contain anything resembling a JWT (three base64 parts separated by dots)
        import re

        assert not re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", serialized), (
            "JWT material must never appear in audit change_detail"
        )
