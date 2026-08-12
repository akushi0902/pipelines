"""Integration tests for /api/v1/auth endpoints.

All tests use FastAPI TestClient with injected deps — no live Redis or IdP.
Session store and AuthModule are backed by in-process fakes.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# ---------------------------------------------------------------------------
# Optional deps guard
# ---------------------------------------------------------------------------

HAS_PYJWT = True
try:
    import jwt as pyjwt  # noqa: F401
    import fakeredis  # noqa: F401
except ImportError:
    HAS_PYJWT = False

pytestmark = pytest.mark.skipif(
    not HAS_PYJWT, reason="PyJWT and fakeredis required for auth tests"
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
# Test app factory with dep overrides
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine():
    from pipelineshield.persistence.models import Base

    _engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(_engine)
    return _engine


@pytest.fixture()
def db_session(engine):
    _Session = sessionmaker(bind=engine)
    session = _Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@pytest.fixture(scope="module")
def seeded_engine(engine):
    _Session = sessionmaker(bind=engine)
    with _Session() as session:
        from tests.fixtures.seed_baseline import seed_baseline
        seed_baseline(session)
        session.commit()
    return engine


@pytest.fixture(scope="module")
def test_auth_module():
    """An AuthModule with pre-seeded JWKS and discovery doc, fakeredis for state stores."""
    from tests.fixtures.oidc_fixtures import (
        TEST_CLIENT_ID,
        TEST_ISSUER,
        get_test_jwks,
        make_discovery_doc,
    )

    from pipelineshield.config import AuthConfig
    from pipelineshield.platform.auth_module import AuthModule
    from pipelineshield.platform.session_store import (
        RedisLoginStateStore,
        RedisSessionStore,
    )

    redis_client = fakeredis.FakeRedis()
    cfg = AuthConfig(
        oidc_issuer=TEST_ISSUER,
        oidc_client_id=TEST_CLIENT_ID,
        oidc_client_secret="test-secret",
        oidc_redirect_uri="https://app.test.example.com/api/v1/auth/callback",
        redis_url="redis://localhost:6379/0",
        session_allowed_redirect_paths=["/", "/dashboard", "/reports"],
    )
    module = AuthModule(
        config=cfg,
        session_store=RedisSessionStore(redis_client),
        login_state_store=RedisLoginStateStore(redis_client),
    )
    module._oidc_config = make_discovery_doc()
    module._jwks_cache = get_test_jwks()
    module._jwks_cached_at = 9_999_999_999.0
    return module


@pytest.fixture()
def app(seeded_engine, test_auth_module):
    from pipelineshield.api.main import create_app
    from pipelineshield.api.v1.routers.auth_router import get_auth_module, get_db

    _app = create_app()
    _Session = sessionmaker(bind=seeded_engine)

    def _get_db():
        session = _Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    _app.dependency_overrides[get_db] = _get_db
    _app.dependency_overrides[get_auth_module] = lambda: test_auth_module
    return _app


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# GET /api/v1/auth/login
# ---------------------------------------------------------------------------


class TestBeginLogin:
    def test_returns_302_to_idp(self, client) -> None:
        verifier = _make_verifier()
        challenge = _s256(verifier)
        resp = client.get(
            f"/api/v1/auth/login?code_challenge={challenge}",
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "idp.test.example.com/authorize" in location
        assert "code_challenge=" in location
        assert "code_challenge_method=S256" in location
        assert "state=" in location
        assert "nonce=" in location

    def test_redirect_includes_client_id(self, client) -> None:
        verifier = _make_verifier()
        challenge = _s256(verifier)
        resp = client.get(
            f"/api/v1/auth/login?code_challenge={challenge}",
            follow_redirects=False,
        )
        assert "pipelineshield-test-client" in resp.headers["location"]

    def test_invalid_challenge_format_returns_400(self, client) -> None:
        resp = client.get(
            "/api/v1/auth/login?code_challenge=tooshort",
            follow_redirects=False,
        )
        assert resp.status_code == 400

    def test_open_redirect_rejected(self, client) -> None:
        verifier = _make_verifier()
        challenge = _s256(verifier)
        resp = client.get(
            f"/api/v1/auth/login?code_challenge={challenge}&redirect=https://evil.com",
            follow_redirects=False,
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /api/v1/auth/callback
# ---------------------------------------------------------------------------


class TestCompleteCallback:
    def _do_login_and_get_state(self, client) -> tuple[str, str]:
        """Begin a login flow and extract state from the redirect URL."""
        from urllib.parse import parse_qs, urlparse

        verifier = _make_verifier()
        challenge = _s256(verifier)
        resp = client.get(
            f"/api/v1/auth/login?code_challenge={challenge}",
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        parsed = urlparse(location)
        params = parse_qs(parsed.query)
        state = params["state"][0]
        nonce = params["nonce"][0]
        return state, nonce, verifier

    def _mock_token_exchange(self, test_auth_module, nonce: str) -> str:
        """Build an id_token for the given nonce and inject a fake token exchange."""
        from tests.fixtures.oidc_fixtures import (
            TEST_CLIENT_ID,
            TEST_ISSUER,
            make_id_token,
        )

        id_token = make_id_token(
            sub="sub|devsecops_demo",
            email="sam.sec@example.com",
            name="Sam (DevSecOps Engineer)",
            nonce=nonce,
        )
        return id_token

    def test_valid_callback_returns_200_and_sets_cookie(
        self, client, test_auth_module
    ) -> None:
        state, nonce, verifier = self._do_login_and_get_state(client)
        id_token = self._mock_token_exchange(test_auth_module, nonce)

        with patch.object(
            test_auth_module,
            "_exchange_code",
            return_value={"id_token": id_token, "access_token": "REDACTED"},
        ):
            resp = client.post(
                "/api/v1/auth/callback",
                json={"code": "test-code", "state": state, "code_verifier": verifier},
            )

        assert resp.status_code == 200
        assert "pipelineshield_session" in resp.cookies
        body = resp.json()
        assert body["persona"] == "devsecops_engineer"
        assert "id_token" not in body
        assert "access_token" not in body

    def test_invalid_state_returns_401(self, client) -> None:
        verifier = _make_verifier()
        resp = client.post(
            "/api/v1/auth/callback",
            json={"code": "test-code", "state": "completely-wrong-state", "code_verifier": verifier},
        )
        assert resp.status_code == 401
        body = resp.json()
        assert "correlation_id" in body
        assert "detail" in body

    def test_wrong_nonce_returns_401(self, client, test_auth_module) -> None:
        state, nonce, verifier = self._do_login_and_get_state(client)
        id_token = self._mock_token_exchange(test_auth_module, "wrong-nonce-xyz")

        with patch.object(
            test_auth_module,
            "_exchange_code",
            return_value={"id_token": id_token},
        ):
            resp = client.post(
                "/api/v1/auth/callback",
                json={"code": "test-code", "state": state, "code_verifier": verifier},
            )

        assert resp.status_code == 401

    def test_pkce_verifier_mismatch_returns_401(self, client) -> None:
        state, nonce, verifier = self._do_login_and_get_state(client)
        wrong_verifier = _make_verifier()
        resp = client.post(
            "/api/v1/auth/callback",
            json={"code": "test-code", "state": state, "code_verifier": wrong_verifier},
        )
        assert resp.status_code == 401

    def test_reused_state_returns_401(self, client, test_auth_module) -> None:
        state, nonce, verifier = self._do_login_and_get_state(client)
        id_token = self._mock_token_exchange(test_auth_module, nonce)

        with patch.object(
            test_auth_module,
            "_exchange_code",
            return_value={"id_token": id_token},
        ):
            r1 = client.post(
                "/api/v1/auth/callback",
                json={"code": "test-code", "state": state, "code_verifier": verifier},
            )
            # Replay the same state
            r2 = client.post(
                "/api/v1/auth/callback",
                json={"code": "test-code", "state": state, "code_verifier": verifier},
            )

        assert r1.status_code == 200
        assert r2.status_code == 401

    def test_error_body_has_no_stack_trace(self, client) -> None:
        verifier = _make_verifier()
        resp = client.post(
            "/api/v1/auth/callback",
            json={"code": "test-code", "state": "bad-state", "code_verifier": verifier},
        )
        body = resp.json()
        assert "traceback" not in str(body).lower()
        assert "File " not in str(body)

    def test_no_token_material_in_error_body(self, client) -> None:
        verifier = _make_verifier()
        resp = client.post(
            "/api/v1/auth/callback",
            json={"code": "test-code", "state": "bad-state", "code_verifier": verifier},
        )
        raw = resp.text
        import re
        assert not re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", raw), (
            "JWT material must not appear in error body"
        )


# ---------------------------------------------------------------------------
# GET /api/v1/auth/session
# ---------------------------------------------------------------------------


class TestGetSession:
    def _create_session(self, test_auth_module) -> str:
        """Directly inject a session into the session store."""
        from pipelineshield.platform.session_store import SessionData

        session_id = secrets.token_urlsafe(32)
        data = SessionData(
            session_id=session_id,
            user_id=uuid.UUID("00000000-0000-0000-0001-000000000003"),
            idp_subject="sub|devsecops_demo",
            persona="devsecops_engineer",
            workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            absolute_expires_at=datetime.now(tz=timezone.utc) + timedelta(hours=8),
            last_seen_at=datetime.now(tz=timezone.utc),
        )
        test_auth_module._sessions.create(data, idle_ttl_seconds=1800)
        return session_id

    def test_valid_session_returns_200(self, client, test_auth_module) -> None:
        session_id = self._create_session(test_auth_module)
        resp = client.get(
            "/api/v1/auth/session",
            cookies={"pipelineshield_session": session_id},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["persona"] == "devsecops_engineer"
        assert body["remaining_idle_seconds"] >= 0
        assert "absolute_expires_at" in body

    def test_no_cookie_returns_401(self, client) -> None:
        resp = client.get("/api/v1/auth/session")
        assert resp.status_code == 401

    def test_unknown_session_returns_401(self, client) -> None:
        resp = client.get(
            "/api/v1/auth/session",
            cookies={"pipelineshield_session": "nonexistent-session-id"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/v1/auth/logout
# ---------------------------------------------------------------------------


class TestLogout:
    def _create_session(self, test_auth_module) -> str:
        from pipelineshield.platform.session_store import SessionData

        session_id = secrets.token_urlsafe(32)
        data = SessionData(
            session_id=session_id,
            user_id=uuid.UUID("00000000-0000-0000-0001-000000000003"),
            idp_subject="sub|devsecops_demo",
            persona="devsecops_engineer",
            workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            absolute_expires_at=datetime.now(tz=timezone.utc) + timedelta(hours=8),
            last_seen_at=datetime.now(tz=timezone.utc),
        )
        test_auth_module._sessions.create(data, idle_ttl_seconds=1800)
        return session_id

    def test_logout_returns_204(self, client, test_auth_module) -> None:
        session_id = self._create_session(test_auth_module)
        resp = client.post(
            "/api/v1/auth/logout",
            cookies={"pipelineshield_session": session_id},
        )
        assert resp.status_code == 204

    def test_session_invalid_after_logout(self, client, test_auth_module) -> None:
        session_id = self._create_session(test_auth_module)
        client.post(
            "/api/v1/auth/logout",
            cookies={"pipelineshield_session": session_id},
        )
        # Replaying the old cookie must return 401
        resp = client.get(
            "/api/v1/auth/session",
            cookies={"pipelineshield_session": session_id},
        )
        assert resp.status_code == 401, "Revoked session must not be accepted"

    def test_logout_clears_cookie(self, client, test_auth_module) -> None:
        session_id = self._create_session(test_auth_module)
        resp = client.post(
            "/api/v1/auth/logout",
            cookies={"pipelineshield_session": session_id},
        )
        assert resp.status_code == 204
        # Cookie should be cleared (either absent or empty-valued)
        session_cookie = resp.cookies.get("pipelineshield_session", "")
        assert not session_cookie

    def test_logout_with_no_cookie_is_idempotent(self, client) -> None:
        resp = client.post("/api/v1/auth/logout")
        assert resp.status_code == 204

    def test_logout_with_unknown_session_is_idempotent(self, client) -> None:
        resp = client.post(
            "/api/v1/auth/logout",
            cookies={"pipelineshield_session": "totally-unknown-session"},
        )
        assert resp.status_code == 204
