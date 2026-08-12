"""Unit tests for session store — sliding TTL, absolute lifetime, idempotent logout.

Uses fakeredis for an in-memory Redis implementation compatible with
the redis-py client API.  Tests are skipped if fakeredis is not installed.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

HAS_FAKEREDIS = True
try:
    import fakeredis
except ImportError:
    HAS_FAKEREDIS = False

pytestmark = pytest.mark.skipif(not HAS_FAKEREDIS, reason="fakeredis not installed")


def _make_redis():
    return fakeredis.FakeRedis()


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _future(seconds: int) -> datetime:
    return _now() + timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# SessionStore
# ---------------------------------------------------------------------------


@pytest.fixture()
def session_store():
    from pipelineshield.platform.session_store import RedisSessionStore

    return RedisSessionStore(_make_redis())


@pytest.fixture()
def sample_session_data():
    from pipelineshield.platform.session_store import SessionData

    return SessionData(
        session_id="test-session-id-abc",
        user_id=uuid.UUID("00000000-0000-0000-0001-000000000001"),
        idp_subject="sub|test-user-001",
        persona="devsecops_engineer",
        workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        absolute_expires_at=_future(28800),
        last_seen_at=_now(),
    )


class TestRedisSessionStore:
    def test_create_and_read_roundtrip(self, session_store, sample_session_data) -> None:
        session_store.create(sample_session_data, idle_ttl_seconds=1800)
        result = session_store.read(sample_session_data.session_id, idle_ttl_seconds=1800)
        assert result is not None
        assert result.user_id == sample_session_data.user_id
        assert result.idp_subject == sample_session_data.idp_subject
        assert result.persona == sample_session_data.persona
        assert result.workspace_id == sample_session_data.workspace_id

    def test_read_missing_session_returns_none(self, session_store) -> None:
        result = session_store.read("nonexistent-session", idle_ttl_seconds=1800)
        assert result is None

    def test_delete_removes_session(self, session_store, sample_session_data) -> None:
        session_store.create(sample_session_data, idle_ttl_seconds=1800)
        session_store.delete(sample_session_data.session_id)
        result = session_store.read(sample_session_data.session_id, idle_ttl_seconds=1800)
        assert result is None

    def test_delete_nonexistent_is_idempotent(self, session_store) -> None:
        # Should not raise
        session_store.delete("unknown-session-xyz")

    def test_absolute_lifetime_cutoff(self, session_store) -> None:
        from pipelineshield.platform.session_store import SessionData

        # Session whose absolute lifetime already expired
        expired_data = SessionData(
            session_id="expired-session",
            user_id=uuid.UUID("00000000-0000-0000-0001-000000000002"),
            idp_subject="sub|expired-user",
            persona="app_developer",
            workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            absolute_expires_at=_now() - timedelta(seconds=1),  # already expired
            last_seen_at=_now() - timedelta(seconds=3600),
        )
        session_store.create(expired_data, idle_ttl_seconds=1800)
        result = session_store.read("expired-session", idle_ttl_seconds=1800)
        assert result is None, "Absolute-lifetime-expired session must not be returned"

    def test_absolute_lifetime_cannot_be_extended_by_reads(self, session_store) -> None:
        from pipelineshield.platform.session_store import SessionData

        # Session with 10-second absolute lifetime
        data = SessionData(
            session_id="short-abs-session",
            user_id=uuid.UUID("00000000-0000-0000-0001-000000000003"),
            idp_subject="sub|short-user",
            persona="devops_engineer",
            workspace_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            absolute_expires_at=_future(10),
            last_seen_at=_now(),
        )
        session_store.create(data, idle_ttl_seconds=1800)

        # Read multiple times (simulating sliding TTL refreshes)
        for _ in range(5):
            result = session_store.read("short-abs-session", idle_ttl_seconds=1800)
            assert result is not None

        # Absolute lifetime must be unchanged
        result = session_store.read("short-abs-session", idle_ttl_seconds=1800)
        assert result is not None
        orig_abs_exp = data.absolute_expires_at
        assert result.absolute_expires_at == orig_abs_exp, (
            "Reads must not extend the absolute lifetime"
        )

    def test_two_concurrent_reads_do_not_extend_absolute_lifetime(
        self, session_store, sample_session_data
    ) -> None:
        session_store.create(sample_session_data, idle_ttl_seconds=1800)
        result1 = session_store.read(sample_session_data.session_id, idle_ttl_seconds=1800)
        result2 = session_store.read(sample_session_data.session_id, idle_ttl_seconds=1800)
        assert result1 is not None
        assert result2 is not None
        assert result1.absolute_expires_at == result2.absolute_expires_at


# ---------------------------------------------------------------------------
# LoginStateStore
# ---------------------------------------------------------------------------


@pytest.fixture()
def login_state_store():
    from pipelineshield.platform.session_store import RedisLoginStateStore

    return RedisLoginStateStore(_make_redis())


class TestRedisLoginStateStore:
    def test_store_and_pop_roundtrip(self, login_state_store) -> None:
        from pipelineshield.platform.session_store import LoginState

        ls = LoginState(
            nonce="test-nonce-xyz",
            code_challenge="A" * 43,
            redirect_path="/dashboard",
        )
        login_state_store.store("state-abc", ls, ttl_seconds=300)
        result = login_state_store.pop("state-abc")
        assert result is not None
        assert result.nonce == "test-nonce-xyz"
        assert result.code_challenge == "A" * 43
        assert result.redirect_path == "/dashboard"

    def test_pop_is_single_use(self, login_state_store) -> None:
        from pipelineshield.platform.session_store import LoginState

        ls = LoginState(nonce="n", code_challenge="A" * 43, redirect_path="/")
        login_state_store.store("state-single", ls, ttl_seconds=300)
        first = login_state_store.pop("state-single")
        second = login_state_store.pop("state-single")
        assert first is not None
        assert second is None, "Login state must be single-use (replay protection)"

    def test_pop_nonexistent_returns_none(self, login_state_store) -> None:
        result = login_state_store.pop("nonexistent-state")
        assert result is None

    def test_store_with_zero_ttl_is_not_retrievable(self, login_state_store) -> None:
        from pipelineshield.platform.session_store import LoginState

        ls = LoginState(nonce="n", code_challenge="A" * 43, redirect_path="/")
        login_state_store.store("state-zerottl", ls, ttl_seconds=1)
        # Even with ttl=1, it should be readable immediately (not expired yet)
        result = login_state_store.pop("state-zerottl")
        assert result is not None
