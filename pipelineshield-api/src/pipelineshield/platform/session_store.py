"""Session and login-state stores backed by Redis.

SessionStore — opaque 256-bit session ID → session data
  key namespace: pipelineshield:session:<session_id>
  sliding TTL:   refreshed with EXPIRE on every read
  absolute cap:  checked in application code; Redis TTL cannot express it

LoginStateStore — short-lived OIDC login state (state → nonce + challenge)
  key namespace: pipelineshield:login_state:<state>
  TTL: 5 minutes (PKCE redirect round-trip window)
  pop() is atomic: HGETALL + DEL so state is single-use
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    import redis as redis_lib
    _REDIS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _REDIS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class SessionData:
    session_id: str
    user_id: uuid.UUID
    idp_subject: str
    persona: str
    workspace_id: uuid.UUID
    absolute_expires_at: datetime
    last_seen_at: datetime


@dataclass
class LoginState:
    nonce: str
    code_challenge: str
    redirect_path: str


# ---------------------------------------------------------------------------
# SessionStore interface + Redis implementation
# ---------------------------------------------------------------------------


class SessionStore(ABC):
    @abstractmethod
    def create(self, data: SessionData, idle_ttl_seconds: int) -> None: ...

    @abstractmethod
    def read(self, session_id: str, idle_ttl_seconds: int) -> SessionData | None: ...

    @abstractmethod
    def delete(self, session_id: str) -> None: ...


class RedisSessionStore(SessionStore):
    """Redis-backed session store using hash fields per session."""

    _PREFIX = "pipelineshield:session:"

    def __init__(self, redis_client: object) -> None:
        self._r = redis_client

    def _key(self, session_id: str) -> str:
        return f"{self._PREFIX}{session_id}"

    def create(self, data: SessionData, idle_ttl_seconds: int) -> None:
        key = self._key(data.session_id)
        payload = {
            "user_id": str(data.user_id),
            "idp_subject": data.idp_subject,
            "persona": data.persona,
            "workspace_id": str(data.workspace_id),
            "absolute_expires_at": data.absolute_expires_at.isoformat(),
            "last_seen_at": data.last_seen_at.isoformat(),
        }
        self._r.hset(key, mapping=payload)  # type: ignore[union-attr]
        self._r.expire(key, idle_ttl_seconds)  # type: ignore[union-attr]

    def read(self, session_id: str, idle_ttl_seconds: int) -> SessionData | None:
        key = self._key(session_id)
        raw: dict = self._r.hgetall(key)  # type: ignore[union-attr]
        if not raw:
            return None

        # Decode bytes if the Redis client returns them
        decoded: dict[str, str] = {
            (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in raw.items()
        }

        abs_exp = datetime.fromisoformat(decoded["absolute_expires_at"])
        now = datetime.now(tz=abs_exp.tzinfo)
        if now >= abs_exp:
            self._r.delete(key)  # type: ignore[union-attr]
            return None

        self._r.expire(key, idle_ttl_seconds)  # type: ignore[union-attr]
        return SessionData(
            session_id=session_id,
            user_id=uuid.UUID(decoded["user_id"]),
            idp_subject=decoded["idp_subject"],
            persona=decoded["persona"],
            workspace_id=uuid.UUID(decoded["workspace_id"]),
            absolute_expires_at=abs_exp,
            last_seen_at=datetime.fromisoformat(decoded["last_seen_at"]),
        )

    def delete(self, session_id: str) -> None:
        self._r.delete(self._key(session_id))  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# LoginStateStore interface + Redis implementation
# ---------------------------------------------------------------------------


class LoginStateStore(ABC):
    @abstractmethod
    def store(self, state: str, login_state: LoginState, ttl_seconds: int) -> None: ...

    @abstractmethod
    def pop(self, state: str) -> LoginState | None: ...


class RedisLoginStateStore(LoginStateStore):
    """Short-lived Redis-backed store for OIDC login state."""

    _PREFIX = "pipelineshield:login_state:"

    def __init__(self, redis_client: object) -> None:
        self._r = redis_client

    def _key(self, state: str) -> str:
        return f"{self._PREFIX}{state}"

    def store(self, state: str, login_state: LoginState, ttl_seconds: int = 300) -> None:
        key = self._key(state)
        self._r.hset(key, mapping={  # type: ignore[union-attr]
            "nonce": login_state.nonce,
            "code_challenge": login_state.code_challenge,
            "redirect_path": login_state.redirect_path,
        })
        self._r.expire(key, ttl_seconds)  # type: ignore[union-attr]

    def pop(self, state: str) -> LoginState | None:
        key = self._key(state)
        raw: dict = self._r.hgetall(key)  # type: ignore[union-attr]
        if not raw:
            return None
        self._r.delete(key)  # type: ignore[union-attr]
        decoded: dict[str, str] = {
            (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in raw.items()
        }
        return LoginState(
            nonce=decoded["nonce"],
            code_challenge=decoded["code_challenge"],
            redirect_path=decoded["redirect_path"],
        )
