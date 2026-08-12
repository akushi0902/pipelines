"""Database engine and session factory.

Connection pool settings per architecture:
- pool_size: 10 per worker
- pool_pre_ping: True
- acquire timeout: 5 seconds
- statement timeout: 30 seconds

DATABASE_URL is injected at runtime from the environment.  No credentials
are hardcoded or stored in configuration files.
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set.  "
            "Configure it before starting the service."
        )
    return url


def create_engine_from_env(
    *,
    pool_size: int = 10,
    max_overflow: int = 5,
    pool_pre_ping: bool = True,
    connect_args: dict | None = None,  # type: ignore[type-arg]
) -> Engine:
    """Create a SQLAlchemy engine with the recommended pool settings."""
    if connect_args is None:
        # 5-second acquire timeout; 30-second statement timeout enforced
        # server-side.
        connect_args = {
            "connect_timeout": 5,
            "options": "-c statement_timeout=30000",
        }

    engine = create_engine(
        _get_database_url(),
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=pool_pre_ping,
        connect_args=connect_args,
    )
    return engine


def make_session_factory(
    engine: Engine,
) -> sessionmaker[Session]:
    """Return a configured session factory bound to *engine*.

    Uses SQLAlchemy 2.0 style — no autocommit parameter (removed in 2.0;
    the session always uses autobegin mode).
    """
    return sessionmaker(engine, autoflush=False)
