"""Dialect-aware SQLAlchemy column types.

DialectJSON renders as JSONB on PostgreSQL (index-able, GIN-friendly) and as
the standard JSON type on SQLite — both behave identically for read-back
equality assertions and checksum comparison.
"""
from __future__ import annotations

from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator


class DialectJSON(TypeDecorator):
    """JSONB on PostgreSQL, JSON everywhere else.

    Using TypeDecorator + load_dialect_impl is the correct SQLAlchemy 2.0
    pattern for dialect-specific type selection without conditional imports
    at column definition time.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):  # type: ignore[override]
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())
