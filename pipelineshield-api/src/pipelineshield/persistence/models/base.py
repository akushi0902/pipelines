"""SQLAlchemy 2.0 DeclarativeBase and shared metadata."""
from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Explicit naming convention for constraints so Alembic can generate
# deterministic migration names for ALTER TABLE operations.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Base(DeclarativeBase):
    """Project-wide declarative base.

    All models inherit from this class.  The shared metadata instance ensures
    Alembic's autogenerate can discover all tables in a single pass.
    """

    metadata = metadata
