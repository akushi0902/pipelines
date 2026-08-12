"""Alembic environment configuration.

Database URL is injected from DATABASE_URL environment variable, OR may be
set programmatically before invoking alembic commands (e.g. in test fixtures
via ``alembic_cfg.set_main_option("sqlalchemy.url", url)``).

Priority:
  1. URL already set in the Config object (e.g. by a test fixture).
  2. DATABASE_URL environment variable.
  3. RuntimeError — service refuses to start without a URL.

Never hardcode credentials here.
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Import the models metadata so autogenerate can detect changes.
from pipelineshield.persistence.models import metadata as target_metadata  # noqa: F401

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Resolve the database URL:
#   1. If already set programmatically (e.g. by a test fixture via
#      alembic_cfg.set_main_option), use it — do NOT overwrite with the
#      environment variable, because the test may intentionally point at a
#      different database than DATABASE_URL.
#   2. Otherwise fall back to DATABASE_URL from the OS environment.
#
# The alembic.ini placeholder ``${DATABASE_URL}`` is NOT auto-interpolated
# by Alembic's ConfigParser; it remains as a literal string until the env.py
# replaces it here.
_configured_url = config.get_main_option("sqlalchemy.url")
if _configured_url and "${" not in _configured_url:
    # URL already contains a real DSN — honour it.
    pass
else:
    _env_url = os.environ.get("DATABASE_URL")
    if not _env_url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Set it to a valid PostgreSQL DSN before running Alembic."
        )
    config.set_main_option("sqlalchemy.url", _env_url)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine, though
    an Engine is acceptable here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate a connection
    with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),  # type: ignore[arg-type]
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
