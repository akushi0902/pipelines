"""Pytest configuration and shared fixtures.

The PIPELINE_SHIELD_DEF_KEY environment variable is set to a test value for
all unit tests so that EnvKeyProvider instantiation succeeds without external
key material.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True, scope="session")
def set_test_encryption_key():
    """Ensure PIPELINE_SHIELD_DEF_KEY is set for all tests."""
    original = os.environ.get("PIPELINE_SHIELD_DEF_KEY")
    if not original:
        os.environ["PIPELINE_SHIELD_DEF_KEY"] = "test-only-passphrase-do-not-use-in-prod"
    yield
    if not original:
        os.environ.pop("PIPELINE_SHIELD_DEF_KEY", None)
