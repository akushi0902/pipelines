"""Baseline seed data fixture.

Creates the minimum set of rows needed for downstream stories to run without
external dependencies:
  - 1 workspace ("PipelineShield Demo")
  - 4 persona role_bindings (one per development persona)
  - 1 sample_pipeline (GitHub Actions demo)

Usage:
    from tests.fixtures.seed_baseline import seed_baseline
    seed_baseline(session)  # pass a SQLAlchemy Session

The seed is idempotent — running it twice against the same database does
not create duplicate rows (it checks for existing data before inserting).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from pipelineshield.persistence.models.workspace import Workspace
from pipelineshield.persistence.models.app_user import AppUser
from pipelineshield.persistence.models.role_binding import RoleBinding
from pipelineshield.persistence.models.sample_pipeline import SamplePipeline

# Stable UUIDs so the seed is repeatable and foreign-key references work
# across stories without needing to look up generated values.
WORKSPACE_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
USERS = {
    "app_developer": uuid.UUID("00000000-0000-0000-0001-000000000001"),
    "devops_engineer": uuid.UUID("00000000-0000-0000-0001-000000000002"),
    "devsecops_engineer": uuid.UUID("00000000-0000-0000-0001-000000000003"),
    "engineering_manager": uuid.UUID("00000000-0000-0000-0001-000000000004"),
    "appsec_lead": uuid.UUID("00000000-0000-0000-0001-000000000005"),
}
SAMPLE_PIPELINE_ID = uuid.UUID("00000000-0000-0000-0002-000000000001")

_SAMPLE_GITHUB_ACTIONS = """\
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: pip install -e .[dev]
      - name: Run tests
        run: pytest
"""


def seed_baseline(session: Session) -> dict[str, object]:
    """Insert baseline seed data into the database.

    Returns a dict with the created (or existing) IDs so callers can
    reference them in downstream fixtures.

    This function is idempotent: if the workspace already exists, it
    skips creation and returns the existing IDs.
    """
    from sqlalchemy import select

    # Check if already seeded.
    existing_ws = session.execute(
        select(Workspace).where(Workspace.id == WORKSPACE_ID)
    ).scalar_one_or_none()

    if existing_ws is not None:
        return {
            "workspace_id": WORKSPACE_ID,
            "user_ids": USERS,
            "sample_pipeline_id": SAMPLE_PIPELINE_ID,
        }

    # 1. Create workspace.
    workspace = Workspace(
        id=WORKSPACE_ID,
        name="PipelineShield Demo",
        slug="pipelineshield-demo",
    )
    session.add(workspace)

    # 2. Create one AppUser per persona.
    persona_data = [
        (
            "app_developer",
            "sub|app_developer_demo",
            "priya.dev@example.com",
            "Priya (App Developer)",
        ),
        (
            "devops_engineer",
            "sub|devops_demo",
            "alex.ops@example.com",
            "Alex (DevOps Engineer)",
        ),
        (
            "devsecops_engineer",
            "sub|devsecops_demo",
            "sam.sec@example.com",
            "Sam (DevSecOps Engineer)",
        ),
        (
            "engineering_manager",
            "sub|manager_demo",
            "morgan.mgr@example.com",
            "Morgan (Engineering Manager)",
        ),
        (
            "appsec_lead",
            "sub|appsec_demo",
            "jordan.sec@example.com",
            "Jordan (AppSec Lead)",
        ),
    ]

    for persona, sub, email, display_name in persona_data:
        user = AppUser(
            id=USERS[persona],
            workspace_id=WORKSPACE_ID,
            sub_claim=sub,
            email=email,
            display_name=display_name,
        )
        session.add(user)

        binding = RoleBinding(
            workspace_id=WORKSPACE_ID,
            app_user_id=USERS[persona],
            persona=persona,
        )
        session.add(binding)

    # 3. Create one sample GitHub Actions pipeline.
    sample = SamplePipeline(
        id=SAMPLE_PIPELINE_ID,
        workspace_id=WORKSPACE_ID,
        name="Demo GitHub Actions CI",
        pipeline_format="github_actions",
        description=(
            "A minimal GitHub Actions workflow demonstrating the controls "
            "that PipelineShield evaluates.  Used for offline development "
            "and as a known-good baseline in integration tests."
        ),
        content=_SAMPLE_GITHUB_ACTIONS,
    )
    session.add(sample)

    session.flush()

    return {
        "workspace_id": WORKSPACE_ID,
        "user_ids": USERS,
        "sample_pipeline_id": SAMPLE_PIPELINE_ID,
    }
