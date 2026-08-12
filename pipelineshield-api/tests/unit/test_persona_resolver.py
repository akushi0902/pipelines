"""Unit tests for PersonaResolver.

Tests:
- Single group maps to the expected persona.
- Multi-group conflicting claims: lower precedence wins.
- Tie-break: lower precedence equal → persona alphabetical order.
- Unmapped group: returns None + trace with groups_seen populated.
- Empty group list: returns None + empty trace.
- Resolution trace records groups_seen, mapping applied, and persona granted.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.group_persona_mapping import GroupPersonaMapping
from pipelineshield.persistence.models.workspace import Workspace
from pipelineshield.platform.persona_resolver import PersonaResolver


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s
        s.rollback()


WORKSPACE_ID = uuid.UUID("00000000-0000-0000-0099-000000000001")
OTHER_WORKSPACE_ID = uuid.UUID("00000000-0000-0000-0099-000000000002")


@pytest.fixture(autouse=True, scope="module")
def seed_data(engine):
    with Session(engine) as s:
        ws = Workspace(id=WORKSPACE_ID, name="Test WS", slug="test-ws")
        ws2 = Workspace(id=OTHER_WORKSPACE_ID, name="Other WS", slug="other-ws")
        s.add(ws)
        s.add(ws2)

        mappings = [
            GroupPersonaMapping(
                id=uuid.uuid4(),
                idp_group="platform-team",
                workspace_id=WORKSPACE_ID,
                persona="devops_engineer",
                precedence=100,
            ),
            GroupPersonaMapping(
                id=uuid.uuid4(),
                idp_group="security-team",
                workspace_id=WORKSPACE_ID,
                persona="devsecops_engineer",
                precedence=50,
            ),
            GroupPersonaMapping(
                id=uuid.uuid4(),
                idp_group="admin-team",
                workspace_id=WORKSPACE_ID,
                persona="appsec_lead",
                precedence=50,  # same precedence as security-team → alpha tie-break
            ),
        ]
        for m in mappings:
            s.add(m)
        s.commit()


class TestPersonaResolver:
    def setup_method(self):
        self.resolver = PersonaResolver()

    def test_single_group_resolves(self, session):
        persona, trace = self.resolver.resolve(
            session,
            idp_groups=["platform-team"],
            workspace_id=WORKSPACE_ID,
        )
        assert persona == "devops_engineer"
        assert trace.persona_granted == "devops_engineer"
        assert trace.mapping_applied_idp_group == "platform-team"
        assert "platform-team" in trace.groups_seen

    def test_multi_group_lower_precedence_wins(self, session):
        # security-team and admin-team both have precedence=50, alphabetical tie-break.
        # platform-team has precedence=100 (loses).
        persona, trace = self.resolver.resolve(
            session,
            idp_groups=["platform-team", "security-team"],
            workspace_id=WORKSPACE_ID,
        )
        # security-team precedence=50 beats platform-team precedence=100
        assert persona == "devsecops_engineer"
        assert trace.mapping_applied_precedence == 50

    def test_precedence_tie_broken_by_persona_alphabetical(self, session):
        # admin-team → appsec_lead (p=50), security-team → devsecops_engineer (p=50)
        # "appsec_lead" < "devsecops_engineer" alphabetically → appsec_lead wins
        persona, trace = self.resolver.resolve(
            session,
            idp_groups=["admin-team", "security-team"],
            workspace_id=WORKSPACE_ID,
        )
        assert persona == "appsec_lead"

    def test_unmapped_group_returns_none(self, session):
        persona, trace = self.resolver.resolve(
            session,
            idp_groups=["unknown-team"],
            workspace_id=WORKSPACE_ID,
        )
        assert persona is None
        assert trace.persona_granted is None
        assert trace.mapping_applied_idp_group is None
        assert "unknown-team" in trace.groups_seen

    def test_empty_groups_returns_none(self, session):
        persona, trace = self.resolver.resolve(
            session,
            idp_groups=[],
            workspace_id=WORKSPACE_ID,
        )
        assert persona is None
        assert trace.groups_seen == []

    def test_wrong_workspace_returns_none(self, session):
        # Mappings exist for WORKSPACE_ID but not OTHER_WORKSPACE_ID.
        persona, trace = self.resolver.resolve(
            session,
            idp_groups=["platform-team"],
            workspace_id=OTHER_WORKSPACE_ID,
        )
        assert persona is None

    def test_trace_records_all_seen_groups(self, session):
        _, trace = self.resolver.resolve(
            session,
            idp_groups=["platform-team", "unknown-x"],
            workspace_id=WORKSPACE_ID,
        )
        assert set(trace.groups_seen) == {"platform-team", "unknown-x"}
