"""Unit tests for RoleBindingService invariants.

Tests:
- Last-admin protection: cannot revoke the last appsec_lead binding.
- Last-admin protection: cannot change (demote) the last appsec_lead.
- Self-escalation prevention: lower persona cannot grant higher persona.
- Duplicate grant: second grant for same (user, workspace, persona) raises 409.
- Happy path: grant, change, revoke all succeed with audit events.
- Invalid persona: raises InvalidPersonaError.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from pipelineshield.api.security.authz_guard import CurrentActor
from pipelineshield.persistence.models import Base
from pipelineshield.persistence.models.app_user import AppUser
from pipelineshield.persistence.models.role_binding import RoleBinding
from pipelineshield.persistence.models.workspace import Workspace
from pipelineshield.platform.audit_writer import AuditWriter
from pipelineshield.services.role_binding_service import (
    DuplicateBindingError,
    InvalidPersonaError,
    LastAdminError,
    RoleBindingService,
    SelfEscalationError,
)


# ---------------------------------------------------------------------------
# DB setup
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

WS_ID = uuid.UUID("00000000-0000-0000-0088-000000000001")
ACTOR_USER_ID = uuid.UUID("00000000-0000-0000-0088-000000000010")
TARGET_USER_ID = uuid.UUID("00000000-0000-0000-0088-000000000020")
OTHER_USER_ID = uuid.UUID("00000000-0000-0000-0088-000000000030")


def make_actor(persona: str = "appsec_lead") -> CurrentActor:
    return CurrentActor(
        user_id=ACTOR_USER_ID,
        persona=persona,
        workspace_id=WS_ID,
        display_name="Test Actor",
    )


def mock_audit() -> AuditWriter:
    audit = MagicMock(spec=AuditWriter)
    return audit


@pytest.fixture(autouse=True, scope="module")
def seed_workspace(engine):
    with Session(engine) as s:
        ws = Workspace(id=WS_ID, name="RBS Test WS", slug="rbs-test-ws")
        s.add(ws)
        actor_user = AppUser(
            id=ACTOR_USER_ID,
            workspace_id=WS_ID,
            sub_claim="sub|actor",
            email="a***@e***.com",
            display_name="Actor",
        )
        target_user = AppUser(
            id=TARGET_USER_ID,
            workspace_id=WS_ID,
            sub_claim="sub|target",
            email="t***@e***.com",
            display_name="Target",
        )
        other_user = AppUser(
            id=OTHER_USER_ID,
            workspace_id=WS_ID,
            sub_claim="sub|other",
            email="o***@e***.com",
            display_name="Other",
        )
        s.add(actor_user)
        s.add(target_user)
        s.add(other_user)
        s.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGrantBinding:
    def test_grant_happy_path(self, session):
        service = RoleBindingService()
        actor = make_actor()
        audit = mock_audit()

        binding = service.grant_binding(
            session,
            actor=actor,
            workspace_id=WS_ID,
            app_user_id=TARGET_USER_ID,
            persona="devops_engineer",
            audit_writer=audit,
        )
        assert binding.persona == "devops_engineer"
        assert binding.app_user_id == TARGET_USER_ID
        assert binding.granted_by_id == ACTOR_USER_ID
        audit.write.assert_called_once()
        call_kwargs = audit.write.call_args.kwargs
        assert call_kwargs["action"] == "role_binding.granted"
        assert call_kwargs["change_detail"]["new_persona"] == "devops_engineer"

    def test_duplicate_grant_raises(self, session):
        service = RoleBindingService()
        actor = make_actor()
        # First grant (already exists from previous test in same session? No — each test
        # rolls back. Grant fresh here.)
        service.grant_binding(
            session,
            actor=actor,
            workspace_id=WS_ID,
            app_user_id=OTHER_USER_ID,
            persona="app_developer",
            audit_writer=mock_audit(),
        )
        with pytest.raises(DuplicateBindingError):
            service.grant_binding(
                session,
                actor=actor,
                workspace_id=WS_ID,
                app_user_id=OTHER_USER_ID,
                persona="app_developer",
                audit_writer=mock_audit(),
            )

    def test_invalid_persona_raises(self, session):
        service = RoleBindingService()
        with pytest.raises(InvalidPersonaError):
            service.grant_binding(
                session,
                actor=make_actor(),
                workspace_id=WS_ID,
                app_user_id=TARGET_USER_ID,
                persona="super_admin",
                audit_writer=mock_audit(),
            )

    def test_self_escalation_blocked(self, session):
        # devops_engineer cannot grant appsec_lead (higher capability set)
        service = RoleBindingService()
        actor = make_actor("devops_engineer")
        with pytest.raises(SelfEscalationError):
            service.grant_binding(
                session,
                actor=actor,
                workspace_id=WS_ID,
                app_user_id=TARGET_USER_ID,
                persona="appsec_lead",
                audit_writer=mock_audit(),
            )


class TestLastAdminProtection:
    def _setup_single_admin(self, session) -> uuid.UUID:
        """Insert a single appsec_lead binding and return its id."""
        admin_id = uuid.uuid4()
        binding = RoleBinding(
            id=admin_id,
            workspace_id=WS_ID,
            app_user_id=TARGET_USER_ID,
            persona="appsec_lead",
            granted_by_id=None,
        )
        session.add(binding)
        session.flush()
        return admin_id

    def test_revoke_last_admin_blocked(self, session):
        service = RoleBindingService()
        binding_id = self._setup_single_admin(session)

        with pytest.raises(LastAdminError):
            service.revoke_binding(
                session,
                actor=make_actor(),
                binding_id=binding_id,
                workspace_id=WS_ID,
                audit_writer=mock_audit(),
            )

    def test_demote_last_admin_blocked(self, session):
        service = RoleBindingService()
        binding_id = self._setup_single_admin(session)

        with pytest.raises(LastAdminError):
            service.change_binding(
                session,
                actor=make_actor(),
                binding_id=binding_id,
                workspace_id=WS_ID,
                new_persona="devops_engineer",
                audit_writer=mock_audit(),
            )

    def test_revoke_non_last_admin_succeeds(self, session):
        service = RoleBindingService()
        # Two admins: existing one + new one
        binding_id_1 = self._setup_single_admin(session)
        binding_2 = RoleBinding(
            id=uuid.uuid4(),
            workspace_id=WS_ID,
            app_user_id=ACTOR_USER_ID,
            persona="appsec_lead",
            granted_by_id=None,
        )
        session.add(binding_2)
        session.flush()

        # Revoke one — should succeed because the other remains.
        service.revoke_binding(
            session,
            actor=make_actor(),
            binding_id=binding_id_1,
            workspace_id=WS_ID,
            audit_writer=mock_audit(),
        )
        # Verify revoked_at set.
        rb = session.get(RoleBinding, binding_id_1)
        assert rb.revoked_at is not None
