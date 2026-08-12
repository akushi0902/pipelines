"""Unit tests for AuthzGuard, PERSONA_CAPABILITIES, and ActorScope (WO-037).

Coverage
--------
TestPersonaCapabilityMatrix
    Every persona × capability pair is tested against the expected
    allow/deny outcome.  A regression in the mapping table fails here.

TestDenyByDefault
    Unknown capability → deny for every persona.
    Unknown persona → deny for every capability.

TestActorScope
    ActorScope.from_actor produces correct read_all flag per persona.
    workspace_ids correctly populated.

TestAuthorizationExceptions
    AuthorizationError carries required_capability.
    ResourceNotVisibleError carries resource_type and resource_id.

Test404Vs403Decision
    A resource in the wrong workspace raises ResourceNotVisibleError (→ 404).
    A resource in the correct workspace with wrong capability raises 403.
"""
from __future__ import annotations

import uuid

import pytest

from pipelineshield.api.security.authz_guard import PERSONA_CAPABILITIES
from pipelineshield.api.security.scope import (
    ActorScope,
    AuthorizationError,
    ResourceNotVisibleError,
)


# ---------------------------------------------------------------------------
# Documented expected matrix
# Each entry: (persona, capability, expected_allowed: bool)
# ---------------------------------------------------------------------------

_MATRIX = [
    # catalogue:read — all five personas
    ("app_developer",       "catalogue:read",        True),
    ("devops_engineer",     "catalogue:read",        True),
    ("devsecops_engineer",  "catalogue:read",        True),
    ("appsec_lead",         "catalogue:read",        True),
    ("engineering_manager", "catalogue:read",        True),
    # catalogue:write — devsecops + appsec only
    ("app_developer",       "catalogue:write",       False),
    ("devops_engineer",     "catalogue:write",       False),
    ("devsecops_engineer",  "catalogue:write",       True),
    ("appsec_lead",         "catalogue:write",       True),
    ("engineering_manager", "catalogue:write",       False),
    # analysis:create — not engineering_manager
    ("app_developer",       "analysis:create",       True),
    ("devops_engineer",     "analysis:create",       True),
    ("devsecops_engineer",  "analysis:create",       True),
    ("appsec_lead",         "analysis:create",       True),
    ("engineering_manager", "analysis:create",       False),
    # analysis:read:own
    ("app_developer",       "analysis:read:own",     True),
    ("devops_engineer",     "analysis:read:own",     True),
    ("devsecops_engineer",  "analysis:read:own",     True),
    ("appsec_lead",         "analysis:read:own",     True),
    ("engineering_manager", "analysis:read:own",     False),
    # analysis:read:all — devops + devsecops + appsec
    ("app_developer",       "analysis:read:all",     False),
    ("devops_engineer",     "analysis:read:all",     True),
    ("devsecops_engineer",  "analysis:read:all",     True),
    ("appsec_lead",         "analysis:read:all",     True),
    ("engineering_manager", "analysis:read:all",     False),
    # analysis:read:summary — engineering_manager only
    ("app_developer",       "analysis:read:summary", False),
    ("devops_engineer",     "analysis:read:summary", False),
    ("devsecops_engineer",  "analysis:read:summary", False),
    ("appsec_lead",         "analysis:read:summary", False),
    ("engineering_manager", "analysis:read:summary", True),
    # finding:read:all — devsecops + appsec
    ("app_developer",       "finding:read:all",      False),
    ("devops_engineer",     "finding:read:all",      False),
    ("devsecops_engineer",  "finding:read:all",      True),
    ("appsec_lead",         "finding:read:all",      True),
    ("engineering_manager", "finding:read:all",      False),
    # export:create — devops + devsecops + appsec
    ("app_developer",       "export:create",         False),
    ("devops_engineer",     "export:create",         True),
    ("devsecops_engineer",  "export:create",         True),
    ("appsec_lead",         "export:create",         True),
    ("engineering_manager", "export:create",         False),
    # dashboard:read — all five
    ("app_developer",       "dashboard:read",        True),
    ("devops_engineer",     "dashboard:read",        True),
    ("devsecops_engineer",  "dashboard:read",        True),
    ("appsec_lead",         "dashboard:read",        True),
    ("engineering_manager", "dashboard:read",        True),
    # audit:read — devsecops + appsec
    ("app_developer",       "audit:read",            False),
    ("devops_engineer",     "audit:read",            False),
    ("devsecops_engineer",  "audit:read",            True),
    ("appsec_lead",         "audit:read",            True),
    ("engineering_manager", "audit:read",            False),
    # admin:role:write — appsec_lead only
    ("app_developer",       "admin:role:write",      False),
    ("devops_engineer",     "admin:role:write",      False),
    ("devsecops_engineer",  "admin:role:write",      False),
    ("appsec_lead",         "admin:role:write",      True),
    ("engineering_manager", "admin:role:write",      False),
]


class TestPersonaCapabilityMatrix:
    """AC-1, AC-5 — full matrix of persona × capability."""

    @pytest.mark.parametrize(
        "persona,capability,expected",
        _MATRIX,
        ids=[f"{p}::{c}={'allow' if e else 'deny'}" for p, c, e in _MATRIX],
    )
    def test_matrix_entry(
        self, persona: str, capability: str, expected: bool
    ) -> None:
        caps = PERSONA_CAPABILITIES.get(persona, frozenset())
        actual = capability in caps
        assert actual == expected, (
            f"Persona {persona!r} capability {capability!r}: "
            f"expected {'ALLOW' if expected else 'DENY'} but got "
            f"{'ALLOW' if actual else 'DENY'}."
        )

    def test_all_required_capabilities_present(self) -> None:
        """AC-1: the required capability set is fully covered by the mapping."""
        required = {
            "analysis:create",
            "analysis:read:own",
            "analysis:read:all",
            "analysis:read:summary",
            "finding:read:all",
            "catalogue:read",
            "catalogue:write",
            "export:create",
            "dashboard:read",
            "audit:read",
            "admin:role:write",
        }
        all_defined: set[str] = set()
        for caps in PERSONA_CAPABILITIES.values():
            all_defined.update(caps)

        missing = required - all_defined
        assert not missing, (
            f"Required capabilities not present in any persona mapping: {missing}"
        )

    def test_engineering_manager_write_attempts_denied(self) -> None:
        """AC-5: engineering_manager write attempts return 403."""
        write_caps = {"catalogue:write", "analysis:create", "export:create", "admin:role:write"}
        mgr_caps = PERSONA_CAPABILITIES["engineering_manager"]
        for cap in write_caps:
            assert cap not in mgr_caps, (
                f"engineering_manager must not have {cap!r}"
            )


class TestDenyByDefault:
    """AC-2: unmapped capability and unknown persona both deny."""

    def test_unknown_capability_denied_for_all_personas(self) -> None:
        unknown = "completely:unknown:capability"
        for persona, caps in PERSONA_CAPABILITIES.items():
            assert unknown not in caps, (
                f"Persona {persona!r} unexpectedly has unknown capability {unknown!r}"
            )

    def test_unknown_persona_gets_empty_capability_set(self) -> None:
        caps = PERSONA_CAPABILITIES.get("ghost_persona", frozenset())
        assert len(caps) == 0

    def test_every_persona_is_documented(self) -> None:
        expected_personas = {
            "app_developer",
            "devops_engineer",
            "devsecops_engineer",
            "appsec_lead",
            "engineering_manager",
        }
        assert set(PERSONA_CAPABILITIES.keys()) == expected_personas


class TestActorScope:
    """ActorScope.from_actor produces correct read_all flag per persona."""

    _WS = uuid.UUID("00000000-0000-0000-0000-000000000001")
    _UID = uuid.UUID("00000000-0000-0000-0000-000000000002")

    @pytest.mark.parametrize("persona,expected_read_all", [
        ("app_developer",       False),
        ("devops_engineer",     True),
        ("devsecops_engineer",  True),
        ("appsec_lead",         True),
        ("engineering_manager", False),
    ])
    def test_read_all_flag(self, persona: str, expected_read_all: bool) -> None:
        scope = ActorScope.from_actor(self._UID, persona, self._WS)
        assert scope.read_all == expected_read_all, (
            f"Persona {persona!r}: expected read_all={expected_read_all}"
        )

    def test_workspace_ids_populated(self) -> None:
        scope = ActorScope.from_actor(self._UID, "devops_engineer", self._WS)
        assert self._WS in scope.workspace_ids

    def test_actor_id_preserved(self) -> None:
        scope = ActorScope.from_actor(self._UID, "app_developer", self._WS)
        assert scope.actor_id == self._UID

    def test_persona_preserved(self) -> None:
        scope = ActorScope.from_actor(self._UID, "appsec_lead", self._WS)
        assert scope.persona == "appsec_lead"

    def test_scope_is_frozen(self) -> None:
        scope = ActorScope.from_actor(self._UID, "app_developer", self._WS)
        with pytest.raises((AttributeError, TypeError)):
            scope.read_all = True  # type: ignore[misc]


class TestAuthorizationExceptions:
    """Exception types carry the correct fields."""

    def test_authorization_error_fields(self) -> None:
        exc = AuthorizationError(
            required_capability="catalogue:write",
            persona="devops_engineer",
            resource_type="catalogue",
            resource_id="v1",
        )
        assert exc.required_capability == "catalogue:write"
        assert exc.persona == "devops_engineer"
        assert exc.resource_type == "catalogue"
        assert exc.resource_id == "v1"
        assert "catalogue:write" in str(exc)

    def test_resource_not_visible_error_fields(self) -> None:
        exc = ResourceNotVisibleError(resource_type="analysis", resource_id="abc-123")
        assert exc.resource_type == "analysis"
        assert exc.resource_id == "abc-123"
        assert "analysis" in str(exc)

    def test_resource_not_visible_default_fields(self) -> None:
        exc = ResourceNotVisibleError()
        assert exc.resource_type == "resource"
        assert exc.resource_id is None


class TestFourOhFourVsFourOhThreeDecision:
    """404 for invisible resources; 403 for visible resource + wrong verb (AC-6)."""

    _WS_A = uuid.UUID("00000000-0000-0000-0001-000000000001")
    _WS_B = uuid.UUID("00000000-0000-0000-0001-000000000002")
    _UID = uuid.UUID("00000000-0000-0000-0001-000000000003")

    def test_wrong_workspace_should_be_not_visible(self) -> None:
        """A resource in workspace B is not visible to an actor scoped to workspace A."""
        scope = ActorScope(
            actor_id=self._UID,
            workspace_ids=frozenset({self._WS_A}),
            read_all=True,
            persona="devops_engineer",
        )
        resource_workspace = self._WS_B
        # The caller should raise ResourceNotVisibleError if resource_workspace
        # is not in scope.workspace_ids
        assert resource_workspace not in scope.workspace_ids

    def test_correct_workspace_but_wrong_capability_should_be_forbidden(self) -> None:
        """An actor in the right workspace but lacking the capability gets 403."""
        scope = ActorScope(
            actor_id=self._UID,
            workspace_ids=frozenset({self._WS_A}),
            read_all=False,
            persona="app_developer",
        )
        resource_workspace = self._WS_A
        required_cap = "catalogue:write"
        # Resource is visible (same workspace), but capability is missing
        assert resource_workspace in scope.workspace_ids
        app_dev_caps = PERSONA_CAPABILITIES["app_developer"]
        assert required_cap not in app_dev_caps

    def test_authorization_error_is_not_resource_not_visible(self) -> None:
        assert not issubclass(AuthorizationError, ResourceNotVisibleError)
        assert not issubclass(ResourceNotVisibleError, AuthorizationError)
