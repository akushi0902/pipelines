"""Authorization scope value objects and typed exceptions.

ActorScope is derived from the authenticated actor's active role bindings and
is passed to repository methods so row-level scoping is expressed in SQL
predicates — not post-fetch filtering.

Exception hierarchy
-------------------
AuthorizationError  → maps to HTTP 403 (resource visible, verb forbidden)
ResourceNotVisibleError → maps to HTTP 404 (resource not visible to actor)
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field


__all__ = [
    "ActorScope",
    "AuthorizationError",
    "ResourceNotVisibleError",
]


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActorScope:
    """Immutable snapshot of an actor's access scope derived from role bindings.

    Parameters
    ----------
    actor_id:
        The authenticated user's primary key.
    workspace_ids:
        Frozenset of workspace UUIDs in which the actor holds an active role
        binding.  List endpoints use this set as an IN predicate; single-
        resource reads verify the resource's workspace_id is a member.
    read_all:
        True for personas that may read all rows within accessible workspaces
        (devops_engineer, devsecops_engineer, appsec_lead).  False for
        app_developer and engineering_manager, which are further restricted
        to their own rows (owner_id) or summary-only responses.
    persona:
        The actor's resolved persona — kept for audit detail.
    """

    actor_id: uuid.UUID
    workspace_ids: frozenset[uuid.UUID]
    read_all: bool
    persona: str

    @classmethod
    def from_actor(
        cls,
        actor_id: uuid.UUID,
        persona: str,
        workspace_id: uuid.UUID,
    ) -> "ActorScope":
        """Build an ActorScope from a single-workspace CurrentActor.

        Used by the route guard until multi-workspace bindings are wired
        (RoleBindingRepository, WO-038).  Produces read_all=True for the
        'read all in workspace' personas.
        """
        _READ_ALL_PERSONAS = frozenset({
            "devops_engineer",
            "devsecops_engineer",
            "appsec_lead",
        })
        return cls(
            actor_id=actor_id,
            workspace_ids=frozenset({workspace_id}),
            read_all=persona in _READ_ALL_PERSONAS,
            persona=persona,
        )


# ---------------------------------------------------------------------------
# Typed authorization exceptions
# ---------------------------------------------------------------------------


class AuthorizationError(Exception):
    """Raised when the actor can see the resource but lacks the required verb.

    Maps to HTTP 403.  The handler must include a ``required_capability``
    field in the RFC 7807 body so the caller understands what is missing.
    """

    def __init__(
        self,
        required_capability: str,
        persona: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.required_capability = required_capability
        self.persona = persona
        self.resource_type = resource_type
        self.resource_id = resource_id
        msg = detail or (
            f"Persona {persona!r} does not have the {required_capability!r} capability."
        )
        super().__init__(msg)


class ResourceNotVisibleError(Exception):
    """Raised when the resource is not visible to the actor.

    Maps to HTTP 404 with a body identical to a genuinely missing resource
    so that the actor cannot infer whether the resource exists.
    """

    def __init__(
        self,
        resource_type: str = "resource",
        resource_id: str | None = None,
    ) -> None:
        self.resource_type = resource_type
        self.resource_id = resource_id
        rid_part = f" {resource_id!r}" if resource_id else ""
        super().__init__(f"The requested {resource_type}{rid_part} was not found.")
