"""Authorization guard — deny-by-default RBAC for FastAPI routes.

Every route declares a capability requirement via ``require_capability()``.
The guard evaluates the current actor's persona against the capability map.
An unmapped capability equals deny.  The client-side role-check is cosmetic
only; this guard is the authoritative enforcement point.

Personas and capabilities
-------------------------
catalogue:read  — all five personas
catalogue:write — devsecops_engineer, appsec_lead only

Observability (policy A09)
--------------------------
Authorization-denial events are logged and counted per actor.  When a single
actor accumulates five or more denials within a short window (tracked in-process
via _AUTHZ_DENIAL_COUNTERS), an alert-worthy WARNING is emitted at ERROR level
so it can be routed to an on-call channel.  This is a lightweight in-process
implementation; a production deployment should replace it with a sliding-window
counter backed by Redis.
"""
from __future__ import annotations

import collections
import logging
import uuid
from dataclasses import dataclass
from typing import Annotated, Callable

import fastapi
from fastapi import Depends, HTTPException, Request

__all__ = [
    "CurrentActor",
    "PERSONA_CAPABILITIES",
    "get_current_actor",
    "require_capability",
    "AUTHZ_DENIAL_ALERT_THRESHOLD",
    "_AUTHZ_DENIAL_COUNTERS",
]

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Observability counters (policy A09)
# ---------------------------------------------------------------------------

# Simple in-process denial counter: actor_id → count
# Replace with Redis INCR/EXPIRE for production multi-process deployments.
_AUTHZ_DENIAL_COUNTERS: dict[str, int] = collections.defaultdict(int)

#: Alert threshold per policy A09 — five denials from one actor is alert-worthy.
AUTHZ_DENIAL_ALERT_THRESHOLD: int = 5

def _record_authz_denial(actor_id: str, capability: str, persona: str) -> None:
    """Increment per-actor denial counter; emit alert-level log at threshold."""
    _AUTHZ_DENIAL_COUNTERS[actor_id] += 1
    count = _AUTHZ_DENIAL_COUNTERS[actor_id]
    if count >= AUTHZ_DENIAL_ALERT_THRESHOLD:
        _LOG.error(
            "authz_denial_threshold_exceeded",
            extra={
                "actor_id": actor_id,
                "denial_count": count,
                "capability": capability,
                "persona": persona,
                "alert": "ALERT: actor has accumulated >= 5 authorization denials",
                "policy": "A09",
            },
        )


# ---------------------------------------------------------------------------
# Actor model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CurrentActor:
    """Immutable snapshot of the authenticated user at the time of the request."""

    user_id: uuid.UUID
    persona: str
    workspace_id: uuid.UUID
    display_name: str


# ---------------------------------------------------------------------------
# Capability map
# ---------------------------------------------------------------------------

PERSONA_CAPABILITIES: dict[str, frozenset[str]] = {
    # app_developer: create and read own analyses; no cross-user or write access.
    "app_developer": frozenset({
        "catalogue:read",
        "analysis:create",
        "analysis:read:own",
        "architecture:read",
        "dashboard:read",
    }),
    # devops_engineer: read all analyses in workspace; can export; no catalogue write.
    "devops_engineer": frozenset({
        "catalogue:read",
        "analysis:create",
        "analysis:read:own",
        "analysis:read:all",
        "architecture:read",
        "export:create",
        "dashboard:read",
    }),
    # devsecops_engineer: full analysis + findings access; can write catalogue; reads audit.
    "devsecops_engineer": frozenset({
        "catalogue:read",
        "catalogue:write",
        "audit:read",
        "analysis:create",
        "analysis:read:own",
        "analysis:read:all",
        "architecture:read",
        "finding:read:all",
        "export:create",
        "dashboard:read",
        "governance:data",
    }),
    # appsec_lead: same as devsecops + role management + governance.
    "appsec_lead": frozenset({
        "catalogue:read",
        "catalogue:write",
        "audit:read",
        "analysis:create",
        "analysis:read:own",
        "analysis:read:all",
        "architecture:read",
        "finding:read:all",
        "export:create",
        "dashboard:read",
        "admin:role:write",
        "governance:data",
    }),
    # engineering_manager: summary-only read; no create, no catalogue write, no findings.
    "engineering_manager": frozenset({
        "catalogue:read",
        "analysis:read:summary",
        "architecture:read",
        "dashboard:read",
    }),
}


# ---------------------------------------------------------------------------
# Base actor dependency (stub — OIDC wired in a later WO)
# ---------------------------------------------------------------------------


async def get_current_actor() -> CurrentActor:  # pragma: no cover
    """Yield the authenticated actor for the current request.

    This stub always raises 401.  In the full implementation it will
    validate the session cookie, resolve the actor from Redis/DB, and
    return the CurrentActor.  Tests override this dependency via
    app.dependency_overrides.
    """
    raise HTTPException(
        status_code=401,
        detail={
            "type": "https://pipelineshield.internal/errors/unauthenticated",
            "title": "Not authenticated",
            "status": 401,
            "detail": "A valid session is required. Please sign in.",
        },
    )


# ---------------------------------------------------------------------------
# Per-route capability guard
# ---------------------------------------------------------------------------


def require_capability(capability: str) -> Callable[..., CurrentActor]:
    """Return a FastAPI dependency that enforces *capability* for the route.

    Usage::

        @router.patch("/catalogue", dependencies=[Depends(require_capability("catalogue:write"))])

    Or to receive the actor::

        @router.patch("/catalogue")
        async def patch(actor: Annotated[CurrentActor, Depends(require_capability("catalogue:write"))]):
            ...
    """

    async def _guard(
        actor: Annotated[CurrentActor, Depends(get_current_actor)],
    ) -> CurrentActor:
        allowed = PERSONA_CAPABILITIES.get(actor.persona, frozenset())
        if capability not in allowed:
            actor_id_str = str(actor.user_id)
            _LOG.warning(
                "authz_denied",
                extra={
                    "capability": capability,
                    "persona": actor.persona,
                    "actor_id": actor_id_str,
                },
            )
            _record_authz_denial(actor_id_str, capability, actor.persona)
            raise HTTPException(
                status_code=403,
                detail={
                    "type": "https://pipelineshield.internal/errors/forbidden",
                    "title": "Forbidden",
                    "status": 403,
                    "detail": (
                        f"Your persona ({actor.persona!r}) does not have "
                        f"the {capability!r} capability."
                    ),
                    "required_capability": capability,
                    "errors": [],
                },
            )
        return actor

    # Expose the required capability on the guard so the route registry test
    # can discover it without walking the full dependency graph.
    _guard._required_capability = capability  # type: ignore[attr-defined]
    return _guard
