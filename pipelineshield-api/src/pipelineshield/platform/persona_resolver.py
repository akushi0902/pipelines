"""PersonaResolver — deterministic IdP group claim → persona mapping.

Resolution algorithm:
1. Query group_persona_mapping for all rows where idp_group IN (groups)
   and workspace_id matches.
2. Sort matches by (precedence ASC, persona ASC) for determinism on ties.
3. The first row wins.  Return the persona plus a resolution trace that
   records which groups were seen, which mapping row applied, and what
   persona was granted.

The resolution trace is embedded in the audit change_detail so the decision
is explainable later without recording raw token content.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from pipelineshield.persistence.models.group_persona_mapping import GroupPersonaMapping


@dataclass
class ResolutionTrace:
    """Audit-safe record of a persona resolution decision."""

    groups_seen: list[str]
    mapping_applied_idp_group: str | None
    mapping_applied_precedence: int | None
    persona_granted: str | None


class PersonaResolver:
    """Maps a list of IdP group claims to a persona within a workspace.

    Each call is stateless; all state lives in the database.
    """

    def resolve(
        self,
        session: Session,
        *,
        idp_groups: Sequence[str],
        workspace_id: uuid.UUID,
    ) -> tuple[str | None, ResolutionTrace]:
        """Return ``(persona, trace)`` for the best matching mapping.

        If no mapping matches, returns ``(None, trace)`` with the groups
        recorded in the trace so the audit event captures what was attempted.
        """
        groups = list(idp_groups)
        if not groups:
            return None, ResolutionTrace(
                groups_seen=[],
                mapping_applied_idp_group=None,
                mapping_applied_precedence=None,
                persona_granted=None,
            )

        stmt = (
            select(GroupPersonaMapping)
            .where(
                GroupPersonaMapping.workspace_id == workspace_id,
                GroupPersonaMapping.idp_group.in_(groups),
            )
            .order_by(
                GroupPersonaMapping.precedence.asc(),
                GroupPersonaMapping.persona.asc(),
            )
        )
        matches = session.execute(stmt).scalars().all()

        if not matches:
            return None, ResolutionTrace(
                groups_seen=groups,
                mapping_applied_idp_group=None,
                mapping_applied_precedence=None,
                persona_granted=None,
            )

        winner = matches[0]
        trace = ResolutionTrace(
            groups_seen=groups,
            mapping_applied_idp_group=winner.idp_group,
            mapping_applied_precedence=winner.precedence,
            persona_granted=winner.persona,
        )
        return winner.persona, trace
