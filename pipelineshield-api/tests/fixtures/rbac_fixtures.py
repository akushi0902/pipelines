"""RBAC test fixtures — group claim sets, workspaces, users, and bindings.

These fixtures cover:
- Single-group user
- Multi-group user with conflicting mappings (precedence decides)
- Unmapped group (no binding)
- Single-admin workspace (last-admin test)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

# Stable IDs for the RBAC fixture workspace.
RBAC_WORKSPACE_ID = uuid.UUID("00000000-0000-0000-0003-000000000001")
SINGLE_ADMIN_WORKSPACE_ID = uuid.UUID("00000000-0000-0000-0003-000000000002")

RBAC_USERS = {
    "single_group_user": uuid.UUID("00000000-0000-0000-0004-000000000001"),
    "multi_group_user": uuid.UUID("00000000-0000-0000-0004-000000000002"),
    "unmapped_user": uuid.UUID("00000000-0000-0000-0004-000000000003"),
    "solo_admin": uuid.UUID("00000000-0000-0000-0004-000000000004"),
}

# Group claim sets for testing PersonaResolver.
GROUP_CLAIMS = {
    "single_group_devops": ["platform-team"],
    "multi_group_conflicting": ["platform-team", "security-team"],
    "unmapped": ["unknown-team"],
    "empty": [],
}

# Mappings:
#   platform-team → devops_engineer (precedence=100)
#   security-team → devsecops_engineer (precedence=50)
#   For multi-group: security-team wins (lower precedence=50)
GROUP_PERSONA_MAPPINGS = [
    {
        "idp_group": "platform-team",
        "workspace_id": RBAC_WORKSPACE_ID,
        "persona": "devops_engineer",
        "precedence": 100,
    },
    {
        "idp_group": "security-team",
        "workspace_id": RBAC_WORKSPACE_ID,
        "persona": "devsecops_engineer",
        "precedence": 50,
    },
    {
        "idp_group": "admin-team",
        "workspace_id": RBAC_WORKSPACE_ID,
        "persona": "appsec_lead",
        "precedence": 10,
    },
    {
        "idp_group": "platform-team",
        "workspace_id": SINGLE_ADMIN_WORKSPACE_ID,
        "persona": "appsec_lead",
        "precedence": 100,
    },
]
