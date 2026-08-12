/**
 * MSW handlers for admin role-binding and group persona mapping endpoints.
 */

import { http, HttpResponse } from 'msw';
import type { RoleBindingItem, GroupPersonaMappingItem } from '../../api/types';

// ---------------------------------------------------------------------------
// Fixture data
// ---------------------------------------------------------------------------

const WORKSPACE_ID = '00000000-0000-0000-0077-000000000001';

const MOCK_BINDING: RoleBindingItem = {
  id: '00000000-0000-0000-0077-000000000100',
  app_user_id: '00000000-0000-0000-0077-000000000010',
  masked_email: 'a***@e***.com',
  display_name: 'Alice Admin',
  persona: 'appsec_lead',
  granted_by_id: null,
  granted_at: '2026-01-01T00:00:00Z',
  revoked_at: null,
};

const MOCK_MAPPING: GroupPersonaMappingItem = {
  id: '00000000-0000-0000-0077-000000000200',
  idp_group: 'platform-team',
  workspace_id: WORKSPACE_ID,
  persona: 'devops_engineer',
  precedence: 100,
  created_at: '2026-01-01T00:00:00Z',
};

// ---------------------------------------------------------------------------
// Default handlers
// ---------------------------------------------------------------------------

export const adminHandlers = [
  // GET role-bindings
  http.get('/api/v1/workspaces/:workspaceId/role-bindings', () =>
    HttpResponse.json({ items: [MOCK_BINDING], total: 1 }),
  ),

  // POST grant binding
  http.post('/api/v1/workspaces/:workspaceId/role-bindings', () =>
    HttpResponse.json(
      {
        ...MOCK_BINDING,
        id: '00000000-0000-0000-0077-000000000101',
        persona: 'devops_engineer',
      },
      { status: 201 },
    ),
  ),

  // PATCH change binding
  http.patch('/api/v1/workspaces/:workspaceId/role-bindings/:bindingId', () =>
    HttpResponse.json({ ...MOCK_BINDING, persona: 'devops_engineer' }),
  ),

  // DELETE revoke binding
  http.delete(
    '/api/v1/workspaces/:workspaceId/role-bindings/:bindingId',
    () => new HttpResponse(null, { status: 204 }),
  ),

  // GET group persona mappings
  http.get('/api/v1/group-persona-mappings', () =>
    HttpResponse.json({ items: [MOCK_MAPPING], total: 1 }),
  ),

  // PUT upsert group persona mappings
  http.put('/api/v1/group-persona-mappings', () =>
    HttpResponse.json({ items: [MOCK_MAPPING], total: 1 }),
  ),
];

// ---------------------------------------------------------------------------
// Override factories for per-test scenarios
// ---------------------------------------------------------------------------

export function adminGrant403Handler() {
  return http.post('/api/v1/workspaces/:workspaceId/role-bindings', () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/forbidden',
        title: 'Forbidden',
        status: 403,
        detail: 'Insufficient capability.',
        errors: [],
      },
      { status: 403 },
    ),
  );
}

export function adminGrant409Handler() {
  return http.post('/api/v1/workspaces/:workspaceId/role-bindings', () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/conflict',
        title: 'Conflict',
        status: 409,
        detail: 'Duplicate active binding.',
        errors: [],
      },
      { status: 409 },
    ),
  );
}

export function adminRevoke409Handler() {
  return http.delete(
    '/api/v1/workspaces/:workspaceId/role-bindings/:bindingId',
    () =>
      HttpResponse.json(
        {
          type: 'https://pipelineshield.internal/errors/conflict',
          title: 'Conflict',
          status: 409,
          detail: 'Cannot revoke the last appsec_lead in this workspace.',
          errors: [],
        },
        { status: 409 },
      ),
  );
}

export function adminListErrorHandler() {
  return http.get('/api/v1/workspaces/:workspaceId/role-bindings', () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/server-error',
        title: 'Internal Server Error',
        status: 500,
        detail: 'Unexpected error.',
        errors: [],
      },
      { status: 500 },
    ),
  );
}
