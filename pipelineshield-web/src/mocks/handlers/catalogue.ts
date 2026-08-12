import { http, HttpResponse } from 'msw';
import type {
  CatalogueGetResponse,
  CataloguePatchResponse,
  AuditEventsResponse,
} from '../../api/types';

const BASE = '/api/v1';

export const MOCK_CATALOGUE: CatalogueGetResponse = {
  version: 1,
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
  created_by: 'seed@pipelineshield.internal',
  grade_bands: [
    { grade: 'A', min_score: 90, max_score: 100 },
    { grade: 'B', min_score: 75, max_score: 89 },
    { grade: 'C', min_score: 60, max_score: 74 },
    { grade: 'D', min_score: 40, max_score: 59 },
    { grade: 'F', min_score: 0, max_score: 39 },
  ],
  categories: [
    { id: 'secrets', name: 'Secrets Management', weight: 15, enabled: true },
    { id: 'signing', name: 'Signing & Provenance', weight: 15, enabled: true },
    { id: 'sast', name: 'SAST', weight: 12, enabled: true },
    { id: 'deps', name: 'Dependency / Container', weight: 12, enabled: true },
    { id: 'iam', name: 'Least-Privilege Identity', weight: 12, enabled: true },
    { id: 'iac', name: 'IaC Security', weight: 10, enabled: true },
    { id: 'supply', name: 'Supply-Chain Integrity', weight: 10, enabled: true },
    { id: 'sbom', name: 'SBOM', weight: 8, enabled: true },
    { id: 'gates', name: 'Approval Gates', weight: 6, enabled: true },
  ],
  controls: [
    {
      id: 'secrets.no_hardcoded',
      category_id: 'secrets',
      severity: 'critical',
      enabled: true,
      reference_tools: ['gitleaks', 'trivy'],
    },
    {
      id: 'signing.artifact_signed',
      category_id: 'signing',
      severity: 'high',
      enabled: true,
      reference_tools: ['cosign'],
    },
  ],
};

export const MOCK_CATALOGUE_V2: CatalogueGetResponse = {
  ...MOCK_CATALOGUE,
  version: 2,
  created_by: 'admin@pipelineshield.internal',
  created_at: '2026-02-01T00:00:00Z',
};

export const MOCK_PATCH_RESPONSE: CataloguePatchResponse = {
  version: 2,
  created_at: '2026-02-01T00:00:00Z',
  created_by: 'admin@pipelineshield.internal',
  diff: [
    {
      path: 'categories.secrets.weight',
      old_value: 15,
      new_value: 20,
    },
  ],
  snapshot: MOCK_CATALOGUE_V2,
};

export const MOCK_AUDIT: AuditEventsResponse = {
  items: [
    {
      id: 'audit-uuid-1',
      occurred_at: '2026-01-01T00:00:00Z',
      actor_id: 'seed@pipelineshield.internal',
      actor_reference: null,
      actor_persona: 'devsecops',
      workspace_id: null,
      action: 'catalogue.version_created',
      resource_type: 'control_catalogue_version',
      resource_id: '1',
      change_detail: {},
      correlation_id: null,
    },
  ],
  next_cursor: null,
  total_returned: 1,
};

// ---------------------------------------------------------------------------
// Default happy-path handlers
// ---------------------------------------------------------------------------

export const catalogueHandlers = [
  http.get(`${BASE}/catalogue`, () => HttpResponse.json(MOCK_CATALOGUE)),

  http.get(`${BASE}/audit-events`, () => HttpResponse.json(MOCK_AUDIT)),

  http.patch(`${BASE}/catalogue`, () =>
    HttpResponse.json(MOCK_PATCH_RESPONSE, { status: 201 }),
  ),
];

// ---------------------------------------------------------------------------
// Override factories for specific test scenarios
// ---------------------------------------------------------------------------

export function cataloguePatch400Handler() {
  return http.patch(`${BASE}/catalogue`, () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/validation',
        title: 'Catalogue Validation Error',
        status: 400,
        detail: 'Weight total must equal 100',
        errors: [
          { field: 'categories.secrets.weight', message: 'Weight causes total to exceed 100' },
        ],
      },
      { status: 400 },
    ),
  );
}

export function cataloguePatch403Handler() {
  return http.patch(`${BASE}/catalogue`, () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/forbidden',
        title: 'Forbidden',
        status: 403,
        detail: 'You do not have catalogue:write permission',
        errors: [],
      },
      { status: 403 },
    ),
  );
}

export function cataloguePatch409Handler() {
  return http.patch(`${BASE}/catalogue`, () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/conflict',
        title: 'Version Conflict',
        status: 409,
        detail: 'base_version 1 is stale; current version is 2',
        errors: [],
      },
      { status: 409 },
    ),
  );
}

export function catalogueGetErrorHandler() {
  return http.get(`${BASE}/catalogue`, () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/server',
        title: 'Internal Server Error',
        status: 500,
        detail: 'Unexpected error',
        errors: [],
      },
      { status: 500 },
    ),
  );
}

export function catalogueGet403Handler() {
  return http.get(`${BASE}/catalogue`, () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/forbidden',
        title: 'Forbidden',
        status: 403,
        detail: 'You do not have catalogue:read permission',
        errors: [],
      },
      { status: 403 },
    ),
  );
}
