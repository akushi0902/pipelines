import { http, HttpResponse, delay } from 'msw';
import type { AnalysisCreateResponse, FormatConfirmationResponse } from '../../api/generated/ingestion';

const BASE = '/api/v1';

// ---------------------------------------------------------------------------
// Default mock fixtures
// ---------------------------------------------------------------------------

export const MOCK_ANALYSIS_SUCCESS: AnalysisCreateResponse = {
  analysis_id: 'aaa00000-0000-0000-0000-000000000001',
  workspace_id: 'bbb00000-0000-0000-0000-000000000001',
  catalogue_version_id: 'ccc00000-0000-0000-0000-000000000001',
  created_at: '2026-08-11T12:00:00Z',
  detected_format: 'github_actions',
  format_confidence: 0.97,
  format_confirmation_required: false,
  coverage_report: { controls_evaluated: 9, controls_passed: 7 },
  advisory_disclaimer:
    'This analysis is advisory only. Validate findings with your security team.',
};

export const MOCK_ANALYSIS_LOW_CONFIDENCE: AnalysisCreateResponse = {
  ...MOCK_ANALYSIS_SUCCESS,
  analysis_id: 'aaa00000-0000-0000-0000-000000000002',
  detected_format: 'gitlab_ci',
  format_confidence: 0.55,
  format_confirmation_required: true,
};

export const MOCK_FORMAT_CONFIRMATION: FormatConfirmationResponse = {
  analysis_id: 'aaa00000-0000-0000-0000-000000000002',
  confirmed_format: 'gitlab_ci',
  format_confirmed_by_user: true,
};

// ---------------------------------------------------------------------------
// Default happy-path handlers
// ---------------------------------------------------------------------------

export const uploadHandlers = [
  http.post(`${BASE}/analyses`, () =>
    HttpResponse.json(MOCK_ANALYSIS_SUCCESS, { status: 201 }),
  ),

  http.post(`${BASE}/analyses/:analysisId/format-confirmation`, () =>
    HttpResponse.json(MOCK_FORMAT_CONFIRMATION, { status: 200 }),
  ),
];

// ---------------------------------------------------------------------------
// Override factories for specific test scenarios
// ---------------------------------------------------------------------------

export function upload413Handler() {
  return http.post(`${BASE}/analyses`, () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/payload-too-large',
        title: 'Payload Too Large',
        status: 413,
        detail: 'The pipeline definition exceeds the 512 KB limit.',
        correlation_id: 'corr-413-test',
        constraint: 'max_bytes=524288',
        errors: [],
      },
      { status: 413 },
    ),
  );
}

export function upload422Handler() {
  return http.post(`${BASE}/analyses`, () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/unprocessable-definition',
        title: 'Unprocessable Definition',
        status: 422,
        detail: 'YAML parse error: unexpected token at line 7.',
        correlation_id: 'corr-422-test',
        constraint: 'yaml_parse_error',
        parse_line: 7,
        parse_column: 3,
        errors: [],
      },
      { status: 422 },
    ),
  );
}

export function upload401Handler() {
  return http.post(`${BASE}/analyses`, () =>
    HttpResponse.json(
      {
        type: 'https://pipelineshield.internal/errors/unauthorized',
        title: 'Unauthorized',
        status: 401,
        detail: 'Session expired. Please sign in again.',
        correlation_id: 'corr-401-test',
        errors: [],
      },
      { status: 401 },
    ),
  );
}

export function uploadLowConfidenceHandler() {
  return http.post(`${BASE}/analyses`, () =>
    HttpResponse.json(MOCK_ANALYSIS_LOW_CONFIDENCE, { status: 201 }),
  );
}

export function uploadHangHandler() {
  return http.post(`${BASE}/analyses`, async () => {
    await delay('infinite');
    return new HttpResponse(null, { status: 0 });
  });
}
