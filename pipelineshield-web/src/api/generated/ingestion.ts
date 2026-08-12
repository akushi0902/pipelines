/**
 * GENERATED FILE — do not edit by hand.
 * Regenerate with: npm run generate:types
 * Source: pipelineshield-api OpenAPI schema (POST /api/v1/analyses)
 *
 * Types mirror the FastAPI schemas in:
 *   pipelineshield-api/src/pipelineshield/api/v1/schemas/analysis.py
 */

export type CiFormat = 'github_actions' | 'gitlab_ci' | 'jenkins';

export const CI_FORMAT_LABELS: Record<CiFormat, string> = {
  github_actions: 'GitHub Actions',
  gitlab_ci: 'GitLab CI',
  jenkins: 'Jenkins',
};

export const VALID_CI_FORMATS: CiFormat[] = ['github_actions', 'gitlab_ci', 'jenkins'];

/** 512 KB maximum payload — matches PAYLOAD_MAX_BYTES on the server */
export const PAYLOAD_MAX_BYTES = 512 * 1024;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

export interface PasteAnalysisRequest {
  definition_text: string;
  filename?: string | null;
  declared_format?: CiFormat | null;
}

export interface FormatConfirmationRequest {
  confirmed_format: CiFormat;
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

export interface AnalysisCreateResponse {
  analysis_id: string;
  workspace_id: string;
  catalogue_version_id: string;
  created_at: string;
  detected_format: string;
  format_confidence: number;
  format_confirmation_required: boolean;
  coverage_report: Record<string, unknown>;
  advisory_disclaimer: string;
}

export interface FormatConfirmationResponse {
  analysis_id: string;
  confirmed_format: string;
  format_confirmed_by_user: boolean;
}

// ---------------------------------------------------------------------------
// Error response (RFC 7807 with ingestion extensions)
// ---------------------------------------------------------------------------

export interface IngestionError {
  type: string;
  title: string;
  status: number;
  detail: string;
  correlation_id?: string | null;
  constraint?: string | null;
  parse_line?: number | null;
  parse_column?: number | null;
  errors?: Array<{ field: string; message: string }>;
}
