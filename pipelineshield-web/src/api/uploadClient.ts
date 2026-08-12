/**
 * Upload API client functions.
 * All calls return ApiResult — callers must handle both ok and error branches.
 */

import { apiFetch } from './client';
import type { ApiResult } from './client';
import type {
  AnalysisCreateResponse,
  CiFormat,
  FormatConfirmationResponse,
} from './generated/ingestion';

const BASE = '/api/v1';

export async function submitFile(file: File): Promise<ApiResult<AnalysisCreateResponse>> {
  const form = new FormData();
  form.append('file', file, file.name);
  return apiFetch<AnalysisCreateResponse>(`${BASE}/analyses`, {
    method: 'POST',
    body: form,
    // Do NOT set Content-Type — browser sets multipart boundary automatically.
  });
}

export async function submitText(
  content: string,
  filename?: string,
): Promise<ApiResult<AnalysisCreateResponse>> {
  return apiFetch<AnalysisCreateResponse>(`${BASE}/analyses`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      definition_text: content,
      ...(filename != null ? { filename } : {}),
    }),
  });
}

export async function confirmFormat(
  analysisId: string,
  confirmedFormat: CiFormat,
): Promise<ApiResult<FormatConfirmationResponse>> {
  return apiFetch<FormatConfirmationResponse>(
    `${BASE}/analyses/${analysisId}/format-confirmation`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirmed_format: confirmedFormat }),
    },
  );
}
