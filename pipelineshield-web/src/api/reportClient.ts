import { apiFetch, type ApiResult } from './client';
import type { AnalysisReport } from './generated/report';

const BASE = '/api/v1';

export async function fetchReport(analysisId: string): Promise<ApiResult<AnalysisReport>> {
  return apiFetch<AnalysisReport>(`${BASE}/analyses/${encodeURIComponent(analysisId)}`);
}
