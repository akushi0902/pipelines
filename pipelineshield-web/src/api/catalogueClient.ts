import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type {
  ApiErrorBody,
  AuditEventsResponse,
  CatalogueGetResponse,
  CataloguePatchRequest,
  CataloguePatchResponse,
} from './types';

const BASE = '/api/v1';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: ApiErrorBody,
  ) {
    super(body.detail ?? `HTTP ${status}`);
    this.name = 'ApiError';
  }
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}

async function apiFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  });
  if (!resp.ok) {
    const raw: unknown = await resp.json().catch(() => ({
      type: 'unknown',
      title: 'Unknown error',
      status: resp.status,
      detail: resp.statusText,
      errors: [],
    }));
    const body = raw as ApiErrorBody;
    throw new ApiError(resp.status, body);
  }
  return resp.json() as Promise<T>;
}

export const CATALOGUE_QUERY_KEY = ['catalogue', 'active'] as const;
export const AUDIT_QUERY_KEY = ['catalogue', 'audit'] as const;

export function useCatalogue() {
  return useQuery<CatalogueGetResponse, ApiError>({
    queryKey: CATALOGUE_QUERY_KEY,
    queryFn: () => apiFetch<CatalogueGetResponse>(`${BASE}/catalogue`),
    retry: (failureCount, err) =>
      isApiError(err) && err.status < 500 ? false : failureCount < 2,
  });
}

export function useCatalogueAuditHistory() {
  return useQuery<AuditEventsResponse, ApiError>({
    queryKey: AUDIT_QUERY_KEY,
    queryFn: () =>
      apiFetch<AuditEventsResponse>(
        `${BASE}/audit-events?resource_type=control_catalogue_version&limit=50`,
      ),
    retry: false,
  });
}

export function usePatchCatalogue() {
  const qc = useQueryClient();
  return useMutation<CataloguePatchResponse, ApiError, CataloguePatchRequest>({
    mutationFn: (body) =>
      apiFetch<CataloguePatchResponse>(`${BASE}/catalogue`, {
        method: 'PATCH',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['catalogue'] });
    },
    retry: false,
  });
}
