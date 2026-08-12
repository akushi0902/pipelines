/**
 * Admin API client — role bindings and group persona mappings.
 *
 * Uses the same `apiFetch` pattern as catalogueClient with ApiError for 4xx/5xx.
 * The server is authoritative; client-side persona checks are cosmetic only.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { UseQueryResult, UseMutationResult } from '@tanstack/react-query';
import type {
  ApiErrorBody,
  ChangeBindingRequest,
  GrantBindingRequest,
  GrantBindingResponse,
  GroupPersonaMappingListResponse,
  RoleBindingListResponse,
} from './types';
import { ApiError } from './catalogueClient';

export type { ApiError };

// ---------------------------------------------------------------------------
// Group Persona Mapping Types
// ---------------------------------------------------------------------------
// Defined locally because GroupPersonaMappingUpsertRequest is not exported
// from ./types.

export interface GroupPersonaMappingUpsertItem {
  idp_group: string;
  workspace_id: string;
  persona: string;
  precedence?: number;
}

export interface GroupPersonaMappingUpsertRequest {
  items: GroupPersonaMappingUpsertItem[];
}

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------

async function apiFetch<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const resp = await fetch(path, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!resp.ok) {
    const body = (await resp.json().catch(() => ({
      type: 'about:blank',
      title: 'Error',
      status: resp.status,
      detail: resp.statusText,
      errors: [],
    }))) as ApiErrorBody;

    throw new ApiError(resp.status, body);
  }

  if (resp.status === 204) {
    return undefined as unknown as T;
  }

  return resp.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Role Bindings
// ---------------------------------------------------------------------------

export function useRoleBindings(
  workspaceId: string,
): UseQueryResult<RoleBindingListResponse, ApiError> {
  return useQuery<RoleBindingListResponse, ApiError>({
    queryKey: ['role-bindings', workspaceId],
    queryFn: () =>
      apiFetch<RoleBindingListResponse>(
        `/api/v1/workspaces/${workspaceId}/role-bindings`,
      ),
    retry: (count, err) => err.status >= 500 && count < 2,
  });
}

export function useGrantBinding(
  workspaceId: string,
): UseMutationResult<GrantBindingResponse, ApiError, GrantBindingRequest> {
  const qc = useQueryClient();

  return useMutation<GrantBindingResponse, ApiError, GrantBindingRequest>({
    mutationFn: (body) =>
      apiFetch<GrantBindingResponse>(
        `/api/v1/workspaces/${workspaceId}/role-bindings`,
        {
          method: 'POST',
          body: JSON.stringify(body),
        },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: ['role-bindings', workspaceId],
      });
    },
  });
}

export function useChangeBinding(
  workspaceId: string,
  bindingId: string,
): UseMutationResult<GrantBindingResponse, ApiError, ChangeBindingRequest> {
  const qc = useQueryClient();

  return useMutation<GrantBindingResponse, ApiError, ChangeBindingRequest>({
    mutationFn: (body) =>
      apiFetch<GrantBindingResponse>(
        `/api/v1/workspaces/${workspaceId}/role-bindings/${bindingId}`,
        {
          method: 'PATCH',
          body: JSON.stringify(body),
        },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: ['role-bindings', workspaceId],
      });
    },
  });
}

export function useRevokeBinding(
  workspaceId: string,
): UseMutationResult<void, ApiError, string> {
  const qc = useQueryClient();

  return useMutation<void, ApiError, string>({
    mutationFn: (bindingId) =>
      apiFetch<void>(
        `/api/v1/workspaces/${workspaceId}/role-bindings/${bindingId}`,
        {
          method: 'DELETE',
        },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: ['role-bindings', workspaceId],
      });
    },
  });
}

// ---------------------------------------------------------------------------
// Group Persona Mappings
// ---------------------------------------------------------------------------

export function useGroupPersonaMappings(): UseQueryResult<
  GroupPersonaMappingListResponse,
  ApiError
> {
  return useQuery<GroupPersonaMappingListResponse, ApiError>({
    queryKey: ['group-persona-mappings'],
    queryFn: () =>
      apiFetch<GroupPersonaMappingListResponse>(
        '/api/v1/group-persona-mappings',
      ),
    retry: (count, err) => err.status >= 500 && count < 2,
  });
}

export function useUpsertGroupPersonaMappings(): UseMutationResult<
  GroupPersonaMappingListResponse,
  ApiError,
  GroupPersonaMappingUpsertRequest
> {
  const qc = useQueryClient();

  return useMutation<
    GroupPersonaMappingListResponse,
    ApiError,
    GroupPersonaMappingUpsertRequest
  >({
    mutationFn: (body) =>
      apiFetch<GroupPersonaMappingListResponse>(
        '/api/v1/group-persona-mappings',
        {
          method: 'PUT',
          body: JSON.stringify(body),
        },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: ['group-persona-mappings'],
      });
    },
  });
}
