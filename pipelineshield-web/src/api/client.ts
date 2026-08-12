/**
 * Generic API client: credentialed fetch with 45 s AbortController timeout.
 * Returns a discriminated-union result so callers handle errors explicitly.
 */

import type { ProblemDetail } from './problem';
import { isProblemDetail } from './problem';

export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: ProblemDetail };

const TIMEOUT_MS = 45_000;

export async function apiFetch<T>(
  url: string,
  init?: RequestInit,
): Promise<ApiResult<T>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      ...init,
      credentials: 'include',
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (response.ok) {
      const data = (await response.json()) as T;
      return { ok: true, data };
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = null;
    }

    if (isProblemDetail(body)) {
      return { ok: false, error: body };
    }

    return {
      ok: false,
      error: {
        type: 'about:blank',
        title: 'Unexpected Error',
        status: response.status,
        detail: `HTTP ${response.status} — ${response.statusText}`,
      },
    };
  } catch (err) {
    clearTimeout(timer);
    const isTimeout = err instanceof DOMException && err.name === 'AbortError';
    return {
      ok: false,
      error: {
        type: 'about:blank',
        title: isTimeout ? 'Request Timed Out' : 'Network Error',
        status: isTimeout ? 408 : 0,
        detail: isTimeout
          ? 'The request exceeded the 45 s limit. Please try again.'
          : 'A network error occurred. Check your connection and retry.',
      },
    };
  }
}
