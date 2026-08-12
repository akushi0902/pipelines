/**
 * RFC 7807 Problem Details type and type guard.
 * All untrusted API payloads must be narrowed through isProblemDetail()
 * before being rendered or used.
 */

export interface ProblemDetail {
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

export function isProblemDetail(value: unknown): value is ProblemDetail {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v['type'] === 'string' &&
    typeof v['title'] === 'string' &&
    typeof v['status'] === 'number' &&
    typeof v['detail'] === 'string'
  );
}
