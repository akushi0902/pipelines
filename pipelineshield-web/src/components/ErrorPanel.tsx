import type { ProblemDetail } from '../api/problem';

interface ErrorPanelProps {
  error: ProblemDetail;
  onRetry?: () => void;
}

export function ErrorPanel({ error, onRetry }: ErrorPanelProps) {
  const isTimeout = error.status === 408;
  const isAuth = error.status === 401;

  return (
    <div
      role="alert"
      aria-label="Submission error"
      className="rounded-lg border border-error bg-error-surface p-5"
    >
      <div className="flex items-start gap-3">
        <span aria-hidden="true" className="mt-0.5 shrink-0 text-error">
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
            />
          </svg>
        </span>
        <div className="flex-1 min-w-0">
          <p className="font-medium text-error">{error.title}</p>
          <p className="mt-1 text-sm text-text-primary break-words">{error.detail}</p>

          {error.constraint != null && (
            <p className="mt-1 text-xs text-text-secondary">
              Constraint: <code className="font-mono">{error.constraint}</code>
            </p>
          )}

          {(error.parse_line != null || error.parse_column != null) && (
            <p className="mt-1 text-xs text-text-secondary">
              Parse location: line {error.parse_line ?? '?'}, column {error.parse_column ?? '?'}
            </p>
          )}

          {error.correlation_id != null && (
            <p className="mt-2 text-xs text-text-secondary">
              Correlation ID:{' '}
              <code className="font-mono break-all">{error.correlation_id}</code>
            </p>
          )}

          {isAuth && (
            <p className="mt-2 text-sm text-text-primary">
              Your session has expired. Please{' '}
              <a href="/auth/login" className="underline text-brand hover:text-brand-hover">
                sign in again
              </a>{' '}
              to continue.
            </p>
          )}
        </div>
      </div>

      {(onRetry != null || isTimeout) && (
        <div className="mt-4 flex gap-3">
          {onRetry != null && (
            <button
              type="button"
              onClick={onRetry}
              className="rounded border border-border bg-surface px-4 py-2 text-sm font-medium text-text-primary hover:bg-surface-overlay focus:outline-none focus:ring-2 focus:ring-border-focus"
            >
              {isTimeout ? 'Retry' : 'Try again'}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
