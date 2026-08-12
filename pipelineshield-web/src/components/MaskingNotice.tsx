/**
 * Non-dismissible notice explaining that secret-shaped values are masked
 * before storage, logging and AI processing. Must be visible at all times
 * when the upload form is rendered.
 */
export function MaskingNotice() {
  return (
    <div
      role="note"
      aria-label="Secret masking notice"
      className="flex gap-3 rounded-lg border border-info bg-info-surface px-4 py-3"
    >
      <span aria-hidden="true" className="mt-0.5 shrink-0 text-info">
        <svg
          className="h-5 w-5"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      </span>
      <div className="text-sm text-text-primary">
        <p className="font-medium">Secret masking active</p>
        <p className="mt-0.5 text-text-secondary">
          Secret-shaped values (tokens, keys, passwords) are automatically detected and
          masked before storage, logging, and AI processing. No plaintext secret leaves
          your browser.
        </p>
      </div>
    </div>
  );
}
