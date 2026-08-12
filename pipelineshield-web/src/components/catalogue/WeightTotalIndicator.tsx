interface Props {
  total: number;
}

export function WeightTotalIndicator({ total }: Props) {
  const isValid = total === 100;

  const statusText = isValid
    ? 'Weight total is exactly 100 — valid'
    : `Weight total is ${total} — must equal 100`;

  return (
    <div
      className="flex items-center gap-2"
      aria-live="polite"
      aria-atomic="true"
    >
      <span
        aria-hidden="true"
        className={`text-lg font-bold ${
          isValid ? 'text-green-700' : 'text-red-700'
        }`}
      >
        {isValid ? '✓' : '✗'}
      </span>

      <span
        className={`text-sm font-semibold ${
          isValid ? 'text-green-700' : 'text-red-700'
        }`}
      >
        {`Weight total: ${total}`}
      </span>

      <span
        className={`text-sm font-normal ${
          isValid ? 'text-green-700' : 'text-red-700'
        }`}
      >
        {isValid ? '(valid)' : '(must equal 100)'}
      </span>

      <span className="sr-only">{statusText}</span>
    </div>
  );
}
