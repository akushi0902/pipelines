import { PAYLOAD_MAX_BYTES } from '../api/generated/ingestion';

interface PasteEditorProps {
  value: string;
  onChange: (text: string) => void;
  onSizeWarning?: (overLimit: boolean) => void;
  disabled?: boolean;
  id?: string;
}

const SIZE_LIMIT_KB = PAYLOAD_MAX_BYTES / 1024;

export function PasteEditor({
  value,
  onChange,
  onSizeWarning,
  disabled = false,
  id = 'paste-editor',
}: PasteEditorProps) {
  const byteLen = new TextEncoder().encode(value).length;
  const overLimit = byteLen > PAYLOAD_MAX_BYTES;

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const next = e.target.value;
    const nextLen = new TextEncoder().encode(next).length;
    onChange(next);
    onSizeWarning?.(nextLen > PAYLOAD_MAX_BYTES);
  };

  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-sm font-medium text-text-primary">
        Paste pipeline definition
      </label>
      <textarea
        id={id}
        value={value}
        onChange={handleChange}
        disabled={disabled}
        rows={12}
        spellCheck={false}
        aria-label="Paste pipeline definition"
        aria-describedby={overLimit ? `${id}-size-warning` : undefined}
        placeholder="Paste your GitHub Actions, GitLab CI, or Jenkins pipeline YAML here…"
        className={[
          'w-full resize-y rounded border p-3 font-mono text-sm text-text-primary bg-surface-raised focus:outline-none focus:ring-2',
          overLimit
            ? 'border-error focus:ring-error'
            : 'border-border focus:ring-border-focus',
          disabled ? 'opacity-50 cursor-not-allowed' : '',
        ].join(' ')}
      />
      {overLimit && (
        <p
          id={`${id}-size-warning`}
          role="alert"
          className="text-xs text-error"
        >
          Content exceeds {SIZE_LIMIT_KB} KB ({(byteLen / 1024).toFixed(1)} KB). This is a UX
          convenience check — the server revalidates authoritatively.
        </p>
      )}
      {!overLimit && value.length > 0 && (
        <p className="text-xs text-text-secondary text-right">
          {(byteLen / 1024).toFixed(1)} / {SIZE_LIMIT_KB} KB
        </p>
      )}
    </div>
  );
}
