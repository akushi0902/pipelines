import { useRef, useState } from 'react';
import { PAYLOAD_MAX_BYTES } from '../api/generated/ingestion';

interface DropZoneProps {
  onFileReady: (file: File) => void;
  onValidationError: (message: string) => void;
  disabled?: boolean;
}

const SIZE_LIMIT_KB = PAYLOAD_MAX_BYTES / 1024;

async function isBinaryFile(file: File): Promise<boolean> {
  const slice = file.slice(0, 4096);
  const buffer = await slice.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  for (const byte of bytes) {
    if (byte === 0) return true;
  }
  return false;
}

export function DropZone({ onFileReady, onValidationError, disabled = false }: DropZoneProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const processFile = async (file: File) => {
    if (file.size === 0) {
      onValidationError('The file is empty. Please select a non-empty pipeline definition file.');
      return;
    }
    if (file.size > PAYLOAD_MAX_BYTES) {
      onValidationError(
        `File exceeds ${SIZE_LIMIT_KB} KB (${(file.size / 1024).toFixed(1)} KB). ` +
          'This is a UX convenience check — the server revalidates authoritatively.',
      );
      return;
    }
    const binary = await isBinaryFile(file);
    if (binary) {
      onValidationError(
        'The file appears to be binary. Only text-based pipeline definitions (YAML, JSON) are accepted.',
      );
      return;
    }
    onFileReady(file);
  };

  const handleDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (disabled) return;

    const { files } = e.dataTransfer;
    if (!files || files.length === 0) return;
    if (files.length > 1) {
      onValidationError('Only a single file can be uploaded at a time. Please drop one file.');
      return;
    }
    const file = files[0];
    if (!file) return;
    await processFile(file);
  };

  const handleInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    await processFile(file);
    // Reset so the same file can be re-selected
    e.target.value = '';
  };

  return (
    <div
      role="region"
      aria-label="File drop zone"
      className={[
        'relative flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-10 transition-colors',
        isDragOver
          ? 'border-dropzone-border bg-dropzone-active'
          : 'border-border bg-surface-raised',
        disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer',
      ].join(' ')}
      onDrop={handleDrop}
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setIsDragOver(true);
      }}
      onDragLeave={() => setIsDragOver(false)}
      onDragEnd={() => setIsDragOver(false)}
      onClick={() => !disabled && inputRef.current?.click()}
      onKeyDown={(e) => {
        if ((e.key === 'Enter' || e.key === ' ') && !disabled) {
          e.preventDefault();
          inputRef.current?.click();
        }
      }}
      tabIndex={disabled ? -1 : 0}
    >
      <svg
        aria-hidden="true"
        className="h-10 w-10 text-text-secondary"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"
        />
      </svg>
      <p className="text-sm text-text-primary font-medium">
        Drag and drop a pipeline definition here
      </p>
      <p className="text-xs text-text-secondary">
        YAML or JSON · maximum {SIZE_LIMIT_KB} KB ·{' '}
        <span className="underline">server revalidates authoritatively</span>
      </p>
      <label className="mt-1 cursor-pointer rounded border border-border bg-surface px-3 py-1.5 text-sm text-text-primary hover:bg-surface-overlay focus-within:ring-2 focus-within:ring-border-focus">
        <span>Browse file</span>
        <input
          ref={inputRef}
          type="file"
          accept=".yml,.yaml,.json,.txt"
          aria-label="Upload pipeline definition file"
          className="sr-only"
          disabled={disabled}
          onChange={handleInputChange}
          tabIndex={-1}
        />
      </label>
    </div>
  );
}
