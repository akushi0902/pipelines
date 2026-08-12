import { useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import type { CiFormat } from '../api/generated/ingestion';
import { CI_FORMAT_LABELS, VALID_CI_FORMATS } from '../api/generated/ingestion';

interface FormatConfirmationDialogProps {
  open: boolean;
  detectedFormat: string;
  onConfirm: (format: CiFormat) => void;
  onReset: () => void;
}

export function FormatConfirmationDialog({
  open,
  detectedFormat,
  onConfirm,
  onReset,
}: FormatConfirmationDialogProps) {
  const defaultFormat: CiFormat =
    VALID_CI_FORMATS.includes(detectedFormat as CiFormat)
      ? (detectedFormat as CiFormat)
      : 'github_actions';

  const [selected, setSelected] = useState<CiFormat>(defaultFormat);

  const handleConfirm = () => {
    onConfirm(selected);
  };

  return (
    <Dialog.Root open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/50" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-surface p-6 shadow-lg focus:outline-none"
          aria-describedby="format-dialog-description"
          onInteractOutside={(e) => e.preventDefault()}
          onEscapeKeyDown={(e) => e.preventDefault()}
        >
          <Dialog.Title className="text-lg font-semibold text-text-primary">
            Confirm pipeline format
          </Dialog.Title>
          <Dialog.Description
            id="format-dialog-description"
            className="mt-2 text-sm text-text-secondary"
          >
            The detector could not identify the format with high confidence
            {detectedFormat !== 'unknown' && (
              <> (detected: <strong className="text-text-primary">{detectedFormat}</strong>)</>
            )}
            . Please confirm the correct format so the analysis can apply the right rule set.
          </Dialog.Description>

          <div className="mt-5">
            <label
              htmlFor="format-select"
              className="block text-sm font-medium text-text-primary mb-1.5"
            >
              Pipeline format
            </label>
            <select
              id="format-select"
              value={selected}
              onChange={(e) => {
                const val = e.target.value;
                if (VALID_CI_FORMATS.includes(val as CiFormat)) {
                  setSelected(val as CiFormat);
                }
              }}
              className="w-full rounded border border-border bg-surface px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-border-focus"
            >
              {VALID_CI_FORMATS.map((fmt) => (
                <option key={fmt} value={fmt}>
                  {CI_FORMAT_LABELS[fmt]}
                </option>
              ))}
            </select>
          </div>

          <div className="mt-6 flex justify-end gap-3">
            <button
              type="button"
              onClick={onReset}
              className="rounded border border-border bg-surface px-4 py-2 text-sm font-medium text-text-primary hover:bg-surface-overlay focus:outline-none focus:ring-2 focus:ring-border-focus"
            >
              Start over
            </button>
            <button
              type="button"
              onClick={handleConfirm}
              className="rounded bg-brand px-4 py-2 text-sm font-medium text-brand-text hover:bg-brand-hover focus:outline-none focus:ring-2 focus:ring-border-focus"
            >
              Confirm format
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
