import * as Dialog from '@radix-ui/react-dialog';
import type { DiffLine } from '../../state/catalogueReducer';

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  diff: DiffLine[];
  triggerRef?: React.RefObject<HTMLButtonElement>;
}

function renderValue(v: unknown): string {
  if (Array.isArray(v)) return (v as unknown[]).map(String).join(', ');
  return String(v);
}

export function CatalogueDiffDialog({ open, onOpenChange, diff }: Props) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 w-full max-w-2xl -translate-x-1/2 -translate-y-1/2 rounded-xl bg-white p-6 shadow-xl focus:outline-none"
          aria-describedby="diff-dialog-description"
        >
          <Dialog.Title className="text-lg font-semibold text-gray-900">
            Staged Changes Preview
          </Dialog.Title>
          <Dialog.Description
            id="diff-dialog-description"
            className="mt-1 text-sm text-gray-500"
          >
            Review all proposed changes before submitting. Each row shows the
            field path, current value, and the value you have staged.
          </Dialog.Description>

          {diff.length === 0 ? (
            <p className="mt-4 text-sm text-gray-500 italic">No staged changes.</p>
          ) : (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-sm border-collapse">
                <thead>
                  <tr className="border-b text-left">
                    <th scope="col" className="py-2 pr-4 font-medium text-gray-700">
                      Field
                    </th>
                    <th scope="col" className="py-2 pr-4 font-medium text-gray-700">
                      Current
                    </th>
                    <th scope="col" className="py-2 font-medium text-gray-700">
                      Proposed
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {diff.map((line) => (
                    <tr key={line.path} className="border-b last:border-b-0">
                      <td className="py-2 pr-4 font-mono text-xs text-gray-600">
                        {line.path}
                      </td>
                      <td className="py-2 pr-4 text-gray-500 line-through">
                        {renderValue(line.current_value)}
                      </td>
                      <td className="py-2 text-green-700 font-medium">
                        {renderValue(line.proposed_value)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="mt-6 flex justify-end">
            <Dialog.Close asChild>
              <button
                className="rounded-md bg-gray-100 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-brand"
                autoFocus
              >
                Close
              </button>
            </Dialog.Close>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
