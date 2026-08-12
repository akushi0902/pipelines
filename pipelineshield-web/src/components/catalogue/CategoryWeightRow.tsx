import * as Switch from '@radix-ui/react-switch';
import type { CategoryDraft } from '../../state/catalogueReducer';
import type { CategoryOut } from '../../api/types';

interface Props {
  category: CategoryOut;
  draft: CategoryDraft | undefined;
  fieldError: string | undefined;
  onWeightChange: (categoryId: string, weight: number) => void;
  onToggleEnabled: (categoryId: string) => void;
  disabled: boolean;
}

export function CategoryWeightRow({
  category,
  draft,
  fieldError,
  onWeightChange,
  onToggleEnabled,
  disabled,
}: Props) {
  const effectiveWeight = draft?.weight !== undefined ? draft.weight : category.weight;
  const effectiveEnabled =
    draft?.enabled !== undefined ? draft.enabled : category.enabled;
  const isDirty =
    draft !== undefined &&
    (draft.weight !== undefined || draft.enabled !== undefined);
  const errorId = `error-cat-weight-${category.id}`;
  const inputId = `weight-${category.id}`;

  return (
    <tr
      className={`border-b last:border-b-0 transition-colors ${
        isDirty ? 'bg-amber-50' : 'hover:bg-gray-50'
      }`}
    >
      <td className="py-3 px-4 font-medium text-gray-900">
        {/* React JSX auto-escapes string content — safe against XSS */}
        {category.name}
        {isDirty && (
          <span className="ml-2 text-xs text-amber-700 font-normal" aria-label="modified">
            ●
          </span>
        )}
      </td>
      <td className="py-3 px-4">
        <div className="flex flex-col">
          <div className="flex items-center gap-2">
            <label htmlFor={inputId} className="sr-only">
              Weight for {category.name}
            </label>
            <input
              id={inputId}
              type="number"
              aria-describedby={fieldError ? errorId : undefined}
              aria-invalid={fieldError !== undefined || undefined}
              value={effectiveWeight}
              min={0}
              max={100}
              disabled={disabled || !effectiveEnabled}
              onChange={(e) => {
                const v = parseInt(e.target.value, 10);
                if (!isNaN(v)) onWeightChange(category.id, v);
              }}
              className="w-20 border rounded px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-brand disabled:bg-gray-100 disabled:cursor-not-allowed"
            />
          </div>
          {fieldError && (
            <p
              id={errorId}
              role="alert"
              className="mt-1 text-xs text-red-600"
            >
              {fieldError}
            </p>
          )}
        </div>
      </td>
      <td className="py-3 px-4">
        <div className="flex items-center gap-2">
          <Switch.Root
            checked={effectiveEnabled}
            onCheckedChange={() => onToggleEnabled(category.id)}
            disabled={disabled}
            aria-label={`${effectiveEnabled ? 'Disable' : 'Enable'} ${category.name}`}
            className="relative h-5 w-9 rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-brand focus:ring-offset-1 data-[state=checked]:bg-brand data-[state=unchecked]:bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Switch.Thumb className="block h-3 w-3 transform rounded-full bg-white shadow transition-transform data-[state=checked]:translate-x-5 data-[state=unchecked]:translate-x-1" />
          </Switch.Root>
          <span className="text-sm text-gray-700" aria-hidden="true">
            {effectiveEnabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
      </td>
    </tr>
  );
}
