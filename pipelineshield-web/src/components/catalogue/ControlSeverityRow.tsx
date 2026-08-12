import * as Select from '@radix-ui/react-select';
import type { ControlDraft } from '../../state/catalogueReducer';
import type { ControlOut, Severity } from '../../api/types';

const SEVERITY_OPTIONS: Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
];

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

interface Props {
  control: ControlOut;
  draft: ControlDraft | undefined;
  fieldError: string | undefined;
  onSeverityChange: (controlId: string, severity: Severity) => void;
  disabled: boolean;
}

export function ControlSeverityRow({
  control,
  draft,
  fieldError,
  onSeverityChange,
  disabled,
}: Props) {
  const effectiveSeverity =
    draft?.severity !== undefined ? draft.severity : control.severity;
  const isDirty = draft?.severity !== undefined;
  const errorId = `error-ctrl-sev-${control.id}`;

  return (
    <tr
      className={`border-b last:border-b-0 transition-colors ${
        isDirty ? 'bg-amber-50' : 'hover:bg-gray-50'
      }`}
    >
      <td className="py-3 px-4 text-sm text-gray-700 font-mono">{control.id}</td>
      <td className="py-3 px-4">
        <div className="flex flex-col">
          <Select.Root
            value={effectiveSeverity}
            onValueChange={(v) => onSeverityChange(control.id, v as Severity)}
            disabled={disabled}
          >
            <Select.Trigger
              aria-label={`Severity for control ${control.id}`}
              aria-describedby={fieldError ? errorId : undefined}
              aria-invalid={fieldError !== undefined || undefined}
              className="inline-flex items-center justify-between gap-2 rounded border px-2 py-1 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-brand disabled:opacity-50 disabled:cursor-not-allowed w-32"
            >
              <Select.Value />
              <Select.Icon className="ml-1">▾</Select.Icon>
            </Select.Trigger>
            <Select.Portal>
              <Select.Content className="z-50 overflow-hidden rounded-md border bg-white shadow-md">
                <Select.Viewport>
                  {SEVERITY_OPTIONS.map((sev) => (
                    <Select.Item
                      key={sev}
                      value={sev}
                      className="relative flex items-center px-3 py-2 text-sm cursor-default select-none hover:bg-gray-100 focus:bg-gray-100 focus:outline-none data-[highlighted]:bg-gray-100"
                    >
                      <Select.ItemText>{SEVERITY_LABELS[sev]}</Select.ItemText>
                    </Select.Item>
                  ))}
                </Select.Viewport>
              </Select.Content>
            </Select.Portal>
          </Select.Root>
          {fieldError && (
            <p id={errorId} role="alert" className="mt-1 text-xs text-red-600">
              {fieldError}
            </p>
          )}
        </div>
      </td>
      <td className="py-3 px-4 text-sm text-gray-500">
        {control.reference_tools.join(', ') || '—'}
      </td>
    </tr>
  );
}
