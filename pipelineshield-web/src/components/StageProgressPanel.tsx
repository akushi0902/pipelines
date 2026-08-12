import { useEffect, useState } from 'react';

const STAGES = [
  'Uploading definition',
  'Masking secrets',
  'Detecting format',
  'Running analysis',
  'Scoring posture',
] as const;

type StageName = (typeof STAGES)[number];

// Approximate durations for each stage transition (ms)
const STAGE_ADVANCE_MS = [1000, 2000, 3000, 9000] as const;

interface StageProgressPanelProps {
  active: boolean;
}

export function StageProgressPanel({ active }: StageProgressPanelProps) {
  const [currentIdx, setCurrentIdx] = useState(0);
  const [announcement, setAnnouncement] = useState<string>('');

  useEffect(() => {
    if (!active) {
      setCurrentIdx(0);
      setAnnouncement('');
      return;
    }

    setCurrentIdx(0);
    setAnnouncement(STAGES[0] ?? 'Processing');

    let idx = 0;
    let timer: ReturnType<typeof setTimeout>;

    const advance = () => {
      idx++;
      if (idx < STAGES.length) {
        setCurrentIdx(idx);
        setAnnouncement(STAGES[idx] ?? 'Processing');
        const delay = STAGE_ADVANCE_MS[idx - 1];
        if (delay != null && idx < STAGE_ADVANCE_MS.length + 1) {
          timer = setTimeout(advance, STAGE_ADVANCE_MS[idx] ?? 3000);
        }
      }
    };

    const firstDelay = STAGE_ADVANCE_MS[0];
    if (firstDelay != null) {
      timer = setTimeout(advance, firstDelay);
    }

    return () => clearTimeout(timer);
  }, [active]);

  if (!active) return null;

  return (
    <div
      className="rounded-lg border border-border bg-surface-raised p-5"
      role="status"
      aria-label="Analysis progress"
    >
      {/* Hidden live region for screen reader announcements */}
      <p className="sr-only" aria-live="polite" aria-atomic="true">
        {announcement}
      </p>

      <p className="mb-4 text-sm font-medium text-text-primary">
        Analysing your pipeline definition…
      </p>
      <p className="mb-5 text-xs text-text-secondary">
        Typical analysis takes 10–18 s. Please keep this tab open.
      </p>

      <ol className="space-y-3" aria-label="Analysis stages">
        {STAGES.map((stage, idx) => {
          const done = idx < currentIdx;
          const inProgress = idx === currentIdx;
          const pending = idx > currentIdx;
          const stageName: StageName = stage;

          return (
            <li key={stageName} className="flex items-center gap-3">
              {/* Icon */}
              <span
                aria-hidden="true"
                className={[
                  'flex h-6 w-6 shrink-0 items-center justify-center rounded-full',
                  done ? 'bg-success text-surface' : '',
                  inProgress ? 'bg-brand text-brand-text' : '',
                  pending ? 'bg-surface-overlay text-text-disabled' : '',
                ].join(' ')}
              >
                {done && (
                  <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                  </svg>
                )}
                {inProgress && (
                  <svg
                    className="h-3.5 w-3.5 animate-spin"
                    fill="none"
                    viewBox="0 0 24 24"
                    role="presentation"
                  >
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                    />
                  </svg>
                )}
                {pending && <span className="h-2 w-2 rounded-full bg-text-disabled" />}
              </span>

              {/* Label */}
              <span
                className={[
                  'text-sm',
                  done ? 'text-success' : '',
                  inProgress ? 'text-text-primary font-medium' : '',
                  pending ? 'text-text-disabled' : '',
                ].join(' ')}
              >
                {stageName}
                {done && <span className="sr-only"> — complete</span>}
                {inProgress && <span className="sr-only"> — in progress</span>}
                {pending && <span className="sr-only"> — pending</span>}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
