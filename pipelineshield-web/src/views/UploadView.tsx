import { useState } from 'react';
import type { ProblemDetail } from '../api/problem';
import type {
  AnalysisCreateResponse,
  CiFormat,
} from '../api/generated/ingestion';
import { PAYLOAD_MAX_BYTES } from '../api/generated/ingestion';
import {
  submitFile,
  submitText,
  confirmFormat,
} from '../api/uploadClient';
import { DropZone } from '../components/DropZone';
import { PasteEditor } from '../components/PasteEditor';
import { MaskingNotice } from '../components/MaskingNotice';
import { StageProgressPanel } from '../components/StageProgressPanel';
import { FormatConfirmationDialog } from '../components/FormatConfirmationDialog';
import { ErrorPanel } from '../components/ErrorPanel';

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

type ViewState =
  | { stage: 'idle'; inputError?: string }
  | { stage: 'submitting' }
  | {
      stage: 'awaiting-confirmation';
      analysisId: string;
      detectedFormat: string;
    }
  | { stage: 'done'; result: AnalysisCreateResponse }
  | { stage: 'error'; error: ProblemDetail };

type InputMode = 'file' | 'paste';

type InputSource =
  | { kind: 'none' }
  | { kind: 'file'; file: File }
  | { kind: 'text'; content: string };

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function UploadView() {
  const [viewState, setViewState] = useState<ViewState>({
    stage: 'idle',
  });

  const [inputMode, setInputMode] = useState<InputMode>('file');

  const [source, setSource] = useState<InputSource>({
    kind: 'none',
  });

  const [selectedFileName, setSelectedFileName] = useState<string | null>(
    null,
  );

  const isIdle = viewState.stage === 'idle';
  const isSubmitting = viewState.stage === 'submitting';
  const isAwaitingConfirmation =
    viewState.stage === 'awaiting-confirmation';
  const isDone = viewState.stage === 'done';

  const canSubmit =
    isIdle &&
    (source.kind === 'file' ||
      (source.kind === 'text' && source.content.trim().length > 0));

  const handleFileReady = (file: File) => {
    setSource({
      kind: 'file',
      file,
    });

    setSelectedFileName(file.name);

    setViewState({
      stage: 'idle',
    });
  };

  const handleFileError = (message: string) => {
    setViewState({
      stage: 'idle',
      inputError: message,
    });

    setSource({
      kind: 'none',
    });

    setSelectedFileName(null);
  };

  const handleTextChange = (text: string) => {
    setSource({
      kind: 'text',
      content: text,
    });

    if (isIdle && viewState.inputError) {
      setViewState({
        stage: 'idle',
      });
    }
  };

  const handleSubmit = async () => {
    if (!canSubmit) {
      return;
    }

    // Client-side size validation.
    // The server remains authoritative.
    if (source.kind === 'text') {
      const byteLen = new TextEncoder()
        .encode(source.content)
        .length;

      if (byteLen > PAYLOAD_MAX_BYTES) {
        setViewState({
          stage: 'idle',
          inputError: `Content exceeds 512 KB (${(
            byteLen / 1024
          ).toFixed(
            1,
          )} KB). The server revalidates authoritatively.`,
        });

        return;
      }
    }

    setViewState({
      stage: 'submitting',
    });

    const result =
      source.kind === 'file'
        ? await submitFile(source.file)
        : source.kind === 'text'
          ? await submitText(source.content)
          : null;

    if (result === null) {
      return;
    }

    if (!result.ok) {
      setViewState({
        stage: 'error',
        error: result.error,
      });

      return;
    }

    if (result.data.format_confirmation_required) {
      setViewState({
        stage: 'awaiting-confirmation',
        analysisId: result.data.analysis_id,
        detectedFormat: result.data.detected_format,
      });

      return;
    }

    setViewState({
      stage: 'done',
      result: result.data,
    });
  };

  const handleFormatConfirm = async (format: CiFormat) => {
    if (viewState.stage !== 'awaiting-confirmation') {
      return;
    }

    const { analysisId } = viewState;

    setViewState({
      stage: 'submitting',
    });

    const result = await confirmFormat(
      analysisId,
      format,
    );

    if (!result.ok) {
      setViewState({
        stage: 'error',
        error: result.error,
      });

      return;
    }

    setViewState({
      stage: 'done',
      result: {
        analysis_id: result.data.analysis_id,
        workspace_id: '',
        catalogue_version_id: '',
        created_at: '',
        detected_format: result.data.confirmed_format,
        format_confidence: 1,
        format_confirmation_required: false,
        coverage_report: {},
        advisory_disclaimer: '',
      },
    });
  };

  const handleReset = () => {
    setViewState({
      stage: 'idle',
    });

    setSource({
      kind: 'none',
    });

    setSelectedFileName(null);
  };

  return (
    <div
      className="mx-auto max-w-2xl px-4 py-8"
      data-testid="upload-view"
    >
      <header className="mb-6">
        <h1 className="text-2xl font-bold text-text-primary">
          Analyse pipeline definition
        </h1>

        <p className="mt-1 text-sm text-text-secondary">
          Upload or paste a CI/CD pipeline definition to run a
          security posture analysis.
        </p>
      </header>

      {/* Non-dismissible masking notice */}
      <MaskingNotice />

      <div className="mt-6 space-y-6">
        {/* Input form */}
        {isIdle && !isDone && (
          <>
            {/* Tab selector */}
            <div
              role="tablist"
              aria-label="Input method"
              className="flex gap-1 rounded-lg border border-border bg-surface-raised p-1"
            >
              {(['file', 'paste'] as const).map((mode) => (
                <button
                  key={mode}
                  role="tab"
                  aria-selected={inputMode === mode}
                  aria-controls={`tab-panel-${mode}`}
                  id={`tab-${mode}`}
                  type="button"
                  onClick={() => {
                    setInputMode(mode);

                    setSource({
                      kind: 'none',
                    });

                    setSelectedFileName(null);

                    setViewState({
                      stage: 'idle',
                    });
                  }}
                  className={[
                    'flex-1 rounded px-3 py-2 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-border-focus',
                    inputMode === mode
                      ? 'bg-surface text-text-primary shadow-sm'
                      : 'text-text-secondary hover:text-text-primary',
                  ].join(' ')}
                >
                  {mode === 'file'
                    ? 'Upload file'
                    : 'Paste text'}
                </button>
              ))}
            </div>

            {/* File tab */}
            <div
              role="tabpanel"
              id="tab-panel-file"
              aria-labelledby="tab-file"
              hidden={inputMode !== 'file'}
            >
              {inputMode === 'file' && (
                <>
                  <DropZone
                    onFileReady={handleFileReady}
                    onValidationError={handleFileError}
                    disabled={isSubmitting}
                  />

                  {selectedFileName != null && (
                    <p className="mt-2 flex items-center gap-1.5 text-sm text-text-secondary">
                      <span aria-hidden="true">📄</span>
                      <span>{selectedFileName}</span>
                    </p>
                  )}
                </>
              )}
            </div>

            {/* Paste tab */}
            <div
              role="tabpanel"
              id="tab-panel-paste"
              aria-labelledby="tab-paste"
              hidden={inputMode !== 'paste'}
            >
              {inputMode === 'paste' && (
                <PasteEditor
                  value={
                    source.kind === 'text'
                      ? source.content
                      : ''
                  }
                  onChange={handleTextChange}
                  disabled={isSubmitting}
                />
              )}
            </div>

            {/* Inline input error */}
            {viewState.stage === 'idle' &&
              viewState.inputError != null && (
                <p
                  role="alert"
                  className="text-sm text-error"
                >
                  {viewState.inputError}
                </p>
              )}

            {/* Submit */}
            <button
              type="button"
              onClick={handleSubmit}
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              className={[
                'w-full rounded px-4 py-3 text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-border-focus transition-colors',
                canSubmit
                  ? 'bg-brand text-brand-text hover:bg-brand-hover'
                  : 'bg-surface-overlay text-text-disabled cursor-not-allowed',
              ].join(' ')}
            >
              Submit for analysis
            </button>
          </>
        )}

        {/* Stage progress */}
        <StageProgressPanel active={isSubmitting} />

        {/* Format confirmation */}
        {isAwaitingConfirmation &&
          viewState.stage === 'awaiting-confirmation' && (
            <FormatConfirmationDialog
              open={true}
              detectedFormat={viewState.detectedFormat}
              onConfirm={handleFormatConfirm}
              onReset={handleReset}
            />
          )}

        {/* Success */}
        {isDone && viewState.stage === 'done' && (
          <div
            role="status"
            aria-label="Analysis complete"
            className="rounded-lg border border-success bg-success-surface p-5"
          >
            <div className="flex items-start gap-3">
              <span
                aria-hidden="true"
                className="mt-0.5 text-success"
              >
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
                    d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
              </span>

              <div>
                <p className="font-medium text-success">
                  Analysis complete
                </p>

                <p className="mt-1 text-sm text-text-secondary">
                  Format:{' '}
                  <strong className="text-text-primary">
                    {viewState.result.detected_format}
                  </strong>

                  {viewState.result.advisory_disclaimer && (
                    <>
                      {' · '}
                      {viewState.result.advisory_disclaimer}
                    </>
                  )}
                </p>

                {viewState.result.analysis_id && (
                  <p className="mt-1 text-xs text-text-secondary">
                    Analysis ID:{' '}
                    <code className="font-mono">
                      {viewState.result.analysis_id}
                    </code>
                  </p>
                )}
              </div>
            </div>

            <button
              type="button"
              onClick={handleReset}
              className="mt-4 rounded border border-border bg-surface px-4 py-2 text-sm font-medium text-text-primary hover:bg-surface-overlay focus:outline-none focus:ring-2 focus:ring-border-focus"
            >
              Analyse another definition
            </button>
          </div>
        )}

        {/* Error */}
        {viewState.stage === 'error' && (
          <ErrorPanel
            error={viewState.error}
            onRetry={handleReset}
          />
        )}
      </div>
    </div>
  );
}
