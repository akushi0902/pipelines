import { useEffect, useReducer, useRef, useState } from 'react';
import {
  useCatalogue,
  useCatalogueAuditHistory,
  usePatchCatalogue,
  isApiError,
} from '../api/catalogueClient';
import {
  catalogueReducer,
  INITIAL_STATE,
  selectCanSubmit,
  selectChangesForApi,
  selectDiff,
  selectEnabledWeightTotal,
} from '../state/catalogueReducer';
import type { Severity } from '../api/types';
import { CategoryWeightRow } from '../components/catalogue/CategoryWeightRow';
import { ControlSeverityRow } from '../components/catalogue/ControlSeverityRow';
import { WeightTotalIndicator } from '../components/catalogue/WeightTotalIndicator';
import { CatalogueDiffDialog } from '../components/catalogue/CatalogueDiffDialog';
import { CatalogueVersionHistory } from '../components/catalogue/CatalogueVersionHistory';
import { PermissionDeniedState } from '../components/catalogue/PermissionDeniedState';

export function CatalogueAdminView() {
  const [state, dispatch] = useReducer(catalogueReducer, INITIAL_STATE);
  const [diffOpen, setDiffOpen] = useState(false);
  const diffTriggerRef = useRef<HTMLButtonElement>(null);

  const catalogueQuery = useCatalogue();
  const auditQuery = useCatalogueAuditHistory();
  const patchMutation = usePatchCatalogue();

  // Sync fetched catalogue into reducer when version changes
  const fetchedCatalogue = catalogueQuery.data;
  useEffect(() => {
    if (
      fetchedCatalogue &&
      state.baseSnapshot?.version !== fetchedCatalogue.version
    ) {
      dispatch({ type: 'LOAD_SUCCESS', payload: fetchedCatalogue });
    }
  // Only re-run when fetchedCatalogue changes — intentionally exclude state.baseSnapshot
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fetchedCatalogue]);

  // -------------------------------------------------------------------------
  // Derived state
  // -------------------------------------------------------------------------
  const weightTotal = selectEnabledWeightTotal(state);
  const diff = selectDiff(state);
  const canSubmit = selectCanSubmit(state);
  const base = state.baseSnapshot;
  const isFetchLoading = catalogueQuery.isLoading;

  // -------------------------------------------------------------------------
  // Handlers
  // -------------------------------------------------------------------------
  function handleWeightChange(categoryId: string, weight: number) {
    dispatch({ type: 'STAGE_CATEGORY_WEIGHT', categoryId, weight });
  }

  function handleToggleEnabled(categoryId: string) {
    dispatch({ type: 'TOGGLE_CATEGORY_ENABLED', categoryId });
  }

  function handleSeverityChange(controlId: string, severity: Severity) {
    dispatch({ type: 'STAGE_CONTROL_SEVERITY', controlId, severity });
  }

  function handleSubmit() {
    if (!base || !canSubmit) return;
    const changes = selectChangesForApi(state);
    dispatch({ type: 'SUBMIT_START' });
    patchMutation.mutate(
      {
        base_version: base.version,
        rationale: state.rationale,
        changes,
      },
      {
        onSuccess: (data) => {
          dispatch({
            type: 'SUBMIT_SUCCESS',
            version: data.version,
            newSnapshot: data.snapshot,
          });
        },
        onError: (err) => {
          if (!isApiError(err)) {
            dispatch({
              type: 'SUBMIT_FAILURE_NETWORK',
              error: 'Network error. Please check your connection and retry.',
            });
            return;
          }
          if (err.status === 403) {
            dispatch({ type: 'SUBMIT_FAILURE_403' });
          } else if (err.status === 409) {
            void catalogueQuery.refetch().then((result) => {
              if (result.data) {
                dispatch({
                  type: 'SUBMIT_FAILURE_409',
                  newBase: result.data,
                });
              }
            });
          } else if (err.status === 400) {
            const fieldErrors: Record<string, string> = {};
            for (const fe of err.body.errors) {
              fieldErrors[fe.field] = fe.message;
            }
            dispatch({
              type: 'SUBMIT_FAILURE_400',
              fieldErrors,
              detail: err.body.detail,
            });
          } else {
            dispatch({
              type: 'SUBMIT_FAILURE_NETWORK',
              error: err.message,
            });
          }
        },
      },
    );
  }

  // -------------------------------------------------------------------------
  // Loading skeleton
  // -------------------------------------------------------------------------
  if (isFetchLoading) {
    return (
      <div
        className="mx-auto max-w-4xl px-4 py-8"
        aria-busy="true"
        aria-label="Loading catalogue"
      >
        <div className="mb-6 h-8 w-64 animate-pulse rounded bg-gray-200" />
        {[...Array(5)].map((_, i) => (
          <div key={i} className="mb-3 h-12 animate-pulse rounded bg-gray-100" />
        ))}
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Load error
  // -------------------------------------------------------------------------
  if (catalogueQuery.isError) {
    const err = catalogueQuery.error;
    if (isApiError(err) && err.status === 403) {
      return (
        <div className="mx-auto max-w-4xl px-4 py-8">
          <PermissionDeniedState />
        </div>
      );
    }
    return (
      <div
        className="mx-auto max-w-4xl px-4 py-8"
        role="alert"
      >
        <div className="rounded border border-red-300 bg-red-50 p-6">
          <h2 className="font-semibold text-red-800">Failed to load catalogue</h2>
          <p className="mt-2 text-sm text-red-700">
            {isApiError(err) ? err.message : 'Unexpected error'}
          </p>
          <button
            onClick={() => void catalogueQuery.refetch()}
            className="mt-3 rounded bg-red-100 px-4 py-2 text-sm font-medium text-red-800 hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-red-400"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Permission denied (via submit 403)
  // -------------------------------------------------------------------------
  if (state.permissionDenied) {
    return (
      <div className="mx-auto max-w-4xl px-4 py-8">
        <PermissionDeniedState />
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Main view
  // -------------------------------------------------------------------------
  return (
    <div className="mx-auto max-w-4xl px-4 py-8" data-testid="catalogue-admin-view">
      {/* Header */}
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">
            Control Catalogue Admin
          </h1>
          {base && (
            <p className="mt-1 text-sm text-gray-500">
              Version {base.version} · created by {base.created_by} ·{' '}
              {new Date(base.created_at).toLocaleDateString()}
            </p>
          )}
        </div>
        <WeightTotalIndicator total={weightTotal} />
      </div>

      {/* Conflict banner */}
      {state.conflictDetected && (
        <div
          role="alert"
          className="mb-4 rounded border border-orange-300 bg-orange-50 p-4 flex items-start justify-between gap-4"
        >
          <div>
            <p className="font-medium text-orange-900">Version conflict detected</p>
            <p className="mt-1 text-sm text-orange-800">
              Another user published a new catalogue version while you were editing.
              Your staged changes have been preserved — please review them against
              the updated base before resubmitting.
            </p>
          </div>
          <button
            onClick={() => dispatch({ type: 'CLEAR_ERRORS' })}
            aria-label="Dismiss conflict notice"
            className="text-orange-700 hover:text-orange-900 focus:outline-none focus:ring-2 focus:ring-orange-400 text-lg font-bold"
          >
            ×
          </button>
        </div>
      )}

      {/* Network error */}
      {state.networkError && (
        <div role="alert" className="mb-4 rounded border border-red-300 bg-red-50 p-4">
          <p className="text-sm text-red-700">{state.networkError}</p>
          <button
            onClick={() => dispatch({ type: 'CLEAR_ERRORS' })}
            className="mt-1 text-xs font-medium text-red-700 underline focus:outline-none focus:ring-2 focus:ring-red-400"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Submit success */}
      {state.submitSuccess && (
        <div
          role="status"
          aria-live="polite"
          className="mb-4 rounded border border-green-300 bg-green-50 p-4"
        >
          <p className="text-sm font-medium text-green-800">
            ✓ Version {state.submitSuccess.version} published successfully.
          </p>
        </div>
      )}

      {/* Categories table */}
      {base && (
        <section aria-labelledby="categories-heading" className="mb-8">
          <h2
            id="categories-heading"
            className="mb-3 text-lg font-semibold text-gray-800"
          >
            Categories
          </h2>
          <div className="overflow-x-auto rounded-lg border border-gray-200">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b bg-gray-50 text-left">
                  <th
                    scope="col"
                    className="py-2 px-4 text-sm font-medium text-gray-600"
                  >
                    Category
                  </th>
                  <th
                    scope="col"
                    className="py-2 px-4 text-sm font-medium text-gray-600"
                  >
                    Weight (0–100)
                  </th>
                  <th
                    scope="col"
                    className="py-2 px-4 text-sm font-medium text-gray-600"
                  >
                    Enabled
                  </th>
                </tr>
              </thead>
              <tbody>
                {base.categories.map((cat) => (
                  <CategoryWeightRow
                    key={cat.id}
                    category={cat}
                    draft={state.categoryDrafts[cat.id]}
                    fieldError={state.fieldErrors[`categories.${cat.id}.weight`]}
                    onWeightChange={handleWeightChange}
                    onToggleEnabled={handleToggleEnabled}
                    disabled={state.isSubmitting}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Controls table */}
      {base && base.controls.length > 0 && (
        <section aria-labelledby="controls-heading" className="mb-8">
          <h2
            id="controls-heading"
            className="mb-3 text-lg font-semibold text-gray-800"
          >
            Controls
          </h2>
          <div className="overflow-x-auto rounded-lg border border-gray-200">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b bg-gray-50 text-left">
                  <th
                    scope="col"
                    className="py-2 px-4 text-sm font-medium text-gray-600"
                  >
                    Control ID
                  </th>
                  <th
                    scope="col"
                    className="py-2 px-4 text-sm font-medium text-gray-600"
                  >
                    Severity
                  </th>
                  <th
                    scope="col"
                    className="py-2 px-4 text-sm font-medium text-gray-600"
                  >
                    Reference Tools
                  </th>
                </tr>
              </thead>
              <tbody>
                {base.controls.map((ctrl) => (
                  <ControlSeverityRow
                    key={ctrl.id}
                    control={ctrl}
                    draft={state.controlDrafts[ctrl.id]}
                    fieldError={
                      state.fieldErrors[`controls.${ctrl.id}.severity`]
                    }
                    onSeverityChange={handleSeverityChange}
                    disabled={state.isSubmitting}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Submit panel */}
      {base && (
        <section
          aria-labelledby="submit-heading"
          className="rounded-lg border border-gray-200 bg-gray-50 p-6"
        >
          <h2
            id="submit-heading"
            className="mb-4 text-lg font-semibold text-gray-800"
          >
            Publish New Version
          </h2>
          <div className="mb-4">
            <label
              htmlFor="rationale"
              className="block text-sm font-medium text-gray-700 mb-1"
            >
              Rationale <span aria-hidden="true">(required)</span>
            </label>
            <textarea
              id="rationale"
              rows={3}
              value={state.rationale}
              onChange={(e) =>
                dispatch({ type: 'SET_RATIONALE', rationale: e.target.value })
              }
              disabled={state.isSubmitting}
              placeholder="Describe why this catalogue change is being made…"
              aria-required="true"
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand disabled:bg-gray-100 disabled:cursor-not-allowed"
            />
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <button
              ref={diffTriggerRef}
              onClick={() => setDiffOpen(true)}
              disabled={diff.length === 0}
              aria-label={`Preview ${diff.length} staged change${diff.length !== 1 ? 's' : ''}`}
              className="rounded border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-brand disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Preview changes ({diff.length})
            </button>
            <button
              onClick={() => dispatch({ type: 'RESET_STAGED' })}
              disabled={
                state.isSubmitting ||
                (Object.keys(state.categoryDrafts).length === 0 &&
                  Object.keys(state.controlDrafts).length === 0)
              }
              className="rounded border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-brand disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Reset changes
            </button>
            <button
              onClick={handleSubmit}
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              className="rounded bg-brand px-5 py-2 text-sm font-semibold text-white hover:bg-brand-dark focus:outline-none focus:ring-2 focus:ring-brand focus:ring-offset-2 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {state.isSubmitting ? 'Publishing…' : 'Publish version'}
            </button>
          </div>
          {!canSubmit && !state.isSubmitting && (
            <p className="mt-2 text-xs text-gray-500">
              {diff.length === 0
                ? 'No changes staged.'
                : weightTotal !== 100
                  ? `Enabled weight total is ${weightTotal}, must equal 100.`
                  : !state.rationale.trim()
                    ? 'A rationale is required.'
                    : ''}
            </p>
          )}
        </section>
      )}

      {/* Diff dialog */}
      <CatalogueDiffDialog
        open={diffOpen}
        onOpenChange={setDiffOpen}
        diff={diff}
        triggerRef={diffTriggerRef}
      />

      {/* Version history */}
      <section
        aria-labelledby="history-heading"
        className="mt-8"
      >
        <h2
          id="history-heading"
          className="mb-3 text-lg font-semibold text-gray-800"
        >
          Version History
        </h2>
        <CatalogueVersionHistory
          items={auditQuery.data?.items ?? []}
          isLoading={auditQuery.isLoading}
          error={
            auditQuery.isError
              ? isApiError(auditQuery.error)
                ? auditQuery.error.message
                : 'Failed to load audit history'
              : null
          }
          onRetry={() => void auditQuery.refetch()}
        />
      </section>
    </div>
  );
}
