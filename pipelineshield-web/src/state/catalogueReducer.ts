import type { CatalogueGetResponse, ChangeOp, Severity } from '../api/types';

// ---------------------------------------------------------------------------
// State shape
// ---------------------------------------------------------------------------

export interface CategoryDraft {
  weight?: number;
  enabled?: boolean;
}

export interface ControlDraft {
  severity?: Severity;
  reference_tools?: string[];
}

export interface DiffLine {
  path: string;
  current_value: unknown;
  proposed_value: unknown;
}

export interface CatalogueState {
  baseSnapshot: CatalogueGetResponse | null;
  categoryDrafts: Record<string, CategoryDraft>;
  controlDrafts: Record<string, ControlDraft>;
  rationale: string;
  isSubmitting: boolean;
  submitSuccess: { version: number } | null;
  fieldErrors: Record<string, string>;
  conflictDetected: boolean;
  networkError: string | null;
  permissionDenied: boolean;
  isLoading: boolean;
  loadError: string | null;
}

export const INITIAL_STATE: CatalogueState = {
  baseSnapshot: null,
  categoryDrafts: {},
  controlDrafts: {},
  rationale: '',
  isSubmitting: false,
  submitSuccess: null,
  fieldErrors: {},
  conflictDetected: false,
  networkError: null,
  permissionDenied: false,
  isLoading: false,
  loadError: null,
};

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export type CatalogueAction =
  | { type: 'LOAD_START' }
  | { type: 'LOAD_SUCCESS'; payload: CatalogueGetResponse }
  | { type: 'LOAD_FAILURE'; error: string }
  | { type: 'STAGE_CATEGORY_WEIGHT'; categoryId: string; weight: number }
  | { type: 'TOGGLE_CATEGORY_ENABLED'; categoryId: string }
  | { type: 'STAGE_CONTROL_SEVERITY'; controlId: string; severity: Severity }
  | { type: 'STAGE_REFERENCE_TOOLS'; controlId: string; tools: string[] }
  | { type: 'SET_RATIONALE'; rationale: string }
  | { type: 'RESET_STAGED' }
  | { type: 'REBASE_AFTER_CONFLICT'; payload: CatalogueGetResponse }
  | { type: 'SUBMIT_START' }
  | { type: 'SUBMIT_SUCCESS'; version: number; newSnapshot: CatalogueGetResponse }
  | { type: 'SUBMIT_FAILURE_400'; fieldErrors: Record<string, string>; detail: string }
  | { type: 'SUBMIT_FAILURE_403' }
  | { type: 'SUBMIT_FAILURE_409'; newBase: CatalogueGetResponse }
  | { type: 'SUBMIT_FAILURE_NETWORK'; error: string }
  | { type: 'CLEAR_ERRORS' };

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

export function catalogueReducer(
  state: CatalogueState,
  action: CatalogueAction,
): CatalogueState {
  switch (action.type) {
    case 'LOAD_START':
      return {
        ...state,
        isLoading: true,
        loadError: null,
      };

    case 'LOAD_SUCCESS':
      return {
        ...state,
        baseSnapshot: action.payload,
        isLoading: false,
        loadError: null,
        permissionDenied: false,
      };

    case 'LOAD_FAILURE':
      return {
        ...state,
        isLoading: false,
        loadError: action.error,
      };

    case 'STAGE_CATEGORY_WEIGHT': {
      const base = state.baseSnapshot?.categories.find(
        (c) => c.id === action.categoryId,
      );

      const existing = state.categoryDrafts[action.categoryId] ?? {};

      const newDraft: CategoryDraft = {
        ...existing,
        weight: action.weight,
      };

      // Remove draft when there is no effective change.
      if (
        base &&
        newDraft.weight === base.weight &&
        newDraft.enabled === undefined
      ) {
        const next = { ...state.categoryDrafts };
        delete next[action.categoryId];

        return {
          ...state,
          categoryDrafts: next,
          fieldErrors: {},
        };
      }

      return {
        ...state,
        categoryDrafts: {
          ...state.categoryDrafts,
          [action.categoryId]: newDraft,
        },
        fieldErrors: {},
      };
    }

    case 'TOGGLE_CATEGORY_ENABLED': {
      const base = state.baseSnapshot?.categories.find(
        (c) => c.id === action.categoryId,
      );

      const existing = state.categoryDrafts[action.categoryId] ?? {};

      const currentEnabled =
        existing.enabled !== undefined
          ? existing.enabled
          : (base?.enabled ?? true);

      const newEnabled = !currentEnabled;

      const newDraft: CategoryDraft = {
        ...existing,
        enabled: newEnabled,
      };

      if (
        base &&
        newDraft.enabled === base.enabled &&
        newDraft.weight === undefined
      ) {
        const next = { ...state.categoryDrafts };
        delete next[action.categoryId];

        return {
          ...state,
          categoryDrafts: next,
        };
      }

      return {
        ...state,
        categoryDrafts: {
          ...state.categoryDrafts,
          [action.categoryId]: newDraft,
        },
      };
    }

    case 'STAGE_CONTROL_SEVERITY': {
      const base = state.baseSnapshot?.controls.find(
        (c) => c.id === action.controlId,
      );

      const existing = state.controlDrafts[action.controlId] ?? {};

      const newDraft: ControlDraft = {
        ...existing,
        severity: action.severity,
      };

      if (
        base &&
        newDraft.severity === base.severity &&
        newDraft.reference_tools === undefined
      ) {
        const next = { ...state.controlDrafts };
        delete next[action.controlId];

        return {
          ...state,
          controlDrafts: next,
        };
      }

      return {
        ...state,
        controlDrafts: {
          ...state.controlDrafts,
          [action.controlId]: newDraft,
        },
      };
    }

    case 'STAGE_REFERENCE_TOOLS': {
      const base = state.baseSnapshot?.controls.find(
        (c) => c.id === action.controlId,
      );

      const existing = state.controlDrafts[action.controlId] ?? {};

      const newDraft: ControlDraft = {
        ...existing,
        reference_tools: action.tools,
      };

      if (
        base &&
        newDraft.severity === undefined &&
        JSON.stringify(newDraft.reference_tools) ===
          JSON.stringify(base.reference_tools)
      ) {
        const next = { ...state.controlDrafts };
        delete next[action.controlId];

        return {
          ...state,
          controlDrafts: next,
        };
      }

      return {
        ...state,
        controlDrafts: {
          ...state.controlDrafts,
          [action.controlId]: newDraft,
        },
      };
    }

    case 'SET_RATIONALE':
      return {
        ...state,
        rationale: action.rationale,
      };

    case 'RESET_STAGED':
      return {
        ...state,
        categoryDrafts: {},
        controlDrafts: {},
        rationale: '',
        submitSuccess: null,
        fieldErrors: {},
        conflictDetected: false,
        networkError: null,
      };

    case 'REBASE_AFTER_CONFLICT':
      return {
        ...state,
        baseSnapshot: action.payload,
        conflictDetected: false,
        isSubmitting: false,
        networkError: null,
      };

    case 'SUBMIT_START':
      return {
        ...state,
        isSubmitting: true,
        submitSuccess: null,
        fieldErrors: {},
        conflictDetected: false,
        networkError: null,
      };

    case 'SUBMIT_SUCCESS':
      return {
        ...state,
        isSubmitting: false,
        baseSnapshot: action.newSnapshot,
        categoryDrafts: {},
        controlDrafts: {},
        rationale: '',
        submitSuccess: {
          version: action.version,
        },
      };

    case 'SUBMIT_FAILURE_400':
      return {
        ...state,
        isSubmitting: false,
        fieldErrors: action.fieldErrors,
        networkError: null,
      };

    case 'SUBMIT_FAILURE_403':
      return {
        ...state,
        isSubmitting: false,
        permissionDenied: true,
        networkError: null,
      };

    case 'SUBMIT_FAILURE_409':
      return {
        ...state,
        isSubmitting: false,
        conflictDetected: true,
        baseSnapshot: action.newBase,
        networkError: null,
      };

    case 'SUBMIT_FAILURE_NETWORK':
      return {
        ...state,
        isSubmitting: false,
        networkError: action.error,
      };

    case 'CLEAR_ERRORS':
      return {
        ...state,
        fieldErrors: {},
        networkError: null,
        conflictDetected: false,
        submitSuccess: null,
      };
  }
}

// ---------------------------------------------------------------------------
// Selectors
// ---------------------------------------------------------------------------

export function selectEnabledWeightTotal(state: CatalogueState): number {
  if (!state.baseSnapshot) return 0;

  return state.baseSnapshot.categories.reduce((total, cat) => {
    const draft = state.categoryDrafts[cat.id];

    const enabled =
      draft?.enabled !== undefined
        ? draft.enabled
        : cat.enabled;

    const weight =
      draft?.weight !== undefined
        ? draft.weight
        : cat.weight;

    return enabled ? total + weight : total;
  }, 0);
}

export function selectDiff(state: CatalogueState): DiffLine[] {
  if (!state.baseSnapshot) return [];

  const lines: DiffLine[] = [];

  for (const [catId, draft] of Object.entries(state.categoryDrafts)) {
    const base = state.baseSnapshot.categories.find(
      (c) => c.id === catId,
    );

    if (!base) continue;

    if (
      draft.weight !== undefined &&
      draft.weight !== base.weight
    ) {
      lines.push({
        path: `categories.${catId}.weight`,
        current_value: base.weight,
        proposed_value: draft.weight,
      });
    }

    if (
      draft.enabled !== undefined &&
      draft.enabled !== base.enabled
    ) {
      lines.push({
        path: `categories.${catId}.enabled`,
        current_value: base.enabled,
        proposed_value: draft.enabled,
      });
    }
  }

  for (const [ctrlId, draft] of Object.entries(
    state.controlDrafts,
  )) {
    const base = state.baseSnapshot.controls.find(
      (c) => c.id === ctrlId,
    );

    if (!base) continue;

    if (
      draft.severity !== undefined &&
      draft.severity !== base.severity
    ) {
      lines.push({
        path: `controls.${ctrlId}.severity`,
        current_value: base.severity,
        proposed_value: draft.severity,
      });
    }

    if (
      draft.reference_tools !== undefined &&
      JSON.stringify(draft.reference_tools) !==
        JSON.stringify(base.reference_tools)
    ) {
      lines.push({
        path: `controls.${ctrlId}.reference_tools`,
        current_value: base.reference_tools,
        proposed_value: draft.reference_tools,
      });
    }
  }

  return lines;
}

// ---------------------------------------------------------------------------
// Submit validation
// ---------------------------------------------------------------------------

export function selectCanSubmit(state: CatalogueState): boolean {
  if (state.isSubmitting) return false;

  if (!state.rationale.trim()) return false;

  if (selectDiff(state).length === 0) return false;

  return true;
}

// ---------------------------------------------------------------------------
// API changes
// ---------------------------------------------------------------------------

export function selectChangesForApi(
  state: CatalogueState,
): ChangeOp[] {
  if (!state.baseSnapshot) return [];

  const ops: ChangeOp[] = [];

  for (const [catId, draft] of Object.entries(
    state.categoryDrafts,
  )) {
    const base = state.baseSnapshot.categories.find(
      (c) => c.id === catId,
    );

    if (!base) continue;

    const fields: ChangeOp['fields'] = {};

    if (
      draft.weight !== undefined &&
      draft.weight !== base.weight
    ) {
      fields.weight = draft.weight;
    }

    if (
      draft.enabled !== undefined &&
      draft.enabled !== base.enabled
    ) {
      fields.enabled = draft.enabled;
    }

    if (Object.keys(fields).length > 0) {
      ops.push({
        target: 'category',
        id: catId,
        fields,
      });
    }
  }

  for (const [ctrlId, draft] of Object.entries(
    state.controlDrafts,
  )) {
    const base = state.baseSnapshot.controls.find(
      (c) => c.id === ctrlId,
    );

    if (!base) continue;

    const fields: ChangeOp['fields'] = {};

    if (
      draft.severity !== undefined &&
      draft.severity !== base.severity
    ) {
      fields.severity = draft.severity;
    }

    if (
      draft.reference_tools !== undefined &&
      JSON.stringify(draft.reference_tools) !==
        JSON.stringify(base.reference_tools)
    ) {
      fields.reference_tools = draft.reference_tools;
    }

    if (Object.keys(fields).length > 0) {
      ops.push({
        target: 'control',
        id: ctrlId,
        fields,
      });
    }
  }

  return ops;
}
