import { describe, expect, it } from 'vitest';
import {
  catalogueReducer,
  INITIAL_STATE,
  selectCanSubmit,
  selectDiff,
} from '../catalogueReducer';
import type { CatalogueGetResponse } from '../../api/types';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BASE_CATALOGUE: CatalogueGetResponse = {
  version: 1,
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
  created_by: 'seed@example.com',
  grade_bands: [{ grade: 'A', min_score: 90, max_score: 100 }],
  categories: [
    { id: 'secrets', name: 'Secrets', weight: 70, enabled: true },
    { id: 'sast', name: 'SAST', weight: 30, enabled: true },
  ],
  controls: [
    {
      id: 'ctrl-1',
      category_id: 'secrets',
      severity: 'critical',
      enabled: true,
      reference_tools: ['gitleaks'],
    },
  ],
};

function loadedState() {
  return catalogueReducer(INITIAL_STATE, {
    type: 'LOAD_SUCCESS',
    payload: BASE_CATALOGUE,
  });
}

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

describe('INITIAL_STATE', () => {
  it('has empty drafts', () => {
    expect(INITIAL_STATE.categoryDrafts).toEqual({});
    expect(INITIAL_STATE.controlDrafts).toEqual({});
  });

  it('has empty rationale', () => {
    expect(INITIAL_STATE.rationale).toBe('');
  });
});

// ---------------------------------------------------------------------------
// LOAD_SUCCESS
// ---------------------------------------------------------------------------

describe('LOAD_SUCCESS', () => {
  it('sets baseSnapshot', () => {
    const s = loadedState();

    expect(s.baseSnapshot).toEqual(BASE_CATALOGUE);
    expect(s.isLoading).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// STAGE_CATEGORY_WEIGHT
// ---------------------------------------------------------------------------

describe('STAGE_CATEGORY_WEIGHT', () => {
  it('records a weight draft', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 80,
    });

    expect(s.categoryDrafts['secrets']?.weight).toBe(80);
  });

  it('removes draft when weight matches base', () => {
    let s = catalogueReducer(loadedState(), {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 80,
    });

    s = catalogueReducer(s, {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 70,
    });

    expect(s.categoryDrafts['secrets']).toBeUndefined();
  });

  it('clears fieldErrors when staging', () => {
    const withErrors = {
      ...loadedState(),
      fieldErrors: { x: 'err' },
    };

    const s = catalogueReducer(withErrors, {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 60,
    });

    expect(s.fieldErrors).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// TOGGLE_CATEGORY_ENABLED
// ---------------------------------------------------------------------------

describe('TOGGLE_CATEGORY_ENABLED', () => {
  it('toggles enabled state from true to false', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'TOGGLE_CATEGORY_ENABLED',
      categoryId: 'secrets',
    });

    expect(s.categoryDrafts['secrets']?.enabled).toBe(false);
  });

  it('toggles back to original and removes draft', () => {
    let s = catalogueReducer(loadedState(), {
      type: 'TOGGLE_CATEGORY_ENABLED',
      categoryId: 'secrets',
    });

    s = catalogueReducer(s, {
      type: 'TOGGLE_CATEGORY_ENABLED',
      categoryId: 'secrets',
    });

    expect(s.categoryDrafts['secrets']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// STAGE_CONTROL_SEVERITY
// ---------------------------------------------------------------------------

describe('STAGE_CONTROL_SEVERITY', () => {
  it('records a severity draft', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'STAGE_CONTROL_SEVERITY',
      controlId: 'ctrl-1',
      severity: 'high',
    });

    expect(s.controlDrafts['ctrl-1']?.severity).toBe('high');
  });

  it('removes draft when severity matches base', () => {
    let s = catalogueReducer(loadedState(), {
      type: 'STAGE_CONTROL_SEVERITY',
      controlId: 'ctrl-1',
      severity: 'high',
    });

    s = catalogueReducer(s, {
      type: 'STAGE_CONTROL_SEVERITY',
      controlId: 'ctrl-1',
      severity: 'critical',
    });

    expect(s.controlDrafts['ctrl-1']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// STAGE_REFERENCE_TOOLS
// ---------------------------------------------------------------------------

describe('STAGE_REFERENCE_TOOLS', () => {
  it('records reference tools draft', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'STAGE_REFERENCE_TOOLS',
      controlId: 'ctrl-1',
      tools: ['gitleaks', 'trivy'],
    });

    expect(s.controlDrafts['ctrl-1']?.reference_tools).toEqual([
      'gitleaks',
      'trivy',
    ]);
  });
});

// ---------------------------------------------------------------------------
// RESET_STAGED
// ---------------------------------------------------------------------------

describe('RESET_STAGED', () => {
  it('clears all drafts and rationale', () => {
    let s = catalogueReducer(loadedState(), {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 60,
    });

    s = catalogueReducer(s, {
      type: 'SET_RATIONALE',
      rationale: 'test',
    });

    s = catalogueReducer(s, {
      type: 'RESET_STAGED',
    });

    expect(s.categoryDrafts).toEqual({});
    expect(s.controlDrafts).toEqual({});
    expect(s.rationale).toBe('');
  });
});

// ---------------------------------------------------------------------------
// REBASE_AFTER_CONFLICT
// ---------------------------------------------------------------------------

describe('REBASE_AFTER_CONFLICT', () => {
  it('updates base snapshot and preserves staged drafts', () => {
    let s = catalogueReducer(loadedState(), {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 65,
    });

    const newBase: CatalogueGetResponse = {
      ...BASE_CATALOGUE,
      version: 3,
    };

    s = catalogueReducer(s, {
      type: 'REBASE_AFTER_CONFLICT',
      payload: newBase,
    });

    expect(s.baseSnapshot?.version).toBe(3);
    expect(s.categoryDrafts['secrets']?.weight).toBe(65);
    expect(s.conflictDetected).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SUBMIT_* transitions
// ---------------------------------------------------------------------------

describe('SUBMIT_START', () => {
  it('sets isSubmitting and clears errors', () => {
    const s = catalogueReducer(
      {
        ...loadedState(),
        fieldErrors: { x: 'err' },
        networkError: 'oops',
      },
      { type: 'SUBMIT_START' },
    );

    expect(s.isSubmitting).toBe(true);
    expect(s.fieldErrors).toEqual({});
    expect(s.networkError).toBeNull();
  });
});

describe('SUBMIT_SUCCESS', () => {
  it('clears drafts and sets submitSuccess', () => {
    let s = catalogueReducer(loadedState(), {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 65,
    });

    s = catalogueReducer(s, {
      type: 'SET_RATIONALE',
      rationale: 'reason',
    });

    s = catalogueReducer(s, {
      type: 'SUBMIT_START',
    });

    s = catalogueReducer(s, {
      type: 'SUBMIT_SUCCESS',
      version: 2,
      newSnapshot: {
        ...BASE_CATALOGUE,
        version: 2,
      },
    });

    expect(s.isSubmitting).toBe(false);
    expect(s.submitSuccess?.version).toBe(2);
    expect(s.categoryDrafts).toEqual({});
    expect(s.rationale).toBe('');
  });
});

describe('SUBMIT_FAILURE_409', () => {
  it('sets conflictDetected and updates base', () => {
    const newBase: CatalogueGetResponse = {
      ...BASE_CATALOGUE,
      version: 5,
    };

    const s = catalogueReducer(
      {
        ...loadedState(),
        isSubmitting: true,
      },
      {
        type: 'SUBMIT_FAILURE_409',
        newBase,
      },
    );

    expect(s.conflictDetected).toBe(true);
    expect(s.baseSnapshot?.version).toBe(5);
    expect(s.isSubmitting).toBe(false);
  });
});

describe('SUBMIT_FAILURE_403', () => {
  it('sets permissionDenied', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'SUBMIT_FAILURE_403',
    });

    expect(s.permissionDenied).toBe(true);
  });
});

describe('SUBMIT_FAILURE_400', () => {
  it('sets fieldErrors', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'SUBMIT_FAILURE_400',
      fieldErrors: {
        'categories.secrets.weight': 'Too high',
      },
      detail: 'Validation error',
    });

    expect(s.fieldErrors['categories.secrets.weight']).toBe('Too high');
    expect(s.isSubmitting).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// selectDiff
// ---------------------------------------------------------------------------

describe('selectDiff', () => {
  it('returns empty diff when no changes staged', () => {
    expect(selectDiff(loadedState())).toHaveLength(0);
  });

  it('returns a diff entry for a staged weight change', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 80,
    });

    const diff = selectDiff(s);

    expect(diff).toHaveLength(1);
    expect(diff[0]?.path).toBe('categories.secrets.weight');
    expect(diff[0]?.current_value).toBe(70);
    expect(diff[0]?.proposed_value).toBe(80);
  });

  it('returns diff entry for enabled toggle', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'TOGGLE_CATEGORY_ENABLED',
      categoryId: 'sast',
    });

    const diff = selectDiff(s);

    expect(
      diff.some((d) => d.path === 'categories.sast.enabled'),
    ).toBe(true);
  });

  it('returns diff entry for severity change', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'STAGE_CONTROL_SEVERITY',
      controlId: 'ctrl-1',
      severity: 'medium',
    });

    const diff = selectDiff(s);

    expect(
      diff.some((d) => d.path === 'controls.ctrl-1.severity'),
    ).toBe(true);
  });

  it('staged value matching base produces no diff entry', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 70,
    });

    expect(selectDiff(s)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// selectCanSubmit
// ---------------------------------------------------------------------------

describe('selectCanSubmit', () => {
  it('returns false when no staged changes', () => {
    const s = {
      ...loadedState(),
      rationale: 'reason',
    };

    expect(selectCanSubmit(s)).toBe(false);
  });

  it('returns true when staged changes and rationale are present', () => {
    let s = catalogueReducer(loadedState(), {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 2000,
    });

    s = catalogueReducer(s, {
      type: 'SET_RATIONALE',
      rationale: 'rebalancing weights',
    });

    expect(selectCanSubmit(s)).toBe(true);
  });

  it('returns false when rationale is empty', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'STAGE_CATEGORY_WEIGHT',
      categoryId: 'secrets',
      weight: 2000,
    });

    expect(
      selectCanSubmit({
        ...s,
        rationale: '',
      }),
    ).toBe(false);
  });

  it('returns false when isSubmitting', () => {
    const s = catalogueReducer(loadedState(), {
      type: 'SUBMIT_START',
    });

    expect(selectCanSubmit(s)).toBe(false);
  });
});
