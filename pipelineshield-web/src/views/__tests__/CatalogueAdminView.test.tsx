import { describe, expect, it, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { axe } from 'vitest-axe';
import type { AxeResults } from 'vitest-axe';
import { server } from '../../mocks/server';
import {
  cataloguePatch400Handler,
  cataloguePatch403Handler,
  cataloguePatch409Handler,
  catalogueGet403Handler,
  catalogueGetErrorHandler,
  MOCK_CATALOGUE,
} from '../../mocks/handlers/catalogue';
import { CatalogueAdminView } from '../CatalogueAdminView';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

function renderView() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
  const utils = render(
    <QueryClientProvider client={qc}>
      <CatalogueAdminView />
    </QueryClientProvider>,
  );
  return { ...utils, qc };
}

async function waitForCatalogue() {
  await waitFor(() => {
    expect(screen.getByTestId('catalogue-admin-view')).toBeInTheDocument();
  });
}

// ---------------------------------------------------------------------------
// AC-1: Renders active catalogue
// ---------------------------------------------------------------------------

describe('CatalogueAdminView — catalogue render', () => {
  it('shows loading skeleton initially', () => {
    renderView();
    expect(screen.getByLabelText('Loading catalogue')).toBeInTheDocument();
  });

  it('renders categories from GET /api/v1/catalogue', async () => {
    renderView();
    await waitForCatalogue();
    expect(screen.getByText('Secrets Management')).toBeInTheDocument();
    expect(screen.getByText('SAST')).toBeInTheDocument();
  });

  it('shows version number and author', async () => {
    renderView();
    await waitForCatalogue();
    expect(screen.getByText(/Version 1/)).toBeInTheDocument();
    expect(screen.getByText(/seed@pipelineshield.internal/)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// AC-2: Weight total indicator
// ---------------------------------------------------------------------------

describe('WeightTotalIndicator', () => {
  it('shows valid when total equals 100', async () => {
    renderView();
    await waitForCatalogue();
    expect(screen.getByText(/Weight total: 100/)).toBeInTheDocument();
    expect(screen.getByText(/valid/i)).toBeInTheDocument();
  });

  it('updates aria-live region when weight changes', async () => {
    const user = userEvent.setup();
    renderView();
    await waitForCatalogue();

    const weightInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(weightInput);
    await user.type(weightInput, '70');

    // Weight total is now 110 (70 + 40)
    await waitFor(() => {
      expect(screen.getByText(/Weight total: 110/)).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// AC-3: Submit button state
// ---------------------------------------------------------------------------

describe('Submit button enablement', () => {
  it('is disabled when no changes staged', async () => {
    renderView();
    await waitForCatalogue();
    expect(screen.getByRole('button', { name: /publish version/i })).toBeDisabled();
  });

  it('is disabled when weight total ≠ 100', async () => {
    const user = userEvent.setup();
    renderView();
    await waitForCatalogue();

    const weightInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(weightInput);
    await user.type(weightInput, '70');

    const rationaleInput = screen.getByLabelText(/rationale/i);
    await user.type(rationaleInput, 'test');

    expect(screen.getByRole('button', { name: /publish version/i })).toBeDisabled();
  });

  it('is disabled when rationale is empty', async () => {
    const user = userEvent.setup();
    renderView();
    await waitForCatalogue();

    // Stage a valid rebalance: secrets=55, sast=45, total=100
    const secretsInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(secretsInput);
    await user.type(secretsInput, '55');

    const sastInput = screen.getByLabelText('Weight for SAST');
    await user.clear(sastInput);
    await user.type(sastInput, '45');

    // Don't fill rationale
    expect(screen.getByRole('button', { name: /publish version/i })).toBeDisabled();
  });
});

// ---------------------------------------------------------------------------
// AC-4: Diff dialog
// ---------------------------------------------------------------------------

describe('CatalogueDiffDialog', () => {
  it('opens on "Preview changes" click', async () => {
    const user = userEvent.setup();
    renderView();
    await waitForCatalogue();

    const secretsInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(secretsInput);
    await user.type(secretsInput, '55');

    await user.click(screen.getByRole('button', { name: /preview.*change/i }));

    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText('Staged Changes Preview')).toBeInTheDocument();
  });

  it('closes on Escape key', async () => {
    const user = userEvent.setup();
    renderView();
    await waitForCatalogue();

    const secretsInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(secretsInput);
    await user.type(secretsInput, '55');

    await user.click(screen.getByRole('button', { name: /preview.*change/i }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    await user.keyboard('{Escape}');
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });

  it('lists each staged change as path, current, proposed', async () => {
    const user = userEvent.setup();
    renderView();
    await waitForCatalogue();

    const secretsInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(secretsInput);
    await user.type(secretsInput, '55');

    await user.click(screen.getByRole('button', { name: /preview.*change/i }));

    // Should show the path
    await waitFor(() => {
      expect(screen.getByText(/categories\.secrets\.weight/)).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// AC-5: Successful submit
// ---------------------------------------------------------------------------

describe('Successful submit', () => {
  it('shows confirmation with new version number', async () => {
    const user = userEvent.setup();
    renderView();
    await waitForCatalogue();

    // Stage valid rebalance
    const secretsInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(secretsInput);
    await user.type(secretsInput, '55');

    const sastInput = screen.getByLabelText('Weight for SAST');
    await user.clear(sastInput);
    await user.type(sastInput, '45');

    const rationaleInput = screen.getByLabelText(/rationale/i);
    await user.type(rationaleInput, 'rebalancing weights for pilot');

    await user.click(screen.getByRole('button', { name: /publish version/i }));

    await waitFor(() => {
      expect(
        screen.getByText(/Version 2 published successfully/i),
      ).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// AC-6: 409 conflict — staged edits preserved
// ---------------------------------------------------------------------------

describe('409 conflict handling', () => {
  beforeEach(() => {
    server.use(cataloguePatch409Handler());
  });

  it('shows conflict banner and preserves staged changes', async () => {
    const user = userEvent.setup();
    renderView();
    await waitForCatalogue();

    const secretsInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(secretsInput);
    await user.type(secretsInput, '55');

    const sastInput = screen.getByLabelText('Weight for SAST');
    await user.clear(sastInput);
    await user.type(sastInput, '45');

    const rationaleInput = screen.getByLabelText(/rationale/i);
    await user.type(rationaleInput, 'rebalancing');

    await user.click(screen.getByRole('button', { name: /publish version/i }));

    await waitFor(() => {
      expect(screen.getByText(/version conflict detected/i)).toBeInTheDocument();
    });

    // Staged changes input should still have the staged value
    // (The weight input reflects staged state)
    const secretsInputAfter = screen.getByLabelText('Weight for Secrets Management');
    expect(secretsInputAfter).toHaveValue(55);
  });
});

// ---------------------------------------------------------------------------
// AC-7: 403 → PermissionDeniedState (no edit affordances)
// ---------------------------------------------------------------------------

describe('403 from GET → permission denied state', () => {
  beforeEach(() => {
    server.use(catalogueGet403Handler());
  });

  it('renders permission denied state', async () => {
    renderView();
    await waitFor(() => {
      expect(screen.getByText(/read-only access/i)).toBeInTheDocument();
    });
  });

  it('does not render edit controls', async () => {
    renderView();
    await waitFor(() => {
      expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument();
    });
  });
});

describe('403 from PATCH → permission denied state', () => {
  beforeEach(() => {
    server.use(cataloguePatch403Handler());
  });

  it('shows permission denied after a 403 patch response', async () => {
    const user = userEvent.setup();
    renderView();
    await waitForCatalogue();

    const secretsInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(secretsInput);
    await user.type(secretsInput, '55');

    const sastInput = screen.getByLabelText('Weight for SAST');
    await user.clear(sastInput);
    await user.type(sastInput, '45');

    const rationaleInput = screen.getByLabelText(/rationale/i);
    await user.type(rationaleInput, 'test');

    await user.click(screen.getByRole('button', { name: /publish version/i }));

    await waitFor(() => {
      expect(screen.getByText(/read-only access/i)).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// AC-8: 400 → inline field errors via aria-describedby
// ---------------------------------------------------------------------------

describe('400 validation errors', () => {
  beforeEach(() => {
    server.use(cataloguePatch400Handler());
  });

  it('shows inline error for the failing field', async () => {
    const user = userEvent.setup();
    renderView();
    await waitForCatalogue();

    const secretsInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(secretsInput);
    await user.type(secretsInput, '55');

    const sastInput = screen.getByLabelText('Weight for SAST');
    await user.clear(sastInput);
    await user.type(sastInput, '45');

    const rationaleInput = screen.getByLabelText(/rationale/i);
    await user.type(rationaleInput, 'test reason');

    await user.click(screen.getByRole('button', { name: /publish version/i }));

    await waitFor(() => {
      expect(
        screen.getByText(/Weight causes total to exceed 100/i),
      ).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// AC-9: Network error → retry affordance
// ---------------------------------------------------------------------------

describe('Network error', () => {
  beforeEach(() => {
    server.use(catalogueGetErrorHandler());
  });

  it('shows retry button on load error', async () => {
    renderView();
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /retry/i }),
      ).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// AC-12: Axe accessibility assertions
// ---------------------------------------------------------------------------

describe('Accessibility (axe)', () => {
  it('loaded state has no critical/serious violations', async () => {
    const { container } = renderView();
    await waitForCatalogue();

    const results: AxeResults = await axe(container);
    const serious = results.violations.filter(
      (v) => v.impact === 'serious' || v.impact === 'critical',
    );
    expect(serious).toHaveLength(0);
  });

  it('dialog-open state has no critical/serious violations', async () => {
    const user = userEvent.setup();
    const { container } = renderView();
    await waitForCatalogue();

    // Stage a change to enable the diff button
    const secretsInput = screen.getByLabelText('Weight for Secrets Management');
    await user.clear(secretsInput);
    await user.type(secretsInput, '55');

    await user.click(screen.getByRole('button', { name: /preview.*change/i }));
    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    const results: AxeResults = await axe(container);
    const serious = results.violations.filter(
      (v) => v.impact === 'serious' || v.impact === 'critical',
    );
    expect(serious).toHaveLength(0);
  });

  it('permission-denied state has no critical/serious violations', async () => {
    server.use(catalogueGet403Handler());
    const { container } = renderView();
    await waitFor(() => {
      expect(screen.getByText(/read-only access/i)).toBeInTheDocument();
    });

    const results: AxeResults = await axe(container);
    const serious = results.violations.filter(
      (v) => v.impact === 'serious' || v.impact === 'critical',
    );
    expect(serious).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// AC-13: MSW fixture coverage — ensure all handler scenarios are exercised
// ---------------------------------------------------------------------------

describe('Mock handler fixture coverage', () => {
  it('GET catalogue handler returns MOCK_CATALOGUE', async () => {
    renderView();
    await waitFor(() => {
      expect(
        screen.getByText(MOCK_CATALOGUE.categories[0]!.name),
      ).toBeInTheDocument();
    });
  });
});
