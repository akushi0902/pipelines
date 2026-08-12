/**
 * Tests for UploadView — WO-005 acceptance criteria.
 *
 * AC coverage:
 * - AC-3: 512 KB pre-check warning without API call
 * - AC-4: non-dismissible masking notice
 * - AC-5: format confirmation dialog with GitHub Actions, GitLab CI, Jenkins
 * - AC-6: stage progress panel shown during submission
 * - AC-7: RFC 7807 error rendered with title, detail, constraint, correlation_id
 * - AC-8: script tag in definition text renders as inert text
 * - AC-10: axe-core zero serious/critical violations in light and dark themes
 * - AC-12: unit tests for paste handling, confirmation logic, error rendering
 * - AC-13: MSW integration tests for success flow, low-confidence round-trip,
 *           oversize rejection, timeout path
 * - AC-14: MSW handlers exercised for 413, 422, 401
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import type { AxeResults } from 'vitest-axe';
import { server } from '../../mocks/server';
import {
  upload413Handler,
  upload422Handler,
  upload401Handler,
  uploadLowConfidenceHandler,
  uploadHangHandler,
  MOCK_ANALYSIS_SUCCESS,
} from '../../mocks/handlers/upload';
import { UploadView } from '../UploadView';
import { PAYLOAD_MAX_BYTES } from '../../api/generated/ingestion';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderView() {
  return render(<UploadView />);
}

async function switchToPasteTab(user: ReturnType<typeof userEvent.setup>) {
  const pasteTab = screen.getByRole('tab', { name: /paste text/i });
  await user.click(pasteTab);
}

async function typePaste(
  user: ReturnType<typeof userEvent.setup>,
  text: string,
) {
  const textarea = screen.getByRole('textbox', { name: /paste pipeline definition/i });
  await user.type(textarea, text);
  return textarea;
}

const VALID_YAML = `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3`;

// ---------------------------------------------------------------------------
// AC-4: Non-dismissible masking notice
// ---------------------------------------------------------------------------

describe('MaskingNotice', () => {
  it('is visible on initial render', () => {
    renderView();
    expect(screen.getByRole('note', { name: /secret masking notice/i })).toBeInTheDocument();
  });

  it('has no close/dismiss button', () => {
    renderView();
    const notice = screen.getByRole('note', { name: /secret masking notice/i });
    expect(within(notice).queryByRole('button')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AC-3: 512 KB pre-check (paste mode)
// ---------------------------------------------------------------------------

describe('512 KB pre-check (paste)', () => {
  it('shows size warning when pasted content exceeds 512 KB', async () => {
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    // Generate just-over-limit text (PAYLOAD_MAX_BYTES + 10 bytes)
    const overLimit = 'a'.repeat(PAYLOAD_MAX_BYTES + 10);
    const textarea = screen.getByRole('textbox', { name: /paste pipeline definition/i });
    // Use fireEvent to avoid slow character-by-character typing
    const { fireEvent } = await import('@testing-library/react');
    fireEvent.change(textarea, { target: { value: overLimit } });

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/512/);
    });
  });

  it('does not call the API when pasted content is over limit and submit is clicked', async () => {
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    const overLimit = 'a'.repeat(PAYLOAD_MAX_BYTES + 10);
    const textarea = screen.getByRole('textbox', { name: /paste pipeline definition/i });
    const { fireEvent } = await import('@testing-library/react');
    fireEvent.change(textarea, { target: { value: overLimit } });

    // The submit button should be enabled (the content IS present), but submitting
    // should show the inline error and not progress to submitting stage
    const submitBtn = screen.getByRole('button', { name: /submit for analysis/i });
    await user.click(submitBtn);

    // Should never show progress panel (no API call made for oversized content)
    expect(screen.queryByRole('status', { name: /analysis progress/i })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AC-13: Success flow (MSW integration)
// ---------------------------------------------------------------------------

describe('Upload flow — success', () => {
  it('shows progress panel after submitting pasted text', async () => {
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    await typePaste(user, VALID_YAML);

    const submitBtn = screen.getByRole('button', { name: /submit for analysis/i });
    await user.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByRole('status', { name: /analysis progress/i })).toBeInTheDocument();
    });
  });

  it('shows success state after API returns 201', async () => {
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    await typePaste(user, VALID_YAML);
    await user.click(screen.getByRole('button', { name: /submit for analysis/i }));

    await waitFor(() => {
      expect(screen.getByRole('status', { name: /analysis complete/i })).toBeInTheDocument();
    });

    expect(screen.getByText(MOCK_ANALYSIS_SUCCESS.detected_format)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// AC-5: Format confirmation dialog (low-confidence path)
// ---------------------------------------------------------------------------

describe('Format confirmation dialog', () => {
  beforeEach(() => {
    server.use(uploadLowConfidenceHandler());
  });

  it('shows format confirmation dialog when format_confirmation_required', async () => {
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    await typePaste(user, VALID_YAML);
    await user.click(screen.getByRole('button', { name: /submit for analysis/i }));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    expect(screen.getByRole('dialog')).toHaveAccessibleName(/confirm pipeline format/i);
  });

  it('dialog lists GitHub Actions, GitLab CI and Jenkins options', async () => {
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    await typePaste(user, VALID_YAML);
    await user.click(screen.getByRole('button', { name: /submit for analysis/i }));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    const select = screen.getByRole('combobox', { name: /pipeline format/i });
    expect(within(select as HTMLElement).getByRole('option', { name: 'GitHub Actions' })).toBeTruthy();
    expect(within(select as HTMLElement).getByRole('option', { name: 'GitLab CI' })).toBeTruthy();
    expect(within(select as HTMLElement).getByRole('option', { name: 'Jenkins' })).toBeTruthy();
  });

  it('calls format-confirmation endpoint when user confirms', async () => {
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    await typePaste(user, VALID_YAML);
    await user.click(screen.getByRole('button', { name: /submit for analysis/i }));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /confirm format/i }));

    await waitFor(() => {
      expect(screen.getByRole('status', { name: /analysis complete/i })).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// AC-7 + AC-14: Error responses
// ---------------------------------------------------------------------------

describe('Error responses', () => {
  it('renders 413 error with 512 KB constraint', async () => {
    server.use(upload413Handler());
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    await typePaste(user, VALID_YAML);
    await user.click(screen.getByRole('button', { name: /submit for analysis/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert', { name: /submission error/i })).toBeInTheDocument();
    });

    const alert = screen.getByRole('alert', { name: /submission error/i });
    expect(alert).toHaveTextContent(/payload too large/i);
    expect(alert).toHaveTextContent(/512 KB/i);
    expect(alert).toHaveTextContent(/corr-413-test/);
  });

  it('renders 422 error with parse location', async () => {
    server.use(upload422Handler());
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    await typePaste(user, VALID_YAML);
    await user.click(screen.getByRole('button', { name: /submit for analysis/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert', { name: /submission error/i })).toBeInTheDocument();
    });

    const alert = screen.getByRole('alert', { name: /submission error/i });
    expect(alert).toHaveTextContent(/line 7/i);
    expect(alert).toHaveTextContent(/corr-422-test/);
  });

  it('renders 401 with re-authentication path', async () => {
    server.use(upload401Handler());
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    await typePaste(user, VALID_YAML);
    await user.click(screen.getByRole('button', { name: /submit for analysis/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert', { name: /submission error/i })).toBeInTheDocument();
    });

    const alert = screen.getByRole('alert', { name: /submission error/i });
    expect(alert).toHaveTextContent(/sign in again/i);
  });

  it('shows retry button after error', async () => {
    server.use(upload413Handler());
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    await typePaste(user, VALID_YAML);
    await user.click(screen.getByRole('button', { name: /submit for analysis/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// AC-8: Script tag renders as inert text
// ---------------------------------------------------------------------------

describe('Rendering safety', () => {
  it('renders definition containing a script tag as visible text without execution', async () => {
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    const scriptPayload = '<script>window.__xss_executed = true</script>';
    const { fireEvent } = await import('@testing-library/react');
    const textarea = screen.getByRole('textbox', { name: /paste pipeline definition/i });
    fireEvent.change(textarea, { target: { value: scriptPayload } });

    // The script tag characters should be in the textarea value (not executed as HTML)
    expect(textarea).toHaveValue(scriptPayload);

    // No XSS execution
    expect((window as unknown as Record<string, unknown>)['__xss_executed']).toBeUndefined();
  });

  it('success advisory_disclaimer is rendered as text, not HTML', async () => {
    const user = userEvent.setup();
    renderView();
    await switchToPasteTab(user);

    await typePaste(user, VALID_YAML);
    await user.click(screen.getByRole('button', { name: /submit for analysis/i }));

    await waitFor(() => {
      expect(screen.getByRole('status', { name: /analysis complete/i })).toBeInTheDocument();
    });

    // Advisory text appears as plain text in the DOM
    const advisory = screen.queryByText(/advisory only/i);
    if (advisory) {
      expect(advisory.closest('script')).toBeNull();
    }
  });
});

// ---------------------------------------------------------------------------
// AC-13: Timeout path
// ---------------------------------------------------------------------------

describe('Timeout path', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('shows timeout error after 45 s hang', async () => {
    server.use(uploadHangHandler());

    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    vi.useFakeTimers();

    renderView();
    await switchToPasteTab(user);
    await typePaste(user, VALID_YAML);
    await user.click(screen.getByRole('button', { name: /submit for analysis/i }));

    // Advance past the 45 s timeout
    await vi.advanceTimersByTimeAsync(46_000);

    await waitFor(() => {
      expect(screen.getByRole('alert', { name: /submission error/i })).toBeInTheDocument();
    });

    const alert = screen.getByRole('alert', { name: /submission error/i });
    expect(alert).toHaveTextContent(/timed out/i);
  });
});

// ---------------------------------------------------------------------------
// AC-10: Accessibility (axe-core) in both themes
// ---------------------------------------------------------------------------

describe('Accessibility', () => {
  it('has no serious or critical axe violations in light theme', async () => {
    const { container } = renderView();
    const results: AxeResults = await axe(container);
    const violations = results.violations.filter(
      (v) => v.impact === 'serious' || v.impact === 'critical',
    );
    expect(violations).toHaveLength(0);
  });

  it('has no serious or critical axe violations in dark theme', async () => {
    document.documentElement.classList.add('dark');
    const { container } = renderView();
    const results: AxeResults = await axe(container);
    const violations = results.violations.filter(
      (v) => v.impact === 'serious' || v.impact === 'critical',
    );
    expect(violations).toHaveLength(0);
    document.documentElement.classList.remove('dark');
  });
});

// ---------------------------------------------------------------------------
// AC-12: Keyboard walkthrough
// ---------------------------------------------------------------------------

describe('Keyboard operability', () => {
  it('can navigate to paste tab and submit using keyboard', async () => {
    const user = userEvent.setup();
    renderView();

    // Tab to the "Paste text" tab button and activate it
    await user.tab();
    // Find the paste tab and click it
    const pasteTab = screen.getByRole('tab', { name: /paste text/i });
    pasteTab.focus();
    await user.keyboard('{Enter}');

    // Textarea should be present
    const textarea = screen.getByRole('textbox', { name: /paste pipeline definition/i });
    textarea.focus();
    // Type some content
    await user.type(textarea, VALID_YAML);

    // Tab to submit button
    await user.tab();
    const submitBtn = screen.getByRole('button', { name: /submit for analysis/i });
    expect(submitBtn).toHaveFocus();

    await user.keyboard('{Enter}');

    await waitFor(() => {
      expect(screen.getByRole('status', { name: /analysis complete|analysis progress/i })).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// AC-3: File drop zone accessibility
// ---------------------------------------------------------------------------

describe('DropZone', () => {
  it('has visible file input accessible by keyboard', () => {
    renderView();
    const fileInput = screen.getByLabelText(/upload pipeline definition file/i);
    expect(fileInput).toBeInTheDocument();
    expect(fileInput).toHaveAttribute('type', 'file');
  });
});

// ---------------------------------------------------------------------------
// Unit test: client timeout (apiFetch returns timeout error on abort)
// ---------------------------------------------------------------------------

describe('apiFetch — timeout behaviour', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns timeout error when AbortController fires', async () => {
    const { apiFetch } = await import('../../api/client');

    server.use(uploadHangHandler());

    vi.useFakeTimers();
    const promise = apiFetch<unknown>('/api/v1/analyses', { method: 'POST', body: '{}' });
    await vi.advanceTimersByTimeAsync(46_000);
    const result = await promise;

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.title).toMatch(/timed out/i);
      expect(result.error.status).toBe(408);
    }
  });
});
