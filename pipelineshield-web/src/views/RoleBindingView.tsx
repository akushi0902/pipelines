/**
 * RoleBindingView — grant/revoke dialog for a workspace member.
 *
 * Rendered as a Radix UI Dialog with focus trap and Escape dismissal.
 * Confirmation is required for revoke operations.
 *
 * The server is authoritative; this view is cosmetic.
 */

import React from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { ApiError } from '../api/catalogueClient';
import { useGrantBinding, useRevokeBinding, useChangeBinding } from '../api/adminClient';
import type { RoleBindingItem, Persona } from '../api/types';
import { VALID_PERSONAS } from '../api/types';

interface RoleBindingViewProps {
  workspaceId: string;
  /** Existing binding to manage (null = new grant mode). */
  binding: RoleBindingItem | null;
  onClose: () => void;
}

const PERSONA_LABELS: Record<Persona, string> = {
  app_developer: 'App Developer',
  devops_engineer: 'DevOps Engineer',
  devsecops_engineer: 'DevSecOps Engineer',
  appsec_lead: 'AppSec Lead',
  engineering_manager: 'Engineering Manager',
};

function ErrorBanner({ message }: { message: string }) {
  return (
    <div role="alert" className="mt-2 p-2 bg-red-50 border border-red-200 rounded text-sm text-red-800">
      {message}
    </div>
  );
}

export default function RoleBindingView({
  workspaceId,
  binding,
  onClose,
}: RoleBindingViewProps) {
  const isGrantMode = binding === null;

  const [userId, setUserId] = React.useState('');
  const [persona, setPersona] = React.useState<Persona>('app_developer');
  const [confirmRevoke, setConfirmRevoke] = React.useState(false);
  const [apiError, setApiError] = React.useState<string | null>(null);

  const grantMutation = useGrantBinding(workspaceId);
  const changeMutation = useChangeBinding(
    workspaceId,
    binding?.id ?? '',
  );
  const revokeMutation = useRevokeBinding(workspaceId);

  const isLoading =
    grantMutation.isPending ||
    changeMutation.isPending ||
    revokeMutation.isPending;

  function handleApiError(err: unknown) {
    if (err instanceof ApiError) {
      const status = err.status;
      if (status === 409) {
        setApiError(err.body.detail ?? 'Conflict: operation not allowed.');
      } else if (status === 403) {
        setApiError('You do not have permission to perform this action.');
      } else {
        setApiError(err.body.detail ?? 'An unexpected error occurred.');
      }
    } else {
      setApiError('Network error. Please try again.');
    }
  }

  function handleGrant() {
    setApiError(null);
    grantMutation.mutate(
      { user_id: userId.trim(), persona },
      {
        onSuccess: () => onClose(),
        onError: handleApiError,
      },
    );
  }

  function handleChange() {
    if (!binding) return;
    setApiError(null);
    changeMutation.mutate(
      { persona },
      {
        onSuccess: () => onClose(),
        onError: handleApiError,
      },
    );
  }

  function handleRevoke() {
    if (!binding) return;
    setApiError(null);
    revokeMutation.mutate(binding.id, {
      onSuccess: () => onClose(),
      onError: handleApiError,
    });
  }

  const title = isGrantMode
    ? 'Grant Access'
    : `Manage ${binding.display_name}`;

  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 bg-white rounded-lg shadow-xl p-6 w-full max-w-md focus:outline-none"
          data-testid="role-binding-dialog"
        >
          <Dialog.Title className="text-base font-semibold text-gray-900 mb-4">
            {title}
          </Dialog.Title>

          {isGrantMode ? (
            <>
              <div className="mb-3">
                <label
                  htmlFor="user-id-input"
                  className="block text-sm font-medium text-gray-700 mb-1"
                >
                  User ID
                </label>
                <input
                  id="user-id-input"
                  type="text"
                  value={userId}
                  onChange={(e) => setUserId(e.target.value)}
                  placeholder="00000000-0000-..."
                  className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
              </div>
              <div className="mb-4">
                <label
                  htmlFor="persona-select-grant"
                  className="block text-sm font-medium text-gray-700 mb-1"
                >
                  Persona
                </label>
                <select
                  id="persona-select-grant"
                  value={persona}
                  onChange={(e) => setPersona(e.target.value as Persona)}
                  className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                >
                  {VALID_PERSONAS.map((p) => (
                    <option key={p} value={p}>
                      {PERSONA_LABELS[p]}
                    </option>
                  ))}
                </select>
              </div>
              {apiError && <ErrorBanner message={apiError} />}
              <div className="flex justify-end gap-2 mt-4">
                <Dialog.Close asChild>
                  <button className="px-3 py-1.5 text-sm text-gray-700 border border-gray-300 rounded hover:bg-gray-50">
                    Cancel
                  </button>
                </Dialog.Close>
                <button
                  onClick={handleGrant}
                  disabled={isLoading || !userId.trim()}
                  className="px-3 py-1.5 text-sm font-medium bg-brand-600 text-white rounded hover:bg-brand-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-brand-500"
                >
                  {isLoading ? 'Granting…' : 'Grant Access'}
                </button>
              </div>
            </>
          ) : (
            <>
              <p className="text-sm text-gray-600 mb-1">
                <span className="font-medium">Email:</span> {binding.masked_email}
              </p>
              <p className="text-sm text-gray-600 mb-4">
                <span className="font-medium">Current persona:</span>{' '}
                {PERSONA_LABELS[binding.persona] ?? binding.persona}
              </p>

              {confirmRevoke ? (
                <>
                  <p className="text-sm text-red-700 mb-4">
                    Are you sure you want to revoke access for{' '}
                    <strong>{binding.display_name}</strong>? This takes effect
                    immediately on their next request.
                  </p>
                  {apiError && <ErrorBanner message={apiError} />}
                  <div className="flex justify-end gap-2">
                    <button
                      onClick={() => setConfirmRevoke(false)}
                      className="px-3 py-1.5 text-sm text-gray-700 border border-gray-300 rounded hover:bg-gray-50"
                    >
                      Back
                    </button>
                    <button
                      onClick={handleRevoke}
                      disabled={isLoading}
                      className="px-3 py-1.5 text-sm font-medium bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-red-500"
                    >
                      {isLoading ? 'Revoking…' : 'Confirm Revoke'}
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <div className="mb-4">
                    <label
                      htmlFor="persona-select-change"
                      className="block text-sm font-medium text-gray-700 mb-1"
                    >
                      Change persona to
                    </label>
                    <select
                      id="persona-select-change"
                      defaultValue={binding.persona}
                      onChange={(e) => setPersona(e.target.value as Persona)}
                      className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                    >
                      {VALID_PERSONAS.map((p) => (
                        <option key={p} value={p}>
                          {PERSONA_LABELS[p]}
                        </option>
                      ))}
                    </select>
                  </div>
                  {apiError && <ErrorBanner message={apiError} />}
                  <div className="flex justify-between mt-4">
                    <button
                      onClick={() => setConfirmRevoke(true)}
                      className="px-3 py-1.5 text-sm font-medium text-red-600 border border-red-300 rounded hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-red-400"
                    >
                      Revoke Access
                    </button>
                    <div className="flex gap-2">
                      <Dialog.Close asChild>
                        <button className="px-3 py-1.5 text-sm text-gray-700 border border-gray-300 rounded hover:bg-gray-50">
                          Cancel
                        </button>
                      </Dialog.Close>
                      <button
                        onClick={handleChange}
                        disabled={isLoading}
                        className="px-3 py-1.5 text-sm font-medium bg-brand-600 text-white rounded hover:bg-brand-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-brand-500"
                      >
                        {isLoading ? 'Saving…' : 'Change Persona'}
                      </button>
                    </div>
                  </div>
                </>
              )}
            </>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
