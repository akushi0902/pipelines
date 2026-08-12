/**
 * AdminView — workspace member table with persona badges and grant history.
 *
 * Controls are rendered based on the current user's persona for UX only.
 * The server remains authoritative; hiding a control is never the gate.
 */

import React from 'react';
import { useRoleBindings } from '../api/adminClient';
import type { RoleBindingItem, Persona } from '../api/types';
import { ApiError } from '../api/catalogueClient';
import RoleBindingView from './RoleBindingView';

interface AdminViewProps {
  workspaceId: string;
  /** Current user's persona — cosmetic only; server enforces authz. */
  currentPersona: Persona | null;
}

const PERSONA_LABELS: Record<Persona, string> = {
  app_developer: 'App Developer',
  devops_engineer: 'DevOps Engineer',
  devsecops_engineer: 'DevSecOps Engineer',
  appsec_lead: 'AppSec Lead',
  engineering_manager: 'Engineering Manager',
};

const PERSONA_BADGE_COLOURS: Record<Persona, string> = {
  app_developer: 'bg-blue-100 text-blue-800',
  devops_engineer: 'bg-green-100 text-green-800',
  devsecops_engineer: 'bg-yellow-100 text-yellow-800',
  appsec_lead: 'bg-red-100 text-red-800',
  engineering_manager: 'bg-purple-100 text-purple-800',
};

function PersonaBadge({ persona }: { persona: Persona }) {
  const colour = PERSONA_BADGE_COLOURS[persona] ?? 'bg-gray-100 text-gray-800';
  const label = PERSONA_LABELS[persona] ?? persona;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${colour}`}>
      {label}
    </span>
  );
}

function LoadingSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading workspace members">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-10 bg-gray-100 rounded mb-2 animate-pulse" />
      ))}
    </div>
  );
}

export default function AdminView({ workspaceId, currentPersona }: AdminViewProps) {
  const { data, isLoading, error, refetch } = useRoleBindings(workspaceId);
  const [selectedBinding, setSelectedBinding] = React.useState<RoleBindingItem | null>(null);
  const [showGrantDialog, setShowGrantDialog] = React.useState(false);

  const canManageRoles = currentPersona === 'appsec_lead';

  if (isLoading) return <LoadingSkeleton />;

  if (error) {
    const status = error instanceof ApiError ? error.status : 0;
    if (status === 403) {
      return (
        <div role="alert" className="p-4 bg-yellow-50 border border-yellow-200 rounded">
          <p className="text-sm text-yellow-800">
            You do not have permission to view workspace members.
          </p>
        </div>
      );
    }
    return (
      <div role="alert" className="p-4 bg-red-50 border border-red-200 rounded">
        <p className="text-sm text-red-800">Failed to load workspace members.</p>
        <button
          onClick={() => void refetch()}
          className="mt-2 text-sm text-red-700 underline"
        >
          Retry
        </button>
      </div>
    );
  }

  const items = data?.items ?? [];

  return (
    <section aria-labelledby="admin-view-heading" data-testid="admin-view">
      <div className="flex items-center justify-between mb-4">
        <h2 id="admin-view-heading" className="text-lg font-semibold text-gray-900">
          Workspace Members
        </h2>
        {canManageRoles && (
          <button
            onClick={() => setShowGrantDialog(true)}
            className="px-3 py-1.5 text-sm font-medium bg-brand-600 text-white rounded hover:bg-brand-700 focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            Grant Access
          </button>
        )}
      </div>

      {items.length === 0 ? (
        <p className="text-sm text-gray-500">No active members in this workspace.</p>
      ) : (
        <table className="min-w-full divide-y divide-gray-200 text-sm">
          <thead>
            <tr>
              <th className="px-4 py-2 text-left font-medium text-gray-600">Member</th>
              <th className="px-4 py-2 text-left font-medium text-gray-600">Persona</th>
              <th className="px-4 py-2 text-left font-medium text-gray-600">Granted</th>
              {canManageRoles && (
                <th className="px-4 py-2 text-left font-medium text-gray-600">
                  Actions
                </th>
              )}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {items.map((binding) => (
              <tr key={binding.id}>
                <td className="px-4 py-2">
                  <p className="font-medium text-gray-900">{binding.display_name}</p>
                  <p className="text-xs text-gray-500">{binding.masked_email}</p>
                </td>
                <td className="px-4 py-2">
                  <PersonaBadge persona={binding.persona} />
                </td>
                <td className="px-4 py-2 text-gray-600">
                  {new Date(binding.granted_at).toLocaleDateString()}
                </td>
                {canManageRoles && (
                  <td className="px-4 py-2">
                    <button
                      onClick={() => setSelectedBinding(binding)}
                      className="text-xs text-brand-600 hover:underline focus:outline-none focus:ring-1 focus:ring-brand-500 rounded"
                    >
                      Manage
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {selectedBinding && (
        <RoleBindingView
          workspaceId={workspaceId}
          binding={selectedBinding}
          onClose={() => setSelectedBinding(null)}
        />
      )}

      {showGrantDialog && (
        <RoleBindingView
          workspaceId={workspaceId}
          binding={null}
          onClose={() => setShowGrantDialog(false)}
        />
      )}
    </section>
  );
}
