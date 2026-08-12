import type { AuditEventItem } from '../../api/types';

interface Props {
  items: AuditEventItem[];
  isLoading: boolean;
  error: string | null;
  onRetry: () => void;
}

function formatDate(iso: string): string {
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

export function CatalogueVersionHistory({
  items,
  isLoading,
  error,
  onRetry,
}: Props) {
  if (isLoading) {
    return (
      <div aria-busy="true" aria-label="Loading version history">
        {[...Array(3)].map((_, i) => (
          <div
            key={i}
            className="mb-2 h-10 animate-pulse rounded bg-gray-100"
          />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div role="alert" className="rounded border border-red-200 bg-red-50 p-4">
        <p className="text-sm text-red-700">{error}</p>
        <button
          onClick={onRetry}
          className="mt-2 text-sm font-medium text-red-700 underline focus:outline-none focus:ring-2 focus:ring-red-400"
        >
          Retry
        </button>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <p className="text-sm text-gray-500 italic">
        No version history available yet.
      </p>
    );
  }

  return (
    <table className="w-full text-sm border-collapse">
      <thead>
        <tr className="border-b text-left">
          <th scope="col" className="py-2 pr-4 font-medium text-gray-700">
            Action
          </th>
          <th scope="col" className="py-2 pr-4 font-medium text-gray-700">
            Actor
          </th>
          <th scope="col" className="py-2 font-medium text-gray-700">
            Time
          </th>
        </tr>
      </thead>
      <tbody>
        {items.map((item) => (
          <tr key={item.id} className="border-b last:border-b-0">
            <td className="py-2 pr-4 text-gray-800">{item.action}</td>
            <td className="py-2 pr-4 text-gray-600">{item.actor_id}</td>
            <td className="py-2 text-gray-500">
              <time dateTime={item.occurred_at}>
                {formatDate(item.occurred_at)}
              </time>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
