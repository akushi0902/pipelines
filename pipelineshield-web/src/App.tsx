import { useState } from 'react';
import { CatalogueAdminView } from './views/CatalogueAdminView';
import { UploadView } from './views/UploadView';
import { ThemeToggle } from './components/ThemeToggle';

type Route = 'upload' | 'admin';

export default function App() {
  const [route, setRoute] = useState<Route>('upload');

  return (
    <div className="min-h-screen bg-surface text-text-primary">
      <header className="border-b border-border bg-surface-raised">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <nav className="flex items-center gap-1" aria-label="Main navigation">
            <button
              type="button"
              role="link"
              onClick={() => setRoute('upload')}
              aria-current={route === 'upload' ? 'page' : undefined}
              className={[
                'rounded px-3 py-1.5 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-border-focus',
                route === 'upload'
                  ? 'bg-surface text-text-primary shadow-sm'
                  : 'text-text-secondary hover:text-text-primary',
              ].join(' ')}
            >
              Upload
            </button>
            <button
              type="button"
              role="link"
              onClick={() => setRoute('admin')}
              aria-current={route === 'admin' ? 'page' : undefined}
              className={[
                'rounded px-3 py-1.5 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-border-focus',
                route === 'admin'
                  ? 'bg-surface text-text-primary shadow-sm'
                  : 'text-text-secondary hover:text-text-primary',
              ].join(' ')}
            >
              Admin
            </button>
          </nav>
          <ThemeToggle />
        </div>
      </header>

      <main>
        {route === 'upload' ? <UploadView /> : <CatalogueAdminView />}
      </main>
    </div>
  );
}
