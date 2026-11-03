import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { IntegrationsPage } from '../src/pages/IntegrationsPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('IntegrationsPage Component', () => {
  it('renders telemetry integrations header and register button', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <IntegrationsPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Telemetry Integrations &amp; Ingestion Clients');
    expect(html).toContain('Register Integration');
    expect(html).toContain('Refresh');
  });
});

