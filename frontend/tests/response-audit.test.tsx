import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { ResponsePage } from '../src/pages/ResponsePage';
import { AuditPage } from '../src/pages/AuditPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('ResponsePage Component', () => {
  it('renders defensive SOAR response queue with approval cards and dual-custody controls', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <ResponsePage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Defensive SOAR Response Queue');
    expect(html).toContain('BLOCK_IP');
    expect(html).toContain('198.51.100.42');
    expect(html).toContain('PENDING_APPROVAL');
    expect(html).toContain('Approve &amp; Execute');
    expect(html).toContain('Rollback');
  });
});

describe('AuditPage Component', () => {
  it('renders cryptographic ledger blocks and interactive chain verification', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <AuditPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Cryptographic Audit Ledger');
    expect(html).toContain('Verify Hash Chain');
    expect(html).toContain('Hash Chain Integrity Intact');
    expect(html).toContain('DETECTION_RULE_UPDATED');
    expect(html).toContain('SHA-256');
  });
});

