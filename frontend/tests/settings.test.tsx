import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { SettingsPage } from '../src/pages/SettingsPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('SettingsPage Component', () => {
  it('renders platform settings, organization governance, and retention configuration', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <SettingsPage initialTab="ORGANIZATION" />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Platform Settings &amp; Tenant Governance');
    expect(html).toContain('Telemetry Retention Policy');
    expect(html).toContain('Organization Profile');
  });

  it('renders RBAC role permissions matrix and active operator identity', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <SettingsPage initialTab="RBAC_TEAM" />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Role-Based Access Control (RBAC)');
    expect(html).toContain('ORG_ADMIN');
    expect(html).toContain('SECURITY_ANALYST');
    expect(html).toContain('AUDITOR');
    expect(html).toContain('READ_ONLY_VIEWER');
    expect(html).toContain('Team Members Directory');
  });

  it('renders deterministic evaluation demo scenarios and reset controls', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <SettingsPage initialTab="DEMO_CONTROLLER" />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Evaluation Demo Scenarios');
    expect(html).toContain('Multi-Stage SQLi &amp; Lateral Movement');
    expect(html).toContain('High-Velocity Credential Stuffing');
    expect(html).toContain('Reset Demo Telemetry');
  });
});
