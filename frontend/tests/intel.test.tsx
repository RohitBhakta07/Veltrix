import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { IntelPage } from '../src/pages/IntelPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('IntelPage Component', () => {
  it('renders threat intelligence indicators, provenance badges, and KPI stats', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    qc.setQueryData(['threat-intel', 'ALL', 'ALL'], {
      success: true,
      data: {
        indicators: [
          {
            indicatorId: 'ind-001',
            type: 'IP',
            value: '198.51.100.42',
            threatType: 'Known Tor Exit Node & Web Scanner',
            severity: 'CRITICAL',
            confidence: 95,
            source: 'AlienVault OTX',
            provenance: 'VERIFIED_FEED',
            retrievedAt: '2026-11-03T18:00:00.000Z',
            firstSeen: '2026-11-01T10:00:00.000Z',
            lastSeen: '2026-11-03T20:00:00.000Z',
            isFlagged: true,
          },
          {
            indicatorId: 'ind-002',
            type: 'DOMAIN',
            value: 'malicious-c2-tunnel.xyz',
            threatType: 'Active Command and Control Beacon',
            severity: 'HIGH',
            confidence: 88,
            source: 'Internal Threat Hunt',
            provenance: 'MANUAL_ANALYST',
            submittedBy: 'analyst@cyberdefend.corp',
            firstSeen: '2026-11-02T12:00:00.000Z',
            lastSeen: '2026-11-03T19:30:00.000Z',
            isFlagged: true,
          },
        ],
      },
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <IntelPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Threat Intelligence &amp; IOC Dossiers');
    expect(html).toContain('198.51.100.42');
    expect(html).toContain('malicious-c2-tunnel.xyz');
    expect(html).toContain('VERIFIED_FEED');
    expect(html).toContain('MANUAL_ANALYST');
    expect(html).toContain('AlienVault OTX');
    expect(html).toContain('Sync Feeds');
    expect(html).toContain('Total Indicators');
  });
});
