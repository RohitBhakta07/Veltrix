import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { OverviewPage } from '../src/pages/OverviewPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('OverviewPage Component', () => {
  it('renders executive overview metrics, headers and control buttons', () => {
    const qc = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
      },
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <OverviewPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Security posture overview');
    expect(html).toContain('Command');
    expect(html).toContain('Refresh');
    expect(html).toContain('24h');
  });

  it('renders KPI metrics and asset risk widgets when dashboard data is populated', () => {
    const qc = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
      },
    });

    // Populate dashboard summary query cache
    qc.setQueryData(['dashboard', 'summary', 24], {
      status: 'success',
      data: {
        rangeHours: 24,
        generatedAt: new Date().toISOString(),
        kpis: {
          eventsInWindow: 14205,
          attacksInWindow: 412,
          detectionsInWindow: 89,
          openIncidents: 4,
          criticalIncidents: 1,
          verifiedAssets: 6,
          totalAssets: 6,
          assetsWithTelemetry: 5,
          avgRiskScore: 68,
          activeScans: 0,
        },
        velocity: [],
        severity: [{ key: 'CRITICAL', count: 12 }],
        mitre: [{ key: 'Initial Access', count: 3 }],
        riskBands: [{ key: 'HIGH', count: 3 }],
        assets: [
          {
            siteId: 'site-001',
            name: 'Shop Core',
            domain: 'shop.veltrix.io',
            environment: 'production',
            status: 'VERIFIED',
            telemetryStatus: 'ACTIVE',
            riskScore: 82,
            riskBand: 'CRITICAL',
            factors: {
              assetCriticalityMultiplier: 1.5,
              threatIntelMultiplier: 1.2,
              vulnerabilityMatchTerm: 20,
              attackSequenceBonus: 10,
              calculationExplanation: 'High threat intensity',
            },
            stats: {
              events24h: 3400,
              attacks24h: 120,
              detections24h: 30,
              openIncidents: 1,
              lastTelemetrySeenAt: new Date().toISOString(),
            },
          },
        ],
        recentIncidents: [],
      },
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <OverviewPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Events in window');
    expect(html).toContain('Attack events');
    expect(html).toContain('shop.veltrix.io');
    expect(html).toContain('82');
  });
});
