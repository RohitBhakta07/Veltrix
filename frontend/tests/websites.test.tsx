import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { WebsitesPage } from '../src/pages/WebsitesPage';
import { WebsiteDetailPage } from '../src/pages/WebsiteDetailPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('WebsitesPage Component', () => {
  it('renders registered website assets inventory and add website button', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <WebsitesPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Website Asset Inventory');
    expect(html).toContain('Register Website');
  });
});

describe('WebsiteDetailPage Component', () => {
  it('renders asset details, breadcrumb back link, and risk scoring breakdown', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    // Populate website detail and risk summary
    qc.setQueryData(['website', 'site-shop-01'], {
      success: true,
      site: {
        siteId: 'site-shop-01',
        orgId: 'org-enterprise-01',
        name: 'Shop Core Production',
        primaryDomain: 'shop.veltrix.io',
        environment: 'PRODUCTION',
        status: 'VERIFIED',
        riskTier: 'CRITICAL',
        approvedSubdomains: ['api.shop.veltrix.io'],
        tags: ['ecommerce', 'pci-dss'],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    });

    qc.setQueryData(['website', 'site-shop-01', 'risk-summary'], {
      status: 'success',
      data: {
        siteId: 'site-shop-01',
        domain: 'shop.veltrix.io',
        environment: 'PRODUCTION',
        riskTier: 'CRITICAL',
        currentRiskScore: 88,
        currentRiskBand: 'CRITICAL',
        factors: {
          baseSeverity: 25,
          assetCriticalityMultiplier: 1.5,
          threatIntelMultiplier: 1.4,
          vulnerabilityMatchTerm: 20,
          attackSequenceBonus: 10,
          calculationExplanation: 'Critical asset undergoing automated exploitation',
        },
      },
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter initialEntries={['/websites/site-shop-01']}>
            <Routes>
              <Route path="/websites/:siteId" element={<WebsiteDetailPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Back to Inventory');
    expect(html).toContain('Shop Core Production');
    expect(html).toContain('shop.veltrix.io');
    expect(html).toContain('Explainable Risk Scoring Breakdown');
    expect(html).toContain('Base Severity');
    expect(html).toContain('Criticality Mult');
    expect(html).toContain('Sequence Bonus');
  });

  it('renders grace period scan freeze alert when domain verification is revoked', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    qc.setQueryData(['website', 'site-frozen-02'], {
      success: true,
      site: {
        siteId: 'site-frozen-02',
        orgId: 'org-enterprise-01',
        name: 'Staging Portal',
        primaryDomain: 'stage.veltrix.io',
        environment: 'STAGING',
        status: 'GRACE_PERIOD',
        riskTier: 'HIGH',
        approvedSubdomains: [],
        tags: ['staging'],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter initialEntries={['/websites/site-frozen-02']}>
            <Routes>
              <Route path="/websites/:siteId" element={<WebsiteDetailPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Domain Verification In Grace Period');
    expect(html).toContain('All active and scheduled scans against this target are frozen');
  });
});
