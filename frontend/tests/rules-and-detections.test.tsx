import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { RulesPage } from '../src/pages/RulesPage';
import { DetectionsPage } from '../src/pages/DetectionsPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('RulesPage Component', () => {
  it('renders sigma detection rules catalog header', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <RulesPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Detection Rules Catalog');
    expect(html).toContain('Sigma-inspired threat detection rules');
  });

  it('renders populated sigma rules with thresholds and toggle controls', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    qc.setQueryData(['detection-rules'], {
      status: 'success',
      data: {
        rules: [
          {
            ruleId: 'SIGMA-SQLI-001',
            orgId: 'org-enterprise-01',
            name: 'SQL Injection Pattern Detection',
            description: 'Identifies SQL injection syntax in request URI and parameters',
            category: 'WEB_APPLICATION',
            severity: 'CRITICAL',
            threshold: 3,
            slidingWindowSeconds: 60,
            isEnabled: true,
            condition: { field: 'requestUri', regex: '.*(UNION|SELECT).*' },
            mitreAttack: {
              techniqueId: 'T1190',
              techniqueName: 'Exploit Public-Facing Application',
              tactic: 'Initial Access',
            },
          },
        ],
      },
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <RulesPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Live Evaluation Tester');
    expect(html).toContain('SIGMA-SQLI-001');
    expect(html).toContain('SQL Injection Pattern Detection');
    expect(html).toContain('Threshold: 3 events');
    expect(html).toContain('Window: 60s');
    expect(html).toContain('MITRE: T1190 (Initial Access)');
    expect(html).toContain('ACTIVE');
  });
});

describe('DetectionsPage Component', () => {
  it('renders detection findings header, action buttons and filters', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <DetectionsPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Detection findings');
    expect(html).toContain('Detect');
    expect(html).toContain('Refresh');
  });

  it('renders populated detection findings table with confidence tier and severity badges', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    qc.setQueryData(
      ['detections', { severity: '', ruleId: '', siteId: '' }],
      {
        status: 'success',
        data: {
          items: [
            {
              detectionId: 'det-sqli-01',
              timestamp: new Date().toISOString(),
              ruleId: 'SIGMA-SQLI-001',
              ruleName: 'SQL Injection Pattern Detection',
              severity: 'CRITICAL',
              siteId: 'site-shop-01',
              confidence: 0.95,
              status: 'NEW',
              evidence: {
                matchedThreshold: 3,
                triggeringEvents: ['evt-1', 'evt-2', 'evt-3'],
                details: {
                  confidenceLevel: 'CONFIRMED_EXPLOITATION',
                  matchedPatterns: ['UNION_SELECT'],
                },
              },
            },
          ],
          total: 1,
        },
      }
    );

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <DetectionsPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('SIGMA-SQLI-001');
    expect(html).toContain('CRITICAL');
    expect(html).toContain('Confirmed exploitation');
  });
});
