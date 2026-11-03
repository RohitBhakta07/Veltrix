import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { IncidentsPage } from '../src/pages/IncidentsPage';
import { IncidentDetailPage } from '../src/pages/IncidentDetailPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('IncidentsPage Component', () => {
  it('renders incident triage queue with status filter buttons and incident list', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    qc.setQueryData(['incidents', 'ALL'], {
      success: true,
      data: {
        items: [
          {
            incidentId: 'inc-sql-001',
            orgId: 'org-test-01',
            title: 'SQL Injection Sequence Detected',
            description: 'Repeated high-frequency union select payload injection',
            severity: 'CRITICAL',
            riskScore: 92,
            status: 'INVESTIGATING',
            associatedEventIds: ['evt-1', 'evt-2'],
            timeline: [],
            suggestedResponses: ['BLOCK_IP'],
            createdAt: '2026-11-03T20:00:00.000Z',
            updatedAt: '2026-11-03T20:10:00.000Z',
          },
          {
            incidentId: 'inc-xss-002',
            orgId: 'org-test-01',
            title: 'Stored XSS in Comment Field',
            description: 'Reflected script payload detected by WAF engine',
            severity: 'HIGH',
            riskScore: 78,
            status: 'OPEN',
            associatedEventIds: ['evt-3'],
            timeline: [],
            suggestedResponses: ['TERMINATE_USER_SESSION'],
            createdAt: '2026-11-03T21:00:00.000Z',
            updatedAt: '2026-11-03T21:05:00.000Z',
          },
        ],
        total: 2,
      },
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <IncidentsPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Security Incidents');
    expect(html).toContain('INVESTIGATING');
    expect(html).toContain('inc-sql-001');
    expect(html).toContain('SQL Injection Sequence Detected');
    expect(html).toContain('inc-xss-002');
    expect(html).toContain('Inspect Triage');
  });
});

describe('IncidentDetailPage Component', () => {
  it('renders incident detail, MITRE kill chain, risk score waterfall, and analyst notes', () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const mockIncident = {
      incidentId: 'inc-sql-001',
      orgId: 'org-test-01',
      title: 'SQL Injection Sequence Detected',
      description: 'Repeated high-frequency union select payload injection',
      severity: 'CRITICAL',
      riskScore: 92,
      riskFactors: {
        assetCriticalityMultiplier: 1.5,
        threatIntelMultiplier: 1.2,
        vulnerabilityMatchTerm: 20,
        attackSequenceBonus: 10,
        calculationExplanation: 'Critical SQL injection attack sequence matched against active database target.',
      },
      status: 'INVESTIGATING',
      assignedTo: 'sec-analyst@cyberdefend.corp',
      associatedEventIds: ['evt-1', 'evt-2'],
      timeline: [
        {
          timestamp: '2026-11-03T20:00:00.000Z',
          eventType: 'WEB_ATTACK_SQLI',
          description: 'SQLi probe payload detected on /api/v1/auth/login',
          sourceIp: '198.51.100.42',
          mitreTactic: 'Initial Access',
        },
        {
          timestamp: '2026-11-03T20:02:00.000Z',
          eventType: 'DATABASE_QUERY_ERROR',
          description: 'Syntax error in dynamic SQL query execution',
          sourceIp: '198.51.100.42',
          mitreTactic: 'Execution',
        },
      ],
      suggestedResponses: ['BLOCK_IP', 'REVOKE_SESSION'],
      notes: [
        {
          noteId: 'note-1',
          author: 'Alice Analyst',
          content: 'Confirmed malicious IP originating from known Tor exit node.',
          timestamp: '2026-11-03T20:15:00.000Z',
        },
      ],
      createdAt: '2026-11-03T20:00:00.000Z',
      updatedAt: '2026-11-03T20:15:00.000Z',
    };

    qc.setQueryData(['incident', 'inc-sql-001'], {
      success: true,
      data: mockIncident,
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter initialEntries={['/incidents/inc-sql-001']}>
            <Routes>
              <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('inc-sql-001');
    expect(html).toContain('SQL Injection Sequence Detected');
    expect(html).toContain('Kill-Chain Progress');
    expect(html).toContain('Explainable Risk Score Waterfall');
    expect(html).toContain('Analyst Notes Thread');
    expect(html).toContain('Alice Analyst');
    expect(html).toContain('Confirmed malicious IP originating from known Tor exit node.');
    expect(html).toContain('Attack Story Replay');
    expect(html).toContain('SQLi probe payload detected on /api/v1/auth/login');
  });
});
