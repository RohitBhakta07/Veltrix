import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { EventsPage } from '../src/pages/EventsPage';
import { AuthProvider } from '../src/features/auth/AuthProvider';

describe('EventsPage Component', () => {
  it('renders telemetry explorer header, filter inputs and pagination controls', () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <EventsPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('Telemetry explorer');
    expect(html).toContain('Detect');
    expect(html).toContain('Severity');
    expect(html).toContain('Event type');
    expect(html).toContain('Source IP');
    expect(html).toContain('198.51.100.23');
    expect(html).toContain('Page size');
  });

  it('renders populated security events table with severity badges and source IPs', () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });

    // Populate events query cache
    qc.setQueryData(
      [
        'events',
        {
          limit: 100,
          cursor: undefined,
          severity: undefined,
          eventType: undefined,
          sourceIp: undefined,
        },
      ],
      {
        status: 'success',
        data: {
          events: [
            {
              eventId: 'evt-sqli-991',
              timestamp: new Date().toISOString(),
              eventType: 'web.attack.sqli',
              category: 'SECURITY_ALERT',
              severity: 'CRITICAL',
              sourceIp: '203.0.113.45',
              sourceSystem: 'WAAP-Edge',
              metadata: {
                requestUri: '/api/v1/auth/login?user=admin%27%20OR%201=1--',
                domain: 'shop.veltrix.io',
              },
            },
            {
              eventId: 'evt-norm-102',
              timestamp: new Date().toISOString(),
              eventType: 'web.request.normal',
              category: 'NETWORK_ACTIVITY',
              severity: 'LOW',
              sourceIp: '198.51.100.12',
              sourceSystem: 'Nginx-Gateway',
              metadata: {
                requestUri: '/static/main.css',
              },
            },
          ],
          total: 2,
          nextCursor: 'cursor-page-2',
        },
      }
    );

    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <MemoryRouter>
            <EventsPage />
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );

    expect(html).toContain('web.attack.sqli');
    expect(html).toContain('203.0.113.45');
    expect(html).toContain('/api/v1/auth/login');
    expect(html).toContain('CRITICAL');
    expect(html).toContain('web.request.normal');
    expect(html).toContain('198.51.100.12');
  });
});

