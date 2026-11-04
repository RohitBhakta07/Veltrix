import { describe, it, expect } from 'vitest';
import { appRoutes } from '../src/app/router';

describe('SOC Console Router Configuration', () => {
  it('registers all required security console routes in the application route tree', () => {
    const rootRoute = appRoutes.find((r) => r.path === '/');
    expect(rootRoute).toBeDefined();

    const childPaths = rootRoute?.children?.map((c) => c.path) || [];
    expect(childPaths).toContain('');
    expect(childPaths).toContain('events');
    expect(childPaths).toContain('detections');
    expect(childPaths).toContain('rules');
    expect(childPaths).toContain('websites');
    expect(childPaths).toContain('websites/:siteId');
    expect(childPaths).toContain('integrations');
    expect(childPaths).toContain('scans');
    expect(childPaths).toContain('findings');
    expect(childPaths).toContain('incidents');
    expect(childPaths).toContain('incidents/:incidentId');
    expect(childPaths).toContain('response');
    expect(childPaths).toContain('audit');
    expect(childPaths).toContain('intel');
    expect(childPaths).toContain('settings');

    const loginRoute = appRoutes.find((r) => r.path === '/login');
    expect(loginRoute).toBeDefined();
  });
});

