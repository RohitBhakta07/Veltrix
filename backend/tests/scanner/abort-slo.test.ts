import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import { performance } from 'node:perf_hooks';
import {
  ActiveSocketRegistry,
  SafeHttpClient,
  DnsResolver,
  createAuthorizedScanScopeContext,
} from '../../src/scanner/transport/index.js';

describe('Phase 8: Emergency Abort Latency & Multi-Tenant Isolation Benchmark (TASK-802)', () => {
  let longPollingServer: http.Server;
  let serverPort: number;

  beforeAll(async () => {
    longPollingServer = http.createServer((_req, _res) => {
      // Intentionally keep request open indefinitely to test socket teardown
    });

    await new Promise<void>((resolve) => {
      longPollingServer.listen(0, '127.0.0.1', () => {
        const addr = longPollingServer.address() as net.AddressInfo;
        serverPort = addr.port;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => longPollingServer.close(() => resolve()));
  });

  it('abortScan(orgId, scanId) signature enforces explicit tenant identity and sub-500ms SLO under identical scan ID collision', async () => {
    const registry = new ActiveSocketRegistry();

    const client = new SafeHttpClient({
      dnsResolver: new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      }),
      socketRegistry: registry,
      allowLoopbackForTesting: true,
    });

    const collisionScanId = 'scan-collision-001';

    // Tenant A Context
    const tenantAContext = createAuthorizedScanScopeContext({
      orgId: 'org-alpha',
      scanId: collisionScanId,
      siteId: 'site-alpha-001',
      primaryDomain: 'alpha.example.com',
      approvedSubdomains: [],
      status: 'VERIFIED',
      scanBlocked: false,
      expiresAt: Date.now() + 86400000,
      allowedPorts: [serverPort],
    });

    // Tenant B Context (Identical scanId!)
    const tenantBContext = createAuthorizedScanScopeContext({
      orgId: 'org-bravo',
      scanId: collisionScanId,
      siteId: 'site-bravo-001',
      primaryDomain: 'bravo.example.com',
      approvedSubdomains: [],
      status: 'VERIFIED',
      scanBlocked: false,
      expiresAt: Date.now() + 86400000,
      allowedPorts: [serverPort],
    });

    // Dispatch 5 concurrent long-polling requests for Tenant A
    const tenantAPromises = Array.from({ length: 5 }, () =>
      client.get(`http://alpha.example.com:${serverPort}/long-poll`, {
        context: tenantAContext,
        allowLoopbackForTesting: true,
        timeoutMs: 15000,
      }).catch((e) => e)
    );

    // Dispatch 5 concurrent long-polling requests for Tenant B
    const tenantBPromises = Array.from({ length: 5 }, () =>
      client.get(`http://bravo.example.com:${serverPort}/long-poll`, {
        context: tenantBContext,
        allowLoopbackForTesting: true,
        timeoutMs: 15000,
      }).catch((e) => e)
    );

    // Give sockets 50ms to establish TCP connection
    await new Promise((r) => setTimeout(r, 50));

    expect(registry.getActiveCount('org-alpha', collisionScanId)).toBe(5);
    expect(registry.getActiveCount('org-bravo', collisionScanId)).toBe(5);

    // Benchmark emergency abort execution for Tenant A
    const start = performance.now();
    const abortedCount = registry.abortScan('org-alpha', collisionScanId);
    const durationMs = performance.now() - start;

    // 1. Verify sub-500ms abort SLO
    expect(abortedCount).toBe(5);
    expect(durationMs).toBeLessThan(500);

    // 2. Tenant A sockets are immediately destroyed
    const tenantAResults = await Promise.all(tenantAPromises);
    expect(tenantAResults.length).toBe(5);
    for (const res of tenantAResults) {
      expect(res).toBeInstanceOf(Error);
    }
    expect(registry.getActiveCount('org-alpha', collisionScanId)).toBe(0);

    // 3. INVIOLABLE MULTI-TENANT ISOLATION:
    // Tenant B sockets with identical scan ID remain 100% active, healthy, and untouched!
    expect(registry.getActiveCount('org-bravo', collisionScanId)).toBe(5);

    // Clean up Tenant B sockets
    registry.abortScan('org-bravo', collisionScanId);
    await Promise.all(tenantBPromises);
    expect(registry.getActiveCount('org-bravo', collisionScanId)).toBe(0);
  });

  it('guarantees intra-tenant concurrency isolation: aborting scan-1 does not disrupt scan-2 within same tenant', async () => {
    const registry = new ActiveSocketRegistry();

    const client = new SafeHttpClient({
      dnsResolver: new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      }),
      socketRegistry: registry,
      allowLoopbackForTesting: true,
    });

    const orgId = 'org-enterprise-01';

    const scan1Context = createAuthorizedScanScopeContext({
      orgId,
      scanId: 'scan-alpha-1',
      siteId: 'site-001',
      primaryDomain: 'primary.example.com',
      approvedSubdomains: [],
      status: 'VERIFIED',
      scanBlocked: false,
      expiresAt: Date.now() + 86400000,
      allowedPorts: [serverPort],
    });

    const scan2Context = createAuthorizedScanScopeContext({
      orgId,
      scanId: 'scan-alpha-2',
      siteId: 'site-002',
      primaryDomain: 'primary.example.com',
      approvedSubdomains: [],
      status: 'VERIFIED',
      scanBlocked: false,
      expiresAt: Date.now() + 86400000,
      allowedPorts: [serverPort],
    });

    const scan1Promises = Array.from({ length: 3 }, () =>
      client.get(`http://primary.example.com:${serverPort}/poll1`, {
        context: scan1Context,
        allowLoopbackForTesting: true,
      }).catch((e) => e)
    );

    const scan2Promises = Array.from({ length: 3 }, () =>
      client.get(`http://primary.example.com:${serverPort}/poll2`, {
        context: scan2Context,
        allowLoopbackForTesting: true,
      }).catch((e) => e)
    );

    await new Promise((r) => setTimeout(r, 50));

    expect(registry.getActiveCount(orgId, 'scan-alpha-1')).toBe(3);
    expect(registry.getActiveCount(orgId, 'scan-alpha-2')).toBe(3);

    // Abort scan-1 only
    registry.abortScan(orgId, 'scan-alpha-1');

    await Promise.all(scan1Promises);
    expect(registry.getActiveCount(orgId, 'scan-alpha-1')).toBe(0);

    // scan-2 remains fully active and unaffected
    expect(registry.getActiveCount(orgId, 'scan-alpha-2')).toBe(3);

    registry.abortScan(orgId, 'scan-alpha-2');
    await Promise.all(scan2Promises);
    expect(registry.getActiveCount(orgId, 'scan-alpha-2')).toBe(0);
  });

  it('destroys incoming sockets registered while an abort is actively occurring (race prevention)', () => {
    const registry = new ActiveSocketRegistry();
    const orgId = 'org-test';
    const scanId = 'scan-racing';

    // Trigger abort
    registry.abortScan(orgId, scanId);

    // A racing socket arrives immediately after
    let destroyed = false;
    const mockSocket = {
      destroy: () => {
        destroyed = true;
      },
      once: () => {},
    } as unknown as net.Socket;

    registry.register(orgId, scanId, mockSocket);

    expect(destroyed).toBe(true);
    expect(registry.getActiveCount(orgId, scanId)).toBe(0);
  });
});
