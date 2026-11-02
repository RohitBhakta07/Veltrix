import { describe, it, expect } from 'vitest';
import net from 'node:net';
import {
  SafeHttpClient,
  DnsResolver,
  type RequestAuthorizationContext,
} from '../../src/scanner/transport/index.js';

describe('Phase 8: DNS Rebinding Mitigation Harness (TASK-802)', () => {
  it('mitigates DNS rebinding via pre-flight DNS pinning and prevents TOCTOU secondary lookup', async () => {
    let queryCount = 0;
    const lookupQueries: string[] = [];

    // Alternating DNS resolver:
    // Query 1: returns public safe IP (93.184.216.34)
    // Query 2: returns AWS IMDS metadata IP (169.254.169.254)
    const alternatingResolver = new DnsResolver({
      lookupFn: async (hostname: string) => {
        lookupQueries.push(hostname);
        queryCount++;
        if (queryCount === 1) {
          return [{ address: '93.184.216.34', family: 4 }];
        }
        return [{ address: '169.254.169.254', family: 4 }];
      },
    });

    let connectedHost: string | null = null;
    let connectedPort: number | null = null;

    const mockConnector = {
      connect(options: { host: string; port: number }) {
        connectedHost = options.host;
        connectedPort = options.port;
        const sock = new net.Socket();
        setTimeout(() => {
          sock.emit('error', new Error('ECONNREFUSED'));
        }, 10);
        return sock;
      },
      connectTls(options: any) {
        return options.socket;
      },
    };

    const client = new SafeHttpClient({
      dnsResolver: alternatingResolver,
      socketConnector: mockConnector,
    });

    const context: RequestAuthorizationContext = {
      purpose: 'AUTHORIZED_SCAN',
      orgId: 'org-enterprise-01',
      scanId: 'scan-001',
      siteId: 'site-001',
      primaryDomain: 'rebind.attacker.org',
      approvedSubdomains: [],
      status: 'VERIFIED',
      scanBlocked: false,
      expiresAt: Date.now() + 86400000,
    };

    // Request is dispatched
    await expect(
      client.get('http://rebind.attacker.org/test', {
        context,
      })
    ).rejects.toThrow();

    // 1. Assert exactly ONE DNS lookup occurred during the entire request lifecycle
    expect(queryCount).toBe(1);
    expect(lookupQueries).toEqual(['rebind.attacker.org']);

    // 2. Assert socket connector received the pinned safe IP from query 1 (93.184.216.34)
    expect(connectedHost).toBe('93.184.216.34');
    expect(connectedPort).toBe(80);

    // 3. Proves socket NEVER connected to the rebound metadata IP (169.254.169.254)
    expect(connectedHost).not.toBe('169.254.169.254');
  });
});
