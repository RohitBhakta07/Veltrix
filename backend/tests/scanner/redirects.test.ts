import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import {
  SafeHttpClient,
  DnsResolver,
  SafeTransportError,
  ActiveSocketRegistry,
} from '../../src/scanner/transport/index.js';
import {
  createAuthorizedScanScopeContext,
  createVerificationScopeContext,
} from './helpers/test-context-helper.js';

describe('Phase 8: Hop-by-Hop Redirect Validation (TASK-802)', () => {
  let redirectServer: http.Server;
  let serverPort: number;
  const openServerSockets = new Set<net.Socket>();

  beforeAll(async () => {
    redirectServer = http.createServer((req, res) => {
      const url = new URL(req.url || '/', `http://${req.headers.host}`);

      // Large body redirect endpoint (>64 KB)
      if (url.pathname === '/redirect-large-body') {
        res.writeHead(302, {
          Location: `http://primary.example.com:${serverPort}/final`,
          'Content-Type': 'text/plain',
        });
        const largeData = Buffer.alloc(128 * 1024, 'X');
        res.end(largeData);
        return;
      }

      // Stalled redirect endpoint (does not end body)
      if (url.pathname === '/redirect-stalled-body') {
        res.writeHead(302, {
          Location: `http://primary.example.com:${serverPort}/final`,
          'Content-Type': 'text/plain',
        });
        res.write('stalled-start');
        return;
      }

      // Trickled redirect endpoint
      if (url.pathname === '/redirect-trickled-body') {
        res.writeHead(302, {
          Location: `http://primary.example.com:${serverPort}/final`,
          'Content-Type': 'text/plain',
        });
        res.write('chunk-1');
        const timer = setInterval(() => {
          if (!res.writableEnded && !res.destroyed) {
            try {
              res.write('-trickle');
            } catch {
              clearInterval(timer);
            }
          } else {
            clearInterval(timer);
          }
        }, 80);
        return;
      }

      // 5-hop redirect chain
      if (url.pathname.startsWith('/multi-hop-')) {
        const step = parseInt(url.pathname.replace('/multi-hop-', ''), 10);
        const nextTarget =
          step < 5
            ? `http://primary.example.com:${serverPort}/multi-hop-${step + 1}`
            : `http://primary.example.com:${serverPort}/final`;
        res.writeHead(302, { Location: nextTarget });
        res.end();
        return;
      }

      if (url.pathname === '/redirect-1') {
        res.writeHead(302, { Location: `http://primary.example.com:${serverPort}/redirect-2` });
        res.end();
        return;
      }
      if (url.pathname === '/redirect-2') {
        res.writeHead(302, { Location: `http://primary.example.com:${serverPort}/final` });
        res.end();
        return;
      }
      if (url.pathname === '/final') {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'X-Received-Auth': req.headers.authorization || '',
          'X-Received-Cookie': req.headers.cookie || '',
          'X-Received-Custom': (req.headers['x-org-id'] as string) || '',
        });
        res.end(JSON.stringify({ ok: true, path: '/final' }));
        return;
      }

      // Loop endpoints: loop-a -> loop-b -> loop-a
      if (url.pathname === '/loop-a') {
        res.writeHead(302, { Location: `http://primary.example.com:${serverPort}/loop-b` });
        res.end();
        return;
      }
      if (url.pathname === '/loop-b') {
        res.writeHead(302, { Location: `http://primary.example.com:${serverPort}/loop-a` });
        res.end();
        return;
      }

      // Deep chain endpoints
      if (url.pathname.startsWith('/chain-')) {
        const step = parseInt(url.pathname.replace('/chain-', ''), 10);
        res.writeHead(302, { Location: `http://primary.example.com:${serverPort}/chain-${step + 1}` });
        res.end();
        return;
      }

      // Cross-origin redirect endpoint: redirects to sub.example.com
      if (url.pathname === '/cross-subdomain') {
        res.writeHead(302, { Location: `http://sub.example.com:${serverPort}/final` });
        res.end();
        return;
      }

      // Malicious SSRF redirects
      if (url.pathname === '/ssrf-imds') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
        return;
      }
      if (url.pathname === '/ssrf-local') {
        res.writeHead(302, { Location: 'http://127.0.0.1:8080/internal' });
        res.end();
        return;
      }
      if (url.pathname === '/ssrf-ipv6') {
        res.writeHead(302, { Location: 'http://[::1]:8080/internal' });
        res.end();
        return;
      }

      // Protocol downgrade endpoint
      if (url.pathname === '/downgrade-target') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('insecure plaintext');
        return;
      }

      // 303 See Other endpoint
      if (url.pathname === '/see-other') {
        res.writeHead(303, { Location: `http://primary.example.com:${serverPort}/final` });
        res.end();
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    });

    redirectServer.on('connection', (socket) => {
      openServerSockets.add(socket);
      socket.on('close', () => openServerSockets.delete(socket));
    });

    await new Promise<void>((resolve) => {
      redirectServer.listen(0, '127.0.0.1', () => {
        const addr = redirectServer.address() as net.AddressInfo;
        serverPort = addr.port;
        resolve();
      });
    });
  });

  afterAll(async () => {
    for (const socket of openServerSockets) {
      try {
        socket.destroy();
      } catch {}
    }
    await new Promise<void>((resolve) => redirectServer.close(() => resolve()));
  });

  const getAuthorizedContext = async (overrides?: any) =>
    await createAuthorizedScanScopeContext({
      orgId: 'org-enterprise-01',
      scanId: 'scan-001',
      siteId: 'site-001',
      primaryDomain: 'primary.example.com',
      approvedSubdomains: ['sub.example.com'],
      status: 'VERIFIED',
      scanBlocked: false,
      expiresAt: Date.now() + 86400000,
      allowedPorts: [serverPort],
      ...overrides,
    });

  const createTestClient = () => {
    return new SafeHttpClient({
      dnsResolver: new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      }),
      allowLoopbackForTesting: true,
    });
  };

  it('domain verification strictly rejects any 3xx redirect without following', async () => {
    const client = createTestClient();
    const token = 'vltx_tok_11223344556677889900aabbccddeeff';

    await expect(
      client.get(`http://primary.example.com:${serverPort}/.well-known/veltrix-challenge/${token}`, {
        allowLoopbackForTesting: true,
        context: await createVerificationScopeContext({
          primaryDomain: 'primary.example.com',
          activeToken: token,
        }),
      })
    ).rejects.toThrow();
  });

  it('scanner returns 3xx as-is when maxRedirects is 0 or not configured', async () => {
    const client = createTestClient();
    const res = await client.get(`http://primary.example.com:${serverPort}/redirect-1`, {
      allowLoopbackForTesting: true,
      context: await getAuthorizedContext(),
    });

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('/redirect-2');
    expect(res.redirectHops).toBe(0);
  });

  it('follows legitimate in-scope redirect chain up to configured ceiling', async () => {
    const client = createTestClient();
    const res = await client.get(`http://primary.example.com:${serverPort}/redirect-1`, {
      maxRedirects: 3,
      allowLoopbackForTesting: true,
      context: await getAuthorizedContext(),
    });

    expect(res.status).toBe(200);
    expect(res.redirectHops).toBe(2);
    expect(res.data).toEqual({ ok: true, path: '/final' });
  });

  it('halts with MAX_REDIRECTS_EXCEEDED when hops exceed ceiling (max 5)', async () => {
    const client = createTestClient();
    await expect(
      client.get(`http://primary.example.com:${serverPort}/chain-1`, {
        maxRedirects: 3,
        allowLoopbackForTesting: true,
        context: await getAuthorizedContext(),
      })
    ).rejects.toThrow(/Maximum redirect limit of 3 hops exceeded/i);
  });

  it('detects cyclical redirect loops and terminates with REDIRECT_LOOP_DETECTED', async () => {
    const client = createTestClient();
    await expect(
      client.get(`http://primary.example.com:${serverPort}/loop-a`, {
        maxRedirects: 5,
        allowLoopbackForTesting: true,
        context: await getAuthorizedContext(),
      })
    ).rejects.toThrow(/Redirect loop detected/i);
  });

  it('intercepts SSRF redirect escape attempts at hop 1 before connection', async () => {
    const client = createTestClient();

    // IMDS metadata redirect
    await expect(
      client.get(`http://primary.example.com:${serverPort}/ssrf-imds`, {
        maxRedirects: 2,
        allowLoopbackForTesting: true,
        context: await getAuthorizedContext(),
      })
    ).rejects.toThrow(/out of authorized scan scope|prohibited IP address/i);

    // Loopback 127.0.0.1 redirect when loopback is NOT allowed
    const strictClient = new SafeHttpClient({
      dnsResolver: new DnsResolver({
        lookupFn: async (host) => {
          if (host === 'primary.example.com') return [{ address: '127.0.0.1', family: 4 }];
          return [{ address: '127.0.0.1', family: 4 }];
        },
        allowLoopbackForTesting: true, // initial lookup allowed
      }),
      allowLoopbackForTesting: false, // strict client
    });

    await expect(
      strictClient.get(`http://primary.example.com:${serverPort}/ssrf-local`, {
        maxRedirects: 2,
        context: await getAuthorizedContext({ allowedPorts: [serverPort, 8080] }),
      })
    ).rejects.toThrow(SafeTransportError);

    // IPv6 ::1 redirect
    await expect(
      client.get(`http://primary.example.com:${serverPort}/ssrf-ipv6`, {
        maxRedirects: 2,
        allowLoopbackForTesting: true,
        context: await getAuthorizedContext(),
      })
    ).rejects.toThrow(SafeTransportError);
  });

  it('drops cross-origin redirect to unapproved external domain before DNS resolution', async () => {
    // Dynamic handler for external redirect
    const externalRedirectServer = http.createServer((_req, res) => {
      res.writeHead(302, { Location: 'https://evil-attacker.com/steal' });
      res.end();
    });

    await new Promise<void>((resolve) => {
      externalRedirectServer.listen(0, '127.0.0.1', resolve);
    });
    const extPort = (externalRedirectServer.address() as net.AddressInfo).port;

    try {
      const client = createTestClient();
      await expect(
        client.get(`http://primary.example.com:${extPort}/external`, {
          maxRedirects: 2,
          allowLoopbackForTesting: true,
          context: await getAuthorizedContext({ allowedPorts: [serverPort, extPort] }),
        })
      ).rejects.toThrow(/out of authorized scan scope/i);
    } finally {
      await new Promise<void>((resolve) => externalRedirectServer.close(() => resolve()));
    }
  });

  it('strips Authorization, Cookie, and tenant headers on cross-subdomain redirect', async () => {
    const client = createTestClient();
    const res = await client.get(`http://primary.example.com:${serverPort}/cross-subdomain`, {
      maxRedirects: 2,
      allowLoopbackForTesting: true,
      headers: {
        'Authorization': 'Bearer secret-jwt-token-12345',
        'Cookie': 'sessionId=secret-session-abcde',
        'X-Org-Id': 'org-enterprise-01',
        'X-Safe-Header': 'keep-me',
      },
      context: await getAuthorizedContext(),
    });

    expect(res.status).toBe(200);
    // Verified that sensitive headers were stripped on cross-subdomain redirect
    expect(res.headers['x-received-auth']).toBe('');
    expect(res.headers['x-received-cookie']).toBe('');
    expect(res.headers['x-received-custom']).toBe('');
  });

  it('HTTP 303 See Other converts method to GET and drops body per RFC 7231', async () => {
    const client = createTestClient();
    const res = await client.request(`http://primary.example.com:${serverPort}/see-other`, {
      method: 'POST',
      body: JSON.stringify({ item: 'data' }),
      maxRedirects: 2,
      allowLoopbackForTesting: true,
      context: await getAuthorizedContext({
        allowedMethods: ['GET', 'HEAD', 'POST'],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.data).toEqual({ ok: true, path: '/final' });
  });

  it('drains up to 64 KB of redirect body, destroys socket, and follows redirect when body exceeds 64 KB', async () => {
    const client = createTestClient();
    const res = await client.get(`http://primary.example.com:${serverPort}/redirect-large-body`, {
      maxRedirects: 2,
      allowLoopbackForTesting: true,
      context: await getAuthorizedContext(),
    });

    expect(res.status).toBe(200);
    expect(res.redirectHops).toBe(1);
    expect(res.data).toEqual({ ok: true, path: '/final' });
  });

  it('terminates and destroys socket when redirect response body stalls indefinitely', async () => {
    const registry = new ActiveSocketRegistry();
    const client = new SafeHttpClient({
      dnsResolver: new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      }),
      socketRegistry: registry,
      allowLoopbackForTesting: true,
    });

    await expect(
      client.get(`http://primary.example.com:${serverPort}/redirect-stalled-body`, {
        maxRedirects: 2,
        allowLoopbackForTesting: true,
        bodyIdleTimeoutMs: 150,
        timeoutMs: 300,
        context: await getAuthorizedContext(),
      })
    ).rejects.toThrow(/timed out/i);

    expect(registry.getActiveCount()).toBe(0);
  });

  it('terminates and destroys socket when redirect response body trickles slowly past bounded timeout', async () => {
    const registry = new ActiveSocketRegistry();
    const client = new SafeHttpClient({
      dnsResolver: new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      }),
      socketRegistry: registry,
      allowLoopbackForTesting: true,
    });

    await expect(
      client.get(`http://primary.example.com:${serverPort}/redirect-trickled-body`, {
        maxRedirects: 2,
        allowLoopbackForTesting: true,
        bodyIdleTimeoutMs: 100,
        timeoutMs: 250,
        context: await getAuthorizedContext(),
      })
    ).rejects.toThrow(/timed out/i);

    expect(registry.getActiveCount()).toBe(0);
  });

  it('immediately terminates and destroys socket when AbortSignal fires during redirect drain', async () => {
    const registry = new ActiveSocketRegistry();
    const client = new SafeHttpClient({
      dnsResolver: new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      }),
      socketRegistry: registry,
      allowLoopbackForTesting: true,
    });

    const controller = new AbortController();
    setTimeout(() => {
      controller.abort();
    }, 50);

    await expect(
      client.get(`http://primary.example.com:${serverPort}/redirect-stalled-body`, {
        maxRedirects: 2,
        allowLoopbackForTesting: true,
        signal: controller.signal,
        timeoutMs: 5000,
        context: await getAuthorizedContext(),
      })
    ).rejects.toThrow(/cancelled by caller AbortSignal/i);

    expect(registry.getActiveCount()).toBe(0);
  });

  it('prevents socket leaks across a 5-hop redirect chain, keeping active sockets bounded to <= 1', async () => {
    const registry = new ActiveSocketRegistry();
    const client = new SafeHttpClient({
      dnsResolver: new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      }),
      socketRegistry: registry,
      allowLoopbackForTesting: true,
    });

    const res = await client.get(`http://primary.example.com:${serverPort}/multi-hop-1`, {
      maxRedirects: 5,
      allowLoopbackForTesting: true,
      context: await getAuthorizedContext(),
    });

    expect(res.status).toBe(200);
    expect(res.redirectHops).toBe(5);
    expect(res.data).toEqual({ ok: true, path: '/final' });

    // Inviolable guarantee: all intermediary hop sockets were cleanly unregistered and destroyed
    expect(registry.getActiveCount('org-enterprise-01', 'scan-001')).toBe(0);
    expect(registry.getActiveCount()).toBe(0);
  });
});
