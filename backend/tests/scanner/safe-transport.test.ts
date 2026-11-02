import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import {
  SafeHttpClient,
  DnsResolver,
  VerificationScopeGuard,
  AuthorizedScanScopeGuard,
  SafeTransportError,
  isProhibitedIp,
  BLOCKED_INTERNAL_PORTS,
  type RequestAuthorizationContext,
} from '../../src/scanner/transport/index.js';

describe('Phase 8: Hardened Safe HTTP Transport Layer (TASK-802)', () => {
  let localHttpServer: http.Server;
  let localHttpPort: number;
  const TEST_PFX_BASE64 = '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';
  let localHttpsServer: https.Server;
  let localHttpsPort: number;


  beforeAll(async () => {
    localHttpServer = http.createServer((req, res) => {
      const url = new URL(req.url || '/', `http://${req.headers.host}`);
      if (url.pathname === '/slow-headers') {
        // Delay sending headers
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('slow headers done');
        }, 300);
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-Received-Method': req.method,
        'X-Received-Host': req.headers.host,
      });
      res.end(JSON.stringify({ ok: true, path: url.pathname }));
    });

    await new Promise<void>((resolve) => {
      localHttpServer.listen(0, '127.0.0.1', () => {
        const addr = localHttpServer.address() as net.AddressInfo;
        localHttpPort = addr.port;
        resolve();
      });
    });

    localHttpsServer = https.createServer(
      {
        pfx: Buffer.from(TEST_PFX_BASE64, 'base64'),
        passphrase: 'veltrix',
      },
      (_req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ secure: true }));
      }
    );

    await new Promise<void>((resolve) => {
      localHttpsServer.listen(0, '127.0.0.1', () => {
        const addr = localHttpsServer.address() as net.AddressInfo;
        localHttpsPort = addr.port;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => localHttpServer.close(() => resolve()));
    await new Promise<void>((resolve) => localHttpsServer.close(() => resolve()));
  });

  describe('1. ScopeGuard Boundary Decoupling', () => {
    it('VerificationScopeGuard permits only primaryDomain challenge path and root HTML path', () => {
      const activeToken = 'vltx_tok_11223344556677889900aabbccddeeff';
      const context: RequestAuthorizationContext = {
        purpose: 'DOMAIN_OWNERSHIP_VERIFICATION',
        primaryDomain: 'portal.example.com',
        activeToken,
      };

      // Challenge path allowed
      const challengeUrl = new URL(`https://portal.example.com/.well-known/veltrix-challenge/${activeToken}`);
      const r1 = VerificationScopeGuard.validate(challengeUrl, 'GET', context);
      expect(r1.allowed).toBe(true);
      expect(r1.maxRedirects).toBe(0);

      // Root path allowed
      const rootUrl = new URL('https://portal.example.com/');
      const r2 = VerificationScopeGuard.validate(rootUrl, 'GET', context);
      expect(r2.allowed).toBe(true);

      // Rejects subdomains even if primary matches
      const subUrl = new URL(`https://sub.portal.example.com/.well-known/veltrix-challenge/${activeToken}`);
      expect(() => VerificationScopeGuard.validate(subUrl, 'GET', context)).toThrow(
        /target host 'sub\.portal\.example\.com' does not match registered primary domain/i
      );

      // Rejects arbitrary paths on pending domain
      const adminUrl = new URL('https://portal.example.com/admin');
      expect(() => VerificationScopeGuard.validate(adminUrl, 'GET', context)).toThrow(
        /Verification request to path .* is unauthorized/i
      );

      // Rejects path traversal bypass attempts
      const traversalUrl = new URL(`https://portal.example.com/.well-known/veltrix-challenge/${activeToken}/../admin`);
      expect(() => VerificationScopeGuard.validate(traversalUrl, 'GET', context)).toThrow(
        /Verification request to path .* is unauthorized/i
      );

      // Rejects non-standard ports
      const portUrl = new URL(`https://portal.example.com:8443/.well-known/veltrix-challenge/${activeToken}`);
      expect(() => VerificationScopeGuard.validate(portUrl, 'GET', context)).toThrow(
        /Port 8443 is prohibited for domain verification/i
      );

      // Rejects mutating methods (POST, PUT, DELETE)
      expect(() => VerificationScopeGuard.validate(challengeUrl, 'POST', context)).toThrow(
        /HTTP method 'POST' is not permitted for domain verification/i
      );
    });

    it('AuthorizedScanScopeGuard requires VERIFIED, unexpired, and non-blocked status', () => {
      const validContext: RequestAuthorizationContext = {
        purpose: 'AUTHORIZED_SCAN',
        orgId: 'org-enterprise-01',
        scanId: 'scan-001',
        siteId: 'site-001',
        primaryDomain: 'example.com',
        approvedSubdomains: ['api.example.com', 'portal.example.com'],
        status: 'VERIFIED',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
        allowedPorts: [80, 443, 8080],
      };

      const scanUrl = new URL('https://api.example.com/api/v1/users');
      const r = AuthorizedScanScopeGuard.validate(scanUrl, 'GET', validContext);
      expect(r.allowed).toBe(true);

      // Fails closed if status is PENDING_VERIFICATION
      expect(() =>
        AuthorizedScanScopeGuard.validate(scanUrl, 'GET', { ...validContext, status: 'PENDING_VERIFICATION' })
      ).toThrow(/Target domain has not completed ownership verification/i);

      // Fails closed if status is GRACE_PERIOD
      expect(() =>
        AuthorizedScanScopeGuard.validate(scanUrl, 'GET', { ...validContext, status: 'GRACE_PERIOD' })
      ).toThrow(/status is 'GRACE_PERIOD'\. Active scans are suspended/i);

      // Fails closed if status is EXPIRED
      expect(() =>
        AuthorizedScanScopeGuard.validate(scanUrl, 'GET', { ...validContext, status: 'EXPIRED' })
      ).toThrow(/Target domain has not completed ownership verification/i);

      // Fails closed if scanBlocked is true
      expect(() =>
        AuthorizedScanScopeGuard.validate(scanUrl, 'GET', { ...validContext, scanBlocked: true })
      ).toThrow(/scanBlocked set to true/i);

      // Fails closed if expiresAt is in the past
      expect(() =>
        AuthorizedScanScopeGuard.validate(scanUrl, 'GET', { ...validContext, expiresAt: Date.now() - 1000 })
      ).toThrow(/Domain ownership verification expired/i);
    });

    it('AuthorizedScanScopeGuard enforces exact approved subdomains with no wildcards', () => {
      const context: RequestAuthorizationContext = {
        purpose: 'AUTHORIZED_SCAN',
        orgId: 'org-enterprise-01',
        scanId: 'scan-001',
        siteId: 'site-001',
        primaryDomain: 'example.com',
        approvedSubdomains: ['app.example.com'],
        status: 'VERIFIED',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
      };

      // Primary allowed
      expect(AuthorizedScanScopeGuard.validate(new URL('https://example.com/login'), 'GET', context).allowed).toBe(true);

      // Explicitly approved subdomain allowed
      expect(AuthorizedScanScopeGuard.validate(new URL('https://app.example.com/dashboard'), 'GET', context).allowed).toBe(true);

      // Unapproved subdomain strictly blocked
      expect(() =>
        AuthorizedScanScopeGuard.validate(new URL('https://unapproved.example.com/'), 'GET', context)
      ).toThrow(/out of authorized scan scope/i);

      // External foreign origin strictly blocked
      expect(() =>
        AuthorizedScanScopeGuard.validate(new URL('https://attacker.com/'), 'GET', context)
      ).toThrow(/out of authorized scan scope/i);
    });

    it('AuthorizedScanScopeGuard enforces path exclusion filters', () => {
      const context: RequestAuthorizationContext = {
        purpose: 'AUTHORIZED_SCAN',
        orgId: 'org-enterprise-01',
        scanId: 'scan-001',
        siteId: 'site-001',
        primaryDomain: 'example.com',
        approvedSubdomains: [],
        status: 'VERIFIED',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
        excludedPaths: ['/auth/logout', /^\/admin(\/.*)?$/],
      };

      // Normal path allowed
      expect(AuthorizedScanScopeGuard.validate(new URL('https://example.com/profile'), 'GET', context).allowed).toBe(true);

      // Excluded string path dropped
      expect(() =>
        AuthorizedScanScopeGuard.validate(new URL('https://example.com/auth/logout'), 'GET', context)
      ).toThrow(/matches excluded path rule/i);

      // Excluded regex path dropped
      expect(() =>
        AuthorizedScanScopeGuard.validate(new URL('https://example.com/admin/delete-all'), 'GET', context)
      ).toThrow(/matches excluded path regex/i);
    });
  });

  describe('2. Outbound Port Restrictions and Inviolable Safety Precedence', () => {
    const baseContext: RequestAuthorizationContext = {
      purpose: 'AUTHORIZED_SCAN',
      orgId: 'org-enterprise-01',
      scanId: 'scan-001',
      siteId: 'site-001',
      primaryDomain: 'example.com',
      approvedSubdomains: [],
      status: 'VERIFIED',
      scanBlocked: false,
      expiresAt: Date.now() + 86400000,
      allowedPorts: [80, 443, 8080],
    };

    it('allows standard ports 80 and 443 and whitelisted non-standard ports', () => {
      expect(AuthorizedScanScopeGuard.validate(new URL('http://example.com/'), 'GET', baseContext).targetPort).toBe(80);
      expect(AuthorizedScanScopeGuard.validate(new URL('https://example.com/'), 'GET', baseContext).targetPort).toBe(443);
      expect(AuthorizedScanScopeGuard.validate(new URL('http://example.com:8080/'), 'GET', baseContext).targetPort).toBe(8080);
    });

    it('rejects unapproved non-standard ports', () => {
      expect(() =>
        AuthorizedScanScopeGuard.validate(new URL('http://example.com:8443/'), 'GET', baseContext)
      ).toThrow(/Port 8443 is non-standard and has not been explicitly authorized/i);
    });

    it('inviolable safety precedence: internal service ports can NEVER be accessed even if specified in allowlist', () => {
      for (const blockedPort of [22, 25, 3306, 5432, 6379, 27017]) {
        expect(BLOCKED_INTERNAL_PORTS.has(blockedPort)).toBe(true);
        const maliciousContext: RequestAuthorizationContext = {
          ...baseContext,
          allowedPorts: [blockedPort], // Attacker attempts to allow internal DB/SSH port
        };

        expect(() =>
          AuthorizedScanScopeGuard.validate(new URL(`http://example.com:${blockedPort}/`), 'GET', maliciousContext)
        ).toThrow(SafeTransportError);
      }
    });
  });

  describe('3. HTTP Method Policy', () => {
    const baseContext: RequestAuthorizationContext = {
      purpose: 'AUTHORIZED_SCAN',
      orgId: 'org-enterprise-01',
      scanId: 'scan-001',
      siteId: 'site-001',
      primaryDomain: 'example.com',
      approvedSubdomains: [],
      status: 'VERIFIED',
      scanBlocked: false,
      expiresAt: Date.now() + 86400000,
    };

    it('defaults to allowing only GET and HEAD', () => {
      expect(AuthorizedScanScopeGuard.validate(new URL('https://example.com/'), 'GET', baseContext).allowed).toBe(true);
      expect(AuthorizedScanScopeGuard.validate(new URL('https://example.com/'), 'HEAD', baseContext).allowed).toBe(true);

      expect(() => AuthorizedScanScopeGuard.validate(new URL('https://example.com/'), 'POST', baseContext)).toThrow(
        /HTTP method 'POST' is not permitted by scan operation policy/i
      );
      expect(() => AuthorizedScanScopeGuard.validate(new URL('https://example.com/'), 'DELETE', baseContext)).toThrow(
        /HTTP method 'DELETE' is not permitted by scan operation policy/i
      );
      expect(() => AuthorizedScanScopeGuard.validate(new URL('https://example.com/'), 'PUT', baseContext)).toThrow(
        /HTTP method 'PUT' is not permitted by scan operation policy/i
      );
    });

    it('permits specialized methods only when explicitly authorized in probe operation policy', () => {
      const probeContext: RequestAuthorizationContext = {
        ...baseContext,
        allowedMethods: ['GET', 'HEAD', 'POST'],
      };
      expect(AuthorizedScanScopeGuard.validate(new URL('https://example.com/'), 'POST', probeContext).allowed).toBe(true);
    });
  });

  describe('4. Comprehensive SSRF IP Filter & Positive IPv6 Policy Matrix', () => {
    const prohibitedCases = [
      // Standard IPv4 loopback & private
      ['127.0.0.1', 'Loopback'],
      ['127.127.127.127', 'Loopback Range'],
      ['0177.0.0.1', 'Octal IPv4 Loopback'],
      ['0x7f.0.0.1', 'Hex IPv4 Loopback'],
      ['2130706433', 'Dword Loopback'],
      ['127.1', 'Zero-compressed Loopback'],
      ['10.0.0.1', 'RFC 1918 Private 10/8'],
      ['172.16.0.1', 'RFC 1918 Private 172.16/12'],
      ['192.168.1.1', 'RFC 1918 Private 192.168/16'],
      ['169.254.169.254', 'AWS IMDS Metadata'],
      ['100.64.0.1', 'Carrier-Grade NAT'],
      ['0.0.0.0', 'Current Network'],
      ['192.0.2.1', 'TEST-NET-1'],
      ['198.51.100.1', 'TEST-NET-2'],
      ['203.0.113.1', 'TEST-NET-3'],
      // IPv6 prohibited
      ['::1', 'IPv6 Loopback'],
      ['fe80::1', 'IPv6 Link-Local'],
      ['fc00::1', 'IPv6 Unique Local (ULA)'],
      ['::ffff:127.0.0.1', 'IPv4-Mapped IPv6 Loopback'],
      ['::ffff:169.254.169.254', 'IPv4-Mapped IPv6 IMDS'],
      ['fd00:ec2::254', 'AWS IMDSv6'],
      ['4000::1', 'Unallocated Non-2000::/3'],
      ['fe00::1', 'Reserved Non-2000::/3'],
      ['f000::1', 'Reserved Non-2000::/3'],
      ['::8.8.8.8', 'Deprecated IPv4-Compatible IPv6'],
      ['2001:4860:1:2:3:4:5:6::', 'Malformed Zero-Compression'],
      ['fe80::1%eth0', 'Scoped Zone Identifier'],
      ['2002:7f00:0001::', '6to4 Embedded 127.0.0.1'],
      ['2002:a9fe:a9fe::', '6to4 Embedded 169.254.169.254'],
      ['2001::1', 'IETF Special-Purpose 2001::/23'],
      ['2001:db8::1', 'Documentation 2001:db8::/32'],
      ['3fff::1', 'Documentation 3fff::/20'],
    ];

    for (const [ip, desc] of prohibitedCases) {
      it(`prohibits ${desc}: ${ip}`, () => {
        expect(isProhibitedIp(ip)).toBe(true);
      });
    }

    const allowedCases = [
      ['93.184.216.34', 'Public Internet IPv4 (example.com)'],
      ['8.8.8.8', 'Google Public DNS IPv4'],
      ['2606:2800:220:1:248:1893:25c8:1946', 'Public Global Unicast IPv6 (example.com)'],
      ['2001:4860:4860::8888', 'Google Public DNS IPv6 (Global Unicast)'],
      ['2002:5db8:d822::1', '6to4 Embedded Public IP 93.184.216.34'],
    ];

    for (const [ip, desc] of allowedCases) {
      it(`permits ${desc}: ${ip}`, () => {
        expect(isProhibitedIp(ip)).toBe(false);
      });
    }
  });

  describe('5. Real Socket Destination Verification & IP Pinning Integration', () => {
    it('proves SafeHttpClient connects directly to pinned IP and records actual remoteAddress', async () => {
      // In-process controlled resolver returning 127.0.0.1 for test host
      const mockDnsResolver = new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      });

      const client = new SafeHttpClient({
        dnsResolver: mockDnsResolver,
        allowLoopbackForTesting: true,
      });

      const res = await client.get(`http://primary.example.com:${localHttpPort}/test-socket`, {
        allowLoopbackForTesting: true,
        context: {
          purpose: 'AUTHORIZED_SCAN',
          orgId: 'org-1',
          scanId: 'scan-1',
          siteId: 'site-1',
          primaryDomain: 'primary.example.com',
          approvedSubdomains: [],
          status: 'VERIFIED',
          scanBlocked: false,
          expiresAt: Date.now() + 86400000,
          allowedPorts: [localHttpPort],
        },
      });

      expect(res.status).toBe(200);
      expect(res.remoteAddress).toBe('127.0.0.1');
      expect(res.remotePort).toBe(localHttpPort);
      expect(res.data).toEqual({ ok: true, path: '/test-socket' });
    });

    it('fails closed immediately if DNS returns multiple records and ANY is prohibited', async () => {
      const dualStackResolver = new DnsResolver({
        lookupFn: async () => [
          { address: '93.184.216.34', family: 4 }, // Safe public
          { address: '10.0.0.1', family: 4 }, // Prohibited RFC 1918
        ],
      });

      const client = new SafeHttpClient({
        dnsResolver: dualStackResolver,
      });

      await expect(
        client.get('http://dualstack.example.com/', {
          context: {
            purpose: 'AUTHORIZED_SCAN',
            orgId: 'org-1',
            scanId: 'scan-1',
            siteId: 'site-1',
            primaryDomain: 'dualstack.example.com',
            approvedSubdomains: [],
            status: 'VERIFIED',
            scanBlocked: false,
            expiresAt: Date.now() + 86400000,
          },
        })
      ).rejects.toThrow(/resolved to prohibited IP address '10\.0\.0\.1'/i);
    });

    it('strictly isolates against ambient HTTP_PROXY and HTTPS_PROXY environment variables', async () => {
      const prevHttpProxy = process.env.HTTP_PROXY;
      const prevHttpsProxy = process.env.HTTPS_PROXY;
      try {
        process.env.HTTP_PROXY = 'http://169.254.169.254:8080';
        process.env.HTTPS_PROXY = 'http://169.254.169.254:8080';

        const mockDnsResolver = new DnsResolver({
          lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
          allowLoopbackForTesting: true,
        });

        const client = new SafeHttpClient({
          dnsResolver: mockDnsResolver,
          allowLoopbackForTesting: true,
        });

        const res = await client.get(`http://primary.example.com:${localHttpPort}/proxy-bypass-test`, {
          allowLoopbackForTesting: true,
          context: {
            purpose: 'AUTHORIZED_SCAN',
            orgId: 'org-1',
            scanId: 'scan-1',
            siteId: 'site-1',
            primaryDomain: 'primary.example.com',
            approvedSubdomains: [],
            status: 'VERIFIED',
            scanBlocked: false,
            expiresAt: Date.now() + 86400000,
            allowedPorts: [localHttpPort],
          },
        });

        // Connected directly to local server, ignoring 169.254.169.254 proxy
        expect(res.status).toBe(200);
        expect(res.remoteAddress).toBe('127.0.0.1');
      } finally {
        process.env.HTTP_PROXY = prevHttpProxy;
        process.env.HTTPS_PROXY = prevHttpsProxy;
      }
    });

    it('enforces TLS certificate validation and rejects untrusted / self-signed certs', async () => {
      const mockConnector = {
        connect(options: { host: string; port: number }) {
          return net.connect({ host: '127.0.0.1', port: localHttpsPort });
        },
        connectTls(options: tls.ConnectionOptions) {
          expect(options.rejectUnauthorized).toBe(true);
          return tls.connect(options);
        },
      };

      const client = new SafeHttpClient({
        dnsResolver: new DnsResolver({
          lookupFn: async () => [{ address: '93.184.216.34', family: 4 }],
        }),
        socketConnector: mockConnector,
      });

      await expect(
        client.get('https://secure.example.com/', {
          context: {
            purpose: 'AUTHORIZED_SCAN',
            orgId: 'org-1',
            scanId: 'scan-1',
            siteId: 'site-1',
            primaryDomain: 'secure.example.com',
            approvedSubdomains: [],
            status: 'VERIFIED',
            scanBlocked: false,
            expiresAt: Date.now() + 86400000,
          },
        })
      ).rejects.toThrow(/self-signed certificate|certificate/i);
    });
  });

  describe('6. Granular Timeouts & AbortSignal', () => {
    it('aborts cleanly when AbortSignal is triggered', async () => {
      const mockDnsResolver = new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      });

      const client = new SafeHttpClient({
        dnsResolver: mockDnsResolver,
        allowLoopbackForTesting: true,
      });

      const controller = new AbortController();
      setTimeout(() => controller.abort(), 20);

      await expect(
        client.get(`http://primary.example.com:${localHttpPort}/slow-headers`, {
          signal: controller.signal,
          allowLoopbackForTesting: true,
          context: {
            purpose: 'AUTHORIZED_SCAN',
            orgId: 'org-1',
            scanId: 'scan-1',
            siteId: 'site-1',
            primaryDomain: 'primary.example.com',
            approvedSubdomains: [],
            status: 'VERIFIED',
            scanBlocked: false,
            expiresAt: Date.now() + 86400000,
            allowedPorts: [localHttpPort],
          },
        })
      ).rejects.toThrow(/cancelled by AbortSignal/i);
    });

    it('enforces total request timeout watchdog', async () => {
      const mockDnsResolver = new DnsResolver({
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        allowLoopbackForTesting: true,
      });

      const client = new SafeHttpClient({
        dnsResolver: mockDnsResolver,
        allowLoopbackForTesting: true,
      });

      await expect(
        client.get(`http://primary.example.com:${localHttpPort}/slow-headers`, {
          timeoutMs: 50,
          allowLoopbackForTesting: true,
          context: {
            purpose: 'AUTHORIZED_SCAN',
            orgId: 'org-1',
            scanId: 'scan-1',
            siteId: 'site-1',
            primaryDomain: 'primary.example.com',
            approvedSubdomains: [],
            status: 'VERIFIED',
            scanBlocked: false,
            expiresAt: Date.now() + 86400000,
            allowedPorts: [localHttpPort],
          },
        })
      ).rejects.toThrow(/timed out/i);
    });
  });
});
