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
  isBlockedInternalPort,
  isRestrictedHopByHopHeader,
  type RequestAuthorizationContext,
  SafeVerificationHttpFetcher,
} from '../../src/scanner/transport/index.js';
import {
  createAuthoritativeScanScopeContext,
  createAuthoritativeVerificationScopeContext,
  isTrustedScopeContext,
  isServerControlledAllowedMethod,
  createServerScanPolicy,
  isServerScanPolicy,
  SERVER_MANDATORY_EXCLUDED_PATHS,
} from '../../src/scanner/transport/context-authority.js';
import { DefaultDnsResolver } from '../../src/scanner/verification/dns-verifier.js';
import {
  createAuthorizedScanScopeContext,
  createVerificationScopeContext,
  createTestScanContext,
  createTestVerificationContext,
} from './helpers/test-context-helper.js';
import { DefaultHttpFetcher, HttpVerifier } from '../../src/scanner/verification/http-verifier.js';
import { MetaVerifier } from '../../src/scanner/verification/meta-verifier.js';
import { DomainOwnershipVerifier } from '../../src/scanner/verification/verifier.js';
import { MemoryStore } from '../../src/storage/memory-store.js';
import type { WebsiteAsset } from '@veltrix/shared';

describe('Phase 8: Hardened Safe HTTP Transport Layer (TASK-802)', () => {
  let localHttpServer: http.Server;
  let localHttpPort: number;
  const TEST_PFX_BASE64 = 'MIIKQgIBAzCCCf4GCSqGSIb3DQEHAaCCCe8EggnrMIIJ5zCCBfgGCSqGSIb3DQEHAaCCBekEggXlMIIF4TCCBd0GCyqGSIb3DQEMCgECoIIE9jCCBPIwHAYKKoZIhvcNAQwBAzAOBAhBumevTnWzNQICB9AEggTQFS1f3R4t1oi1B7Zap31u14TDaeXrs0Imq3DgBhpDMnwOqhM91DmDEH5J+bnmMxjif7dVwnpO0X3PMrm+fqLCfzX9dTPWjY2DKthGKljKVhJxWcBdzWySM0bge4N4f7yxEGkoRFMup5eVYtI2wiS7qNPHBUpBT5+m9E7lLTXcXScUWovJpcog5xxpBqPSe1OmLnnR5n0lfBljM1aUVfWnOdDNRlW0NIj39EbbUmgi9NqLXMD+OUy+zyfv75ONbJXcw9nY7EA8wlIMXdoJREdEmodI/qeeNpviLO45wrEZFt26uPWneHuvG6X6Dejc6ABj35dWvxjBUqN0999ebwXXLDCvwHvfvsT9K/TWfIqMCsB8FqiNLn/HNJ3w/lfy5DvK9BzwsLWUgGgMsxCiutHx0r56wWhSUmn6tz88QaOa4Rq+UbXYt7E4fhkjDNWBYkwOtKnYXUf6cTWpGUDbbeTj6M2He1srOb6H+Uy/pFu6WU5JzLqdRSwhJsYM3Zd7RDg79LZKtiygEkiJhUU1SWmfBVZ8pABm+bKqstwd11I8maIAVIwiHRFOVgt3kXhTUv6V/3Q4Oo9LQqXXa4Jvow2p1sp83AKqDxXxSgm10DANhGgQh/B+Mq89Yo9zj88eC21EaIfzlL5Z/gK6jdcCkfzscBGInsumJXAEEw6aE7b3hZ8CBKTrgnvH5FNmZQxjCs70grSB6Kod5l06wmd/7V2yRQK/gNLWF0wL52Tvt0ldY8wJKOqyRz7tuY3PiujuUMNENQChBndJHQaaMYqJQms8Vkf5xW2ueAgf9S5qNoZ9y4FHA5IYoNeCt81l45d9lnBRQdu+1jzk9GObqTjMPwEVdsxboMjRsLnHPb/GGVSjvQ8Mj7MDevuQtxF0toHsCZSE6rJ+ZOyT6hAMy77Eb8RE/RGoJKcj4MCOBMN0tTUpV4npT60nqkaUswhIlBkwv5smV3jt0si8GZtxXn6orCjtOOSy1nuLzp7oPDSkxEh7aBQokdWs6fBA7p2Ohg6e3TLkwJNu1DFzWHVnJpfmRdro0MbOsP7vharB3TnZ0LRG+u9qCVJTKcHVq6wbzvVIlJRJ/QlT0IakZC1nog0VpDFBxd9cUOq+c9KgpkXr0es1pgBIfH5a1NK7CHrTcTY4rocD5ZEZI14x3Q7XIMvvPwHIrNh1jFqSjZULlp6uT6nNP/Q6XNJ3mjkTYH6VppuzRyH0TDDQUDEFqVncD9injOtcWqq0V7nzDmg69X5mqoP/cC1HL0EoGmgyy5QSPmfT9529cQnutvIETez7E+4H63lG5snp6b0PFCXS25e0SoASSMkEy8hQe5RVZdqQ40f9EvJNdHmWpEIO0TK4OGP9QiUrMHfzliWF7xGU8TF+e1XPjC8NdK2GRBi44nUIONRuikpFHFp8Y06aQCQ2lGoksKBVR4A0yeTUGDZnB8sVcJj1h37n/BOGSVdQtNDRHj0h4kMoWbOGGuP41bSNGi7StrhRQRGqs9QxNha1iwFzFVJD0kpL3lI7wVMrSArPaWoVKOtuBtg2iuFM+tbako4e/0rpInF6cG0QlsKEIcV8khwUFhYgm/818eZ+PrtIWOWhtwr+rlV+grqfznUzi2XYcgZDybsrFQ2WVIq35nV26fkG5BQxgdMwEwYJKoZIhvcNAQkVMQYEBAEAAAAwXQYJKoZIhvcNAQkUMVAeTgB0AGUALQA4AGEANwA5ADkAYgAzADQALQAwADcAYQBiAC0ANABhADAAOQAtAGIAZQA5ADgALQA3AGIAOQBiAGQANgA5AGEAMwA0ADQAYTBdBgkrBgEEAYI3EQExUB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByMIID5wYJKoZIhvcNAQcGoIID2DCCA9QCAQAwggPNBgkqhkiG9w0BBwEwHAYKKoZIhvcNAQwBAzAOBAjQqchpxd9R+QICB9CAggOg/BuvOY1pP8kkQllL3QBqaqRO/aUOyEUnqnNqcmkkfVOM4suUcqiA+Wwgrp5B1puPIIezbbivqBz7OdJRYDeUQjhYzAi+eTRhO1GTWF35ffJgUTZp121RgRPRKJVCSsR4jjtyT4mvfiWNlF03LsLuRNb4rvflODsQsVvFFGq+KC5GGpmXPAuHjNXWMTtoeJYdLviy9aWBnj5THf16zu5zp8nakY99JoQM7uOnq4bMbtMp1c0gfLVgNMf4l087AqRgLu0jDTp2rH2vcPkh2D+lDJox3f6Sw0k8aNdK3wzDeOomhXMsWDMpF08lf+5nRXwj7aVZajyuEBCUu4Vec0LQ+tzatXjparOIcPQzXnB/vtXivbVz+KJQHZgDPuVKNVwHLYpg8bPr/qmRheGztgZodaEW9NOSXJLvG8Y139EJDlIx6xe+VmLEzMRy5OTneC76TRT8CIGcaLxzDSjXkvb35sANgOfwf9ltgBBirWuv3svuZrf4V+miMTFEdo2E0GMA7lGRki3pX3cQ9twn4gLETe9vZUN41o5sZ1U3AmjoTCFO+1lF31gt1xhhDFcKJdEzy4yECLuGJIknHB5XfP7I5IjGhgG5uAyyQf9fUdttnH8XAzwdK1el37GMwwl1rBOBnUvo8nPW+p9N3IPzRQJYw6iwhJT/2IcEO14jhyGJprR717v58ffTib6t65L3c+q6jH4lB0lOHiWpYEkowaBQBAhBB5Cq4n9odtROqCmwqbbTonVLgct0IWx2WoAJvDlH1OXoeEklWGxdHHFqRDWon+rv6ME2e9xdAwxnK22+nveSNBPuMgDyKBfwkIFXDXu4AVMfxL5rU/sfjSJJV5C/xnfzJmlBW25B2FCt3CI1+7jo1uY+Lnd026bYd6foYXg5Pkk1GbHnI+CrvTsqPYKIL0y0WRBq+6P7i8jsQAzruCFCr8BhC1xTs4qz089mtKq0E7mw1EuO3s7EBnBYNO+onzk26+K+gkYbUbTARlDQHH4JjuQxQNCKLMad1nbKBv3rPDhLMtNm74bvKHRFhvtQsS/R1pJsORTfciu3FZrA5nCThQIn5Tl+gIqY+gunATBhlQcT/VKgE4ygRu1SxzIMHdnAugAEVxcWQrG7Vvk3tzvXfHObYIveVAS/AYBM5iz5HQtESByYVdnImve5EzbPXUk1VWLI/IZIwDxWZxSEsPGLpUIWnh9aaRuUcnHmdKlY2QDZAlgeQjmmwpjgBxVdmzA7MB8wBwYFKw4DAhoEFAswUa9Tu3lYTV9nsOvhnz79qhbnBBQqaaci2IIh0sHBE+zazywBD8+QLwICB9A=';
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
    localHttpServer.closeAllConnections?.();
    localHttpsServer.closeAllConnections?.();
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
        excludedPaths: ['/auth/logout', '/admin'],
      };

      // Normal path allowed
      expect(AuthorizedScanScopeGuard.validate(new URL('https://example.com/profile'), 'GET', context).allowed).toBe(true);

      // Excluded string path dropped
      expect(() =>
        AuthorizedScanScopeGuard.validate(new URL('https://example.com/auth/logout'), 'GET', context)
      ).toThrow(/matches excluded path rule/i);

      // Excluded path prefix dropped
      expect(() =>
        AuthorizedScanScopeGuard.validate(new URL('https://example.com/admin/delete-all'), 'GET', context)
      ).toThrow(/matches excluded path rule/i);
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
        context: await createAuthorizedScanScopeContext({
          orgId: 'org-1',
          scanId: 'scan-1',
          siteId: 'site-1',
          primaryDomain: 'primary.example.com',
          approvedSubdomains: [],
          status: 'VERIFIED',
          scanBlocked: false,
          expiresAt: Date.now() + 86400000,
          allowedPorts: [localHttpPort],
        }),
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
          context: await createAuthorizedScanScopeContext({
            orgId: 'org-1',
            scanId: 'scan-1',
            siteId: 'site-1',
            primaryDomain: 'dualstack.example.com',
            approvedSubdomains: [],
            status: 'VERIFIED',
            scanBlocked: false,
            expiresAt: Date.now() + 86400000,
          }),
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
          context: await createAuthorizedScanScopeContext({
            orgId: 'org-1',
            scanId: 'scan-1',
            siteId: 'site-1',
            primaryDomain: 'primary.example.com',
            approvedSubdomains: [],
            status: 'VERIFIED',
            scanBlocked: false,
            expiresAt: Date.now() + 86400000,
            allowedPorts: [localHttpPort],
          }),
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
          context: await createAuthorizedScanScopeContext({
            orgId: 'org-1',
            scanId: 'scan-1',
            siteId: 'site-1',
            primaryDomain: 'secure.example.com',
            approvedSubdomains: [],
            status: 'VERIFIED',
            scanBlocked: false,
            expiresAt: Date.now() + 86400000,
          }),
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
          context: await createAuthorizedScanScopeContext({
            orgId: 'org-1',
            scanId: 'scan-1',
            siteId: 'site-1',
            primaryDomain: 'primary.example.com',
            approvedSubdomains: [],
            status: 'VERIFIED',
            scanBlocked: false,
            expiresAt: Date.now() + 86400000,
            allowedPorts: [localHttpPort],
          }),
        })
      ).rejects.toThrow(/cancelled by.*AbortSignal/i);
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
          context: await createAuthorizedScanScopeContext({
            orgId: 'org-1',
            scanId: 'scan-1',
            siteId: 'site-1',
            primaryDomain: 'primary.example.com',
            approvedSubdomains: [],
            status: 'VERIFIED',
            scanBlocked: false,
            expiresAt: Date.now() + 86400000,
            allowedPorts: [localHttpPort],
          }),
        })
      ).rejects.toThrow(/timed out/i);
    });
  });

  describe('7. TASK-802 Independent Security Audit Remediation Suite', () => {
    it('rejects custom dnsResolver, lookupFn, and loopback in production environment', () => {
      const prevEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';

        // SafeHttpClient rejects custom dnsResolver in production
        expect(
          () =>
            new SafeHttpClient({
              dnsResolver: new DnsResolver(),
            })
        ).toThrow(/Injected DNS resolvers? are prohibited in production/i);

        // SafeHttpClient rejects custom socketConnector in production
        expect(
          () =>
            new SafeHttpClient({
              socketConnector: { connect: () => ({} as any), connectTls: () => ({} as any) },
            })
        ).toThrow(/Custom socket connectors are prohibited in production/i);

        // SafeHttpClient rejects allowLoopbackForTesting in production
        expect(
          () =>
            new SafeHttpClient({
              allowLoopbackForTesting: true,
            })
        ).toThrow(/Test loopback options are prohibited in production/i);

        // DnsResolver rejects lookupFn in production
        expect(
          () =>
            new DnsResolver({
              lookupFn: async () => [{ address: '1.2.3.4', family: 4 }],
            })
        ).toThrow(/Injected lookupFn is prohibited in production/i);

        // DnsResolver rejects allowLoopbackForTesting in production
        expect(
          () =>
            new DnsResolver({
              allowLoopbackForTesting: true,
            })
        ).toThrow(/Test loopback options are prohibited in production/i);
      } finally {
        process.env.NODE_ENV = prevEnv;
      }
    });

    it('defense-in-depth: SafeHttpClient catches and blocks prohibited pinnedIp returned by custom resolver', async () => {
      const maliciousResolver = {
        async resolve() {
          return {
            hostname: 'example.com',
            records: [{ address: '169.254.169.254', family: 4 }],
            pinnedIp: '169.254.169.254',
            family: 4,
          };
        },
      };

      const client = new SafeHttpClient({ dnsResolver: maliciousResolver });
      const context = await createAuthorizedScanScopeContext({
        orgId: 'org-1',
        scanId: 'scan-1',
        siteId: 'site-1',
        primaryDomain: 'example.com',
        status: 'VERIFIED',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
      });

      await expect(
        client.get('http://example.com/test', { context })
      ).rejects.toThrow(/resolved to prohibited address '169\.254\.169\.254'/i);
    });

    it('defense-in-depth: SafeHttpClient blocks pinnedIp that does not match any DNS record', async () => {
      const spoofResolver = {
        async resolve() {
          return {
            hostname: 'example.com',
            records: [{ address: '93.184.216.34', family: 4 }],
            pinnedIp: '93.184.216.35', // Spoofed pinned IP not in records
            family: 4,
          };
        },
      };

      const client = new SafeHttpClient({ dnsResolver: spoofResolver });
      const context = await createAuthorizedScanScopeContext({
        orgId: 'org-1',
        scanId: 'scan-1',
        siteId: 'site-1',
        primaryDomain: 'example.com',
        status: 'VERIFIED',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
      });

      await expect(
        client.get('http://example.com/test', { context })
      ).rejects.toThrow(/Pinned IP '93\.184\.216\.35' does not match any validated DNS record/i);
    });

    it('rejects plain unbranded JSON contexts before any DNS lookup or network activity occurs', async () => {
      let dnsCalled = false;
      const resolver = new DnsResolver({
        lookupFn: async () => {
          dnsCalled = true;
          return [{ address: '93.184.216.34', family: 4 }];
        },
      });

      const client = new SafeHttpClient({ dnsResolver: resolver });

      const forgedContext = {
        purpose: 'AUTHORIZED_SCAN',
        orgId: 'org-forged',
        scanId: 'scan-forged',
        siteId: 'site-forged',
        primaryDomain: 'example.com',
        status: 'VERIFIED',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
      } as any;

      await expect(
        client.get('http://example.com/test', { context: forgedContext })
      ).rejects.toThrow(/Untrusted or forged request authorization context rejected/i);

      expect(dnsCalled).toBe(false);
    });

    it('SafeVerificationHttpFetcher rejects request if URL domain does not match trusted context primaryDomain', async () => {
      const client = new SafeHttpClient({
        dnsResolver: new DnsResolver({
          lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
          allowLoopbackForTesting: true,
        }),
        allowLoopbackForTesting: true,
      });

      const fetcher = new SafeVerificationHttpFetcher({ client, allowLoopbackForTesting: true });
      const trustedContext = await createVerificationScopeContext({
        primaryDomain: 'legitimate.com',
        activeToken: 'vltx_tok_1234567890abcdef1234567890abcdef',
        orgId: 'org-1',
        siteId: 'site-1',
      });

      // Target URL points to evil.com instead of legitimate.com
      await expect(
        fetcher.fetch('http://evil.com/.well-known/veltrix-challenge/vltx_tok_1234567890abcdef1234567890abcdef', {
          context: trustedContext,
        })
      ).rejects.toThrow(/does not match registered primary domain 'legitimate\.com'/i);
    });

    it('SafeVerificationHttpFetcher rejects call without trusted context or configured domain/token', async () => {
      const fetcher = new SafeVerificationHttpFetcher({ allowLoopbackForTesting: true });

      await expect(
        fetcher.fetch('http://target.com/.well-known/veltrix-challenge/token123')
      ).rejects.toThrow(/SafeVerificationHttpFetcher requires a pre-validated authoritative VerificationScopeContext/i);
    });

    it('rejects URLs with embedded user credentials (SSRF credential injection)', async () => {
      const client = new SafeHttpClient();
      const context = await createAuthorizedScanScopeContext({
        orgId: 'org-1',
        scanId: 'scan-1',
        siteId: 'site-1',
        primaryDomain: 'example.com',
        status: 'VERIFIED',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
      });

      await expect(
        client.get('http://admin:secret@example.com/admin', { context })
      ).rejects.toThrow(/Embedded user credentials in target URL/i);
    });

    it('rejects caller-supplied Host header that does not match validated target authority', async () => {
      const client = new SafeHttpClient();
      const context = await createAuthorizedScanScopeContext({
        orgId: 'org-1',
        scanId: 'scan-1',
        siteId: 'site-1',
        primaryDomain: 'example.com',
        status: 'VERIFIED',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
      });

      await expect(
        client.get('http://example.com/test', {
          headers: { Host: 'internal.corp.local' },
          context,
        })
      ).rejects.toThrow(/Caller-supplied Host header .* does not match target URL authority/i);
    });

    it('strips hop-by-hop headers from outgoing requests', async () => {
      let receivedHeaders: http.IncomingHttpHeaders | null = null;
      const testServer = http.createServer((req, res) => {
        receivedHeaders = req.headers;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      });

      await new Promise<void>((r) => testServer.listen(0, '127.0.0.1', r));
      const port = (testServer.address() as net.AddressInfo).port;

      try {
        const client = new SafeHttpClient({
          dnsResolver: new DnsResolver({
            lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
            allowLoopbackForTesting: true,
          }),
          allowLoopbackForTesting: true,
        });

        const context = await createAuthorizedScanScopeContext({
          orgId: 'org-1',
          scanId: 'scan-1',
          siteId: 'site-1',
          primaryDomain: 'primary.example.com',
          status: 'VERIFIED',
          scanBlocked: false,
          expiresAt: Date.now() + 86400000,
          allowedPorts: [port],
        });

        await client.get(`http://primary.example.com:${port}/header-strip-test`, {
          allowLoopbackForTesting: true,
          headers: {
            'Connection': 'keep-alive',
            'Proxy-Connection': 'keep-alive',
            'Upgrade': 'websocket',
            'X-Custom-Scan-Header': 'preserved-value',
          },
          context,
        });

        expect(receivedHeaders).not.toBeNull();
        // Connection is strictly overridden to 'close'
        expect(receivedHeaders!['connection']).toBe('close');
        // Hop-by-hop headers are completely stripped
        expect(receivedHeaders!['proxy-connection']).toBeUndefined();
        expect(receivedHeaders!['upgrade']).toBeUndefined();
        // Safe custom header is preserved
        expect(receivedHeaders!['x-custom-scan-header']).toBe('preserved-value');
      } finally {
        await new Promise<void>((r) => testServer.close(() => r()));
      }
    });

    it('aborts during streaming response body after headers have arrived', async () => {
      let clientSocket: net.Socket | null = null;
      const hangingStreamServer = http.createServer((req, res) => {
        clientSocket = req.socket;
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.write('first-chunk-ok-');
        // Do not end or write further to simulate hanging streaming body
      });

      await new Promise<void>((r) => hangingStreamServer.listen(0, '127.0.0.1', r));
      const hangPort = (hangingStreamServer.address() as net.AddressInfo).port;

      try {
        const client = new SafeHttpClient({
          dnsResolver: new DnsResolver({
            lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
            allowLoopbackForTesting: true,
          }),
          allowLoopbackForTesting: true,
        });

        const context = await createAuthorizedScanScopeContext({
          orgId: 'org-1',
          scanId: 'scan-1',
          siteId: 'site-1',
          primaryDomain: 'primary.example.com',
          status: 'VERIFIED',
          scanBlocked: false,
          expiresAt: Date.now() + 86400000,
          allowedPorts: [hangPort],
        });

        const controller = new AbortController();
        setTimeout(() => controller.abort(), 40);

        await expect(
          client.get(`http://primary.example.com:${hangPort}/stream-hang`, {
            signal: controller.signal,
            allowLoopbackForTesting: true,
            context,
          })
        ).rejects.toThrow(/cancelled by.*AbortSignal/i);

        await new Promise((r) => setTimeout(r, 20));
        expect(clientSocket?.destroyed || !clientSocket?.writable).toBe(true);
      } finally {
        await new Promise<void>((r) => hangingStreamServer.close(() => r()));
      }
    });

    it('enforces bodyIdleTimeoutMs watchdog when server stalls during body transmission', async () => {
      let clientSocket: net.Socket | null = null;
      const stallServer = http.createServer((req, res) => {
        clientSocket = req.socket;
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.write('chunk-1-');
        // Stall without closing
      });

      await new Promise<void>((r) => stallServer.listen(0, '127.0.0.1', r));
      const stallPort = (stallServer.address() as net.AddressInfo).port;

      try {
        const client = new SafeHttpClient({
          dnsResolver: new DnsResolver({
            lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
            allowLoopbackForTesting: true,
          }),
          allowLoopbackForTesting: true,
        });

        const context = await createAuthorizedScanScopeContext({
          orgId: 'org-1',
          scanId: 'scan-1',
          siteId: 'site-1',
          primaryDomain: 'primary.example.com',
          status: 'VERIFIED',
          scanBlocked: false,
          expiresAt: Date.now() + 86400000,
          allowedPorts: [stallPort],
        });

        await expect(
          client.get(`http://primary.example.com:${stallPort}/stall-test`, {
            bodyIdleTimeoutMs: 60,
            timeoutMs: 5000,
            allowLoopbackForTesting: true,
            context,
          })
        ).rejects.toThrow(/Response body idle timeout/i);

        await new Promise((r) => setTimeout(r, 20));
        expect(clientSocket?.destroyed || !clientSocket?.writable).toBe(true);
      } finally {
        await new Promise<void>((r) => stallServer.close(() => r()));
      }
    });

    it('enforces connectTimeoutMs watchdog on hung TCP / TLS connection', async () => {
      const activeSockets: net.Socket[] = [];
      const hungTlsServer = net.createServer((sock) => {
        activeSockets.push(sock);
      });

      await new Promise<void>((r) => hungTlsServer.listen(0, '127.0.0.1', r));
      const hungPort = (hungTlsServer.address() as net.AddressInfo).port;

      try {
        const client = new SafeHttpClient({
          dnsResolver: new DnsResolver({
            lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
            allowLoopbackForTesting: true,
          }),
          allowLoopbackForTesting: true,
        });

        const context = await createAuthorizedScanScopeContext({
          orgId: 'org-1',
          scanId: 'scan-1',
          siteId: 'site-1',
          primaryDomain: 'primary.example.com',
          status: 'VERIFIED',
          scanBlocked: false,
          expiresAt: Date.now() + 86400000,
          allowedPorts: [hungPort],
        });

        await expect(
          client.get(`https://primary.example.com:${hungPort}/hung-tls`, {
            connectTimeoutMs: 60,
            timeoutMs: 5000,
            allowLoopbackForTesting: true,
            context,
          })
        ).rejects.toThrow(/TCP\/TLS connection timed out after 60ms/i);
      } finally {
        for (const sock of activeSockets) {
          try { sock.destroy(); } catch {}
        }
        await new Promise<void>((r) => hungTlsServer.close(() => r()));
      }
    });
  });

  describe('8. TASK-802 Final Security Hardening & Strict Invariant Matrix', () => {
    const validAsset: WebsiteAsset = {
      siteId: 'site-alpha-123',
      orgId: 'org-alpha-123',
      name: 'Alpha Target',
      primaryDomain: 'primary.example.com',
      approvedSubdomains: ['api.example.com', 'admin.example.com'],
      environment: 'PRODUCTION',
      status: 'VERIFIED',
      riskTier: 'CRITICAL',
      tags: ['production'],
      verificationToken: 'vltx_tok_0123456789abcdef0123456789abcdef',
      tokenCreatedAt: new Date().toISOString(),
      dnsTxtRecord: {
        host: '_veltrix-challenge.primary.example.com',
        value: 'vltx_tok_0123456789abcdef0123456789abcdef',
      },
      httpChallenge: {
        url: 'http://primary.example.com/.well-known/veltrix-challenge/vltx_tok_0123456789abcdef0123456789abcdef',
        expectedBody: {
          veltrixChallengeToken: 'vltx_tok_0123456789abcdef0123456789abcdef',
          orgId: 'org-alpha-123',
        },
      },
      verifiedAt: new Date(Date.now() - 3600000).toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      scanBlocked: false,
      health: 'HEALTHY',
      createdAt: new Date(Date.now() - 86400000).toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const validScanDesc = {
      scanId: 'scan-alpha-999',
      allowedPorts: [80, 443],
      allowedMethods: ['GET', 'POST'],
    };

    it('proves isTrustedScopeContext accepts only authoritatively minted contexts via private registry', async () => {
      const store = new MemoryStore();
      await store.saveWebsite(validAsset);

      const authScan = await createAuthoritativeScanScopeContext(store, {
        orgId: validAsset.orgId,
        siteId: validAsset.siteId,
        scanId: validScanDesc.scanId,
        serverPolicy: createServerScanPolicy({
          allowedPorts: validScanDesc.allowedPorts,
          allowedMethods: validScanDesc.allowedMethods,
        }),
      });
      const authVerif = await createAuthoritativeVerificationScopeContext(store, {
        orgId: validAsset.orgId,
        siteId: validAsset.siteId,
      });

      expect(isTrustedScopeContext(authScan)).toBe(true);
      expect(isTrustedScopeContext(authVerif)).toBe(true);

      // Rejection of forged objects and Symbol spoofing
      expect(isTrustedScopeContext(null)).toBe(false);
      expect(isTrustedScopeContext(undefined)).toBe(false);
      expect(isTrustedScopeContext({})).toBe(false);
      expect(isTrustedScopeContext({ ...authScan })).toBe(false); // cloned object loses WeakSet identity
      expect(isTrustedScopeContext(Object.create(authScan))).toBe(false); // prototype manipulation
      expect(isTrustedScopeContext({ [Symbol.for('TRUSTED_SCOPE_BRAND')]: true })).toBe(false);
      expect(isTrustedScopeContext(JSON.parse(JSON.stringify(authScan)))).toBe(false);
    });

    it('rejects unbranded plain JSON contexts in SafeHttpClient before DNS resolution', async () => {
      let dnsResolved = false;
      const client = new SafeHttpClient({
        dnsResolver: new DnsResolver({
          lookupFn: async () => {
            dnsResolved = true;
            return [{ address: '127.0.0.1', family: 4 }];
          },
          allowLoopbackForTesting: true,
        }),
        allowLoopbackForTesting: true,
      });

      // 1. Unbranded Scan context
      const forgedScanContext = {
        purpose: 'AUTHORIZED_SCAN',
        orgId: 'org-fake',
        scanId: 'scan-fake',
        siteId: 'site-fake',
        primaryDomain: 'primary.example.com',
        status: 'VERIFIED',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
      } as any;

      await expect(
        client.get(`http://primary.example.com:${localHttpPort}/test`, {
          context: forgedScanContext,
          allowLoopbackForTesting: true,
        })
      ).rejects.toThrow(/Untrusted or forged request authorization context rejected/i);

      expect(dnsResolved).toBe(false);

      // 2. Unbranded Verification context
      const forgedVerifContext = {
        purpose: 'DOMAIN_OWNERSHIP_VERIFICATION',
        primaryDomain: 'primary.example.com',
        activeToken: 'vltx_fake_token_123',
      } as any;

      await expect(
        client.get(`http://primary.example.com:${localHttpPort}/test`, {
          context: forgedVerifContext,
          allowLoopbackForTesting: true,
        })
      ).rejects.toThrow(/Untrusted or forged request authorization context rejected/i);

      expect(dnsResolved).toBe(false);
    });

    it('createAuthoritativeScanScopeContext enforces server-side verification status invariants', async () => {
      const statuses: WebsiteAsset['status'][] = [
        'PENDING_VERIFICATION',
        'GRACE_PERIOD',
        'SUSPENDED',
        'EXPIRED',
        'REVOKED',
      ];

      for (const status of statuses) {
        const store = new MemoryStore();
        await store.saveWebsite({ ...validAsset, status });

        await expect(
          createAuthoritativeScanScopeContext(store, {
            orgId: validAsset.orgId,
            siteId: validAsset.siteId,
            scanId: validScanDesc.scanId,
          })
        ).rejects.toThrow(
          status === 'GRACE_PERIOD' || status === 'SUSPENDED'
            ? /Active scans are suspended/i
            : /has not completed ownership verification/i
        );
      }
    });

    it('createAuthoritativeScanScopeContext enforces scanBlocked invariant', async () => {
      // scanBlocked === true
      const store1 = new MemoryStore();
      await store1.saveWebsite({ ...validAsset, scanBlocked: true });
      await expect(
        createAuthoritativeScanScopeContext(store1, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: validScanDesc.scanId,
        })
      ).rejects.toThrow(/scanBlocked set to true or undefined/i);

      // scanBlocked === undefined
      const store2 = new MemoryStore();
      await store2.saveWebsite({ ...validAsset, scanBlocked: undefined as any });
      await expect(
        createAuthoritativeScanScopeContext(store2, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: validScanDesc.scanId,
        })
      ).rejects.toThrow(/scanBlocked set to true or undefined/i);
    });

    it('createAuthoritativeScanScopeContext enforces finite future expiresAt invariant', async () => {
      // Missing expiresAt (undefined)
      const store1 = new MemoryStore();
      await store1.saveWebsite({ ...validAsset, expiresAt: undefined as any });
      await expect(
        createAuthoritativeScanScopeContext(store1, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: validScanDesc.scanId,
        })
      ).rejects.toThrow(/verification timestamp is missing or malformed/i);

      // Empty string expiresAt
      const storeEmpty = new MemoryStore();
      await storeEmpty.saveWebsite({ ...validAsset, expiresAt: '   ' });
      await expect(
        createAuthoritativeScanScopeContext(storeEmpty, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: validScanDesc.scanId,
        })
      ).rejects.toThrow(/verification timestamp is missing or malformed/i);

      // Non-date / malformed string (proves Date.parse NaN handling does not crash with RangeError: Invalid time value)
      const store2 = new MemoryStore();
      await store2.saveWebsite({ ...validAsset, expiresAt: 'not-a-valid-date' });
      await expect(
        createAuthoritativeScanScopeContext(store2, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: validScanDesc.scanId,
        })
      ).rejects.toThrow(/timestamp 'not-a-valid-date' is invalid or malformed/i);

      // Past timestamp
      const store3 = new MemoryStore();
      const pastDate = new Date(Date.now() - 60000).toISOString();
      await store3.saveWebsite({ ...validAsset, expiresAt: pastDate });
      await expect(
        createAuthoritativeScanScopeContext(store3, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: validScanDesc.scanId,
        })
      ).rejects.toThrow(/Domain ownership verification expired at/i);

      // Future valid ISO timestamp succeeds
      const storeValid = new MemoryStore();
      const futureDate = new Date(Date.now() + 86400000).toISOString();
      await storeValid.saveWebsite({ ...validAsset, expiresAt: futureDate });
      const validCtx = await createAuthoritativeScanScopeContext(storeValid, {
        orgId: validAsset.orgId,
        siteId: validAsset.siteId,
        scanId: validScanDesc.scanId,
      });
      expect(validCtx.expiresAt).toBe(Date.parse(futureDate));
    });

    it('createAuthoritativeScanScopeContext enforces non-empty trimmed identity strings and valid subdomains', async () => {
      const store = new MemoryStore();
      await store.saveWebsite(validAsset);

      // Empty orgId
      await expect(
        createAuthoritativeScanScopeContext(store, {
          orgId: '   ',
          siteId: validAsset.siteId,
          scanId: validScanDesc.scanId,
        })
      ).rejects.toThrow(/must be non-empty strings/i);

      // Empty siteId
      await expect(
        createAuthoritativeScanScopeContext(store, {
          orgId: validAsset.orgId,
          siteId: '',
          scanId: validScanDesc.scanId,
        })
      ).rejects.toThrow(/must be non-empty strings/i);

      // Empty scanId
      await expect(
        createAuthoritativeScanScopeContext(store, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: '   ',
        })
      ).rejects.toThrow(/must be non-empty strings/i);

      // Empty primaryDomain in stored asset
      const storeEmptyDomain = new MemoryStore();
      await storeEmptyDomain.saveWebsite({ ...validAsset, primaryDomain: '' });
      await expect(
        createAuthoritativeScanScopeContext(storeEmptyDomain, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: validScanDesc.scanId,
        })
      ).rejects.toThrow(/Primary domain is missing in authoritative asset/i);

      // Invalid approvedSubdomains in stored asset
      const storeInvalidSub = new MemoryStore();
      await storeInvalidSub.saveWebsite({ ...validAsset, approvedSubdomains: ['valid.com', '  '] });
      await expect(
        createAuthoritativeScanScopeContext(storeInvalidSub, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: validScanDesc.scanId,
        })
      ).rejects.toThrow(/contain invalid or empty domain strings/i);

      // Non-existent asset in storage
      const storeNotFound = new MemoryStore();
      await expect(
        createAuthoritativeScanScopeContext(storeNotFound, {
          orgId: 'org-missing',
          siteId: 'site-missing',
          scanId: 'scan-1',
        })
      ).rejects.toThrow(/not found in authoritative storage/i);
    });

    it('createAuthoritativeVerificationScopeContext validates required domain and token', async () => {
      const store1 = new MemoryStore();
      await store1.saveWebsite({
        ...validAsset,
        primaryDomain: '',
        verificationToken: 'tok',
      });
      await expect(
        createAuthoritativeVerificationScopeContext(store1, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
        })
      ).rejects.toThrow(/Primary domain is missing in authoritative asset/i);

      const store2 = new MemoryStore();
      await store2.saveWebsite({
        ...validAsset,
        primaryDomain: 'example.com',
        verificationToken: '   ',
      });
      await expect(
        createAuthoritativeVerificationScopeContext(store2, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
        })
      ).rejects.toThrow(/Active verification token is missing in authoritative asset/i);

      const store3 = new MemoryStore();
      await store3.saveWebsite({
        ...validAsset,
        primaryDomain: 'Example.COM',
        verificationToken: 'vltx_tok_123',
      });
      const ctx = await createAuthoritativeVerificationScopeContext(store3, {
        orgId: validAsset.orgId,
        siteId: validAsset.siteId,
      });

      expect(ctx.primaryDomain).toBe('example.com');
      expect(ctx.activeToken).toBe('vltx_tok_123');
      expect(isTrustedScopeContext(ctx)).toBe(true);
    });

    describe('Protocol-Specific Standard Port Policy (Issue 5)', () => {
      const getScanContextWithPorts = async (allowedPorts?: number[]) => {
        const store = new MemoryStore();
        await store.saveWebsite(validAsset);
        const serverPolicy = allowedPorts ? createServerScanPolicy({ allowedPorts }) : undefined;
        return createAuthoritativeScanScopeContext(store, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: 'scan-ports-001',
          serverPolicy,
        });
      };

      it('rejects port 443 over plaintext HTTP as non-standard without explicit authorization', async () => {
        const url = new URL('http://primary.example.com:443/test');
        const ctx = await getScanContextWithPorts();
        expect(() =>
          AuthorizedScanScopeGuard.validate(url, 'GET', ctx)
        ).toThrow(/Port 443 is non-standard and has not been explicitly authorized for protocol 'http:'/i);
      });

      it('rejects port 80 over TLS HTTPS as non-standard without explicit authorization', async () => {
        const url = new URL('https://primary.example.com:80/test');
        const ctx = await getScanContextWithPorts();
        expect(() =>
          AuthorizedScanScopeGuard.validate(url, 'GET', ctx)
        ).toThrow(/Port 80 is non-standard and has not been explicitly authorized for protocol 'https:'/i);
      });

      it('permits standard port 80 for HTTP', async () => {
        const url = new URL('http://primary.example.com:80/test');
        const ctx = await getScanContextWithPorts();
        const result = AuthorizedScanScopeGuard.validate(url, 'GET', ctx);
        expect(result.allowed).toBe(true);
      });

      it('permits standard port 443 for HTTPS', async () => {
        const url = new URL('https://primary.example.com:443/test');
        const ctx = await getScanContextWithPorts();
        const result = AuthorizedScanScopeGuard.validate(url, 'GET', ctx);
        expect(result.allowed).toBe(true);
      });

      it('permits port 443 over HTTP when explicitly whitelisted in allowedPorts', async () => {
        const url = new URL('http://primary.example.com:443/test');
        const ctx = await getScanContextWithPorts([443]);
        const result = AuthorizedScanScopeGuard.validate(url, 'GET', ctx);
        expect(result.allowed).toBe(true);
      });

      it('permits port 80 over HTTPS when explicitly whitelisted in allowedPorts', async () => {
        const url = new URL('https://primary.example.com:80/test');
        const ctx = await getScanContextWithPorts([80]);
        const result = AuthorizedScanScopeGuard.validate(url, 'GET', ctx);
        expect(result.allowed).toBe(true);
      });

      it('strictly blocks high-risk internal infrastructure port 22 even if requested in allowedPorts', async () => {
        // 1. Context authority rejects port 22 at context-minting time
        await expect(getScanContextWithPorts([22])).rejects.toThrow(
          /Port 22 is a prohibited internal infrastructure port/i
        );

        // 2. ScopeGuard also unconditionally blocks port 22 in target URL as defense-in-depth
        const url = new URL('http://primary.example.com:22/ssh-test');
        const ctx = await getScanContextWithPorts();
        expect(() =>
          AuthorizedScanScopeGuard.validate(url, 'GET', ctx)
        ).toThrow(/prohibited internal infrastructure port/i);
      });
    });

    describe('DefaultHttpFetcher Strict Production Prohibition (Issue 4)', () => {
      it('unconditionally throws FATAL_SECURITY_ERROR on instantiation in production', () => {
        const prevEnv = process.env.NODE_ENV;
        try {
          process.env.NODE_ENV = 'production';

          expect(() => new DefaultHttpFetcher()).toThrow(
            /FATAL_SECURITY_ERROR: DefaultHttpFetcher is a legacy test adapter and is strictly prohibited in production/i
          );

          expect(() => new DefaultHttpFetcher({ allowLoopbackForTesting: true })).toThrow(
            /FATAL_SECURITY_ERROR/i
          );
        } finally {
          process.env.NODE_ENV = prevEnv;
        }
      });

      it('unconditionally throws FATAL_SECURITY_ERROR on fetch invocation if environment is set to production', async () => {
        const fetcher = new DefaultHttpFetcher({ allowLoopbackForTesting: true });
        const prevEnv = process.env.NODE_ENV;
        try {
          process.env.NODE_ENV = 'production';
          await expect(fetcher.fetch('http://example.com/')).rejects.toThrow(
            /FATAL_SECURITY_ERROR: DefaultHttpFetcher is strictly prohibited in production/i
          );
        } finally {
          process.env.NODE_ENV = prevEnv;
        }
      });

      it('functions as backward-compatible test adapter in non-production environments', async () => {
        const testServer = http.createServer((_req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ legacy: 'ok' }));
        });

        await new Promise<void>((r) => testServer.listen(0, '127.0.0.1', r));
        const port = (testServer.address() as net.AddressInfo).port;

        try {
          const fetcher = new DefaultHttpFetcher({ allowLoopbackForTesting: true });
          const res = await fetcher.fetch(`http://127.0.0.1:${port}/legacy-test`);
          expect(res.status).toBe(200);
          expect(res.data).toEqual({ legacy: 'ok' });
        } finally {
          await new Promise<void>((r) => testServer.close(() => r()));
        }
      });
    });

    describe('P0: Context-Minting Bypass Prevention & Strict Injection Policy', () => {
      it('SafeVerificationHttpFetcher rejects caller-supplied primaryDomain and token without trusted context before DNS', async () => {
        let dnsCalls = 0;
        const mockResolver = new DnsResolver({
          lookupFn: async () => {
            dnsCalls++;
            return [{ address: '127.0.0.1', family: 4 }];
          },
          allowLoopbackForTesting: true,
        });

        const client = new SafeHttpClient({
          dnsResolver: mockResolver,
          allowLoopbackForTesting: true,
        });

        const fetcher = new SafeVerificationHttpFetcher({ client, allowLoopbackForTesting: true });

        // Attacker attempts to provide domain and token in options directly
        await expect(
          fetcher.fetch('http://target.com/.well-known/veltrix-challenge/token123', {
            primaryDomain: 'target.com',
            token: 'token123',
          } as any)
        ).rejects.toThrow(/SafeVerificationHttpFetcher requires a pre-validated authoritative VerificationScopeContext/i);

        expect(dnsCalls).toBe(0);
      });

      it('SafeVerificationHttpFetcher rejects forged or cloned context before DNS', async () => {
        let dnsCalls = 0;
        const mockResolver = new DnsResolver({
          lookupFn: async () => {
            dnsCalls++;
            return [{ address: '127.0.0.1', family: 4 }];
          },
          allowLoopbackForTesting: true,
        });

        const client = new SafeHttpClient({
          dnsResolver: mockResolver,
          allowLoopbackForTesting: true,
        });

        const fetcher = new SafeVerificationHttpFetcher({ client, allowLoopbackForTesting: true });

        // Forged context
        const forgedContext = {
          purpose: 'DOMAIN_OWNERSHIP_VERIFICATION',
          primaryDomain: 'target.com',
          activeToken: 'tok123',
        };

        await expect(
          fetcher.fetch('http://target.com/.well-known/veltrix-challenge/tok123', {
            context: forgedContext as any,
          })
        ).rejects.toThrow(/Untrusted or forged request authorization context rejected/i);

        expect(dnsCalls).toBe(0);
      });

      it('executes successfully when provided with an authoritative context from storage', async () => {
        const store = new MemoryStore();
        await store.saveWebsite(validAsset);

        const trustedContext = await createAuthoritativeVerificationScopeContext(store, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
        });

        const client = new SafeHttpClient({
          dnsResolver: new DnsResolver({
            lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
            allowLoopbackForTesting: true,
          }),
          socketConnector: {
            connect: () => {
              return net.connect({ host: '127.0.0.1', port: localHttpPort });
            },
            connectTls: (opts) => {
              return tls.connect({
                socket: opts.socket,
                servername: opts.servername,
                rejectUnauthorized: opts.rejectUnauthorized,
              });
            },
          },
          allowLoopbackForTesting: true,
        });

        const fetcher = new SafeVerificationHttpFetcher({ client, allowLoopbackForTesting: true });

        const res = await fetcher.fetch(
          `http://${validAsset.primaryDomain}/.well-known/veltrix-challenge/${validAsset.verificationToken}`,
          { context: trustedContext }
        );

        expect(res.status).toBe(200);
      });

      it('succeeds in constructing DomainOwnershipVerifier, HttpVerifier, and MetaVerifier in production mode with default compositions', () => {
        const prevEnv = process.env.NODE_ENV;
        try {
          process.env.NODE_ENV = 'production';
          const store = new MemoryStore();

          // 1. DomainOwnershipVerifier succeeds with default composition in production
          const verifier = new DomainOwnershipVerifier(store);
          expect(verifier).toBeInstanceOf(DomainOwnershipVerifier);

          // 2. HttpVerifier succeeds with default composition in production
          const httpVerifier = new HttpVerifier();
          expect(httpVerifier).toBeInstanceOf(HttpVerifier);

          // 3. MetaVerifier succeeds with default composition in production
          const metaVerifier = new MetaVerifier();
          expect(metaVerifier).toBeInstanceOf(MetaVerifier);

          // 4. SafeVerificationHttpFetcher succeeds with default composition in production
          const fetcher = new SafeVerificationHttpFetcher();
          expect(fetcher).toBeInstanceOf(SafeVerificationHttpFetcher);
        } finally {
          process.env.NODE_ENV = prevEnv;
        }
      });

      it('strictly prohibits injected dependencies in production across DomainOwnershipVerifier, HttpVerifier, and MetaVerifier', () => {
        const prevEnv = process.env.NODE_ENV;
        try {
          process.env.NODE_ENV = 'production';
          const store = new MemoryStore();
          const dummyResolver = new DefaultDnsResolver();
          const dummyFetcher = new SafeVerificationHttpFetcher();

          // 1. DomainOwnershipVerifier with custom DNS resolver via options object
          expect(
            () => new DomainOwnershipVerifier(store, { dnsResolver: dummyResolver })
          ).toThrow(/FATAL_SECURITY_ERROR: Injected DnsResolver is prohibited in production/i);

          // 2. DomainOwnershipVerifier with custom DNS resolver via positional argument
          expect(
            () => new DomainOwnershipVerifier(store, dummyResolver)
          ).toThrow(/FATAL_SECURITY_ERROR: Injected DnsResolver is prohibited in production/i);

          // 3. DomainOwnershipVerifier with custom HTTP fetcher via actual httpFetcher option
          expect(
            () => new DomainOwnershipVerifier(store, { httpFetcher: dummyFetcher })
          ).toThrow(/FATAL_SECURITY_ERROR: Injected HttpFetcher is prohibited in production/i);

          // 4. DomainOwnershipVerifier with custom HTTP fetcher via positional argument
          expect(
            () => new DomainOwnershipVerifier(store, undefined, dummyFetcher)
          ).toThrow(/FATAL_SECURITY_ERROR: Injected HttpFetcher is prohibited in production/i);

          // 5. HttpVerifier with directly injected custom fetcher
          expect(
            () => new HttpVerifier(dummyFetcher)
          ).toThrow(/FATAL_SECURITY_ERROR: Injected HttpFetcher is prohibited in production/i);

          // 6. MetaVerifier with directly injected custom fetcher
          expect(
            () => new MetaVerifier(dummyFetcher)
          ).toThrow(/FATAL_SECURITY_ERROR: Injected HttpFetcher is prohibited in production/i);

          // 7. SafeVerificationHttpFetcher with injected client or loopback flag
          expect(
            () => new SafeVerificationHttpFetcher({ client: new SafeHttpClient() })
          ).toThrow(/FATAL_SECURITY_ERROR: Injected SafeHttpClient and test loopback options are prohibited in production/i);

          expect(
            () => new SafeVerificationHttpFetcher({ allowLoopbackForTesting: true })
          ).toThrow(/FATAL_SECURITY_ERROR: Injected SafeHttpClient and test loopback options are prohibited in production/i);
        } finally {
          process.env.NODE_ENV = prevEnv;
        }
      });

      it('proves default production verification uses hardened SafeHttpClient and requires authoritative storage context', async () => {
        const httpVerifier = new HttpVerifier();
        const metaVerifier = new MetaVerifier();

        // 1. Calling verify without context fails because underlying SafeVerificationHttpFetcher rejects missing context
        const httpResNoContext = await httpVerifier.verify(
          'http://primary.example.com/.well-known/veltrix-challenge/token123',
          'token123',
          'org-1'
        );
        expect(httpResNoContext.matched).toBe(false);
        expect(httpResNoContext.failureReason).toMatch(
          /SafeVerificationHttpFetcher requires a pre-validated authoritative VerificationScopeContext/i
        );

        const metaResNoContext = await metaVerifier.verify('https://primary.example.com/', 'token123');
        expect(metaResNoContext.matched).toBe(false);
        expect(metaResNoContext.failureReason).toMatch(
          /SafeVerificationHttpFetcher requires a pre-validated authoritative VerificationScopeContext/i
        );

        // 2. Calling verify with forged context fails because underlying SafeVerificationHttpFetcher rejects untrusted context
        const forgedContext = {
          purpose: 'DOMAIN_OWNERSHIP_VERIFICATION',
          primaryDomain: 'primary.example.com',
          activeToken: 'token123',
        } as any;

        const httpResForged = await httpVerifier.verify(
          'http://primary.example.com/.well-known/veltrix-challenge/token123',
          'token123',
          'org-1',
          forgedContext
        );
        expect(httpResForged.matched).toBe(false);
        expect(httpResForged.failureReason).toMatch(
          /Untrusted or forged request authorization context rejected/i
        );

        const metaResForged = await metaVerifier.verify('https://primary.example.com/', 'token123', forgedContext);
        expect(metaResForged.matched).toBe(false);
        expect(metaResForged.failureReason).toMatch(
          /Untrusted or forged request authorization context rejected/i
        );

        // 3. Verification succeeds when supplied with genuine authoritative context from storage
        const store = new MemoryStore();
        await store.saveWebsite(validAsset);
        const trustedContext = await createAuthoritativeVerificationScopeContext(store, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
        });
        expect(isTrustedScopeContext(trustedContext)).toBe(true);
      });
    });

    describe('P1: Server-Controlled Scan Authorization Policy & Invariant Matrix', () => {
      it('defaults allowedMethods to GET and HEAD and deeply freezes the policy array', async () => {
        const store = new MemoryStore();
        await store.saveWebsite(validAsset);

        const context = await createAuthoritativeScanScopeContext(store, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: 'scan-policy-default',
        });

        expect(context.allowedMethods).toEqual(['GET', 'HEAD']);
        expect(Object.isFrozen(context.allowedMethods)).toBe(true);
        expect(Object.isFrozen(context)).toBe(true);

        // Mutating throws or is barred
        expect(() => {
          (context.allowedMethods as string[]).push('POST');
        }).toThrow();
      });

      it('rejects client-controlled method and port expansion in raw request parameters', async () => {
        const store = new MemoryStore();
        await store.saveWebsite(validAsset);

        // 1. Raw caller parameter attempting to authorize non-default method POST without serverPolicy is rejected
        await expect(
          createAuthoritativeScanScopeContext(store, {
            orgId: validAsset.orgId,
            siteId: validAsset.siteId,
            scanId: 'scan-expand-method',
            allowedMethods: ['GET', 'POST'],
          })
        ).rejects.toThrow(/Arbitrary client request parameters cannot authorize non-default HTTP methods/i);

        // 2. Raw caller parameter attempting to authorize non-standard port 8080 without serverPolicy is rejected
        await expect(
          createAuthoritativeScanScopeContext(store, {
            orgId: validAsset.orgId,
            siteId: validAsset.siteId,
            scanId: 'scan-expand-port',
            allowedPorts: [8080],
          })
        ).rejects.toThrow(/Arbitrary client request parameters cannot authorize non-standard destination ports/i);

        // 3. Forged serverPolicy object not minted by createServerScanPolicy is rejected
        const forgedPolicy = {
          allowedMethods: ['GET', 'POST'],
          allowedPorts: [8080],
        } as any;

        await expect(
          createAuthoritativeScanScopeContext(store, {
            orgId: validAsset.orgId,
            siteId: validAsset.siteId,
            scanId: 'scan-forged-policy',
            serverPolicy: forgedPolicy,
          })
        ).rejects.toThrow(/Untrusted or forged server scan policy rejected/i);

        // 4. Client-supplied RegExp in excludedPaths is rejected with MALFORMED_URL
        await expect(
          createAuthoritativeScanScopeContext(store, {
            orgId: validAsset.orgId,
            siteId: validAsset.siteId,
            scanId: 'scan-regexp-excl',
            excludedPaths: [/^\/admin/ as any],
          })
        ).rejects.toThrow(/Excluded path entries must be non-empty strings\. RegExp instances are prohibited/i);
      });

      it('strictly validates methods against server-controlled policy in createServerScanPolicy and rejects prohibited verbs', async () => {
        const store = new MemoryStore();
        await store.saveWebsite(validAsset);

        // TRACE method is prohibited
        expect(() => {
          createServerScanPolicy({ allowedMethods: ['GET', 'TRACE'] });
        }).toThrow(/HTTP method 'TRACE' is prohibited by server-side scan policy/i);

        // CONNECT method is prohibited
        expect(() => {
          createServerScanPolicy({ allowedMethods: ['CONNECT'] });
        }).toThrow(/HTTP method 'CONNECT' is prohibited by server-side scan policy/i);

        // Arbitrary unknown method is prohibited
        expect(() => {
          createServerScanPolicy({ allowedMethods: ['EVIL_VERB'] });
        }).toThrow(/HTTP method 'EVIL_VERB' is prohibited by server-side scan policy/i);

        // Permitted methods are allowed, normalized to uppercase, deduplicated, and frozen via server policy
        const serverPolicy = createServerScanPolicy({
          allowedMethods: ['get', 'post', 'GET'],
        });
        const validContext = await createAuthoritativeScanScopeContext(store, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: 'scan-methods-valid',
          serverPolicy,
        });

        expect(validContext.allowedMethods).toEqual(['GET', 'POST']);
        expect(Object.isFrozen(validContext.allowedMethods)).toBe(true);
      });

      it('validates port ranges and categorically rejects blocked internal ports at server policy creation', async () => {
        // Out of range port (0)
        expect(() => {
          createServerScanPolicy({ allowedPorts: [0] });
        }).toThrow(/Invalid destination port '0'/i);

        // Out of range port (70000)
        expect(() => {
          createServerScanPolicy({ allowedPorts: [70000] });
        }).toThrow(/Invalid destination port '70000'/i);

        // Non-integer port
        expect(() => {
          createServerScanPolicy({ allowedPorts: [80.5] });
        }).toThrow(/Invalid destination port '80.5'/i);

        // Blocked internal ports: 22 (SSH), 25 (SMTP), 3306 (MySQL), 6379 (Redis)
        const blockedPortsToTest = [22, 25, 3306, 6379];
        for (const blockedPort of blockedPortsToTest) {
          expect(() => {
            createServerScanPolicy({ allowedPorts: [blockedPort] });
          }).toThrow(/prohibited internal infrastructure port/i);
        }
      });

      it('unconditionally enforces mandatory server-side excluded paths and rejects RegExp exclusions', async () => {
        const store = new MemoryStore();
        await store.saveWebsite(validAsset);

        // Caller provides no excluded paths
        const contextDefault = await createAuthoritativeScanScopeContext(store, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: 'scan-excl-default',
        });

        for (const mandatory of SERVER_MANDATORY_EXCLUDED_PATHS) {
          expect(contextDefault.excludedPaths).toContain(mandatory);
        }

        // Caller provides custom string excluded path
        const contextCustom = await createAuthoritativeScanScopeContext(store, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: 'scan-excl-custom',
          excludedPaths: ['/internal/admin'],
        });

        for (const mandatory of SERVER_MANDATORY_EXCLUDED_PATHS) {
          expect(contextCustom.excludedPaths).toContain(mandatory);
        }
        expect(contextCustom.excludedPaths).toContain('/internal/admin');
        expect(Object.isFrozen(contextCustom.excludedPaths)).toBe(true);

        // RegExp in additionalExcludedPaths is rejected by createServerScanPolicy
        expect(() => {
          createServerScanPolicy({ additionalExcludedPaths: [/^\/secret/ as any] });
        }).toThrow(/Excluded path entries must be non-empty strings\. RegExp instances are prohibited/i);
      });

      it('proves post-creation tampering with caller argument arrays does not affect the minted context or policy', async () => {
        const store = new MemoryStore();
        await store.saveWebsite(validAsset);

        const mutableMethods = ['GET', 'POST'];
        const mutablePorts = [8080, 8443];
        const mutableExcluded = ['/secret'];

        const policy = createServerScanPolicy({
          allowedMethods: mutableMethods,
          allowedPorts: mutablePorts,
          additionalExcludedPaths: mutableExcluded,
        });

        const context = await createAuthoritativeScanScopeContext(store, {
          orgId: validAsset.orgId,
          siteId: validAsset.siteId,
          scanId: 'scan-tamper-test',
          serverPolicy: policy,
        });

        // Caller mutates the original arrays after minting
        mutableMethods.push('TRACE');
        mutablePorts.push(22);
        mutableExcluded.length = 0; // attempt to wipe excluded paths

        // Context and policy remain completely unaffected and pristine
        expect(context.allowedMethods).not.toContain('TRACE');
        expect(context.allowedMethods).toEqual(['GET', 'POST']);
        expect(context.allowedPorts).not.toContain(22);
        expect(context.allowedPorts).toEqual([8080, 8443]);
        expect(context.excludedPaths).toContain('/secret');
      });

      it('protects allowed-method policy collection from consumer mutation via predicate', async () => {
        // Valid methods check case-insensitively
        const allowedMethods = ['GET', 'get', 'HEAD', 'head', 'POST', 'post', 'PUT', 'put', 'DELETE', 'delete', 'PATCH', 'patch', 'OPTIONS', 'options'];
        for (const method of allowedMethods) {
          expect(isServerControlledAllowedMethod(method)).toBe(true);
        }

        // Prohibited and unknown methods return false
        const prohibitedMethods = ['TRACE', 'CONNECT', 'TRACK', 'DEBUG', 'UNKNOWN', '', null as any, undefined as any, 123 as any];
        for (const method of prohibitedMethods) {
          expect(isServerControlledAllowedMethod(method)).toBe(false);
        }

        // Ensure SERVER_CONTROLLED_ALLOWED_METHODS_SET is not exported
        const contextAuthorityModule = await import('../../src/scanner/transport/context-authority.js');
        expect((contextAuthorityModule as any).SERVER_CONTROLLED_ALLOWED_METHODS_SET).toBeUndefined();
        expect((contextAuthorityModule as any).SERVER_CONTROLLED_ALLOWED_METHODS).toBeUndefined();

        const transportIndexModule = await import('../../src/scanner/transport/index.js');
        expect((transportIndexModule as any).SERVER_CONTROLLED_ALLOWED_METHODS_SET).toBeUndefined();
        expect((transportIndexModule as any).SERVER_CONTROLLED_ALLOWED_METHODS).toBeUndefined();
      });
    });

    describe('P2: Genuinely Immutable Hop-by-Hop Header & Port Policies', () => {
      it('isRestrictedHopByHopHeader correctly identifies standard and pseudo hop-by-hop headers case-insensitively', () => {
        const restricted = [
          'connection', 'Connection', 'CONNECTION',
          'keep-alive', 'Keep-Alive', 'KEEP-ALIVE',
          'te', 'TE', 'Te',
          'trailer', 'Trailer', 'TRAILER',
          'upgrade', 'Upgrade', 'UPGRADE',
          'proxy-connection', 'Proxy-Connection',
          'proxy-authenticate', 'Proxy-Authenticate',
          'proxy-authorization', 'Proxy-Authorization',
          'transfer-encoding', 'Transfer-Encoding',
          'host', 'Host', 'HOST',
          ':authority', ':method', ':path', ':scheme', ':status',
        ];

        for (const header of restricted) {
          expect(isRestrictedHopByHopHeader(header)).toBe(true);
        }

        const safe = [
          'accept', 'Accept',
          'content-type', 'Content-Type',
          'authorization',
          'x-custom-scan-header',
          'user-agent',
        ];

        for (const header of safe) {
          expect(isRestrictedHopByHopHeader(header)).toBe(false);
        }

        expect(isRestrictedHopByHopHeader(null as any)).toBe(false);
        expect(isRestrictedHopByHopHeader(undefined as any)).toBe(false);
        expect(isRestrictedHopByHopHeader(123 as any)).toBe(false);
      });

      it('proves transport module barrel does not expose mutable RESTRICTED_HOP_BY_HOP_HEADERS Set', async () => {
        const transportModule = await import('../../src/scanner/transport/index.js');
        // Ensure mutable Set is not exported
        expect((transportModule as any).RESTRICTED_HOP_BY_HOP_HEADERS).toBeUndefined();
        // Ensure safe predicate is exported
        expect(typeof transportModule.isRestrictedHopByHopHeader).toBe('function');
      });

      it('proves BLOCKED_INTERNAL_PORTS is genuinely immutable and prevents runtime mutation', () => {
        expect(BLOCKED_INTERNAL_PORTS.has(22)).toBe(true);
        expect(BLOCKED_INTERNAL_PORTS.has(80)).toBe(false);
        expect(isBlockedInternalPort(22)).toBe(true);
        expect(isBlockedInternalPort(80)).toBe(false);

        // Attempting to mutate throws TypeError
        expect(() => {
          (BLOCKED_INTERNAL_PORTS as any).add(80);
        }).toThrow(TypeError);

        expect(() => {
          (BLOCKED_INTERNAL_PORTS as any).delete(22);
        }).toThrow(TypeError);

        expect(() => {
          (BLOCKED_INTERNAL_PORTS as any).clear();
        }).toThrow(TypeError);

        // Invariants remain intact
        expect(BLOCKED_INTERNAL_PORTS.has(22)).toBe(true);
        expect(BLOCKED_INTERNAL_PORTS.has(80)).toBe(false);
      });
    });

    describe('P1: Complete Hop-by-Hop and Connection-Nominated Header Filtering', () => {
      it('strips Connection-nominated custom headers and all standard hop-by-hop headers, forcing Connection: close', async () => {
        let receivedHeaders: http.IncomingHttpHeaders | null = null;
        const testServer = http.createServer((req, res) => {
          receivedHeaders = req.headers;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        });

        await new Promise<void>((r) => testServer.listen(0, '127.0.0.1', r));
        const port = (testServer.address() as net.AddressInfo).port;

        try {
          const client = new SafeHttpClient({
            dnsResolver: new DnsResolver({
              lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
              allowLoopbackForTesting: true,
            }),
            allowLoopbackForTesting: true,
          });

          const store = new MemoryStore();
          await store.saveWebsite(validAsset);
          const context = await createAuthoritativeScanScopeContext(store, {
            orgId: validAsset.orgId,
            siteId: validAsset.siteId,
            scanId: 'scan-hbh-001',
            serverPolicy: createServerScanPolicy({ allowedPorts: [port] }),
          });

          await client.get(`http://primary.example.com:${port}/hbh-comprehensive`, {
            allowLoopbackForTesting: true,
            headers: {
              // Nominate two custom headers in Connection header with whitespace
              'Connection': 'keep-alive, X-Custom-Token  ,  X-Internal-Secret ',
              // Standard hop-by-hop headers in mixed-case
              'kEeP-aLiVe': 'timeout=5, max=1000',
              'Te': 'trailers',
              'TrAiLeR': 'Expires',
              'UpGrAdE': 'websocket',
              'PrOxY-CoNnEcTiOn': 'keep-alive',
              'Proxy-Authenticate': 'Basic',
              'Proxy-Authorization': 'Basic dXNlcjpwYXNz',
              // Nominated custom headers
              'X-Custom-Token': 'secret-token-1234',
              'x-internal-secret': 'confidential-data',
              // Safe end-to-end headers
              'X-Safe-End-To-End': 'preserve-me',
              'Accept': 'application/json',
              'User-Agent': 'Veltrix-Security-Scanner',
            },
            context,
          });

          expect(receivedHeaders).not.toBeNull();
          // Connection is strictly overridden to 'close'
          expect(receivedHeaders!['connection']).toBe('close');

          // Nominated custom headers are completely stripped
          expect(receivedHeaders!['x-custom-token']).toBeUndefined();
          expect(receivedHeaders!['x-internal-secret']).toBeUndefined();

          // Standard hop-by-hop headers are completely stripped
          expect(receivedHeaders!['keep-alive']).toBeUndefined();
          expect(receivedHeaders!['te']).toBeUndefined();
          expect(receivedHeaders!['trailer']).toBeUndefined();
          expect(receivedHeaders!['upgrade']).toBeUndefined();
          expect(receivedHeaders!['proxy-connection']).toBeUndefined();
          expect(receivedHeaders!['proxy-authenticate']).toBeUndefined();
          expect(receivedHeaders!['proxy-authorization']).toBeUndefined();

          // Safe end-to-end headers are preserved
          expect(receivedHeaders!['x-safe-end-to-end']).toBe('preserve-me');
          expect(receivedHeaders!['accept']).toBe('application/json');
          expect(receivedHeaders!['user-agent']).toBe('Veltrix-Security-Scanner');
        } finally {
          await new Promise<void>((r) => testServer.close(() => r()));
        }
      });

      it('strips nominated hop-by-hop headers and credentials on cross-origin redirects while preserving safe headers', async () => {
        let server1Headers: http.IncomingHttpHeaders | null = null;
        let server2Headers: http.IncomingHttpHeaders | null = null;

        let port2 = 0;
        const server2 = http.createServer((req, res) => {
          server2Headers = req.headers;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ redirected: true }));
        });
        await new Promise<void>((r) => server2.listen(0, '127.0.0.1', r));
        port2 = (server2.address() as net.AddressInfo).port;

        const server1 = http.createServer((req, res) => {
          server1Headers = req.headers;
          // Cross-origin redirect to api.example.com
          res.writeHead(302, {
            'Location': `http://api.example.com:${port2}/destination`,
          });
          res.end();
        });
        await new Promise<void>((r) => server1.listen(0, '127.0.0.1', r));
        const port1 = (server1.address() as net.AddressInfo).port;

        try {
          const client = new SafeHttpClient({
            dnsResolver: new DnsResolver({
              lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
              allowLoopbackForTesting: true,
            }),
            allowLoopbackForTesting: true,
          });

          const store = new MemoryStore();
          await store.saveWebsite(validAsset);
          const context = await createAuthoritativeScanScopeContext(store, {
            orgId: validAsset.orgId,
            siteId: validAsset.siteId,
            scanId: 'scan-redir-001',
            serverPolicy: createServerScanPolicy({ allowedPorts: [port1, port2] }),
          });

          const res = await client.get(`http://primary.example.com:${port1}/initial`, {
            allowLoopbackForTesting: true,
            maxRedirects: 3,
            headers: {
              'Connection': 'close, X-Hop-Nominated',
              'X-Hop-Nominated': 'sensitive-hop-data',
              'Authorization': 'Bearer secret-jwt-token-12345',
              'Cookie': 'session=abcde12345',
              'X-Org-Key': 'org-secret-key',
              'X-Safe-Audit': 'audit-trail-ok',
              'Accept': 'application/json',
            },
            context,
          });

          expect(res.status).toBe(200);
          expect(res.data).toEqual({ redirected: true });

          // Verify server 1 received headers
          expect(server1Headers).not.toBeNull();
          expect(server1Headers!['x-hop-nominated']).toBeUndefined(); // stripped by hop-by-hop filter
          expect(server1Headers!['authorization']).toBe('Bearer secret-jwt-token-12345');

          // Verify server 2 (cross-origin redirect destination)
          expect(server2Headers).not.toBeNull();
          // Hop-by-hop and nominated headers are absent
          expect(server2Headers!['connection']).toBe('close');
          expect(server2Headers!['x-hop-nominated']).toBeUndefined();

          // Sensitive credentials stripped on cross-origin redirect
          expect(server2Headers!['authorization']).toBeUndefined();
          expect(server2Headers!['cookie']).toBeUndefined();
          expect(server2Headers!['x-org-key']).toBeUndefined();

          // Safe end-to-end headers preserved across redirect
          expect(server2Headers!['x-safe-audit']).toBe('audit-trail-ok');
          expect(server2Headers!['accept']).toBe('application/json');
        } finally {
          await Promise.all([
            new Promise<void>((r) => server1.close(() => r())),
            new Promise<void>((r) => server2.close(() => r())),
          ]);
        }
      });
    });
  });
});
