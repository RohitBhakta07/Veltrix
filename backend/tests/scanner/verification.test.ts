import { describe, it, expect, beforeEach, beforeAll, afterAll, vi } from 'vitest';
import request from 'supertest';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { createApp } from '../../src/app.js';
import { MemoryStore } from '../../src/storage/memory-store.js';
import { resetStorageForTesting } from '../../src/storage/index.js';
import { JwtService } from '../../src/auth/jwt-service.js';
import { LocalAuthProvider } from '../../src/auth/local-auth-provider.js';
import { resetAuthProviderForTesting } from '../../src/auth/index.js';
import {
  DomainOwnershipVerifier,
  type DnsResolverInterface,
  type HttpFetcherInterface,
  isProhibitedIp,
  isProhibitedIpv4,
} from '../../src/scanner/verification/verifier.js';
import { DnsVerifier } from '../../src/scanner/verification/dns-verifier.js';
import {
  HttpVerifier,
  DefaultHttpFetcher,
  DefaultSocketConnector,
  type AddressResolverInterface,
  type SocketConnectorInterface,
} from '../../src/scanner/verification/http-verifier.js';
import { MetaVerifier } from '../../src/scanner/verification/meta-verifier.js';
import type { WebsiteAsset } from '@veltrix/shared';

describe('Phase 8: Domain Ownership Verification Subsystem (TASK-801)', () => {
  let app: any;
  let storage: MemoryStore;
  let jwtService: JwtService;

  let superAdminToken: string;
  let orgAdminTokenA: string;
  let orgAnalystTokenA: string;
  let orgAdminTokenB: string;
  let auditorTokenA: string;

  // Mock storage for DNS & HTTP fetchers
  const mockDnsRecords = new Map<string, string[][]>();
  const mockHttpResponses = new Map<string, { status: number; data?: unknown; text?: string }>();

  let testHttpServer: http.Server;
  let testHttpsServer: https.Server;
  let testHttpPort: number;
  let testHttpsPort: number;

  const TEST_PFX_BASE64 =
    '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';

  beforeAll(async () => {
    // Start local HTTP server
    testHttpServer = http.createServer((req, res) => {
      if (req.url === '/redirect') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data' });
        res.end();
        return;
      }
      if (req.url === '/redirect-local') {
        res.writeHead(301, { Location: 'http://127.0.0.1/admin' });
        res.end();
        return;
      }
      if (req.url === '/oversized-header') {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Length': '200000',
        });
        res.end('{}');
        return;
      }
      if (req.url === '/oversized-body') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('A'.repeat(150 * 1024));
        return;
      }
      if (req.url === '/slow') {
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ slow: true }));
        }, 1500);
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ veltrixChallengeToken: 'test-tok', orgId: 'test-org' }));
    });

    await new Promise<void>((resolve) => {
      testHttpServer.listen(0, '127.0.0.1', () => {
        testHttpPort = (testHttpServer.address() as net.AddressInfo).port;
        resolve();
      });
    });

    // Start local HTTPS server with self-signed test cert for test.veltrix.local
    testHttpsServer = https.createServer(
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
      testHttpsServer.listen(0, '127.0.0.1', () => {
        testHttpsPort = (testHttpsServer.address() as net.AddressInfo).port;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => testHttpServer.close(() => resolve()));
    await new Promise<void>((resolve) => testHttpsServer.close(() => resolve()));
  });

  const testDnsResolver: DnsResolverInterface = {
    async resolveTxt(host: string): Promise<string[][]> {
      const records = mockDnsRecords.get(host.toLowerCase());
      if (!records) {
        const err = new Error(`ENOTFOUND: Record '${host}' not found.`);
        (err as any).code = 'ENOTFOUND';
        throw err;
      }
      return records;
    },
  };

  const testHttpFetcher: HttpFetcherInterface = {
    async fetch(url: string): Promise<{ status: number; data: unknown; text?: string }> {
      const resp = mockHttpResponses.get(url);
      if (!resp) {
        return { status: 404, data: null, text: 'Not Found' };
      }
      return {
        status: resp.status,
        data: resp.data ?? null,
        text: resp.text ?? (typeof resp.data === 'object' ? JSON.stringify(resp.data) : String(resp.data)),
      };
    },
  };

  beforeEach(async () => {
    jwtService = new JwtService('test-secret-phase-8-verification-key-32chars');
    const localProvider = new LocalAuthProvider(jwtService);
    resetAuthProviderForTesting(localProvider);

    storage = new MemoryStore();
    resetStorageForTesting(storage);

    mockDnsRecords.clear();
    mockHttpResponses.clear();

    app = createApp();

    superAdminToken = jwtService.signAccessToken({
      userId: 'usr-super',
      username: 'super.admin',
      email: 'super@veltrix.io',
      role: 'SUPER_ADMIN',
      orgId: 'org-system',
    });

    orgAdminTokenA = jwtService.signAccessToken({
      userId: 'usr-admin-a',
      username: 'admin.alpha',
      email: 'admin@alpha.org',
      role: 'ORG_ADMIN',
      orgId: 'org-alpha',
    });

    orgAnalystTokenA = jwtService.signAccessToken({
      userId: 'usr-analyst-a',
      username: 'analyst.alpha',
      email: 'analyst@alpha.org',
      role: 'SECURITY_ANALYST',
      orgId: 'org-alpha',
    });

    orgAdminTokenB = jwtService.signAccessToken({
      userId: 'usr-admin-b',
      username: 'admin.beta',
      email: 'admin@beta.org',
      role: 'ORG_ADMIN',
      orgId: 'org-beta',
    });

    auditorTokenA = jwtService.signAccessToken({
      userId: 'usr-auditor-a',
      username: 'auditor.alpha',
      email: 'auditor@alpha.org',
      role: 'AUDITOR',
      orgId: 'org-alpha',
    });
  });

  describe('1. Challenge Generation & Formatting', () => {
    it('generates cryptographic random challenge tokens and multi-channel records', () => {
      const challenge = DomainOwnershipVerifier.generateChallenge('org-alpha', 'portal.alpha.org');

      expect(challenge.token).toMatch(/^vltx_tok_[a-f0-9]{32}$/);
      expect(challenge.tokenHash).toHaveLength(64);

      // DNS TXT structure
      expect(challenge.dnsTxtRecord.host).toBe('_veltrix-challenge.portal.alpha.org');
      expect(challenge.dnsTxtRecord.value).toBe(`veltrix-verify=org-alpha.${challenge.token}`);

      // HTTP challenge structure
      expect(challenge.httpChallenge.url).toBe(
        `https://portal.alpha.org/.well-known/veltrix-challenge/${challenge.token}`
      );
      expect(challenge.httpChallenge.expectedBody.veltrixChallengeToken).toBe(challenge.token);
      expect(challenge.httpChallenge.expectedBody.orgId).toBe('org-alpha');

      // Meta Tag structure
      expect(challenge.metaTag.name).toBe('veltrix-site-verification');
      expect(challenge.metaTag.content).toBe(challenge.token);
      expect(challenge.metaTag.tag).toBe(
        `<meta name="veltrix-site-verification" content="${challenge.token}" />`
      );
    });

    it('persists challenge tokens and metaTag upon website asset registration', async () => {
      const res = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Secure Core Portal',
          primaryDomain: 'core.alpha.org',
          environment: 'PRODUCTION',
          riskTier: 'HIGH',
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.site.status).toBe('PENDING_VERIFICATION');
      expect(res.body.site.scanBlocked).toBe(true);
      expect(res.body.site.verificationToken).toMatch(/^vltx_tok_/);
      expect(res.body.site.metaTag).toBeDefined();
      expect(res.body.site.metaTag.content).toBe(res.body.site.verificationToken);
    });
  });

  describe('2. DNS TXT Verification Engine', () => {
    it('successfully verifies domain ownership via matching DNS TXT record', async () => {
      const verifier = new DomainOwnershipVerifier(storage, { dnsResolver: testDnsResolver });

      const reg = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'DNS Target App',
          primaryDomain: 'dns-target.alpha.org',
        });

      const siteId = reg.body.site.siteId;
      const expectedHost = reg.body.site.dnsTxtRecord.host;
      const expectedValue = reg.body.site.dnsTxtRecord.value;

      // Seed mock DNS record
      mockDnsRecords.set(expectedHost.toLowerCase(), [[expectedValue]]);

      const result = await verifier.verifyDomain('org-alpha', siteId, 'DNS_TXT');

      expect(result.verified).toBe(true);
      expect(result.status).toBe('VERIFIED');
      expect(result.expiresAt).toBeDefined();

      // Verify DB record is updated
      const updatedSite = await storage.getWebsiteById('org-alpha', siteId);
      expect(updatedSite!.status).toBe('VERIFIED');
      expect(updatedSite!.scanBlocked).toBe(false);
      expect(updatedSite!.verifiedMethod).toBe('DNS_TXT');
      expect(updatedSite!.verifiedAt).toBeDefined();
    });

    it('handles multi-chunk DNS TXT records per RFC 1035', async () => {
      const dnsVerifier = new DnsVerifier(testDnsResolver);

      const host = '_veltrix-challenge.multichunk.test';
      const chunk1 = 'veltrix-verify=org-test.';
      const chunk2 = 'vltx_tok_1234567890abcdef1234567890abcdef';
      const expectedFull = chunk1 + chunk2;

      mockDnsRecords.set(host.toLowerCase(), [[chunk1, chunk2]]);

      const result = await dnsVerifier.verify(host, expectedFull);
      expect(result.matched).toBe(true);
      expect(result.recordsFound).toContain(expectedFull);
    });

    it('fails closed when DNS TXT record does not match expected token', async () => {
      const verifier = new DomainOwnershipVerifier(storage, { dnsResolver: testDnsResolver });

      const reg = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Mismatch App',
          primaryDomain: 'mismatch.alpha.org',
        });

      const siteId = reg.body.site.siteId;
      mockDnsRecords.set(reg.body.site.dnsTxtRecord.host.toLowerCase(), [
        ['veltrix-verify=org-alpha.WRONG_TOKEN'],
      ]);

      const result = await verifier.verifyDomain('org-alpha', siteId, 'DNS_TXT');
      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
      expect(result.error?.code).toBe('CHALLENGE_VERIFICATION_FAILED');

      const site = await storage.getWebsiteById('org-alpha', siteId);
      expect(site!.status).toBe('PENDING_VERIFICATION');
      expect(site!.scanBlocked).toBe(true);
    });

    it('handles DNS resolution timeout and non-existent host safely without crashing', async () => {
      const timeoutResolver: DnsResolverInterface = {
        async resolveTxt(): Promise<string[][]> {
          const err = new Error('DNS query timed out');
          (err as any).code = 'ETIMEOUT';
          throw err;
        },
      };

      const verifier = new DomainOwnershipVerifier(storage, { dnsResolver: timeoutResolver });

      const reg = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Timeout App',
          primaryDomain: 'timeout.alpha.org',
        });

      const result = await verifier.verifyDomain('org-alpha', reg.body.site.siteId, 'DNS_TXT');
      expect(result.verified).toBe(false);
      expect(result.error?.message).toContain('timed out');
    });
  });

  describe('3. HTTP Challenge Verification Engine', () => {
    it('successfully verifies domain ownership via HTTP challenge endpoint', async () => {
      const verifier = new DomainOwnershipVerifier(storage, { httpFetcher: testHttpFetcher });

      const reg = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'HTTP Target App',
          primaryDomain: 'http-target.alpha.org',
        });

      const siteId = reg.body.site.siteId;
      const challengeUrl = reg.body.site.httpChallenge.url;
      const expectedBody = reg.body.site.httpChallenge.expectedBody;

      // Seed mock HTTP response
      mockHttpResponses.set(challengeUrl, {
        status: 200,
        data: expectedBody,
      });

      const result = await verifier.verifyDomain('org-alpha', siteId, 'HTTP_CHALLENGE');
      expect(result.verified).toBe(true);
      expect(result.status).toBe('VERIFIED');

      const site = await storage.getWebsiteById('org-alpha', siteId);
      expect(site!.status).toBe('VERIFIED');
      expect(site!.scanBlocked).toBe(false);
      expect(site!.verifiedMethod).toBe('HTTP_CHALLENGE');
    });

    it('rejects HTTP challenge if target returns non-200 or mismatched payload', async () => {
      const verifier = new DomainOwnershipVerifier(storage, { httpFetcher: testHttpFetcher });

      const reg = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'HTTP Error App',
          primaryDomain: 'http-error.alpha.org',
        });

      const siteId = reg.body.site.siteId;
      const challengeUrl = reg.body.site.httpChallenge.url;

      // 404 response
      mockHttpResponses.set(challengeUrl, { status: 404 });
      let result = await verifier.verifyDomain('org-alpha', siteId, 'HTTP_CHALLENGE');
      expect(result.verified).toBe(false);
      expect(result.error?.message).toContain('status 404');

      // 200 but wrong orgId
      mockHttpResponses.set(challengeUrl, {
        status: 200,
        data: { veltrixChallengeToken: reg.body.site.verificationToken, orgId: 'wrong-org' },
      });
      result = await verifier.verifyDomain('org-alpha', siteId, 'HTTP_CHALLENGE');
      expect(result.verified).toBe(false);
      expect(result.error?.message).toContain('did not match expected JSON');
    });
  });

  describe('4. HTML Meta Tag Verification Engine', () => {
    it('successfully verifies domain ownership via <meta name="veltrix-site-verification">', async () => {
      const verifier = new DomainOwnershipVerifier(storage, { httpFetcher: testHttpFetcher });

      const reg = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Meta Target App',
          primaryDomain: 'meta-target.alpha.org',
        });

      const siteId = reg.body.site.siteId;
      const token = reg.body.site.verificationToken;
      const rootUrl = `https://meta-target.alpha.org/`;

      // Seed mock HTML page containing the meta tag
      const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Meta Target</title>
          <meta charset="utf-8" />
          <meta name="veltrix-site-verification" content="${token}" />
        </head>
        <body><h1>Welcome</h1></body>
        </html>
      `;

      mockHttpResponses.set(rootUrl, { status: 200, text: htmlContent });

      const result = await verifier.verifyDomain('org-alpha', siteId, 'META_TAG');
      expect(result.verified).toBe(true);
      expect(result.status).toBe('VERIFIED');

      const site = await storage.getWebsiteById('org-alpha', siteId);
      expect(site!.status).toBe('VERIFIED');
      expect(site!.scanBlocked).toBe(false);
      expect(site!.verifiedMethod).toBe('META_TAG');
    });

    it('supports alternative attribute order and property attribute in meta tag', async () => {
      const metaVerifier = new MetaVerifier(testHttpFetcher);
      const token = 'vltx_tok_11223344556677889900aabbccddeeff';
      const rootUrl = 'https://alt-meta.test/';

      // content before name, using property="veltrix-site-verification"
      const htmlContent = `
        <html><head>
          <meta content="${token}" property="veltrix-site-verification" />
        </head></html>
      `;
      mockHttpResponses.set(rootUrl, { status: 200, text: htmlContent });

      const res = await metaVerifier.verify(rootUrl, token);
      expect(res.matched).toBe(true);
    });

    it('rejects meta tag verification if tag is absent or token does not match', async () => {
      const verifier = new DomainOwnershipVerifier(storage, { httpFetcher: testHttpFetcher });

      const reg = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Missing Meta App',
          primaryDomain: 'missing-meta.alpha.org',
        });

      const siteId = reg.body.site.siteId;
      const rootUrl = `https://missing-meta.alpha.org/`;

      // HTML without verification meta tag
      mockHttpResponses.set(rootUrl, {
        status: 200,
        text: '<html><head><title>No Tag</title></head></html>',
      });

      const result = await verifier.verifyDomain('org-alpha', siteId, 'META_TAG');
      expect(result.verified).toBe(false);
      expect(result.error?.message).toContain('No \'<meta name="veltrix-site-verification"');
    });
  });

  describe('5. Expiry, Grace Period & Scan Authorization Guard (TASK-801 Security Invariants)', () => {
    it('isScanAuthorized strictly blocks unverified, expired, and grace-period sites', async () => {
      const baseSite: WebsiteAsset = {
        siteId: 'site-test-1',
        orgId: 'org-alpha',
        name: 'Test Site',
        primaryDomain: 'auth-test.alpha.org',
        approvedSubdomains: [],
        environment: 'PRODUCTION',
        status: 'PENDING_VERIFICATION',
        riskTier: 'HIGH',
        tags: [],
        verificationToken: 'vltx_tok_123',
        tokenCreatedAt: new Date().toISOString(),
        dnsTxtRecord: { host: '_veltrix.test', value: 'verify' },
        httpChallenge: { url: 'https://test', expectedBody: { veltrixChallengeToken: '123', orgId: 'org-alpha' } },
        scanBlocked: true,
        health: { telemetryStatus: 'HEALTHY', eventsPerMinute: 0 },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      // 1. Pending verification: blocked
      let check = DomainOwnershipVerifier.isScanAuthorized(baseSite);
      expect(check.authorized).toBe(false);
      expect(check.code).toBe('DOMAIN_NOT_VERIFIED');

      // 2. Active Verified: permitted
      const verifiedSite: WebsiteAsset = {
        ...baseSite,
        status: 'VERIFIED',
        scanBlocked: false,
        verifiedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 80 * 24 * 3600 * 1000).toISOString(), // 80 days future
      };
      check = DomainOwnershipVerifier.isScanAuthorized(verifiedSite);
      expect(check.authorized).toBe(true);

      // 3. Grace period (day 83-90): scanBlocked is true, blocked
      const graceSite: WebsiteAsset = {
        ...verifiedSite,
        status: 'GRACE_PERIOD',
        scanBlocked: true,
      };
      check = DomainOwnershipVerifier.isScanAuthorized(graceSite);
      expect(check.authorized).toBe(false);
      expect(check.code).toBe('DOMAIN_VERIFICATION_SUSPENDED');

      // 4. Expired (day 91+): blocked
      const expiredSite: WebsiteAsset = {
        ...verifiedSite,
        status: 'VERIFIED',
        expiresAt: new Date(Date.now() - 1000).toISOString(), // past date
      };
      check = DomainOwnershipVerifier.isScanAuthorized(expiredSite);
      expect(check.authorized).toBe(false);
      expect(check.code).toBe('VERIFICATION_EXPIRED');
    });

    it('enforces automatic expiry transition and logs audit event', async () => {
      const verifier = new DomainOwnershipVerifier(storage);

      const siteId = 'site-expired-auto';
      const expiredAt = new Date(Date.now() - 5000).toISOString();

      await storage.saveWebsite({
        siteId,
        orgId: 'org-alpha',
        name: 'Auto Expire Site',
        primaryDomain: 'auto-expire.alpha.org',
        approvedSubdomains: [],
        environment: 'PRODUCTION',
        status: 'VERIFIED',
        riskTier: 'HIGH',
        tags: [],
        verificationToken: 'vltx_tok_exp',
        tokenCreatedAt: new Date().toISOString(),
        dnsTxtRecord: { host: '_vltx.test', value: 'exp' },
        httpChallenge: { url: 'https://test', expectedBody: { veltrixChallengeToken: 'exp', orgId: 'org-alpha' } },
        scanBlocked: false,
        expiresAt: expiredAt,
        health: { telemetryStatus: 'HEALTHY', eventsPerMinute: 0 },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      const updated = await verifier.checkAndEnforceExpiry('org-alpha', siteId);
      expect(updated!.status).toBe('EXPIRED');
      expect(updated!.scanBlocked).toBe(true);

      // Check scan authorization endpoint
      const res = await request(app)
        .get(`/api/v1/websites/${siteId}/scan-authorization`)
        .set('Authorization', `Bearer ${orgAdminTokenA}`);

      expect(res.status).toBe(200);
      expect(res.body.data.authorized).toBe(false);
      expect(res.body.data.scanBlocked).toBe(true);
    });

    it('revoking verification sets GRACE_PERIOD and immediately freezes scanning (scanBlocked: true)', async () => {
      const verifier = new DomainOwnershipVerifier(storage);

      const siteId = 'site-to-revoke';
      await storage.saveWebsite({
        siteId,
        orgId: 'org-alpha',
        name: 'Revoke Site',
        primaryDomain: 'revoke.alpha.org',
        approvedSubdomains: [],
        environment: 'PRODUCTION',
        status: 'VERIFIED',
        riskTier: 'HIGH',
        tags: [],
        verificationToken: 'vltx_tok_rev',
        tokenCreatedAt: new Date().toISOString(),
        dnsTxtRecord: { host: '_vltx.test', value: 'rev' },
        httpChallenge: { url: 'https://test', expectedBody: { veltrixChallengeToken: 'rev', orgId: 'org-alpha' } },
        scanBlocked: false,
        expiresAt: new Date(Date.now() + 60 * 86400000).toISOString(),
        health: { telemetryStatus: 'HEALTHY', eventsPerMinute: 0 },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      const revoked = await verifier.revokeVerification('org-alpha', siteId, 'Security audit requirement');
      expect(revoked!.status).toBe('GRACE_PERIOD');
      expect(revoked!.scanBlocked).toBe(true);

      const authCheck = DomainOwnershipVerifier.isScanAuthorized(revoked!);
      expect(authCheck.authorized).toBe(false);
      expect(authCheck.code).toBe('DOMAIN_VERIFICATION_SUSPENDED');
    });

    it('allows successful renewal within grace period, resetting 90-day expiry and unblocking scanning', async () => {
      const verifier = new DomainOwnershipVerifier(storage, { dnsResolver: testDnsResolver });

      const siteId = 'site-renewal';
      const token = 'vltx_tok_renew1234567890abcdef123456';
      const host = '_veltrix-challenge.renew.alpha.org';
      const value = `veltrix-verify=org-alpha.${token}`;

      await storage.saveWebsite({
        siteId,
        orgId: 'org-alpha',
        name: 'Renewal Site',
        primaryDomain: 'renew.alpha.org',
        approvedSubdomains: [],
        environment: 'PRODUCTION',
        status: 'GRACE_PERIOD',
        riskTier: 'HIGH',
        tags: [],
        verificationToken: token,
        tokenCreatedAt: new Date().toISOString(),
        dnsTxtRecord: { host, value },
        httpChallenge: { url: 'https://test', expectedBody: { veltrixChallengeToken: token, orgId: 'org-alpha' } },
        scanBlocked: true,
        health: { telemetryStatus: 'HEALTHY', eventsPerMinute: 0 },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      // Seed valid DNS record for renewal
      mockDnsRecords.set(host.toLowerCase(), [[value]]);

      const renewResult = await verifier.verifyDomain('org-alpha', siteId, 'DNS_TXT');
      expect(renewResult.verified).toBe(true);
      expect(renewResult.status).toBe('VERIFIED');

      const site = await storage.getWebsiteById('org-alpha', siteId);
      expect(site!.status).toBe('VERIFIED');
      expect(site!.scanBlocked).toBe(false);

      const authCheck = DomainOwnershipVerifier.isScanAuthorized(site!);
      expect(authCheck.authorized).toBe(true);
    });
  });

  describe('6. SSRF Protection & Malicious IP Normalization', () => {
    it('rejects all forms of private, loopback, link-local, and cloud metadata IPs', () => {
      // Loopback variants
      expect(isProhibitedIp('127.0.0.1')).toBe(true);
      expect(isProhibitedIp('127.127.127.127')).toBe(true);
      expect(isProhibitedIp('0177.0.0.1')).toBe(true); // octal
      expect(isProhibitedIp('0x7f.0.0.1')).toBe(true); // hex
      expect(isProhibitedIp('2130706433')).toBe(true); // dword
      expect(isProhibitedIp('127.1')).toBe(true); // zero-compressed

      // Private RFC 1918
      expect(isProhibitedIp('10.0.0.1')).toBe(true);
      expect(isProhibitedIp('172.16.0.1')).toBe(true);
      expect(isProhibitedIp('192.168.1.1')).toBe(true);

      // Cloud Metadata & CGNAT
      expect(isProhibitedIp('169.254.169.254')).toBe(true);
      expect(isProhibitedIp('100.64.0.1')).toBe(true);

      // Positive IPv6 Global-Unicast Policy (RFC 4291 section 2.4): addresses outside 2000::/3 are rejected by default
      expect(isProhibitedIp('4000::1')).toBe(true); // outside 2000::/3 (unallocated)
      expect(isProhibitedIp('fe00::1')).toBe(true); // outside 2000::/3 (reserved)
      expect(isProhibitedIp('f000::1')).toBe(true); // outside 2000::/3 (reserved)

      // Deprecated IPv4-compatible IPv6 (::0:0/96, RFC 4291 section 2.5.5.1) - strictly prohibited
      expect(isProhibitedIp('::8.8.8.8')).toBe(true); // IPv4-compatible deprecated
      expect(isProhibitedIp('::127.0.0.1')).toBe(true);
      expect(isProhibitedIp('::10.0.0.1')).toBe(true);
      expect(isProhibitedIp('::93.184.216.34')).toBe(true);

      // IPv4-mapped IPv6 (::ffff:0:0/96, RFC 4291 / RFC 6890 Table 20 non-global)
      expect(isProhibitedIp('::ffff:127.0.0.1')).toBe(true);
      expect(isProhibitedIp('::ffff:10.0.0.1')).toBe(true);
      expect(isProhibitedIp('::ffff:169.254.169.254')).toBe(true);
      expect(isProhibitedIp('::ffff:93.184.216.34')).toBe(true);

      // IPv6 Loopback, Unspecified, ULA, Link-Local, Site-Local, and IMDSv6
      expect(isProhibitedIp('::1')).toBe(true);
      expect(isProhibitedIp('::')).toBe(true);
      expect(isProhibitedIp('0:0:0:0:0:0:0:1')).toBe(true);
      expect(isProhibitedIp('fe80::1')).toBe(true);
      expect(isProhibitedIp('febf::ffff')).toBe(true);
      expect(isProhibitedIp('fec0::1')).toBe(true);
      expect(isProhibitedIp('fc00::1')).toBe(true);
      expect(isProhibitedIp('fd00::1')).toBe(true);
      expect(isProhibitedIp('fd00:ec2::254')).toBe(true);

      // SIIT (::ffff:0:0:0/96, RFC 7915 / RFC 2765)
      expect(isProhibitedIp('::ffff:0:127.0.0.1')).toBe(true);
      expect(isProhibitedIp('::ffff:0:93.184.216.34')).toBe(true);
      expect(isProhibitedIp('0:0:0:0:ffff:0:a00:1')).toBe(true);

      // 6to4 (2002::/16, RFC 3056) - checks embedded IPv4 bytes 2..5
      expect(isProhibitedIp('2002:7f00:0001::')).toBe(true); // embedded 127.0.0.1
      expect(isProhibitedIp('2002:0a00:0001::')).toBe(true); // embedded 10.0.0.1
      expect(isProhibitedIp('2002:c0a8:0101::')).toBe(true); // embedded 192.168.1.1
      expect(isProhibitedIp('2002:a9fe:a9fe::')).toBe(true); // embedded 169.254.169.254 (IMDS)
      expect(isProhibitedIp('2002:5db8:d822::1')).toBe(false); // embedded public 93.184.216.34 allowed

      // Teredo (2001::/32, RFC 4380)
      expect(isProhibitedIp('2001:0000:4136:e378:8000:63bf:3fff:fdd2')).toBe(true);
      expect(isProhibitedIp('2001::1')).toBe(true);

      // IETF Special-Purpose (2001::/23, RFC 6890)
      expect(isProhibitedIp('2001:2::1')).toBe(true); // BMWG Benchmarking (RFC 5180)
      expect(isProhibitedIp('2001:3::1')).toBe(true); // AMT (RFC 7450)
      expect(isProhibitedIp('2001:4:112::1')).toBe(true); // AS112-v6 (RFC 7535)
      expect(isProhibitedIp('2001:10::1')).toBe(true); // ORCHID (RFC 4843)
      expect(isProhibitedIp('2001:20::1')).toBe(true); // ORCHIDv2 (RFC 7343)
      expect(isProhibitedIp('2001:30::1')).toBe(true); // Drone ID DETs (RFC 9374)
      expect(isProhibitedIp('2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff')).toBe(true); // Top of 2001::/23

      // Documentation (2001:db8::/32 and 3fff::/20)
      expect(isProhibitedIp('2001:db8::1')).toBe(true);
      expect(isProhibitedIp('3fff::1')).toBe(true);

      // NAT64 (64:ff9b::/96 and 64:ff9b:1::/48)
      expect(isProhibitedIp('64:ff9b::192.168.1.1')).toBe(true);
      expect(isProhibitedIp('64:ff9b:1::1')).toBe(true);

      // Discard-only (100::/64)
      expect(isProhibitedIp('100::1')).toBe(true);

      // Multicast (ff00::/8)
      expect(isProhibitedIp('ff02::1')).toBe(true);
      expect(isProhibitedIp('ff05::2')).toBe(true);

      // Strict IPv6 Syntax Validation (RFC 4291 / RFC 5952)
      // When '::' is present, it must compress at least one 16-bit zero hextet (missing >= 1)
      expect(isProhibitedIp('2001:4860:1:2:3:4:5:6::')).toBe(true); // 8 hextets plus '::' (0 compressed) -> rejected
      expect(isProhibitedIp('::2001:4860:1:2:3:4:5:6')).toBe(true); // leading '::' with 8 hextets -> rejected
      expect(isProhibitedIp('2001:4860:1:2::3:4:5:6')).toBe(true); // middle '::' with 8 hextets -> rejected

      // Valid compressed & fully expanded global unicast IPv6 addresses (allowed)
      expect(isProhibitedIp('2001:4860::1')).toBe(false); // valid compressed
      expect(isProhibitedIp('2001:4860:0:0:0:0:0:1')).toBe(false); // valid fully expanded (8 hextets, no '::')
      expect(isProhibitedIp('2001:4860:0001:0002:0003:0004:0005:0006')).toBe(false); // valid fully expanded

      // Zone identifiers (%interface, RFC 4007 / RFC 6874) - rejected rather than silently stripped
      expect(isProhibitedIp('fe80::1%eth0')).toBe(true); // link-local with zone ID rejected
      expect(isProhibitedIp('2001:4860::1%1')).toBe(true); // global unicast with zone ID rejected
      expect(isProhibitedIp('[fe80::1%eth0]')).toBe(true); // bracketed with zone ID rejected

      // Legitimate Public IPv4 & IPv6: allowed
      expect(isProhibitedIp('93.184.216.34')).toBe(false);
      expect(isProhibitedIp('2606:4700:4700::1111')).toBe(false); // Cloudflare Public DNS
      expect(isProhibitedIp('2001:4860:4860::8888')).toBe(false); // Google Public DNS
      expect(isProhibitedIp('2600:9000:21a2:b200:1a:8b67:9c00:93a1')).toBe(false); // AWS CloudFront
      expect(isProhibitedIp('2606:2800:220:1:248:1893:25c8:1946')).toBe(false); // Example.com

      // Malformed IPv6 fails closed
      expect(isProhibitedIp(':::1')).toBe(true);
      expect(isProhibitedIp('2001:xyz::1')).toBe(true);
      expect(isProhibitedIp('1:2:3:4:5:6:7:8:9')).toBe(true);
      expect(isProhibitedIp(':2001:4860::1')).toBe(true);
      expect(isProhibitedIp('2001:4860::1:')).toBe(true);
      expect(isProhibitedIp('')).toBe(true);
      expect(isProhibitedIp('   ')).toBe(true);
    });

    it('independently verifies isProhibitedIp() without URL parsing or HTTP wrapping', () => {
      // Direct functional verification of exported isProhibitedIp()
      // 1. Strict parser regression cases
      expect(isProhibitedIp('2001:4860:1:2:3:4:5:6::')).toBe(true);
      expect(isProhibitedIp('2001:4860::1')).toBe(false);
      expect(isProhibitedIp('2001:4860:0:0:0:0:0:1')).toBe(false);
      expect(isProhibitedIp('::8.8.8.8')).toBe(true);

      // 2. Zone identifiers must be rejected, never stripped
      expect(isProhibitedIp('fe80::1%en0')).toBe(true);
      expect(isProhibitedIp('2001:4860::1%eth0')).toBe(true);

      // 3. Positive IPv6 Global-Unicast Policy (2000::/3)
      expect(isProhibitedIp('4000::1')).toBe(true);
      expect(isProhibitedIp('fe00::1')).toBe(true);
      expect(isProhibitedIp('f000::1')).toBe(true);
      expect(isProhibitedIp('3fff::1')).toBe(true); // documentation in 2000::/3
      expect(isProhibitedIp('2001:db8::1')).toBe(true); // documentation in 2000::/3
      expect(isProhibitedIp('2001:2::1')).toBe(true); // BMWG in 2000::/3

      // 4. Legitimate public IPv6 global unicast allowed
      expect(isProhibitedIp('2606:4700:4700::1111')).toBe(false);
      expect(isProhibitedIp('2001:4860:4860::8888')).toBe(false);

      // 5. 6to4 policy: public IPv4 allowed, private/loopback/IMDS prohibited
      expect(isProhibitedIp('2002:5db8:d822::1')).toBe(false); // embedded public 93.184.216.34
      expect(isProhibitedIp('2002:7f00:0001::')).toBe(true); // embedded 127.0.0.1
      expect(isProhibitedIp('2002:a9fe:a9fe::')).toBe(true); // embedded 169.254.169.254
      expect(isProhibitedIp('2002:0a00:0001::')).toBe(true); // embedded 10.0.0.1
    });
  });

  describe('7. RBAC & Cross-Tenant Security', () => {
    it('SUPER_ADMIN can verify any website; SECURITY_ANALYST is blocked', async () => {
      const reg = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'RBAC Target App',
          primaryDomain: 'rbac-target.alpha.org',
        });

      const siteId = reg.body.site.siteId;

      // SECURITY_ANALYST cannot verify
      const analystRes = await request(app)
        .post(`/api/v1/websites/${siteId}/verify`)
        .set('Authorization', `Bearer ${orgAnalystTokenA}`)
        .send({ method: 'DNS_TXT' });
      expect(analystRes.status).toBe(403);

      // SUPER_ADMIN is permitted (returns 400 because DNS record not seeded, but not 403)
      const superRes = await request(app)
        .post(`/api/v1/websites/${siteId}/verify`)
        .set('Authorization', `Bearer ${superAdminToken}`)
        .send({ method: 'DNS_TXT' });
      expect(superRes.status).not.toBe(403);
    });

    it('strictly isolates websites between tenants', async () => {
      const regA = await request(app)
        .post('/api/v1/websites')
        .set('Authorization', `Bearer ${orgAdminTokenA}`)
        .send({
          name: 'Tenant A App',
          primaryDomain: 'app.alpha.org',
        });

      const siteIdA = regA.body.site.siteId;

      // Tenant B attempting to verify Tenant A's website gets 404
      const resB = await request(app)
        .post(`/api/v1/websites/${siteIdA}/verify`)
        .set('Authorization', `Bearer ${orgAdminTokenB}`)
        .send({ method: 'DNS_TXT' });
      expect(resB.status).toBe(404);
    });
  });

  describe('8. DefaultHttpFetcher Connection-Level IP Pinning & SSRF Remediation (PR #15 Security Remediation)', () => {
    it('real socket destination verification: connects directly to controlled local TCP server without connector redirection, verifying live socket remoteAddress, remotePort, and single DNS lookup', async () => {
      // 1. Controlled local TCP/HTTP server
      let serverReceivedConnection = false;
      let serverClientRemoteAddress = '';
      const localServer = http.createServer((req, res) => {
        serverReceivedConnection = true;
        serverClientRemoteAddress = req.socket.remoteAddress || '';
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ veltrixChallengeToken: 'real-socket-tok', orgId: 'org-alpha' }));
      });

      let localPort = 0;
      await new Promise<void>((resolve) => {
        localServer.listen(0, '127.0.0.1', () => {
          localPort = (localServer.address() as net.AddressInfo).port;
          resolve();
        });
      });

      try {
        // 2. Track DNS lookups to verify exactly one lookup occurs between validation and connection
        let lookupCount = 0;
        const trackingResolver: AddressResolverInterface = {
          async lookup(hostname: string) {
            lookupCount++;
            return [{ address: '127.0.0.1', family: 4 }];
          },
        };

        // 3. Spy on DefaultSocketConnector.prototype.connect to verify connector parameters without redirecting
        const connectSpy = vi.spyOn(DefaultSocketConnector.prototype, 'connect');

        let liveSocketRemoteAddress = '';
        let liveSocketRemotePort = 0;

        // 4. Instantiate DefaultHttpFetcher without mockConnector (uses real DefaultSocketConnector)
        const fetcher = new DefaultHttpFetcher({
          addressResolver: trackingResolver,
          allowLoopbackForTesting: true,
          onSocketConnected(info) {
            liveSocketRemoteAddress = info.remoteAddress;
            liveSocketRemotePort = info.remotePort;
          },
        });

        const targetUrl = `http://real-target.alpha.org:${localPort}/.well-known/veltrix-challenge/real-socket-tok`;
        const res = await fetcher.fetch(targetUrl);

        // Verification assertions:
        expect(res.status).toBe(200);
        expect((res.data as any)?.veltrixChallengeToken).toBe('real-socket-tok');

        // Verify that connector received the exact validated IP and port
        expect(connectSpy).toHaveBeenCalledWith({
          host: '127.0.0.1',
          port: localPort,
        });

        // Verify the actual connected live socket's remoteAddress and remotePort (NOT mocked)
        expect(liveSocketRemoteAddress).toBe('127.0.0.1');
        expect(liveSocketRemotePort).toBe(localPort);
        expect(res.remoteAddress).toBe('127.0.0.1');

        // Verify server-side receipt from client
        expect(serverReceivedConnection).toBe(true);
        expect(serverClientRemoteAddress).toBe('127.0.0.1');

        // Verify no second DNS lookup occurred between validation and connection
        expect(lookupCount).toBe(1);

        connectSpy.mockRestore();
      } finally {
        await new Promise<void>((resolve) => localServer.close(() => resolve()));
      }
    });

    it('mock connector parameter verification: proves DefaultHttpFetcher passes the exact pinned IP and target port to the socket connector', async () => {
      let connectorHostArg = '';
      let connectorPortArg = 0;
      const mockConnector: SocketConnectorInterface = {
        connect(options) {
          connectorHostArg = options.host;
          connectorPortArg = options.port;
          // In this unit test of connector dispatch parameters, the socket is redirected
          // to our test server to avoid connecting to public IP 104.20.23.154.
          return net.connect({ host: '127.0.0.1', port: testHttpPort });
        },
        connectTls(options) {
          return tls.connect(options);
        },
      };

      const safeResolver: AddressResolverInterface = {
        async lookup() {
          return [{ address: '104.20.23.154', family: 4 }];
        },
      };

      const fetcher = new DefaultHttpFetcher({
        addressResolver: safeResolver,
        socketConnector: mockConnector,
      });

      const res = await fetcher.fetch('http://verified.domain.com/test');
      expect(res.status).toBe(200);

      // Verify connector parameter assertions (distinguished from real socket tests)
      expect(connectorHostArg).toBe('104.20.23.154');
      expect(connectorPortArg).toBe(80);
    });

    it('prevents DNS rebinding: pins validated safe IP on single lookup and never connects to rebound private IP', async () => {
      let lookupCount = 0;
      const rebindResolver: AddressResolverInterface = {
        async lookup(hostname: string) {
          lookupCount++;
          if (lookupCount === 1) {
            // First lookup during validation returns a valid public IP
            return [{ address: '93.184.216.34', family: 4 }];
          }
          // Subsequent lookup returns malicious internal cloud metadata IP
          return [{ address: '169.254.169.254', family: 4 }];
        },
      };

      let connectedHost = '';
      const mockConnector: SocketConnectorInterface = {
        connect(options) {
          connectedHost = options.host;
          // Mock connector redirecting to local test server
          return net.connect({ host: '127.0.0.1', port: testHttpPort });
        },
        connectTls(options) {
          return tls.connect(options);
        },
      };

      const fetcher = new DefaultHttpFetcher({
        addressResolver: rebindResolver,
        socketConnector: mockConnector,
      });

      const res = await fetcher.fetch('http://rebind.attacker.org/test');
      expect(res.status).toBe(200);

      // Invariant: The connection MUST connect only to the validated pinned IP (93.184.216.34)
      expect(connectedHost).toBe('93.184.216.34');
      expect(connectedHost).not.toBe('169.254.169.254');
      // Proves no second DNS lookup occurred
      expect(lookupCount).toBe(1);
    });

    it('rejects destination if any resolved address is prohibited (fails closed on multi-IP resolution)', async () => {
      const multiResolver: AddressResolverInterface = {
        async lookup() {
          return [
            { address: '93.184.216.34', family: 4 }, // Safe public IP
            { address: '10.0.0.1', family: 4 },       // Prohibited RFC 1918 address
          ];
        },
      };

      const fetcher = new DefaultHttpFetcher({ addressResolver: multiResolver });

      await expect(fetcher.fetch('http://multi-ip.attacker.org/test')).rejects.toThrow(
        "SSRF blocked: Host 'multi-ip.attacker.org' resolved to prohibited IP address '10.0.0.1'."
      );
    });

    it('fails closed when DNS resolution returns an empty address list', async () => {
      const emptyResolver: AddressResolverInterface = {
        async lookup() {
          return [];
        },
      };

      const fetcher = new DefaultHttpFetcher({ addressResolver: emptyResolver });

      await expect(fetcher.fetch('http://empty.attacker.org/test')).rejects.toThrow(
        "DNS resolution returned no addresses for verification target 'empty.attacker.org'."
      );
    });

    it('fails closed on DNS timeout in both development and production', async () => {
      const timeoutResolver: AddressResolverInterface = {
        async lookup() {
          await new Promise((r) => setTimeout(r, 100));
          throw new Error('ETIMEDOUT: DNS query timed out');
        },
      };

      const fetcher = new DefaultHttpFetcher({ addressResolver: timeoutResolver });

      // Development / test environment
      await expect(fetcher.fetch('http://timeout.attacker.org/test', { timeoutMs: 50 })).rejects.toThrow(
        "DNS resolution failed for verification target 'timeout.attacker.org'"
      );

      // Production environment
      const origEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        await expect(fetcher.fetch('http://timeout.attacker.org/test', { timeoutMs: 50 })).rejects.toThrow(
          "DNS resolution failed for verification target 'timeout.attacker.org'"
        );
      } finally {
        process.env.NODE_ENV = origEnv;
      }
    });

    it('fails closed on DNS resolver failure in both development and production', async () => {
      const notFoundResolver: AddressResolverInterface = {
        async lookup() {
          const err = new Error('getaddrinfo ENOTFOUND nonexistent.domain');
          (err as any).code = 'ENOTFOUND';
          throw err;
        },
      };

      const fetcher = new DefaultHttpFetcher({ addressResolver: notFoundResolver });

      // Test environment
      await expect(fetcher.fetch('http://nonexistent.domain/test')).rejects.toThrow(
        "DNS resolution failed for verification target 'nonexistent.domain'"
      );

      // Production environment
      const origEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        await expect(fetcher.fetch('http://nonexistent.domain/test')).rejects.toThrow(
          "DNS resolution failed for verification target 'nonexistent.domain'"
        );
      } finally {
        process.env.NODE_ENV = origEnv;
      }
    });

    it('strictly blocks all prohibited IPv4 and IPv6 destinations (literal hostnames and resolved addresses)', async () => {
      const fetcher = new DefaultHttpFetcher();

      const prohibitedTargets = [
        // IPv4 loopback & unusual numeric forms
        'http://127.0.0.1/test',
        'http://127.1/test',
        'http://0177.0.0.1/test',
        'http://0x7f.0.0.1/test',
        'http://2130706433/test',
        'http://0x7f000001/test',
        // RFC 1918
        'http://10.0.0.1/test',
        'http://172.16.0.1/test',
        'http://192.168.1.1/test',
        // Cloud Metadata & CGNAT
        'http://169.254.169.254/latest/meta-data',
        'http://100.64.0.1/test',
        // IPv6 Loopback, ULA, Link-Local, and IMDSv6
        'http://[::1]/test',
        'http://[::]/test',
        'http://[fe80::1]/test',
        'http://[febf::ffff]/test',
        'http://[fec0::1]/test',
        'http://[fc00::1]/test',
        'http://[fd00::1]/test',
        'http://[fd00:ec2::254]/latest/meta-data',
        'http://[::ffff:127.0.0.1]/test',
        'http://[::ffff:169.254.169.254]/test',
        'http://[::ffff:93.184.216.34]/test',
        'http://[::127.0.0.1]/test',
        'http://[::8.8.8.8]/test',
        // Outside 2000::/3 (Positive Global-Unicast Policy)
        'http://[4000::1]/test',
        'http://[fe00::1]/test',
        'http://[f000::1]/test',
        // SIIT
        'http://[::ffff:0:127.0.0.1]/test',
        'http://[::ffff:0:169.254.169.254]/test',
        // 6to4 with private/loopback/IMDS
        'http://[2002:7f00:0001::]/test',
        'http://[2002:0a00:0001::]/test',
        'http://[2002:a9fe:a9fe::]/test',
        // Teredo & IETF Special-Purpose
        'http://[2001::1]/test',
        'http://[2001:2::1]/test',
        'http://[2001:10::1]/test',
        'http://[2001:20::1]/test',
        'http://[2001:30::1]/test',
        'http://[2001:db8::1]/test',
        'http://[3fff::1]/test',
        // NAT64 & Discard
        'http://[64:ff9b::192.168.1.1]/test',
        'http://[64:ff9b:1::1]/test',
        'http://[100::1]/test',
        // Multicast
        'http://[ff02::1]/test',
        // Prohibited literal hosts
        'http://localhost/test',
        'http://internal-service.local/test',
        'http://metadata.google.internal/test',
      ];

      for (const target of prohibitedTargets) {
        await expect(fetcher.fetch(target)).rejects.toThrow(/SSRF blocked/);
      }
    });

    it('blocks DNS resolution resolving to malformed IPv6 representations, zero-compression, or zone IDs', async () => {
      const malformedCases = [
        '2001:4860:1:2:3:4:5:6::', // 0 hextets compressed with ::
        'fe80::1%eth0',             // zone identifier
        '2001:xyz::1',              // malformed hex
      ];

      for (const badAddress of malformedCases) {
        const badResolver: AddressResolverInterface = {
          async lookup() {
            return [{ address: badAddress, family: 6 }];
          },
        };
        const fetcher = new DefaultHttpFetcher({ addressResolver: badResolver });
        await expect(fetcher.fetch('http://attacker-controlled.domain/test')).rejects.toThrow(/SSRF blocked/);
      }
    });

    it('enforces TLS SNI and rejects untrusted / self-signed certificates with rejectUnauthorized: true', async () => {
      const mockConnector: SocketConnectorInterface = {
        connect(options) {
          return net.connect({ host: '127.0.0.1', port: testHttpsPort });
        },
        connectTls(options) {
          return tls.connect(options);
        },
      };

      const safeResolver: AddressResolverInterface = {
        async lookup() {
          return [{ address: '93.184.216.34', family: 4 }];
        },
      };

      const fetcher = new DefaultHttpFetcher({
        addressResolver: safeResolver,
        socketConnector: mockConnector,
      });

      // Self-signed certificate must fail verification closed
      await expect(fetcher.fetch('https://test.veltrix.org/test')).rejects.toThrow(
        /self-signed certificate/i
      );
    });

    it('strictly blocks HTTP redirect attempts to internal destinations without making follow-up connections', async () => {
      const safeResolver: AddressResolverInterface = {
        async lookup() {
          return [{ address: '93.184.216.34', family: 4 }];
        },
      };

      const mockConnector: SocketConnectorInterface = {
        connect(options) {
          return net.connect({ host: '127.0.0.1', port: testHttpPort });
        },
        connectTls(options) {
          return tls.connect(options);
        },
      };

      const fetcher = new DefaultHttpFetcher({
        addressResolver: safeResolver,
        socketConnector: mockConnector,
      });

      // Redirect to AWS IMDS
      await expect(fetcher.fetch('http://safe.example.com/redirect')).rejects.toThrow(
        "HTTP redirect to 'http://169.254.169.254/latest/meta-data' blocked. Redirects are disabled for domain verification."
      );

      // Redirect to localhost
      await expect(fetcher.fetch('http://safe.example.com/redirect-local')).rejects.toThrow(
        "HTTP redirect to 'http://127.0.0.1/admin' blocked. Redirects are disabled for domain verification."
      );
    });

    it('ambient HTTP_PROXY and HTTPS_PROXY environment variables cannot bypass pinned connection', async () => {
      const origHttpProxy = process.env.HTTP_PROXY;
      const origHttpsProxy = process.env.HTTPS_PROXY;

      try {
        process.env.HTTP_PROXY = 'http://127.0.0.1:9999';
        process.env.HTTPS_PROXY = 'http://127.0.0.1:9999';

        let connectedHost = '';
        let connectedPort = 0;
        const mockConnector: SocketConnectorInterface = {
          connect(options) {
            connectedHost = options.host;
            connectedPort = options.port;
            return net.connect({ host: '127.0.0.1', port: testHttpPort });
          },
          connectTls(options) {
            return tls.connect(options);
          },
        };

        const safeResolver: AddressResolverInterface = {
          async lookup() {
            return [{ address: '93.184.216.34', family: 4 }];
          },
        };

        const fetcher = new DefaultHttpFetcher({
          addressResolver: safeResolver,
          socketConnector: mockConnector,
        });

        const res = await fetcher.fetch('http://safe.example.com/test');
        expect(res.status).toBe(200);

        // Confirm connection was made directly to pinned IP (93.184.216.34:80), NOT to proxy port 9999
        expect(connectedHost).toBe('93.184.216.34');
        expect(connectedPort).toBe(80);
        expect(connectedPort).not.toBe(9999);
      } finally {
        if (origHttpProxy === undefined) delete process.env.HTTP_PROXY;
        else process.env.HTTP_PROXY = origHttpProxy;
        if (origHttpsProxy === undefined) delete process.env.HTTPS_PROXY;
        else process.env.HTTPS_PROXY = origHttpsProxy;
      }
    });

    it('rejects responses exceeding 128KB limit via Content-Length or streaming data', async () => {
      const safeResolver: AddressResolverInterface = {
        async lookup() {
          return [{ address: '93.184.216.34', family: 4 }];
        },
      };

      const mockConnector: SocketConnectorInterface = {
        connect(options) {
          return net.connect({ host: '127.0.0.1', port: testHttpPort });
        },
        connectTls(options) {
          return tls.connect(options);
        },
      };

      const fetcher = new DefaultHttpFetcher({
        addressResolver: safeResolver,
        socketConnector: mockConnector,
      });

      // 1. Content-Length header > 128KB
      await expect(fetcher.fetch('http://safe.example.com/oversized-header')).rejects.toThrow(
        "Verification response exceeded maximum allowed size of 128KB (200000 bytes)."
      );

      // 2. Stream chunk accumulation > 128KB
      await expect(fetcher.fetch('http://safe.example.com/oversized-body')).rejects.toThrow(
        "Verification response exceeded maximum allowed size of 128KB."
      );
    });

    it('strictly aborts requests exceeding configured timeout', async () => {
      const safeResolver: AddressResolverInterface = {
        async lookup() {
          return [{ address: '93.184.216.34', family: 4 }];
        },
      };

      const mockConnector: SocketConnectorInterface = {
        connect(options) {
          return net.connect({ host: '127.0.0.1', port: testHttpPort });
        },
        connectTls(options) {
          return tls.connect(options);
        },
      };

      const fetcher = new DefaultHttpFetcher({
        addressResolver: safeResolver,
        socketConnector: mockConnector,
      });

      await expect(fetcher.fetch('http://safe.example.com/slow', { timeoutMs: 100 })).rejects.toThrow(
        "Verification request timed out after 100ms."
      );
    });

    it('permits legitimate public IPv4 and IPv6 destinations during resolution and connection', async () => {
      const publicTargets = [
        { host: 'public-v4.example.com', ip: '93.184.216.34', family: 4 },
        { host: 'cloudflare-v6.example.com', ip: '2606:4700:4700::1111', family: 6 },
        { host: 'google-v6.example.com', ip: '2001:4860:4860::8888', family: 6 },
        { host: 'aws-v6.example.com', ip: '2600:9000:21a2:b200:1a:8b67:9c00:93a1', family: 6 },
        { host: '6to4-public.example.com', ip: '2002:5db8:d822::1', family: 6 },
      ];

      for (const target of publicTargets) {
        let connectedHost = '';
        const resolver: AddressResolverInterface = {
          async lookup() {
            return [{ address: target.ip, family: target.family }];
          },
        };

        const mockConnector: SocketConnectorInterface = {
          connect(options) {
            connectedHost = options.host;
            // Unit test assertion on connector parameter dispatch; redirect to local test server
            return net.connect({ host: '127.0.0.1', port: testHttpPort });
          },
          connectTls(options) {
            return tls.connect(options);
          },
        };

        const fetcher = new DefaultHttpFetcher({
          addressResolver: resolver,
          socketConnector: mockConnector,
        });

        const res = await fetcher.fetch(`http://${target.host}/test`);
        expect(res.status).toBe(200);
        expect(connectedHost).toBe(target.ip);
      }
    });

    it('throws FATAL_SECURITY_ERROR when custom socket connector or allowLoopbackForTesting is passed in production', () => {
      const origEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        const dummyConnector: SocketConnectorInterface = {
          connect: () => ({} as any),
          connectTls: () => ({} as any),
        };
        expect(() => new DefaultHttpFetcher({ socketConnector: dummyConnector })).toThrow(
          'FATAL_SECURITY_ERROR: Custom socket connectors and test loopback options are prohibited in production.'
        );
        expect(() => new DefaultHttpFetcher({ allowLoopbackForTesting: true })).toThrow(
          'FATAL_SECURITY_ERROR: Custom socket connectors and test loopback options are prohibited in production.'
        );
      } finally {
        process.env.NODE_ENV = origEnv;
      }
    });
  });
});
