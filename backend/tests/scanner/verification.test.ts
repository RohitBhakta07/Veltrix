import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
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
import { HttpVerifier } from '../../src/scanner/verification/http-verifier.js';
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

      // IPv6 Loopback, ULA, Link-Local, and IMDSv6
      expect(isProhibitedIp('::1')).toBe(true);
      expect(isProhibitedIp('::')).toBe(true);
      expect(isProhibitedIp('fe80::1')).toBe(true);
      expect(isProhibitedIp('fc00::1')).toBe(true);
      expect(isProhibitedIp('fd00:ec2::254')).toBe(true);
      expect(isProhibitedIp('::ffff:127.0.0.1')).toBe(true);
      expect(isProhibitedIp('::ffff:169.254.169.254')).toBe(true);

      // Valid Public IPs: allowed
      expect(isProhibitedIp('93.184.216.34')).toBe(false);
      expect(isProhibitedIp('2606:2800:220:1:248:1893:25c8:1946')).toBe(false);
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
});
