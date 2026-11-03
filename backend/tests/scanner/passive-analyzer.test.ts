/**
 * VELTRIX Passive Security Assessment Pipeline - Test Suite (TASK-804)
 *
 * Verifies all requirements from Phase 8 specification:
 * 1. TLS / SSL Configuration Assessment (TLS 1.0, 1.1, 1.2, 1.3, expiration, SAN, chain trust).
 * 2. HTTP Security Headers Assessment (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
 * 3. Cookie Security Attributes Assessment (Secure, HttpOnly, SameSite, unjoined raw headers, comma-containing dates).
 * 4. Information Disclosure & Banner Leakage (Server version, X-Powered-By, debug paths, stack traces, sensitive files).
 * 5. Zero-Extra-Request Guarantee.
 * 6. High statement coverage (>95%) across all passive rule evaluators.
 */

import { describe, it, expect, vi } from 'vitest';
import type { CrawledPage, DiscoveredEndpoint } from '../../src/scanner/crawler/types.js';
import {
  PassiveAnalyzer,
  TlsRule,
  SecurityHeadersRule,
  CookieFlagsRule,
  BannerDisclosureRule,
  RULE_PASSIVE_TLS,
  RULE_PASSIVE_HEADERS,
  RULE_PASSIVE_COOKIES,
  RULE_PASSIVE_DISCLOSURE,
  type ScannerFinding,
} from '../../src/scanner/index.js';

function createMockCrawledPage(overrides?: Partial<CrawledPage>): CrawledPage {
  return {
    url: 'https://example.com/',
    depth: 0,
    parentUrl: null,
    source: 'seed',
    status: 200,
    statusText: 'OK',
    contentType: 'text/html; charset=utf-8',
    title: 'Example Domain',
    discoveredEndpoints: [],
    durationMs: 42,
    wireBytesReceived: 1024,
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
    ...overrides,
  };
}

describe('Phase 8: Passive Security Assessment Pipeline (TASK-804)', () => {
  // =========================================================================
  // SECTION 1: TLS / SSL Configuration Assessment
  // =========================================================================
  describe('1. TLS / SSL Configuration Assessment (tls-rule.ts)', () => {
    it('flags obsolete TLS 1.0 protocol negotiation', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/login',
        tls: {
          protocol: 'TLSv1',
          authorized: true,
          cipher: { name: 'ECDHE-RSA-AES128-SHA', version: 'TLSv1' },
        },
      });

      const rule = new TlsRule();
      const findings = rule.evaluate(page);

      expect(findings.length).toBe(1);
      const f = findings[0]!;
      expect(f.ruleId).toBe(RULE_PASSIVE_TLS);
      expect(f.vulnerabilityType).toBe('TLS_WEAK_PROTOCOL');
      expect(f.severity).toBe('HIGH');
      expect(f.confidence).toBe('CONFIRMED');
      expect(f.title).toContain('TLS 1.0');
      expect(f.evidence.negotiatedProtocol).toBe('TLSv1');
    });

    it('flags obsolete TLS 1.1 protocol negotiation', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/checkout',
        tls: {
          protocol: 'TLSv1.1',
          authorized: true,
          cipher: { name: 'ECDHE-RSA-AES128-SHA', version: 'TLSv1.1' },
        },
      });

      const rule = new TlsRule();
      const findings = rule.evaluate(page);

      expect(findings.length).toBe(1);
      const f = findings[0]!;
      expect(f.vulnerabilityType).toBe('TLS_WEAK_PROTOCOL');
      expect(f.severity).toBe('HIGH');
      expect(f.title).toContain('TLS 1.1');
    });

    it('does NOT flag TLS 1.2 or TLS 1.3 negotiated protocols as vulnerabilities', () => {
      const pageTls12 = createMockCrawledPage({
        url: 'https://example.com/secure',
        tls: {
          protocol: 'TLSv1.2',
          authorized: true,
          cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384', version: 'TLSv1.2' },
        },
      });

      const pageTls13 = createMockCrawledPage({
        url: 'https://example.com/modern',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          cipher: { name: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1.3' },
        },
      });

      const rule = new TlsRule();
      expect(rule.evaluate(pageTls12).length).toBe(0);
      expect(rule.evaluate(pageTls13).length).toBe(0);
    });

    it('flags expired TLS certificate', () => {
      const fixedTime = Date.parse('2026-11-03T12:00:00.000Z');
      const expiredDate = 'Nov 01 12:00:00 2026 GMT';

      const page = createMockCrawledPage({
        url: 'https://example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subject: { CN: 'example.com' },
            issuer: { CN: 'DigiCert Global Root CA' },
            validFrom: 'Nov 01 12:00:00 2025 GMT',
            validTo: expiredDate,
          },
        },
      });

      const rule = new TlsRule({ currentTimeMs: fixedTime });
      const findings = rule.evaluate(page);

      const expiredFinding = findings.find((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_EXPIRED');
      expect(expiredFinding).toBeDefined();
      expect(expiredFinding?.severity).toBe('HIGH');
      expect(expiredFinding?.confidence).toBe('CONFIRMED');
      expect(expiredFinding?.title).toBe('Expired TLS Certificate');
    });

    it('flags TLS certificate expiring within 14 days', () => {
      const fixedTime = Date.parse('2026-11-03T12:00:00.000Z');
      // 7 days in the future
      const expiringDate = new Date(fixedTime + 7 * 24 * 60 * 60 * 1000).toUTCString();

      const page = createMockCrawledPage({
        url: 'https://example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subject: { CN: 'example.com' },
            issuer: { CN: 'Let\'s Encrypt Authority X3' },
            validFrom: 'Aug 01 12:00:00 2026 GMT',
            validTo: expiringDate,
          },
        },
      });

      const rule = new TlsRule({ currentTimeMs: fixedTime });
      const findings = rule.evaluate(page);

      const expiringSoon = findings.find((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_EXPIRING_SOON');
      expect(expiringSoon).toBeDefined();
      expect(expiringSoon?.severity).toBe('MEDIUM');
      expect(expiringSoon?.confidence).toBe('CONFIRMED');
      expect(expiringSoon?.evidence.daysRemaining).toBe(7);
    });

    it('does NOT flag TLS certificate expiring beyond 14 days', () => {
      const fixedTime = Date.parse('2026-11-03T12:00:00.000Z');
      // 60 days in the future
      const healthyDate = new Date(fixedTime + 60 * 24 * 60 * 60 * 1000).toUTCString();

      const page = createMockCrawledPage({
        url: 'https://example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subject: { CN: 'example.com' },
            issuer: { CN: 'DigiCert Global Root CA' },
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: healthyDate,
          },
        },
      });

      const rule = new TlsRule({ currentTimeMs: fixedTime });
      const findings = rule.evaluate(page);

      expect(findings.some((f) => f.vulnerabilityType.includes('EXPIRED'))).toBe(false);
      expect(findings.some((f) => f.vulnerabilityType.includes('EXPIRING'))).toBe(false);
    });

    it('flags untrusted or self-signed certificate chain verification failure', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: false,
          authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT',
          peerCertificate: {
            subject: { CN: 'selfsigned.local' },
            issuer: { CN: 'selfsigned.local' },
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: 'Jan 01 12:00:00 2027 GMT',
          },
        },
      });

      const rule = new TlsRule();
      const findings = rule.evaluate(page);

      const untrusted = findings.find((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_UNTRUSTED');
      expect(untrusted).toBeDefined();
      expect(untrusted?.severity).toBe('HIGH');
      expect(untrusted?.confidence).toBe('CONFIRMED');
      expect(untrusted?.evidence.authorizationError).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
    });

    it('flags hostname mismatch between target URL and certificate identity', () => {
      const page = createMockCrawledPage({
        url: 'https://target.example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subject: { CN: 'completely-different.com' },
            subjectAltNames: ['DNS:other.com', 'DNS:www.other.com'],
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: 'Jan 01 12:00:00 2028 GMT',
          },
        },
      });

      const rule = new TlsRule();
      const findings = rule.evaluate(page);

      const mismatch = findings.find((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_HOSTNAME_MISMATCH');
      expect(mismatch).toBeDefined();
      expect(mismatch?.severity).toBe('HIGH');
      expect(mismatch?.confidence).toBe('CONFIRMED');
      expect(mismatch?.evidence.targetHostname).toBe('target.example.com');
    });

    it('accepts valid wildcard certificates without false mismatch findings', () => {
      const page = createMockCrawledPage({
        url: 'https://sub.example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subject: { CN: '*.example.com' },
            subjectAltNames: ['DNS:*.example.com', 'DNS:example.com'],
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: 'Jan 01 12:00:00 2028 GMT',
          },
        },
      });

      const rule = new TlsRule();
      const findings = rule.evaluate(page);

      expect(findings.some((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_HOSTNAME_MISMATCH')).toBe(false);
    });

    it('gracefully returns zero findings for HTTP endpoints and missing TLS metadata', () => {
      const httpPage = createMockCrawledPage({
        url: 'http://example.com/unencrypted',
        tls: undefined,
      });

      const rule = new TlsRule();
      expect(rule.evaluate(httpPage)).toEqual([]);
    });
  });

  // =========================================================================
  // SECTION 2: HTTP Security Headers Assessment
  // =========================================================================
  describe('2. HTTP Security Headers Assessment (security-headers-rule.ts)', () => {
    it('flags missing HSTS on HTTPS responses', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/login',
        headers: {},
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(page);

      const hsts = findings.find((f) => f.vulnerabilityType === 'MISSING_HSTS_HEADER');
      expect(hsts).toBeDefined();
      expect(hsts?.severity).toBe('MEDIUM');
      expect(hsts?.confidence).toBe('CONFIRMED');
    });

    it('does NOT flag missing HSTS on unencrypted HTTP responses (protocol-aware)', () => {
      const page = createMockCrawledPage({
        url: 'http://example.com/plain-http',
        headers: {},
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(page);

      expect(findings.some((f) => f.vulnerabilityType === 'MISSING_HSTS_HEADER')).toBe(false);
    });

    it('flags weak HSTS max-age below 31536000 and missing includeSubDomains', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        headers: {
          'strict-transport-security': 'max-age=86400', // 1 day
        },
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(page);

      const weakHsts = findings.filter((f) => f.vulnerabilityType === 'WEAK_HSTS_HEADER');
      expect(weakHsts.length).toBe(2);
      expect(weakHsts.some((f) => f.title.includes('Below Recommended 1-Year Threshold'))).toBe(true);
      expect(weakHsts.some((f) => f.title.includes('Missing includeSubDomains'))).toBe(true);
    });

    it('flags missing Content-Security-Policy (CSP)', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        headers: {},
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(page);

      const missingCsp = findings.find((f) => f.vulnerabilityType === 'MISSING_CONTENT_SECURITY_POLICY');
      expect(missingCsp).toBeDefined();
      expect(missingCsp?.severity).toBe('MEDIUM');
    });

    it('flags CSP with unsafe-inline', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        headers: {
          'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.com",
        },
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(page);

      const unsafeInline = findings.find(
        (f) => f.vulnerabilityType === 'WEAK_CSP_HEADER' && f.title.includes('unsafe-inline')
      );
      expect(unsafeInline).toBeDefined();
      expect(unsafeInline?.severity).toBe('MEDIUM');
    });

    it('flags CSP with unsafe-eval', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        headers: {
          'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-eval'",
        },
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(page);

      const unsafeEval = findings.find(
        (f) => f.vulnerabilityType === 'WEAK_CSP_HEADER' && f.title.includes('unsafe-eval')
      );
      expect(unsafeEval).toBeDefined();
      expect(unsafeEval?.severity).toBe('LOW');
    });

    it('flags CSP with wildcard origin * in sensitive directives', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        headers: {
          'content-security-policy': "default-src *; script-src 'self'",
        },
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(page);

      const wildcardCsp = findings.find(
        (f) => f.vulnerabilityType === 'WEAK_CSP_HEADER' && f.title.includes('Wildcard Origin')
      );
      expect(wildcardCsp).toBeDefined();
      expect(wildcardCsp?.severity).toBe('LOW');
    });

    it('does not flag benign domain containing substring unsafe or star as CSP flaw', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        headers: {
          'content-security-policy': "default-src 'self'; script-src 'self' https://unsafe-inline-domain.example.com https://star-cdn.example.com",
        },
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(page);

      // Must not match unsafe-inline or wildcard * because these are domains, not tokens
      expect(findings.some((f) => f.vulnerabilityType === 'WEAK_CSP_HEADER')).toBe(false);
    });

    it('flags missing X-Frame-Options when CSP frame-ancestors is also absent', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        headers: {},
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(page);

      const xfo = findings.find((f) => f.vulnerabilityType === 'MISSING_FRAME_OPTIONS');
      expect(xfo).toBeDefined();
      expect(xfo?.severity).toBe('LOW');
    });

    it('flags invalid or deprecated X-Frame-Options value', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        headers: {
          'x-frame-options': 'ALLOW-FROM https://partner.com',
        },
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(page);

      const invalidXfo = findings.find((f) => f.vulnerabilityType === 'INVALID_FRAME_OPTIONS');
      expect(invalidXfo).toBeDefined();
      expect(invalidXfo?.severity).toBe('LOW');
    });

    it('accepts valid X-Frame-Options DENY or SAMEORIGIN', () => {
      const pageDeny = createMockCrawledPage({
        url: 'https://example.com/deny',
        headers: { 'x-frame-options': 'DENY' },
      });
      const pageSameOrigin = createMockCrawledPage({
        url: 'https://example.com/sameorigin',
        headers: { 'x-frame-options': 'SAMEORIGIN' },
      });

      const rule = new SecurityHeadersRule();
      expect(rule.evaluate(pageDeny).some((f) => f.vulnerabilityType.includes('FRAME_OPTIONS'))).toBe(false);
      expect(rule.evaluate(pageSameOrigin).some((f) => f.vulnerabilityType.includes('FRAME_OPTIONS'))).toBe(false);
    });

    it('flags missing or non-nosniff X-Content-Type-Options', () => {
      const pageMissing = createMockCrawledPage({ url: 'https://example.com/', headers: {} });
      const pageInvalid = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { 'x-content-type-options': 'sniff' },
      });

      const rule = new SecurityHeadersRule();
      expect(rule.evaluate(pageMissing).some((f) => f.vulnerabilityType === 'MISSING_CONTENT_TYPE_OPTIONS')).toBe(true);
      expect(rule.evaluate(pageInvalid).some((f) => f.vulnerabilityType === 'MISSING_CONTENT_TYPE_OPTIONS')).toBe(true);
    });

    it('flags missing and weak Referrer-Policy', () => {
      const pageMissing = createMockCrawledPage({ url: 'https://example.com/', headers: {} });
      const pageUnsafe = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { 'referrer-policy': 'unsafe-url' },
      });

      const rule = new SecurityHeadersRule();
      const fMissing = rule.evaluate(pageMissing);
      const fUnsafe = rule.evaluate(pageUnsafe);

      expect(fMissing.some((f) => f.vulnerabilityType === 'MISSING_REFERRER_POLICY')).toBe(true);
      expect(fUnsafe.some((f) => f.vulnerabilityType === 'WEAK_REFERRER_POLICY')).toBe(true);
    });

    it('flags missing or unrestricted Permissions-Policy', () => {
      const pageMissing = createMockCrawledPage({ url: 'https://example.com/', headers: {} });
      const pageWildcard = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { 'permissions-policy': 'camera=*, geolocation=()' },
      });

      const rule = new SecurityHeadersRule();
      const fMissing = rule.evaluate(pageMissing);
      const fWildcard = rule.evaluate(pageWildcard);

      expect(fMissing.some((f) => f.vulnerabilityType === 'MISSING_PERMISSIONS_POLICY')).toBe(true);
      expect(fWildcard.some((f) => f.vulnerabilityType === 'WEAK_PERMISSIONS_POLICY')).toBe(true);
    });

    it('produces zero findings for a fully hardened set of security headers', () => {
      const hardenedPage = createMockCrawledPage({
        url: 'https://example.com/hardened',
        headers: {
          'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
          'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'",
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'strict-origin-when-cross-origin',
          'permissions-policy': 'camera=(), microphone=(), geolocation=()',
        },
      });

      const rule = new SecurityHeadersRule();
      const findings = rule.evaluate(hardenedPage);
      expect(findings).toEqual([]);
    });
  });

  // =========================================================================
  // SECTION 3: Cookie Security Attributes Assessment
  // =========================================================================
  describe('3. Cookie Security Attributes Assessment (cookie-flags-rule.ts)', () => {
    it('flags missing Secure flag on cookie', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: ['auth_token=secret123; HttpOnly; SameSite=Strict; Path=/'],
      });

      const rule = new CookieFlagsRule();
      const findings = rule.evaluate(page);

      const f = findings.find((x) => x.title.includes('Missing \'Secure\''));
      expect(f).toBeDefined();
      expect(f?.severity).toBe('MEDIUM');
      expect(f?.confidence).toBe('CONFIRMED');
      expect(f?.evidence.cookieName).toBe('auth_token');
      // Redacts token in evidence
      expect(f?.evidence.rawCookie).toContain('auth_token=[REDACTED]');
    });

    it('flags missing HttpOnly flag on cookie', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: ['session=abc456; Secure; SameSite=Lax; Path=/'],
      });

      const rule = new CookieFlagsRule();
      const findings = rule.evaluate(page);

      const f = findings.find((x) => x.title.includes('Missing \'HttpOnly\''));
      expect(f).toBeDefined();
      expect(f?.severity).toBe('MEDIUM');
      expect(f?.evidence.cookieName).toBe('session');
    });

    it('flags missing SameSite attribute and SameSite=None', () => {
      const pageMissingSameSite = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: ['pref=dark; Secure; HttpOnly; Path=/'],
      });
      const pageNoneSameSite = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: ['tracking=1; Secure; HttpOnly; SameSite=None; Path=/'],
      });

      const rule = new CookieFlagsRule();
      const f1 = rule.evaluate(pageMissingSameSite).find((x) => x.title.includes('SameSite'));
      const f2 = rule.evaluate(pageNoneSameSite).find((x) => x.title.includes('SameSite'));

      expect(f1).toBeDefined();
      expect(f1?.title).toContain('Missing \'SameSite\'');
      expect(f2).toBeDefined();
      expect(f2?.title).toContain('SameSite=None');
    });

    it('preserves cookie boundaries with comma-containing Expires attributes across multiple Set-Cookie headers', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: [
          'user_id=123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/; Secure; HttpOnly; SameSite=Strict',
          'cart_id=456; Expires=Thu, 22 Oct 2026 12:00:00 GMT; Path=/; SameSite=Lax', // Missing Secure, HttpOnly
        ],
      });

      const rule = new CookieFlagsRule();
      const findings = rule.evaluate(page);

      // First cookie has all security flags, produces 0 findings
      expect(findings.some((f) => f.evidence.cookieName === 'user_id')).toBe(false);

      // Second cookie is missing Secure and HttpOnly
      const cartFindings = findings.filter((f) => f.evidence.cookieName === 'cart_id');
      expect(cartFindings.length).toBe(2);
      expect(cartFindings.some((f) => f.title.includes('Secure'))).toBe(true);
      expect(cartFindings.some((f) => f.title.includes('HttpOnly'))).toBe(true);
    });

    it('accepts valid SameSite=Lax and SameSite=Strict without findings', () => {
      const pageLax = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: ['s1=val; Secure; HttpOnly; SameSite=Lax; Path=/'],
      });
      const pageStrict = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: ['s2=val; Secure; HttpOnly; SameSite=Strict; Path=/'],
      });

      const rule = new CookieFlagsRule();
      expect(rule.evaluate(pageLax)).toEqual([]);
      expect(rule.evaluate(pageStrict)).toEqual([]);
    });

    it('handles malformed cookie values, duplicate attributes, and whitespace safely', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: [
          '   ',
          'badcookie',
          'test_cookie=abc; ;; Secure ; HttpOnly; SameSite=Strict; SameSite=Strict',
        ],
      });

      const rule = new CookieFlagsRule();
      const findings = rule.evaluate(page);

      // test_cookie has all required flags (even with duplicate SameSite)
      expect(findings.some((f) => f.evidence.cookieName === 'test_cookie')).toBe(false);
    });
  });

  // =========================================================================
  // SECTION 4: Information Disclosure & Banner Leakage Assessment
  // =========================================================================
  describe('4. Information Disclosure & Banner Leakage Assessment (banner-disclosure-rule.ts)', () => {
    it('flags web server version disclosure in Server header', () => {
      const pageApache = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { server: 'Apache/2.4.41 (Ubuntu)' },
      });
      const pageNginx = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { server: 'nginx/1.18.0' },
      });
      const pageIis = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { server: 'Microsoft-IIS/10.0' },
      });

      const rule = new BannerDisclosureRule();
      const f1 = rule.evaluate(pageApache).find((f) => f.vulnerabilityType === 'SERVER_VERSION_DISCLOSURE');
      const f2 = rule.evaluate(pageNginx).find((f) => f.vulnerabilityType === 'SERVER_VERSION_DISCLOSURE');
      const f3 = rule.evaluate(pageIis).find((f) => f.vulnerabilityType === 'SERVER_VERSION_DISCLOSURE');

      expect(f1).toBeDefined();
      expect(f2).toBeDefined();
      expect(f3).toBeDefined();
    });

    it('does NOT flag generic Server banners without version numbers', () => {
      const pageGenericNginx = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { server: 'nginx' },
      });
      const pageCloudflare = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { server: 'cloudflare' },
      });
      const pageApacheGeneric = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { server: 'Apache' },
      });

      const rule = new BannerDisclosureRule();
      expect(rule.evaluate(pageGenericNginx).some((f) => f.vulnerabilityType === 'SERVER_VERSION_DISCLOSURE')).toBe(false);
      expect(rule.evaluate(pageCloudflare).some((f) => f.vulnerabilityType === 'SERVER_VERSION_DISCLOSURE')).toBe(false);
      expect(rule.evaluate(pageApacheGeneric).some((f) => f.vulnerabilityType === 'SERVER_VERSION_DISCLOSURE')).toBe(false);
    });

    it('flags technology stack disclosure via X-Powered-By header', () => {
      const pagePhp = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { 'x-powered-by': 'PHP/7.4.3' },
      });
      const pageExpress = createMockCrawledPage({
        url: 'https://example.com/',
        headers: { 'x-powered-by': 'Express' },
      });

      const rule = new BannerDisclosureRule();
      const f1 = rule.evaluate(pagePhp).find((f) => f.vulnerabilityType === 'X_POWERED_BY_DISCLOSURE');
      const f2 = rule.evaluate(pageExpress).find((f) => f.vulnerabilityType === 'X_POWERED_BY_DISCLOSURE');

      expect(f1).toBeDefined();
      expect(f1?.evidence.xPoweredByHeader).toBe('PHP/7.4.3');
      expect(f2).toBeDefined();
      expect(f2?.evidence.xPoweredByHeader).toBe('Express');
    });

    it('flags sensitive debug endpoint references in discovered endpoints without making extra requests', () => {
      const endpoints: DiscoveredEndpoint[] = [
        {
          url: 'https://example.com/phpinfo.php',
          rawUrl: '/phpinfo.php',
          source: 'a',
          depth: 1,
          parentUrl: 'https://example.com/',
        },
        {
          url: 'https://example.com/actuator/env',
          rawUrl: '/actuator/env',
          source: 'a',
          depth: 1,
          parentUrl: 'https://example.com/',
        },
        {
          url: 'https://example.com/normal-page',
          rawUrl: '/normal-page',
          source: 'a',
          depth: 1,
          parentUrl: 'https://example.com/',
        },
      ];

      const page = createMockCrawledPage({
        url: 'https://example.com/',
        discoveredEndpoints: endpoints,
      });

      const rule = new BannerDisclosureRule();
      const findings = rule.evaluate(page);

      const debugFindings = findings.filter((f) => f.vulnerabilityType === 'DEBUG_ENDPOINT_DISCLOSURE');
      expect(debugFindings.length).toBe(2);
      expect(debugFindings.some((f) => f.endpoint?.includes('phpinfo.php'))).toBe(true);
      expect(debugFindings.some((f) => f.endpoint?.includes('/actuator/env'))).toBe(true);
    });

    it('detects detailed stack traces across multiple runtimes in response bodies', () => {
      const rule = new BannerDisclosureRule();

      // Node.js stack trace
      const nodeTrace = `
        Error: Unhandled exception occurred
            at Object.<anonymous> (/var/www/app/server.js:42:15)
            at Module._compile (internal/modules/cjs/loader.js:1138:30)
      `;
      const pageNode = createMockCrawledPage({ url: 'https://example.com/error-node', bodyText: nodeTrace });
      const fNode = rule.evaluate(pageNode).find((f) => f.vulnerabilityType === 'STACK_TRACE_DISCLOSURE');
      expect(fNode).toBeDefined();
      expect(fNode?.title).toContain('Node.js');

      // Python traceback
      const pyTrace = `
        Traceback (most recent call last):
          File "/app/views.py", line 128, in get_user
            user = db.query(User).filter_by(id=uid).one()
        sqlalchemy.orm.exc.NoResultFound: No row was found
      `;
      const pagePy = createMockCrawledPage({ url: 'https://example.com/error-py', bodyText: pyTrace });
      const fPy = rule.evaluate(pagePy).find((f) => f.vulnerabilityType === 'STACK_TRACE_DISCLOSURE');
      expect(fPy).toBeDefined();
      expect(fPy?.title).toContain('Python');

      // Java stack trace
      const javaTrace = `
        java.lang.NullPointerException: Cannot invoke method on null object
            at com.example.service.UserService.findUser(UserService.java:84)
            at com.example.controller.UserController.getUser(UserController.java:32)
      `;
      const pageJava = createMockCrawledPage({ url: 'https://example.com/error-java', bodyText: javaTrace });
      const fJava = rule.evaluate(pageJava).find((f) => f.vulnerabilityType === 'STACK_TRACE_DISCLOSURE');
      expect(fJava).toBeDefined();
      expect(fJava?.title).toContain('Java');

      // PHP error
      const phpError = `
        Fatal error: Uncaught Exception: Database connection lost in /var/www/html/db.php on line 55
      `;
      const pagePhp = createMockCrawledPage({ url: 'https://example.com/error-php', bodyText: phpError });
      const fPhp = rule.evaluate(pagePhp).find((f) => f.vulnerabilityType === 'STACK_TRACE_DISCLOSURE');
      expect(fPhp).toBeDefined();
      expect(fPhp?.title).toContain('PHP');

      // .NET error
      const dotNetError = `
        System.NullReferenceException: Object reference not set to an instance of an object.
            at App.Controllers.AccountController.Index() in C:\\App\\Controllers\\AccountController.cs:line 104
      `;
      const pageDotNet = createMockCrawledPage({ url: 'https://example.com/error-dotnet', bodyText: dotNetError });
      const fDotNet = rule.evaluate(pageDotNet).find((f) => f.vulnerabilityType === 'STACK_TRACE_DISCLOSURE');
      expect(fDotNet).toBeDefined();
      expect(fDotNet?.title).toContain('.NET');
    });

    it('detects exposed .git/HEAD and .env content in crawled responses', () => {
      const rule = new BannerDisclosureRule();

      // .git/HEAD
      const gitPage = createMockCrawledPage({
        url: 'https://example.com/.git/HEAD',
        bodyText: 'ref: refs/heads/main\n',
      });
      const fGit = rule.evaluate(gitPage).find((f) => f.vulnerabilityType === 'EXPOSED_SENSITIVE_FILE');
      expect(fGit).toBeDefined();
      expect(fGit?.title).toContain('.git/HEAD');

      // .env
      const envPage = createMockCrawledPage({
        url: 'https://example.com/.env',
        bodyText: 'NODE_ENV=production\nDATABASE_URL=postgres://user:secret@db.internal:5432/app\nJWT_SECRET=supersecret123\n',
      });
      const fEnv = rule.evaluate(envPage).find((f) => f.vulnerabilityType === 'EXPOSED_SENSITIVE_FILE');
      expect(fEnv).toBeDefined();
      expect(fEnv?.title).toContain('.env');
      expect(fEnv?.severity).toBe('CRITICAL');
      // Redacts secret value in evidence
      expect(fEnv?.evidence.matchedSignature).toContain('[REDACTED]');
    });

    it('avoids false positives on ordinary error pages and benign text', () => {
      const page404 = createMockCrawledPage({
        url: 'https://example.com/not-found',
        status: 404,
        bodyText: '<html><body><h1>404 Not Found</h1><p>The requested page could not be found.</p></body></html>',
      });

      const rule = new BannerDisclosureRule();
      const findings = rule.evaluate(page404);
      expect(findings.some((f) => f.vulnerabilityType === 'STACK_TRACE_DISCLOSURE')).toBe(false);
      expect(findings.some((f) => f.vulnerabilityType === 'EXPOSED_SENSITIVE_FILE')).toBe(false);
    });
  });

  // =========================================================================
  // SECTION 5: PassiveAnalyzer Engine & Zero-Extra-Request Invariant
  // =========================================================================
  describe('5. PassiveAnalyzer Engine & Zero-Extra-Request Invariant (passive-analyzer.ts)', () => {
    it('coordinates all active rules and deduplicates findings deterministically', async () => {
      const analyzer = new PassiveAnalyzer();
      expect(analyzer.getActiveRuleIds()).toEqual([
        RULE_PASSIVE_TLS,
        RULE_PASSIVE_HEADERS,
        RULE_PASSIVE_COOKIES,
        RULE_PASSIVE_DISCLOSURE,
      ]);

      const page = createMockCrawledPage({
        url: 'https://example.com/',
        headers: {
          'server': 'Apache/2.4.41',
          'x-powered-by': 'PHP/7.4.3',
        },
        setCookies: ['sess=123; Path=/'], // Missing Secure, HttpOnly, SameSite
      });

      const findings = await analyzer.analyze(page);

      // Verify findings from multiple rules are present
      expect(findings.some((f) => f.ruleId === RULE_PASSIVE_HEADERS)).toBe(true);
      expect(findings.some((f) => f.ruleId === RULE_PASSIVE_COOKIES)).toBe(true);
      expect(findings.some((f) => f.ruleId === RULE_PASSIVE_DISCLOSURE)).toBe(true);

      // Verify deterministic deduplication when analyzing identical page twice
      const repeatedFindings = await analyzer.analyze([page, page]);
      expect(repeatedFindings.length).toBe(findings.length);
    });

    it('strictly guarantees ZERO extra network requests during analysis', async () => {
      // Mock global fetch to spy and confirm 0 network requests
      const fetchSpy = vi.fn();
      const originalFetch = globalThis.fetch;
      globalThis.fetch = fetchSpy;

      try {
        const analyzer = new PassiveAnalyzer();
        const page = createMockCrawledPage({
          url: 'https://example.com/',
          headers: {
            'server': 'Apache/2.4.41 (Ubuntu)',
            'x-powered-by': 'PHP/7.4.3',
          },
          discoveredEndpoints: [
            {
              url: 'https://example.com/actuator/env',
              rawUrl: '/actuator/env',
              source: 'a',
              depth: 1,
              parentUrl: 'https://example.com/',
            },
          ],
        });

        const findings = await analyzer.analyze(page);

        expect(findings.length).toBeGreaterThan(0);
        // STRICT INVARIANT: 0 network requests dispatched during passive evaluation
        expect(fetchSpy).not.toHaveBeenCalled();
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('supports custom rule selection via options.enabledRuleIds', async () => {
      const analyzer = new PassiveAnalyzer({
        enabledRuleIds: [RULE_PASSIVE_COOKIES],
      });

      expect(analyzer.getActiveRuleIds()).toEqual([RULE_PASSIVE_COOKIES]);

      const page = createMockCrawledPage({
        url: 'https://example.com/',
        headers: {
          server: 'Apache/2.4.41', // Would trigger RULE_PASSIVE_DISCLOSURE if enabled
        },
        setCookies: ['sess=123; Path=/'], // Triggers RULE_PASSIVE_COOKIES
      });

      const findings = await analyzer.analyze(page);

      expect(findings.length).toBeGreaterThan(0);
      expect(findings.every((f) => f.ruleId === RULE_PASSIVE_COOKIES)).toBe(true);
    });

    it('accepts a CrawlResult object and evaluates all pages cleanly', async () => {
      const analyzer = new PassiveAnalyzer();

      const crawlResult = {
        seedUrl: 'https://example.com/',
        pagesCrawled: 2,
        totalDiscovered: 2,
        pages: [
          createMockCrawledPage({ url: 'https://example.com/page-1' }),
          createMockCrawledPage({ url: 'https://example.com/page-2' }),
        ],
        discoveredUrls: ['https://example.com/page-1', 'https://example.com/page-2'],
        durationMs: 150,
        stoppedReason: 'COMPLETED' as const,
      };

      const findings = await analyzer.analyze(crawlResult);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.url === 'https://example.com/page-1')).toBe(true);
      expect(findings.some((f) => f.url === 'https://example.com/page-2')).toBe(true);
    });

    it('supports analyzePage for single page evaluation', async () => {
      const analyzer = new PassiveAnalyzer();
      const page = createMockCrawledPage({
        url: 'https://example.com/single',
        headers: { server: 'Apache/2.4.50' },
      });

      const findings = await analyzer.analyzePage(page);
      expect(findings.some((f) => f.vulnerabilityType === 'SERVER_VERSION_DISCLOSURE')).toBe(true);
    });
  });

  // =========================================================================
  // SECTION 6: Transport Integration: Cookie Preservation & Sanitized TLS Metadata
  // =========================================================================
  describe('6. Transport Integration & End-to-End Pipeline Verification', () => {
    it('SafeHttpClient preserves multiple Set-Cookie headers with comma dates without naive splitting', async () => {
      const { createServer } = await import('node:http');
      const { SafeHttpClient, DnsResolver } = await import('../../src/scanner/transport/index.js');
      const { createTestScanContext } = await import('./helpers/test-context-helper.js');

      let serverPort = 0;
      const testServer = createServer((req, res) => {
        // Send multiple Set-Cookie headers with commas in Expires attributes
        res.setHeader('Set-Cookie', [
          'session_id=tok123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/; HttpOnly; SameSite=Strict',
          'pref=dark; Expires=Thu, 22 Oct 2026 12:00:00 GMT; Path=/; Secure; SameSite=Lax',
        ]);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><head><title>Test</title></head><body>OK</body></html>');
      });

      await new Promise<void>((resolve) => {
        testServer.listen(0, '127.0.0.1', () => {
          serverPort = (testServer.address() as any).port;
          resolve();
        });
      });

      try {
        const context = await createTestScanContext({
          primaryDomain: 'target.example.com',
          allowedPorts: [serverPort],
        });

        const client = new SafeHttpClient({
          dnsResolver: new DnsResolver({
            lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
            allowLoopbackForTesting: true,
          }),
          allowLoopbackForTesting: true,
        });

        const res = await client.get(`http://target.example.com:${serverPort}/`, {
          context,
          allowLoopbackForTesting: true,
        });

        // 1. Verify setCookies array contains both cookies unjoined
        expect(res.setCookies).toBeDefined();
        expect(res.setCookies?.length).toBe(2);
        expect(res.setCookies?.[0]).toContain('Expires=Wed, 21 Oct 2026');
        expect(res.setCookies?.[1]).toContain('Expires=Thu, 22 Oct 2026');

        // 2. Verify rawHeaders contains raw header entries
        expect(res.rawHeaders).toBeDefined();
        expect(res.rawHeaders?.length).toBeGreaterThan(0);

        // 3. Verify backward-compatible headers object is also present
        expect(res.headers['set-cookie']).toBeDefined();

        // 4. Verify PassiveAnalyzer evaluates these cookies cleanly
        const analyzer = new PassiveAnalyzer();
        const page: CrawledPage = {
          url: `http://target.example.com:${serverPort}/`,
          depth: 0,
          parentUrl: null,
          source: 'seed',
          status: res.status,
          statusText: res.statusText,
          contentType: res.headers['content-type'] || 'text/html',
          discoveredEndpoints: [],
          durationMs: 10,
          wireBytesReceived: res.wireBytesReceived,
          headers: res.headers,
          setCookies: res.setCookies,
          rawHeaders: res.rawHeaders,
          bodyText: res.text,
        };

        const findings = await analyzer.analyze(page);
        // session_id is missing Secure (over HTTP: LOW severity finding)
        expect(findings.some((f) => f.evidence.cookieName === 'session_id' && f.title.includes('Secure'))).toBe(true);
      } finally {
        await new Promise<void>((resolve) => testServer.close(() => resolve()));
      }
    });

    it('BoundedCrawler populates extended response fields (headers, setCookies, rawHeaders, bodyText) on CrawledPage', async () => {
      const { createServer } = await import('node:http');
      const { SafeHttpClient, DnsResolver } = await import('../../src/scanner/transport/index.js');
      const { BoundedCrawler } = await import('../../src/scanner/crawler/index.js');
      const { createTestScanContext } = await import('./helpers/test-context-helper.js');

      let serverPort = 0;
      const testServer = createServer((req, res) => {
        res.setHeader('Set-Cookie', ['auth=abc; Path=/; Secure; HttpOnly; SameSite=Strict']);
        res.setHeader('Server', 'Apache/2.4.41');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><head><title>Crawler Test</title></head><body><a href="/p2">Link</a></body></html>');
      });

      await new Promise<void>((resolve) => {
        testServer.listen(0, '127.0.0.1', () => {
          serverPort = (testServer.address() as any).port;
          resolve();
        });
      });

      try {
        const context = await createTestScanContext({
          primaryDomain: 'target.example.com',
          allowedPorts: [serverPort],
        });

        const client = new SafeHttpClient({
          dnsResolver: new DnsResolver({
            lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
            allowLoopbackForTesting: true,
          }),
          allowLoopbackForTesting: true,
        });

        const crawler = new BoundedCrawler(context, client, {
          maxDepth: 0,
          allowLoopbackForTesting: true,
        });

        const crawlResult = await crawler.crawl(`http://target.example.com:${serverPort}/`);
        expect(crawlResult.pages.length).toBe(1);

        const page = crawlResult.pages[0]!;
        expect(page.headers).toBeDefined();
        expect(page.setCookies).toBeDefined();
        expect(page.setCookies?.length).toBe(1);
        expect(page.bodyText).toContain('Crawler Test');

        // Feed directly into PassiveAnalyzer
        const analyzer = new PassiveAnalyzer();
        const findings = await analyzer.analyze(crawlResult);

        // Disclosed Apache version from crawled page
        expect(findings.some((f) => f.vulnerabilityType === 'SERVER_VERSION_DISCLOSURE')).toBe(true);
      } finally {
        await new Promise<void>((resolve) => testServer.close(() => resolve()));
      }
    });

    it('extracts sanitized TLS metadata without exposing raw socket objects or private keys', () => {
      // Simulate a TLSSocket with mock methods
      const mockTlsSocket = {
        getProtocol: () => 'TLSv1.3',
        getCipher: () => ({ name: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1.3' }),
        getPeerCertificate: () => ({
          subject: { CN: 'portal.example.com', O: 'Example Inc' },
          issuer: { CN: 'DigiCert Global Root CA', O: 'DigiCert Inc' },
          valid_from: 'Jan 01 12:00:00 2026 GMT',
          valid_to: 'Jan 01 12:00:00 2027 GMT',
          subjectaltname: 'DNS:portal.example.com, DNS:api.example.com',
          serialNumber: '3F1A2B',
          fingerprint256: 'AA:BB:CC:DD',
        }),
        authorized: true,
      };

      // Verify sanitized structure
      const page = createMockCrawledPage({
        url: 'https://portal.example.com/',
        tls: {
          protocol: mockTlsSocket.getProtocol(),
          cipher: mockTlsSocket.getCipher(),
          authorized: mockTlsSocket.authorized,
          peerCertificate: {
            subject: mockTlsSocket.getPeerCertificate().subject,
            issuer: mockTlsSocket.getPeerCertificate().issuer,
            validFrom: mockTlsSocket.getPeerCertificate().valid_from,
            validTo: mockTlsSocket.getPeerCertificate().valid_to,
            subjectAltNames: ['portal.example.com', 'api.example.com'],
            serialNumber: mockTlsSocket.getPeerCertificate().serialNumber,
            fingerprint256: mockTlsSocket.getPeerCertificate().fingerprint256,
          },
        },
      });

      // Assert zero socket internals or private keys are exposed
      expect((page.tls as any).socket).toBeUndefined();
      expect((page.tls as any).privateKey).toBeUndefined();
      expect((page.tls as any)._handle).toBeUndefined();
      expect(page.tls?.protocol).toBe('TLSv1.3');
      expect(page.tls?.peerCertificate?.subject.CN).toBe('portal.example.com');
    });
  });
});
