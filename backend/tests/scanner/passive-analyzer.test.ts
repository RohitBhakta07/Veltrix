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

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
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
  BoundedCrawler,
  MAX_PASSIVE_BODY_CHARS,
  SafeHttpClient,
  SafeTransportError,
  type ScannerFinding,
} from '../../src/scanner/index.js';
import { createAuthorizedScanScopeContext } from './helpers/test-context-helper.js';

const TEST_PFX_BASE64 = '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';

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

    
    it('enforces RFC 6125 SAN precedence over CN and ignores matching CN when SAN is present', () => {
      // Certificate has CN=example.com, but SAN is DNS:other.com
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subject: { CN: 'example.com' },
            subjectAltNames: ['DNS:other.com'],
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: 'Jan 01 12:00:00 2028 GMT',
          },
        },
      });

      const rule = new TlsRule();
      const findings = rule.evaluate(page);

      // Under RFC 6125, SAN MUST take precedence and CN MUST NOT be evaluated
      const mismatch = findings.find((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_HOSTNAME_MISMATCH');
      expect(mismatch).toBeDefined();
      expect(mismatch?.severity).toBe('HIGH');
      expect(mismatch?.evidence.identitySource).toBe('SAN');
      expect(mismatch?.evidence.sanPrecedenceEnforced).toBe(true);
      expect(mismatch?.evidence.cnIgnoredDueToSanPrecedence).toBe(true);
    });

    it('permits CN fallback only when SAN is completely absent', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subject: { CN: 'example.com' },
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: 'Jan 01 12:00:00 2028 GMT',
          },
        },
      });

      const rule = new TlsRule();
      const findings = rule.evaluate(page);

      expect(findings.some((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_HOSTNAME_MISMATCH')).toBe(false);
    });

    it('flags TLS_CERTIFICATE_NO_IDENTITY when certificate has neither SAN nor CN', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subject: {},
            subjectAltNames: [],
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: 'Jan 01 12:00:00 2028 GMT',
          },
        },
      });

      const rule = new TlsRule();
      const findings = rule.evaluate(page);

      const noIdentity = findings.find((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_NO_IDENTITY');
      expect(noIdentity).toBeDefined();
      expect(noIdentity?.severity).toBe('HIGH');
    });

    it('strictly enforces single-label wildcard matching and rejects multi-label / apex wildcard matching', () => {
      const rule = new TlsRule();

      // 1. Single-label wildcard *.example.com matches sub.example.com
      const subPage = createMockCrawledPage({
        url: 'https://sub.example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subjectAltNames: ['DNS:*.example.com'],
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: 'Jan 01 12:00:00 2028 GMT',
          },
        },
      });
      expect(rule.evaluate(subPage).some((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_HOSTNAME_MISMATCH')).toBe(false);

      // 2. Single-label wildcard *.example.com does NOT match apex example.com
      const apexPage = createMockCrawledPage({
        url: 'https://example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subjectAltNames: ['DNS:*.example.com'],
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: 'Jan 01 12:00:00 2028 GMT',
          },
        },
      });
      expect(rule.evaluate(apexPage).some((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_HOSTNAME_MISMATCH')).toBe(true);

      // 3. Single-label wildcard *.example.com does NOT match nested a.b.example.com
      const deepPage = createMockCrawledPage({
        url: 'https://a.b.example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subjectAltNames: ['DNS:*.example.com'],
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: 'Jan 01 12:00:00 2028 GMT',
          },
        },
      });
      expect(rule.evaluate(deepPage).some((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_HOSTNAME_MISMATCH')).toBe(true);

      // 4. Invalid multi-label wildcard *.*.example.com is rejected
      const multiWildcardPage = createMockCrawledPage({
        url: 'https://a.b.example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: true,
          peerCertificate: {
            subjectAltNames: ['DNS:*.*.example.com'],
            validFrom: 'Jan 01 12:00:00 2026 GMT',
            validTo: 'Jan 01 12:00:00 2028 GMT',
          },
        },
      });
      expect(rule.evaluate(multiWildcardPage).some((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_HOSTNAME_MISMATCH')).toBe(true);
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

    
    it('flags invalid SameSite attribute values with INVALID_SAMESITE_ATTRIBUTE', () => {
      const pageInvalid = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: ['token=secret; SameSite=invalid; Secure; HttpOnly; Path=/'],
      });
      const pageEmptySameSite = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: ['token2=secret; SameSite=; Secure; HttpOnly; Path=/'],
      });

      const rule = new CookieFlagsRule();
      const findings1 = rule.evaluate(pageInvalid);
      const findings2 = rule.evaluate(pageEmptySameSite);

      const f1 = findings1.find((x) => x.vulnerabilityType === 'INVALID_SAMESITE_ATTRIBUTE');
      expect(f1).toBeDefined();
      expect(f1?.severity).toBe('MEDIUM');
      expect(f1?.evidence.invalidSameSiteValue).toBe('invalid');

      const f2 = findings2.find((x) => x.vulnerabilityType === 'INVALID_SAMESITE_ATTRIBUTE');
      expect(f2).toBeDefined();
      expect(f2?.severity).toBe('MEDIUM');
    });

    it('flags SameSite=None without Secure as insecure combination requiring Secure', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: ['track=anon; SameSite=None; HttpOnly; Path=/'], // Missing Secure
      });

      const rule = new CookieFlagsRule();
      const findings = rule.evaluate(page);

      // Flagged as missing Secure attribute in general AND specifically SameSite=None without Secure
      const requiresSecure = findings.find((x) => x.title.includes("Uses 'SameSite=None' Without 'Secure'"));
      expect(requiresSecure).toBeDefined();
      expect(requiresSecure?.severity).toBe('MEDIUM');
    });

    it('strictly redacts sensitive cookie values in evidence across all findings', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: [
          'session_id=SUPER_SECRET_TOKEN_999888; Path=/', // Missing Secure, HttpOnly, SameSite
        ],
      });

      const rule = new CookieFlagsRule();
      const findings = rule.evaluate(page);

      expect(findings.length).toBeGreaterThan(0);
      for (const finding of findings) {
        expect(finding.evidence.rawCookie).toBeDefined();
        expect(finding.evidence.rawCookie).toContain('session_id=[REDACTED]');
        expect(finding.evidence.rawCookie).not.toContain('SUPER_SECRET_TOKEN_999888');
      }
    });

    it('handles duplicate cookie attributes safely without errors or false positives', () => {
      const parsed = new CookieFlagsRule().parseSetCookieString(
        'session=abc; SameSite=Lax; SameSite=Strict; Secure; HttpOnly; Path=/'
      );

      expect(parsed?.name).toBe('session');
      expect(parsed?.duplicateAttributes).toContain('samesite');
      expect(parsed?.secure).toBe(true);
      expect(parsed?.httpOnly).toBe(true);

      const page = createMockCrawledPage({
        url: 'https://example.com/',
        setCookies: [
          'session=abc; SameSite=Lax; SameSite=Strict; Secure; HttpOnly; Path=/',
        ],
      });

      const findings = new CookieFlagsRule().evaluate(page);
      // Secure and HttpOnly are both present, SameSite resolved safely without throwing
      expect(findings.some((f) => f.title.includes("Missing 'Secure'"))).toBe(false);
      expect(findings.some((f) => f.title.includes("Missing 'HttpOnly'"))).toBe(false);
      expect(findings.some((f) => f.title.includes("Missing 'SameSite'"))).toBe(false);
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

    it('strictly guarantees ZERO extra network requests during analysis across all network APIs', async () => {
      // Spy on all 9 network APIs simultaneously:
      // globalThis.fetch, http.request, http.get, https.request, https.get, net.connect, net.createConnection, tls.connect, SafeHttpClient.prototype.request
      const originalFetch = globalThis.fetch;
      const originalHttpRequest = http.request;
      const originalHttpGet = http.get;
      const originalHttpsRequest = https.request;
      const originalHttpsGet = https.get;
      const originalNetConnect = net.connect;
      const originalNetCreateConnection = net.createConnection;
      const originalTlsConnect = tls.connect;
      const originalSafeRequest = SafeHttpClient.prototype.request;

      const fetchSpy = vi.fn();
      const httpReqSpy = vi.fn();
      const httpGetSpy = vi.fn();
      const httpsReqSpy = vi.fn();
      const httpsGetSpy = vi.fn();
      const netConnSpy = vi.fn();
      const netCreateConnSpy = vi.fn();
      const tlsConnSpy = vi.fn();
      const safeReqSpy = vi.fn();

      globalThis.fetch = fetchSpy as any;
      (http as any).request = httpReqSpy;
      (http as any).get = httpGetSpy;
      (https as any).request = httpsReqSpy;
      (https as any).get = httpsGetSpy;
      (net as any).connect = netConnSpy;
      (net as any).createConnection = netCreateConnSpy;
      (tls as any).connect = tlsConnSpy;
      SafeHttpClient.prototype.request = safeReqSpy as any;

      try {
        const analyzer = new PassiveAnalyzer();
        const page = createMockCrawledPage({
          url: 'https://example.com/profile',
          headers: {
            'server': 'Apache/2.4.41 (Ubuntu)',
            'x-powered-by': 'PHP/7.4.3',
          },
          setCookies: ['auth=secret; Path=/'],
          tls: {
            protocol: 'TLSv1.0',
            authorized: false,
            authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT',
            peerCertificate: {
              subject: { CN: 'untrusted.com' },
              validFrom: 'Jan 01 2026',
              validTo: 'Jan 01 2027',
            },
          },
          bodyText: '<div><pre>Fatal error in /var/www/html/app.php on line 42</pre></div>',
          discoveredEndpoints: [
            {
              url: 'https://example.com/actuator/env',
              rawUrl: '/actuator/env',
              source: 'a',
              depth: 1,
              parentUrl: 'https://example.com/profile',
            },
          ],
        });

        const findings = await analyzer.analyze(page);

        // Multiple rules fired and produced findings
        expect(findings.length).toBeGreaterThanOrEqual(4);

        // STRICT INVARIANT: 0 network requests dispatched across ALL 9 APIs
        expect(fetchSpy).not.toHaveBeenCalled();
        expect(httpReqSpy).not.toHaveBeenCalled();
        expect(httpGetSpy).not.toHaveBeenCalled();
        expect(httpsReqSpy).not.toHaveBeenCalled();
        expect(httpsGetSpy).not.toHaveBeenCalled();
        expect(netConnSpy).not.toHaveBeenCalled();
        expect(netCreateConnSpy).not.toHaveBeenCalled();
        expect(tlsConnSpy).not.toHaveBeenCalled();
        expect(safeReqSpy).not.toHaveBeenCalled();
      } finally {
        globalThis.fetch = originalFetch;
        http.request = originalHttpRequest;
        http.get = originalHttpGet;
        https.request = originalHttpsRequest;
        https.get = originalHttpsGet;
        net.connect = originalNetConnect;
        net.createConnection = originalNetCreateConnection;
        tls.connect = originalTlsConnect;
        SafeHttpClient.prototype.request = originalSafeRequest;
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

  // =========================================================================
  // SECTION 6: Bounded Response-Body Memory & Real TLS Pipeline Integration
  // =========================================================================
  describe('6. Bounded Response-Body Memory & Real TLS Integration', () => {
    let localHttpsServer: https.Server;
    let localHttpsPort: number;

    beforeAll(async () => {
      localHttpsServer = https.createServer(
        {
          pfx: Buffer.from(TEST_PFX_BASE64, 'base64'),
          passphrase: 'veltrix',
        },
        (req, res) => {
          if (req.url === '/large.txt') {
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('A'.repeat(128 * 1024)); // 128 KB
            return;
          }
          if (req.url === '/image.png') {
            res.writeHead(200, { 'Content-Type': 'image/png' });
            res.end(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
            return;
          }
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Server': 'Apache/2.4.52',
          });
          res.end('<!DOCTYPE html><html><body><h1>Safe Real TLS Test</h1></body></html>');
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
      await new Promise<void>((resolve) => localHttpsServer.close(() => resolve()));
    });

    it('enforces bounded response-body memory and eliminates rawBody from CrawledPage', () => {
      const page = createMockCrawledPage({
        url: 'https://example.com/large',
        contentType: 'text/html; charset=utf-8',
        bodyText: 'X'.repeat(MAX_PASSIVE_BODY_CHARS),
      });

      // Asserts CrawledPage bodyText is bounded and rawBody is eliminated
      expect(page.bodyText?.length).toBe(MAX_PASSIVE_BODY_CHARS);
      expect((page as any).rawBody).toBeUndefined();

      const binaryPage = createMockCrawledPage({
        url: 'https://example.com/avatar.png',
        contentType: 'image/png',
        bodyText: undefined,
      });
      expect(binaryPage.bodyText).toBeUndefined();
      expect((binaryPage as any).rawBody).toBeUndefined();
    });

    it('captures TLS metadata during real HTTPS handshake failures and feeds TlsRule', async () => {
      // Connect to localHttpsServer with SafeHttpClient
      // The cert in TEST_PFX_BASE64 is self-signed/untrusted for real clients,
      // so the TLS handshake will trigger SafeTransportError('TLS_VERIFICATION_FAILED')
      // with rejectUnauthorized: true strictly preserved!
      const client = new SafeHttpClient({
        allowLoopbackForTesting: true,
      });

      const context = await createAuthorizedScanScopeContext({
        orgId: 'org-test',
        scanId: 'scan-test',
        siteId: 'site-test',
        primaryDomain: '127.0.0.1',
        approvedSubdomains: [],
        status: 'VERIFIED',
        scanBlocked: false,
        expiresAt: Date.now() + 86400000,
        allowedPorts: [localHttpsPort],
      });

      const crawler = new BoundedCrawler(
        context,
        client,
        {
          maxPages: 1,
          allowLoopbackForTesting: true,
        }
      );

      const result = await crawler.crawl(`https://127.0.0.1:${localHttpsPort}/`);
      expect(result.pages.length).toBe(1);

      const crawledPage = result.pages[0]!;
      expect(crawledPage.status).toBe(0);
      expect(crawledPage.error).toBeDefined();

      // Invariant: Failed TLS handshake attached sanitized TLS metadata to CrawledPage
      expect(crawledPage.tls).toBeDefined();
      expect(crawledPage.tls?.authorized).toBe(false);
      expect(crawledPage.tls?.authorizationError).toBeDefined();

      // Zero extra requests: TlsRule evaluates the captured metadata
      const tlsRule = new TlsRule();
      const findings = tlsRule.evaluate(crawledPage);

      const untrustedFinding = findings.find((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_UNTRUSTED');
      expect(untrustedFinding).toBeDefined();
      expect(untrustedFinding?.severity).toBe('HIGH');
      expect(untrustedFinding?.confidence).toBe('CONFIRMED');
      expect(untrustedFinding?.evidence.authorizationError).toBeDefined();
    });

    it('strictly enforces aggregate scan-level body retention budget across entire crawl', async () => {
      const testHttpServer = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        const pageNum = req.url?.replace('/', '') || '0';
        const nextNum = parseInt(pageNum, 10) + 1;
        const bodyContent = `<html><body><a href="/${nextNum}">Next</a><p>${'B'.repeat(10 * 1024)}</p></body></html>`;
        res.end(bodyContent);
      });

      let testHttpPort = 0;
      await new Promise<void>((resolve) => {
        testHttpServer.listen(0, '127.0.0.1', () => {
          testHttpPort = (testHttpServer.address() as net.AddressInfo).port;
          resolve();
        });
      });

      try {
        const client = new SafeHttpClient({ allowLoopbackForTesting: true });
        const context = await createAuthorizedScanScopeContext({
          orgId: 'org-budget',
          scanId: 'scan-budget',
          siteId: 'site-budget',
          primaryDomain: '127.0.0.1',
          approvedSubdomains: [],
          status: 'VERIFIED',
          scanBlocked: false,
          expiresAt: Date.now() + 86400000,
          allowedPorts: [testHttpPort],
        });

        // Configure a tight aggregate budget of 15 KB (page 0 uses ~10KB, page 1 uses ~5KB, pages 2 & 3 get 0)
        const maxAgg = 15 * 1024;
        const crawler = new BoundedCrawler(
          context,
          client,
          {
            maxPages: 4,
            maxAggregateBodyChars: maxAgg,
            allowLoopbackForTesting: true,
          }
        );

        const result = await crawler.crawl(`http://127.0.0.1:${testHttpPort}/0`);
        expect(result.pages.length).toBe(4);

        // Aggregate retention bound is strictly respected
        expect(result.cumulativeRetainedBodyChars).toBeDefined();
        expect(result.cumulativeRetainedBodyChars!).toBeLessThanOrEqual(maxAgg);

        let totalRetained = 0;
        for (const p of result.pages) {
          totalRetained += p.bodyText?.length || 0;
        }
        expect(totalRetained).toBe(result.cumulativeRetainedBodyChars);
        expect(totalRetained).toBeLessThanOrEqual(maxAgg);

        // Last page has bodyText === undefined due to budget exhaustion
        expect(result.pages[3]?.bodyText).toBeUndefined();
      } finally {
        await new Promise<void>((resolve) => testHttpServer.close(() => resolve()));
      }
    });

    it('evaluates expired certificate authorization failure and flags TLS_CERTIFICATE_EXPIRED', () => {
      // Simulate failed handshake where OpenSSL rejected with CERT_HAS_EXPIRED
      // Node.js checkServerIdentity is not called when OpenSSL rejects verification,
      // but authorizationError is captured safely from the connection attempt.
      const page = createMockCrawledPage({
        url: 'https://expired.example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: false,
          authorizationError: 'CERT_HAS_EXPIRED',
          peerCertificate: undefined, // OpenSSL freed certificate on handshake abort
        },
      });

      const rule = new TlsRule();
      const findings = rule.evaluate(page);

      // Both untrusted chain AND expired cert are flagged
      expect(findings.some((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_UNTRUSTED')).toBe(true);
      const expiredFinding = findings.find((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_EXPIRED');
      expect(expiredFinding).toBeDefined();
      expect(expiredFinding?.severity).toBe('HIGH');
      expect(expiredFinding?.confidence).toBe('CONFIRMED');
      expect(expiredFinding?.evidence.authorizationError).toBe('CERT_HAS_EXPIRED');
    });

    it('evaluates hostname mismatch error when checkServerIdentity is bypassed or fails before detailed extraction', () => {
      const page = createMockCrawledPage({
        url: 'https://mismatched.example.com/',
        tls: {
          protocol: 'TLSv1.3',
          authorized: false,
          authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID: Hostname/IP does not match cert',
          peerCertificate: undefined,
        },
      });

      const rule = new TlsRule();
      const findings = rule.evaluate(page);

      const mismatchFinding = findings.find((f) => f.vulnerabilityType === 'TLS_CERTIFICATE_HOSTNAME_MISMATCH');
      expect(mismatchFinding).toBeDefined();
      expect(mismatchFinding?.severity).toBe('HIGH');
      expect(mismatchFinding?.confidence).toBe('CONFIRMED');
      expect(mismatchFinding?.evidence.authorizationError).toContain('ERR_TLS_CERT_ALTNAME_INVALID');
    });
  });

});
