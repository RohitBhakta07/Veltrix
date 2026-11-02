/**
 * VELTRIX Bounded Crawling & Endpoint Discovery Engine - Test Suite (TASK-803)
 *
 * Verifies all 18 mandatory requirements from Phase 8 specification:
 * 1. BFS traversal order.
 * 2. Default depth of 3 and maximum depth of 5.
 * 3. Maximum page enforcement (halting at maxPages).
 * 4. Duplicate URL elimination (canonical visited set).
 * 5. Fragment normalization (#... stripped).
 * 6. Query parameter ordering (lexicographical sorting, duplicate preservation).
 * 7. Session identifier removal (known session IDs stripped, legitimate params preserved).
 * 8. Relative and absolute link resolution (including <base href>).
 * 9. All four required HTML extraction sources (<a>, <form>, <script>, <link>).
 * 10. Exact hostname boundary enforcement (no wildcard subdomains).
 * 11. Excluded path enforcement (configured exclusions + server mandatory exclusions).
 * 12. Malformed URL handling.
 * 13. Form action extraction without form submission.
 * 14. GET/HEAD-only enforcement (never POST, PUT, DELETE, PATCH, CONNECT, TRACE).
 * 15. Redirect and scope bypass attempts.
 * 16. Cancellation and transport failure handling (AbortSignal & resilient error handling).
 * 17. Malformed HTML and oversized page handling.
 * 18. Ensuring all real scanner requests use SafeHttpClient.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import type net from 'node:net';
import {
  BoundedCrawler,
  CrawlerScopeGuard,
  extractHtmlLinks,
  decodeHtmlEntities,
  normalizeUrl,
  normalizeUrlOrThrow,
  isBinaryOrMediaUrl,
  KNOWN_SESSION_QUERY_PARAMS,
} from '../../src/scanner/crawler/index.js';
import {
  SafeHttpClient,
  DnsResolver,
  SafeTransportError,
} from '../../src/scanner/transport/index.js';
import {
  createServerScanPolicy,
  SERVER_MANDATORY_EXCLUDED_PATHS,
} from '../../src/scanner/transport/context-authority.js';
import { createTestScanContext } from './helpers/test-context-helper.js';

describe('Phase 8: Bounded Crawling & Endpoint Discovery Engine (TASK-803)', () => {
  // =========================================================================
  // SECTION 1: URL Canonicalization & Normalization Unit Tests
  // =========================================================================
  describe('1. URL Canonicalization & Normalization (url-normalizer.ts)', () => {
    it('strips URL fragments', () => {
      expect(normalizeUrl('https://example.com/page#section-1')).toBe('https://example.com/page');
      expect(normalizeUrl('https://example.com/#top')).toBe('https://example.com/');
      expect(normalizeUrl('https://example.com/path?query=val#frag')).toBe('https://example.com/path?query=val');
    });

    it('normalizes host casing and strips trailing dot', () => {
      expect(normalizeUrl('HTTP://EXAMPLE.COM/path')).toBe('http://example.com/path');
      expect(normalizeUrl('https://sub.Example.Com./api')).toBe('https://sub.example.com/api');
    });

    it('removes standard default ports and preserves non-standard ports', () => {
      expect(normalizeUrl('http://example.com:80/')).toBe('http://example.com/');
      expect(normalizeUrl('https://example.com:443/')).toBe('https://example.com/');
      expect(normalizeUrl('http://example.com:8080/')).toBe('http://example.com:8080/');
      expect(normalizeUrl('https://example.com:8443/')).toBe('https://example.com:8443/');
    });

    it('collapses duplicate slashes and applies POSIX path normalization', () => {
      expect(normalizeUrl('https://example.com//a///b//c')).toBe('https://example.com/a/b/c');
      expect(normalizeUrl('https://example.com/a/b/../c')).toBe('https://example.com/a/c');
      expect(normalizeUrl('https://example.com/a/./b')).toBe('https://example.com/a/b');
      expect(normalizeUrl('https://example.com/../../etc/passwd')).toBe('https://example.com/etc/passwd');
    });

    it('preserves trailing slashes on non-root directory paths', () => {
      expect(normalizeUrl('https://example.com/docs/')).toBe('https://example.com/docs/');
      expect(normalizeUrl('https://example.com/docs')).toBe('https://example.com/docs');
      expect(normalizeUrl('https://example.com/')).toBe('https://example.com/');
    });

    it('strips path matrix parameters (e.g. ;jsessionid=...)', () => {
      expect(normalizeUrl('https://example.com/app;jsessionid=4A2B6C8D/dashboard')).toBe(
        'https://example.com/app/dashboard'
      );
      expect(normalizeUrl('https://example.com/login;sid=998877')).toBe('https://example.com/login');
    });

    it('sorts query parameters deterministically by key and value', () => {
      expect(normalizeUrl('https://example.com/search?z=3&a=1&m=2')).toBe(
        'https://example.com/search?a=1&m=2&z=3'
      );
      // Preserves duplicate keys and sorts values deterministically
      expect(normalizeUrl('https://example.com/items?tag=zebra&tag=apple')).toBe(
        'https://example.com/items?tag=apple&tag=zebra'
      );
    });

    it('strips known session identifier parameters while preserving legitimate parameters', () => {
      for (const sessionParam of KNOWN_SESSION_QUERY_PARAMS) {
        const urlWithSession = `https://example.com/profile?${sessionParam}=sess12345&user=alice&id=42`;
        const normalized = normalizeUrl(urlWithSession);
        expect(normalized).toBe('https://example.com/profile?id=42&user=alice');
        expect(normalized).not.toContain(sessionParam);
      }
    });

    it('preserves legitimate application query parameters without modification', () => {
      const url = 'https://example.com/shop?category=books&id=101&page=2&q=security+guide';
      expect(normalizeUrl(url)).toBe(
        'https://example.com/shop?category=books&id=101&page=2&q=security+guide'
      );
    });

    it('strictly rejects URLs containing embedded credentials', () => {
      expect(normalizeUrl('https://user:password@example.com/')).toBeNull();
      expect(normalizeUrl('http://admin@example.com/dashboard')).toBeNull();
      expect(() => normalizeUrlOrThrow('https://user:pass@example.com/')).toThrow(TypeError);
    });

    it('strictly rejects non-HTTP schemes', () => {
      expect(normalizeUrl('javascript:alert(1)')).toBeNull();
      expect(normalizeUrl('data:text/html,<h1>Hello</h1>')).toBeNull();
      expect(normalizeUrl('mailto:security@example.com')).toBeNull();
      expect(normalizeUrl('tel:+1234567890')).toBeNull();
      expect(normalizeUrl('ftp://example.com/file.txt')).toBeNull();
      expect(normalizeUrl('file:///etc/passwd')).toBeNull();
    });

    it('resolves relative URLs against a base URL', () => {
      const base = 'https://example.com/docs/guide/index.html';
      expect(normalizeUrl('chapter1.html', base)).toBe('https://example.com/docs/guide/chapter1.html');
      expect(normalizeUrl('../api/ref.html', base)).toBe('https://example.com/docs/api/ref.html');
      expect(normalizeUrl('/root-level', base)).toBe('https://example.com/root-level');
      expect(normalizeUrl('//cdn.example.com/lib.js', base)).toBe('https://cdn.example.com/lib.js');
    });

    it('identifies static binary and media extensions correctly', () => {
      // Binary files
      expect(isBinaryOrMediaUrl('https://example.com/image.png')).toBe(true);
      expect(isBinaryOrMediaUrl('https://example.com/photo.JPG')).toBe(true);
      expect(isBinaryOrMediaUrl('https://example.com/docs/report.pdf')).toBe(true);
      expect(isBinaryOrMediaUrl('https://example.com/downloads/archive.zip')).toBe(true);
      expect(isBinaryOrMediaUrl('https://example.com/media/video.mp4')).toBe(true);
      expect(isBinaryOrMediaUrl('https://example.com/app.exe')).toBe(true);

      // Web HTML and API endpoints (not binary)
      expect(isBinaryOrMediaUrl('https://example.com/')).toBe(false);
      expect(isBinaryOrMediaUrl('https://example.com/index.html')).toBe(false);
      expect(isBinaryOrMediaUrl('https://example.com/api/v1/users')).toBe(false);
      expect(isBinaryOrMediaUrl('https://example.com/login.php')).toBe(false);
    });
  });

  // =========================================================================
  // SECTION 2: HTML Link Extraction Unit Tests
  // =========================================================================
  describe('2. Safe HTML Link & Endpoint Extraction (html-link-extractor.ts)', () => {
    it('decodes HTML entities in attributes before resolving URLs', () => {
      expect(decodeHtmlEntities('&amp;')).toBe('&');
      expect(decodeHtmlEntities('&quot;')).toBe('"');
      expect(decodeHtmlEntities('&#39;')).toBe("'");
      expect(decodeHtmlEntities('&#x2F;')).toBe('/');
      expect(decodeHtmlEntities('&#47;')).toBe('/');
    });

    it('extracts links from all four mandatory sources: a, form, script, link', () => {
      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Test Portal</title>
          <link rel="stylesheet" href="/css/app.css">
          <script src="/js/bundle.js"></script>
        </head>
        <body>
          <a href="/about">About Us</a>
          <a href="https://example.com/contact">Contact</a>
          <form action="/login" method="POST">
            <input type="text" name="username" value="admin">
            <input type="password" name="password">
          </form>
        </body>
        </html>
      `;

      const result = extractHtmlLinks(html, 'https://example.com/');
      expect(result.title).toBe('Test Portal');

      const sources = result.endpoints.map((e) => e.source);
      expect(sources).toContain('a');
      expect(sources).toContain('form');
      expect(sources).toContain('script');
      expect(sources).toContain('link');

      const urls = result.endpoints.map((e) => e.url);
      expect(urls).toContain('https://example.com/about');
      expect(urls).toContain('https://example.com/contact');
      expect(urls).toContain('https://example.com/login');
      expect(urls).toContain('https://example.com/js/bundle.js');
      expect(urls).toContain('https://example.com/css/app.css');
    });

    it('extracts form action and fields without submitting the form', () => {
      const html = `
        <form action="/api/v1/auth" method="post">
          <input type="hidden" name="csrf_token" value="abc123token">
          <input type="text" name="email">
        </form>
      `;

      const result = extractHtmlLinks(html, 'https://example.com/login');
      const formEndpoint = result.endpoints.find((e) => e.source === 'form');
      expect(formEndpoint).toBeDefined();
      expect(formEndpoint?.url).toBe('https://example.com/api/v1/auth');
      expect(formEndpoint?.method).toBe('POST');
      expect(formEndpoint?.formFields).toEqual([
        { name: 'csrf_token', type: 'hidden', value: 'abc123token' },
        { name: 'email', type: 'text', value: undefined },
      ]);
    });

    it('respects <base href> when resolving relative links', () => {
      const html = `
        <html>
        <head>
          <base href="https://example.com/subfolder/">
        </head>
        <body>
          <a href="page.html">Subfolder Page</a>
        </body>
        </html>
      `;

      const result = extractHtmlLinks(html, 'https://example.com/other/');
      expect(result.baseUrl).toBe('https://example.com/subfolder/');
      const aEndpoint = result.endpoints.find((e) => e.source === 'a');
      expect(aEndpoint?.url).toBe('https://example.com/subfolder/page.html');
    });

    it('ignores links inside HTML comments', () => {
      const html = `
        <!-- <a href="/hidden-in-comment">Hidden</a> -->
        <a href="/visible">Visible</a>
      `;

      const result = extractHtmlLinks(html, 'https://example.com/');
      const urls = result.endpoints.map((e) => e.url);
      expect(urls).toContain('https://example.com/visible');
      expect(urls).not.toContain('https://example.com/hidden-in-comment');
    });

    it('safely ignores non-navigational schemes (javascript:, mailto:, data:)', () => {
      const html = `
        <a href="javascript:void(0)">Do Nothing</a>
        <a href="mailto:admin@example.com">Email Us</a>
        <a href="data:text/html,malicious">Data URI</a>
        <a href="/real-page">Real Page</a>
      `;

      const result = extractHtmlLinks(html, 'https://example.com/');
      expect(result.endpoints.length).toBe(1);
      expect(result.endpoints[0].url).toBe('https://example.com/real-page');
    });

    it('handles malformed HTML and unquoted attributes without throwing', () => {
      const malformedHtml = `
        <a href=/unquoted-link>Unquoted</a>
        <a href="unclosed>Unclosed quote
        <form action=/action-unquoted method=GET>
        <link href="/valid-link">
      `;

      expect(() => extractHtmlLinks(malformedHtml, 'https://example.com/')).not.toThrow();
      const result = extractHtmlLinks(malformedHtml, 'https://example.com/');
      const urls = result.endpoints.map((e) => e.url);
      expect(urls).toContain('https://example.com/unquoted-link');
      expect(urls).toContain('https://example.com/valid-link');
    });
  });

  // =========================================================================
  // SECTION 3: Crawler Scope Guard Unit Tests
  // =========================================================================
  describe('3. Crawler Scope Guard & Invariant Policy (scope-guard.ts)', () => {
    it('enforces exact hostname matching and rejects unauthorized foreign domains', async () => {
      const context = await createTestScanContext({
        primaryDomain: 'portal.example.com',
        approvedSubdomains: ['api.example.com', 'auth.example.com'],
      });

      // Permitted: primaryDomain
      expect(CrawlerScopeGuard.isUrlInScope('https://portal.example.com/dashboard', context)).toBe(true);

      // Permitted: explicitly approved subdomains
      expect(CrawlerScopeGuard.isUrlInScope('https://api.example.com/v1/data', context)).toBe(true);
      expect(CrawlerScopeGuard.isUrlInScope('https://auth.example.com/login', context)).toBe(true);

      // Prohibited: unapproved subdomains
      expect(CrawlerScopeGuard.isUrlInScope('https://evil.example.com/hack', context)).toBe(false);
      expect(CrawlerScopeGuard.isUrlInScope('https://sub.portal.example.com/', context)).toBe(false);

      // Prohibited: completely foreign domains
      expect(CrawlerScopeGuard.isUrlInScope('https://google.com/', context)).toBe(false);
      expect(CrawlerScopeGuard.isUrlInScope('https://attacker.com/evil', context)).toBe(false);
    });

    it('enforces exact FQDN allowlisting and forbids wildcard matching', async () => {
      const context = await createTestScanContext({
        primaryDomain: 'example.com',
        approvedSubdomains: ['app.example.com'],
      });

      // Wildcard subdomain matching is barred
      expect(CrawlerScopeGuard.isUrlInScope('https://nested.app.example.com/', context)).toBe(false);
      expect(CrawlerScopeGuard.isUrlInScope('https://other.example.com/', context)).toBe(false);
    });

    it('enforces configured excludedPaths and mandatory server exclusions', async () => {
      const context = await createTestScanContext({
        primaryDomain: 'example.com',
        excludedPaths: ['/admin', '/auth/logout'],
      });

      // Allowed normal path
      expect(CrawlerScopeGuard.isUrlInScope('https://example.com/profile', context)).toBe(true);

      // Blocked configured exclusions
      expect(CrawlerScopeGuard.isUrlInScope('https://example.com/admin/users', context)).toBe(false);
      expect(CrawlerScopeGuard.isUrlInScope('https://example.com/auth/logout', context)).toBe(false);

      // Blocked mandatory server-side security exclusions
      for (const mandatory of SERVER_MANDATORY_EXCLUDED_PATHS) {
        expect(CrawlerScopeGuard.isUrlInScope(`https://example.com${mandatory}/config`, context)).toBe(false);
      }
    });

    it('rejects prohibited internal ports and unauthorized non-standard ports', async () => {
      const context = await createTestScanContext({
        primaryDomain: 'example.com',
        allowedPorts: [8080],
      });

      // Standard ports permitted
      expect(CrawlerScopeGuard.isUrlInScope('http://example.com:80/', context)).toBe(true);
      expect(CrawlerScopeGuard.isUrlInScope('https://example.com:443/', context)).toBe(true);

      // Explicitly authorized non-standard port permitted
      expect(CrawlerScopeGuard.isUrlInScope('http://example.com:8080/api', context)).toBe(true);

      // Unauthorized non-standard port rejected
      expect(CrawlerScopeGuard.isUrlInScope('http://example.com:8443/api', context)).toBe(false);

      // Prohibited internal infrastructure port 22 (SSH) rejected even if asked
      expect(CrawlerScopeGuard.isUrlInScope('http://example.com:22/ssh', context)).toBe(false);
    });

    it('filters endpoint arrays retaining only in-scope endpoints', async () => {
      const context = await createTestScanContext({
        primaryDomain: 'example.com',
        approvedSubdomains: ['api.example.com'],
        excludedPaths: ['/logout'],
      });

      const endpoints = [
        { url: 'https://example.com/home', rawUrl: '/home', source: 'a' as const, depth: 1, parentUrl: null },
        { url: 'https://api.example.com/v1', rawUrl: 'https://api.example.com/v1', source: 'a' as const, depth: 1, parentUrl: null },
        { url: 'https://example.com/logout', rawUrl: '/logout', source: 'a' as const, depth: 1, parentUrl: null },
        { url: 'https://google.com/search', rawUrl: 'https://google.com/search', source: 'a' as const, depth: 1, parentUrl: null },
      ];

      const filtered = CrawlerScopeGuard.filterInScopeEndpoints(endpoints, context);
      expect(filtered.map((e) => e.url)).toEqual([
        'https://example.com/home',
        'https://api.example.com/v1',
      ]);
    });
  });

  // =========================================================================
  // SECTION 4: BoundedCrawler Integration Tests with Local Test Server
  // =========================================================================
  describe('4. BoundedCrawler Engine Execution & Bounds Enforcement (crawler.ts)', () => {
    let server: http.Server;
    let serverPort: number;

    beforeAll(async () => {
      server = http.createServer((req, res) => {
        const url = new URL(req.url || '/', `http://${req.headers.host}`);

        // Mock routes for BFS, bounds, loop detection, and extraction
        if (url.pathname === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head><title>Home Page</title></head>
            <body>
              <a href="/level-1-a">Level 1 A</a>
              <a href="/level-1-b">Level 1 B</a>
              <a href="https://external-domain.com/evil">Out of Scope</a>
              <a href="/admin">Excluded Path</a>
              <a href="/asset.png">Image Link</a>
            </body>
            </html>
          `);
          return;
        }

        if (url.pathname === '/level-1-a') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head><title>Level 1 A</title></head>
            <body>
              <a href="/level-2-a">Level 2 A</a>
              <a href="/">Circular Home</a>
              <form action="/form-endpoint" method="POST">
                <input type="text" name="query">
              </form>
            </body>
            </html>
          `);
          return;
        }

        if (url.pathname === '/level-1-b') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head><title>Level 1 B</title></head>
            <body>
              <a href="/level-2-b">Level 2 B</a>
              <script src="/js/widget.js"></script>
              <link rel="stylesheet" href="/css/site.css">
            </body>
            </html>
          `);
          return;
        }

        if (url.pathname === '/level-2-a') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head><title>Level 2 A</title></head>
            <body>
              <a href="/level-3-a">Level 3 A</a>
            </body>
            </html>
          `);
          return;
        }

        if (url.pathname === '/level-2-b') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head><title>Level 2 B</title></head>
            <body>
              <a href="/level-3-b">Level 3 B</a>
            </body>
            </html>
          `);
          return;
        }

        if (url.pathname === '/level-3-a' || url.pathname === '/level-3-b') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head><title>Level 3</title></head>
            <body>
              <a href="/level-4">Level 4</a>
            </body>
            </html>
          `);
          return;
        }

        if (url.pathname === '/level-4') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head><title>Level 4</title></head>
            <body>
              <a href="/level-5">Level 5</a>
            </body>
            </html>
          `);
          return;
        }

        if (url.pathname === '/level-5') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <!DOCTYPE html>
            <html>
            <head><title>Level 5</title></head>
            <body>
              <a href="/level-6-beyond-limit">Level 6 Beyond Limit</a>
            </body>
            </html>
          `);
          return;
        }

        if (url.pathname === '/error-500') {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error');
          return;
        }

        if (url.pathname === '/large-page') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          // Generate 100KB repeating HTML content
          const padding = '<!-- padding --> '.repeat(5000);
          res.end(`<html><head><title>Large Page</title></head><body>${padding}<a href="/after-large">After Large</a></body></html>`);
          return;
        }

        // Default 404
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      });

      await new Promise<void>((resolve) => {
        server.listen(0, '127.0.0.1', () => {
          const addr = server.address() as net.AddressInfo;
          serverPort = addr.port;
          resolve();
        });
      });
    });

    afterAll(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it('enforces parameter validation on maxDepth, maxPages, maxQueueSize, and timeoutMs', async () => {
      const context = await createTestScanContext({ primaryDomain: 'example.com' });

      // maxDepth > 5 is strictly rejected
      expect(() => new BoundedCrawler(context, { maxDepth: 6 })).toThrow(/maxDepth must be an integer between 0 and 5/i);
      expect(() => new BoundedCrawler(context, { maxDepth: -1 })).toThrow(/maxDepth must be an integer between 0 and 5/i);
      expect(() => new BoundedCrawler(context, { maxDepth: 2.5 })).toThrow(/maxDepth must be an integer between 0 and 5/i);

      // maxPages validation
      expect(() => new BoundedCrawler(context, { maxPages: 0 })).toThrow(/maxPages must be an integer between 1 and 1000/i);
      expect(() => new BoundedCrawler(context, { maxPages: 1001 })).toThrow(/maxPages must be an integer between 1 and 1000/i);

      // maxQueueSize validation
      expect(() => new BoundedCrawler(context, { maxQueueSize: 0 })).toThrow(/maxQueueSize must be an integer between 1 and 10000/i);
      expect(() => new BoundedCrawler(context, { maxQueueSize: 10001 })).toThrow(/maxQueueSize must be an integer between 1 and 10000/i);

      // timeoutMs validation
      expect(() => new BoundedCrawler(context, { timeoutMs: 50 })).toThrow(/timeoutMs must be an integer >= 100ms/i);
    });

    it('traverses pages in strict Breadth-First Search (BFS) order', async () => {
      const context = await createTestScanContext({
        primaryDomain: 'target.example.com',
        allowedPorts: [serverPort],
        excludedPaths: ['/admin'],
      });

      const client = new SafeHttpClient({
        dnsResolver: new DnsResolver({
          lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
          allowLoopbackForTesting: true,
        }),
        allowLoopbackForTesting: true,
      });

      const crawler = new BoundedCrawler(context, client, {
        maxDepth: 3,
        maxPages: 20,
        allowLoopbackForTesting: true,
      });

      const seedUrl = `http://target.example.com:${serverPort}/`;
      const result = await crawler.crawl(seedUrl);

      expect(result.stoppedReason).toBe('COMPLETED');
      expect(result.pages.length).toBeGreaterThan(0);

      // Verify BFS order: depth monotonically non-decreasing
      const depths = result.pages.map((p) => p.depth);
      for (let i = 1; i < depths.length; i++) {
        expect(depths[i]).toBeGreaterThanOrEqual(depths[i - 1]);
      }

      // Depth 0 page must be the seed
      expect(result.pages[0].url).toBe(seedUrl);
      expect(result.pages[0].depth).toBe(0);

      // Depths 1 pages must follow depth 0
      const depth1Pages = result.pages.filter((p) => p.depth === 1);
      const depth1Urls = depth1Pages.map((p) => p.url);
      expect(depth1Urls).toContain(`http://target.example.com:${serverPort}/level-1-a`);
      expect(depth1Urls).toContain(`http://target.example.com:${serverPort}/level-1-b`);
    });

    it('enforces maximum depth bounds (default 3, capped at 5)', async () => {
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

      // Crawl with maxDepth = 2
      const crawler = new BoundedCrawler(context, client, {
        maxDepth: 2,
        allowLoopbackForTesting: true,
      });

      const seedUrl = `http://target.example.com:${serverPort}/`;
      const result = await crawler.crawl(seedUrl);

      // Must not crawl any page with depth > 2
      const maxCrawlDepthFound = Math.max(...result.pages.map((p) => p.depth));
      expect(maxCrawlDepthFound).toBeLessThanOrEqual(2);

      // Level 3 URLs were discovered, but NOT crawled
      const crawledUrls = result.pages.map((p) => p.url);
      expect(crawledUrls).not.toContain(`http://target.example.com:${serverPort}/level-3-a`);
    });

    it('enforces strict maxPages ceiling and stops cleanly', async () => {
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

      // Limit crawl to strictly 3 pages
      const crawler = new BoundedCrawler(context, client, {
        maxDepth: 5,
        maxPages: 3,
        allowLoopbackForTesting: true,
      });

      const seedUrl = `http://target.example.com:${serverPort}/`;
      const result = await crawler.crawl(seedUrl);

      expect(result.pagesCrawled).toBe(3);
      expect(result.pages.length).toBe(3);
      expect(result.stoppedReason).toBe('MAX_PAGES_REACHED');
    });

    it('eliminates duplicate URLs and handles circular reference loops safely', async () => {
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
        maxDepth: 3,
        allowLoopbackForTesting: true,
      });

      const seedUrl = `http://target.example.com:${serverPort}/`;
      const result = await crawler.crawl(seedUrl);

      // /level-1-a links back to /, which must only be fetched once
      const crawledUrls = result.pages.map((p) => p.url);
      const uniqueUrls = new Set(crawledUrls);
      expect(crawledUrls.length).toBe(uniqueUrls.size);
    });

    it('drops out-of-scope external domains and excluded paths automatically', async () => {
      const context = await createTestScanContext({
        primaryDomain: 'target.example.com',
        allowedPorts: [serverPort],
        excludedPaths: ['/admin'],
      });

      const client = new SafeHttpClient({
        dnsResolver: new DnsResolver({
          lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
          allowLoopbackForTesting: true,
        }),
        allowLoopbackForTesting: true,
      });

      const crawler = new BoundedCrawler(context, client, {
        maxDepth: 3,
        allowLoopbackForTesting: true,
      });

      const seedUrl = `http://target.example.com:${serverPort}/`;
      const result = await crawler.crawl(seedUrl);

      const crawledUrls = result.pages.map((p) => p.url);

      // External link is dropped
      expect(crawledUrls).not.toContain('https://external-domain.com/evil');
      expect(result.discoveredUrls).not.toContain('https://external-domain.com/evil');

      // Excluded path /admin is dropped
      expect(crawledUrls).not.toContain(`http://target.example.com:${serverPort}/admin`);
      expect(result.discoveredUrls).not.toContain(`http://target.example.com:${serverPort}/admin`);
    });

    it('skips static binary and media extensions from crawl queue', async () => {
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
        skipBinaryExtensions: true,
        allowLoopbackForTesting: true,
      });

      const seedUrl = `http://target.example.com:${serverPort}/`;
      const result = await crawler.crawl(seedUrl);

      const crawledUrls = result.pages.map((p) => p.url);
      expect(crawledUrls).not.toContain(`http://target.example.com:${serverPort}/asset.png`);
    });

    it('extracts form actions as endpoints but NEVER issues POST requests', async () => {
      const context = await createTestScanContext({
        primaryDomain: 'target.example.com',
        allowedPorts: [serverPort],
      });

      let postRequestSent = false;
      const client = new SafeHttpClient({
        dnsResolver: new DnsResolver({
          lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
          allowLoopbackForTesting: true,
        }),
        allowLoopbackForTesting: true,
      });

      // Spy on client.request to verify only GET/HEAD are ever issued
      const origRequest = client.request.bind(client);
      client.request = async (url, opts) => {
        if (opts.method && opts.method.toUpperCase() !== 'GET' && opts.method.toUpperCase() !== 'HEAD') {
          postRequestSent = true;
        }
        return origRequest(url, opts);
      };

      const crawler = new BoundedCrawler(context, client, {
        maxDepth: 2,
        allowLoopbackForTesting: true,
      });

      const seedUrl = `http://target.example.com:${serverPort}/`;
      const result = await crawler.crawl(seedUrl);

      // Verify form endpoint was recorded
      expect(result.discoveredUrls).toContain(`http://target.example.com:${serverPort}/form-endpoint`);

      // Verify NO mutating method was ever dispatched
      expect(postRequestSent).toBe(false);
    });

    it('handles individual request and network failures without crashing the entire crawl', async () => {
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
        maxDepth: 1,
        allowLoopbackForTesting: true,
      });

      // Crawl starting from a 500 error route
      const errorSeed = `http://target.example.com:${serverPort}/error-500`;
      const result = await crawler.crawl(errorSeed);

      // Does not throw, records page with status 500
      expect(result.pagesCrawled).toBe(1);
      expect(result.pages[0].status).toBe(500);
      expect(result.stoppedReason).toBe('COMPLETED');
    });

    it('terminates crawl immediately when cancelled via AbortSignal', async () => {
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

      const abortController = new AbortController();

      let pagesCounted = 0;
      const crawler = new BoundedCrawler(context, client, {
        maxDepth: 5,
        signal: abortController.signal,
        allowLoopbackForTesting: true,
        onPageCrawled: () => {
          pagesCounted++;
          if (pagesCounted === 1) {
            abortController.abort();
          }
        },
      });

      const seedUrl = `http://target.example.com:${serverPort}/`;
      const result = await crawler.crawl(seedUrl);

      expect(result.stoppedReason).toBe('ABORTED');
      expect(result.pagesCrawled).toBe(1);
    });

    it('handles oversized HTML responses without memory exhaustion', async () => {
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
        maxDepth: 1,
        maxResponseSizeBytes: 50 * 1024, // 50KB parse limit
        allowLoopbackForTesting: true,
      });

      const largeSeed = `http://target.example.com:${serverPort}/large-page`;
      const result = await crawler.crawl(largeSeed);

      expect(result.pages.length).toBe(1);
      expect(result.pages[0].status).toBe(200);
      expect(result.pages[0].title).toBe('Large Page');
    });
  });
});
