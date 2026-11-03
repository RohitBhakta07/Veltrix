/**
 * VELTRIX Passive Security Rule: Information Disclosure & Banner Leakage (TASK-804)
 *
 * Inspects existing response headers, body content, and discovered endpoint metadata
 * for information disclosure and technology banner leakage.
 *
 * Invariants:
 * - Operates strictly on existing crawled page data; NEVER generates extra requests.
 * - Never attempts to probe or confirm discovered debug endpoints, .git/HEAD, or .env.
 * - Flags server banners ONLY when version numbers are disclosed (avoids flagging harmless names).
 * - Identifies detailed stack traces and framework error disclosures in response bodies.
 */

import type { CrawledPage } from '../../crawler/types.js';
import {
  type PassiveRuleInterface,
  type ScannerFinding,
  RULE_PASSIVE_DISCLOSURE,
} from '../../types.js';

export class BannerDisclosureRule implements PassiveRuleInterface {
  public readonly id = RULE_PASSIVE_DISCLOSURE;
  public readonly name = 'Passive Information Disclosure & Banner Leakage Rule';
  public readonly description =
    'Detects server version disclosure, X-Powered-By leakage, referenced debug endpoints, stack traces, and exposed sensitive file content from existing response data.';

  // Known sensitive debug, diagnostic, and management path patterns
  private static readonly DEBUG_PATH_PATTERNS: readonly RegExp[] = [
    /(?:^|\/)(?:phpinfo\.php|_profiler|actuator(?:\/[a-zA-Z0-9_\-]+)?|elmah\.axd|trace\.axd|swagger-ui(?:\.html)?|\.git\/HEAD|\.env|server-status|web\.config|server-info)(?:$|[?#\/])/i,
  ];

  // Stack trace and framework error signatures across major runtimes
  private static readonly STACK_TRACE_PATTERNS: readonly { readonly name: string; readonly pattern: RegExp }[] = [
    {
      name: 'Node.js',
      pattern: /(?:\bat (?:async )?[a-zA-Z0-9_$.<>]+\s+\([^)]+:\d+:\d+\)|\bError: [^\n]+\n\s+at [a-zA-Z0-9_$.<>]+\s+\()/i,
    },
    {
      name: 'Python',
      pattern: /Traceback \(most recent call last\):[\s\S]{1,600}?File "[^"]+", line \d+/i,
    },
    {
      name: 'Java',
      pattern: /(?:java\.[a-z.]+(?:Exception|Error)|[a-zA-Z0-9_.]+Exception): [^\n]+\n\s+at [a-zA-Z0-9_.$]+\([A-Za-z0-9_]+\.java:\d+\)/i,
    },
    {
      name: 'PHP',
      pattern: /(?:Fatal error|Parse error|Uncaught Exception|Warning): [^\n]+ in \/[^\n]+ on line \d+/i,
    },
    {
      name: '.NET / ASP',
      pattern: /(?:System\.[a-zA-Z0-9_.]+Exception: [^\n]+\n\s+at |Server Error in '\/' Application\.[\s\S]{1,500}Source File: )/i,
    },
  ];

  public evaluate(page: CrawledPage): readonly ScannerFinding[] {
    const findings: ScannerFinding[] = [];
    const headers = page.headers || {};
    const body = page.bodyText || page.rawBody?.toString('utf8') || '';

    // 1. Web Server Banner Version Disclosure
    const serverHeader = headers['server'];
    if (serverHeader && typeof serverHeader === 'string') {
      const trimmedServer = serverHeader.trim();
      // Only flag when version numbers are disclosed (e.g. Apache/2.4.41, nginx/1.18.0, Microsoft-IIS/10.0)
      // Generic banners like "nginx" or "cloudflare" are harmless and not flagged
      const versionPattern = /[a-zA-Z\-_]+(?:\/|\s+)\d+(?:\.\d+)+/i;
      if (versionPattern.test(trimmedServer)) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'SERVER_VERSION_DISCLOSURE',
            title: 'Web Server Version Banner Disclosure',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            description: `The 'Server' response header on ${page.url} discloses specific web server software and version numbers: '${trimmedServer}'. This assists attackers in vulnerability fingerprinting.`,
            remediation:
              'Configure the web server to suppress or genericize the Server header (e.g., "ServerTokens Prod" in Apache, "server_tokens off;" in nginx).',
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              serverHeader: trimmedServer,
            }),
          })
        );
      }
    }

    // 2. X-Powered-By Technology Stack Disclosure
    const xPoweredBy = headers['x-powered-by'];
    if (xPoweredBy && typeof xPoweredBy === 'string' && xPoweredBy.trim().length > 0) {
      const trimmedPoweredBy = xPoweredBy.trim();
      findings.push(
        Object.freeze({
          ruleId: this.id,
          vulnerabilityType: 'X_POWERED_BY_DISCLOSURE',
          title: 'Runtime Technology Stack Disclosure via X-Powered-By',
          severity: 'LOW',
          confidence: 'CONFIRMED',
          description: `The 'X-Powered-By' header on ${page.url} discloses backend technology stack information: '${trimmedPoweredBy}'.`,
          remediation:
            'Disable the X-Powered-By header in application or framework settings (e.g., app.disable("x-powered-by") in Express, expose_php = Off in php.ini).',
          url: page.url,
          evidence: Object.freeze({
            targetUrl: page.url,
            xPoweredByHeader: trimmedPoweredBy,
          }),
        })
      );
    }

    // 3. Sensitive Debug / Management Endpoint References in Discovered Endpoints
    if (page.discoveredEndpoints && page.discoveredEndpoints.length > 0) {
      const seenDebugUrls = new Set<string>();

      for (const ep of page.discoveredEndpoints) {
        if (seenDebugUrls.has(ep.url)) continue;

        let pathname = '';
        try {
          pathname = new URL(ep.url).pathname;
        } catch {
          pathname = ep.url;
        }

        const isDebugMatch = BannerDisclosureRule.DEBUG_PATH_PATTERNS.some((pat) =>
          pat.test(pathname)
        );

        if (isDebugMatch) {
          seenDebugUrls.add(ep.url);
          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'DEBUG_ENDPOINT_DISCLOSURE',
              title: 'Sensitive Debug, Diagnostic, or Configuration Endpoint Referenced',
              severity: 'MEDIUM',
              confidence: 'HIGH',
              description: `A reference to a sensitive debug, management, or administrative endpoint was discovered on ${page.url}: '${ep.url}'. Passive inspection identified this surface reference without active probing.`,
              remediation:
                'Remove references to debug and administrative endpoints from public client HTML. Restrict internal endpoints with network ACLs or reverse-proxy controls.',
              url: page.url,
              endpoint: ep.url,
              evidence: Object.freeze({
                targetUrl: page.url,
                referencingUrl: page.url,
                referencedEndpoint: ep.url,
                rawLinkSource: ep.source,
                discoveredPath: pathname,
                observation:
                  'Endpoint referenced in crawled HTML source; zero additional requests were made.',
              }),
            })
          );
        }
      }
    }

    // 4. Detailed Stack Trace Disclosures in Body
    if (body.length > 0) {
      for (const { name: runtimeName, pattern } of BannerDisclosureRule.STACK_TRACE_PATTERNS) {
        const match = pattern.exec(body);
        if (match) {
          const matchIndex = match.index;
          const snippetStart = Math.max(0, matchIndex - 40);
          const snippetEnd = Math.min(body.length, matchIndex + match[0].length + 40);
          const snippet = body.slice(snippetStart, snippetEnd).trim();

          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'STACK_TRACE_DISCLOSURE',
              title: `Detailed ${runtimeName} Stack Trace Disclosed in Response`,
              severity: 'MEDIUM',
              confidence: 'HIGH',
              description: `A detailed application stack trace (${runtimeName}) was detected in the response body of ${page.url}, exposing internal code paths, line numbers, or framework exceptions.`,
              remediation:
                'Implement centralized custom error handling pages. Ensure debug mode and verbose stack traces are disabled in production environments.',
              url: page.url,
              evidence: Object.freeze({
                targetUrl: page.url,
                detectedRuntime: runtimeName,
                responseStatus: page.status,
                responseBodySnippet: snippet.slice(0, 300),
              }),
            })
          );
          break; // Stop after first matched stack trace to avoid duplicate findings for the same error dump
        }
      }
    }

    // 5. Exposed Source Repository (.git/HEAD) or Environment (.env) in Response Body
    if (body.length > 0) {
      // Check .git/HEAD signature
      const isGitHead =
        /^ref:\s+refs\/heads\/[a-zA-Z0-9_\-\/]+/m.test(body) ||
        (/^[0-9a-f]{40}\s*$/m.test(body) && page.url.includes('.git/HEAD'));

      if (isGitHead) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'EXPOSED_SENSITIVE_FILE',
            title: 'Exposed Git Source Repository Metadata (.git/HEAD)',
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            description: `The response body of ${page.url} contains definitive contents of a Git repository HEAD reference, indicating that the source repository is publicly accessible.`,
            remediation:
              'Configure web server access rules to strictly deny access to dotfiles and the .git directory.',
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              fileType: '.git/HEAD',
              responseBodySnippet: body.slice(0, 100),
            }),
          })
        );
      }

      // Check .env signature
      const envMatch =
        /(?:(?:DB|DATABASE|MYSQL|POSTGRES)_(?:PASSWORD|PASS|URL)|AWS_SECRET_ACCESS_KEY|JWT_SECRET|API_KEY)\s*=[^\s]+/i.exec(
          body
        );

      if (envMatch) {
        const sanitizedEnvSnippet = envMatch[0].replace(/=.*$/, '=[REDACTED]');
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'EXPOSED_SENSITIVE_FILE',
            title: 'Exposed Environment Configuration File (.env)',
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            description: `The response body of ${page.url} contains environment variable configuration keys (e.g., credentials, secrets, database connection strings).`,
            remediation:
              'Remove the .env file from the web server public directory immediately and rotate all exposed secrets and credentials.',
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              fileType: '.env',
              matchedSignature: sanitizedEnvSnippet,
            }),
          })
        );
      }
    }

    return Object.freeze(findings);
  }
}
