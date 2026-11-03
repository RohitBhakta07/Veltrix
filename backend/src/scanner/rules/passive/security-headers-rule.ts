/**
 * VELTRIX Passive Security Rule: HTTP Security Headers Assessment (TASK-804)
 *
 * Evaluates server response headers for presence, syntax, and defensive strength:
 * - Strict-Transport-Security (HSTS) on HTTPS responses.
 * - Content-Security-Policy (CSP) with directive-level parsing (unsafe-inline, unsafe-eval, wildcard *).
 * - X-Frame-Options (DENY, SAMEORIGIN).
 * - X-Content-Type-Options (nosniff).
 * - Referrer-Policy (restrictive policies vs. unsafe-url).
 * - Permissions-Policy (camera, microphone, geolocation restrictions).
 *
 * Invariants:
 * - Never makes extra network requests.
 * - Protocol-aware: HSTS absence is not flagged on unencrypted HTTP responses.
 * - Directive-aware: Avoids substring-based false positives in CSP.
 */

import type { CrawledPage } from '../../crawler/types.js';
import {
  type PassiveRuleInterface,
  type ScannerFinding,
  RULE_PASSIVE_HEADERS,
} from '../../types.js';

export class SecurityHeadersRule implements PassiveRuleInterface {
  public readonly id = RULE_PASSIVE_HEADERS;
  public readonly name = 'Passive HTTP Security Headers Rule';
  public readonly description =
    'Evaluates presence, syntax, and strength of essential HTTP security headers on crawled responses.';

  public evaluate(page: CrawledPage): readonly ScannerFinding[] {
    const findings: ScannerFinding[] = [];
    const headers = page.headers || {};
    const isHttps = page.url.startsWith('https://');

    // 1. Strict-Transport-Security (HSTS) - HTTPS only
    if (isHttps) {
      const hstsHeader = headers['strict-transport-security'];
      if (!hstsHeader || hstsHeader.trim().length === 0) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'MISSING_HSTS_HEADER',
            title: 'Missing Strict-Transport-Security (HSTS) Header',
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            description: `The HTTPS endpoint ${page.url} does not declare a Strict-Transport-Security header, allowing potential SSL-stripping and man-in-the-middle attacks.`,
            remediation:
              'Configure the web server to send "Strict-Transport-Security: max-age=31536000; includeSubDomains" on all HTTPS responses.',
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              protocol: 'https',
              observation: 'Strict-Transport-Security header is absent.',
            }),
          })
        );
      } else {
        const rawHsts = hstsHeader.trim();
        const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(rawHsts);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1] ?? '0', 10) : null;

        if (maxAge === null || maxAge < 31536000) {
          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'WEAK_HSTS_HEADER',
              title: 'HSTS max-age Below Recommended 1-Year Threshold',
              severity: 'LOW',
              confidence: 'CONFIRMED',
              description: `The Strict-Transport-Security header on ${page.url} defines a max-age of ${
                maxAge ?? 0
              } seconds, which is below the recommended minimum of 31536000 seconds (1 year).`,
              remediation:
                'Update Strict-Transport-Security to specify max-age=31536000 or greater.',
              url: page.url,
              evidence: Object.freeze({
                targetUrl: page.url,
                headerValue: rawHsts,
                maxAge: maxAge ?? 0,
                recommendedMinMaxAge: 31536000,
              }),
            })
          );
        }

        if (!/\bincludesubdomains\b/i.test(rawHsts)) {
          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'WEAK_HSTS_HEADER',
              title: 'HSTS Header Missing includeSubDomains Directive',
              severity: 'LOW',
              confidence: 'CONFIRMED',
              description: `The Strict-Transport-Security header on ${page.url} does not include the includeSubDomains directive, leaving subdomains vulnerable to protocol downgrade attacks.`,
              remediation:
                'Add the "includeSubDomains" directive to the Strict-Transport-Security header.',
              url: page.url,
              evidence: Object.freeze({
                targetUrl: page.url,
                headerValue: rawHsts,
                missingDirective: 'includeSubDomains',
              }),
            })
          );
        }
      }
    }

    // 2. Content-Security-Policy (CSP)
    const cspHeader = headers['content-security-policy'];
    let cspDirectives: Map<string, Set<string>> | null = null;

    if (!cspHeader || cspHeader.trim().length === 0) {
      findings.push(
        Object.freeze({
          ruleId: this.id,
          vulnerabilityType: 'MISSING_CONTENT_SECURITY_POLICY',
          title: 'Missing Content-Security-Policy (CSP) Header',
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          description: `No Content-Security-Policy header was detected on ${page.url}. CSP provides defense-in-depth against Cross-Site Scripting (XSS), data injection, and malicious frame embedding.`,
          remediation:
            'Define and deploy a Content-Security-Policy header restricting script execution, style sources, and object embedding.',
          url: page.url,
          evidence: Object.freeze({
            targetUrl: page.url,
            observation: 'Content-Security-Policy header is absent.',
          }),
        })
      );
    } else {
      cspDirectives = this.parseCspDirectives(cspHeader);

      // Check unsafe-inline in script directives
      const scriptTokens = this.getCspTokens(cspDirectives, ['script-src', 'script-src-elem', 'default-src']);
      if (scriptTokens.has("'unsafe-inline'")) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'WEAK_CSP_HEADER',
            title: "Content-Security-Policy Contains 'unsafe-inline' Directive",
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            description: `The Content-Security-Policy header on ${page.url} allows 'unsafe-inline' in script directives, negating XSS protection for inline scripts and event handlers.`,
            remediation:
              "Remove 'unsafe-inline' from script-src directives. Migrate inline code to external scripts or use cryptographic nonces ('nonce-...') or hashes ('sha256-...').",
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              directiveMatched: "'unsafe-inline'",
              headerSnippet: cspHeader.slice(0, 300),
            }),
          })
        );
      }

      // Check unsafe-eval in script directives
      if (scriptTokens.has("'unsafe-eval'")) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'WEAK_CSP_HEADER',
            title: "Content-Security-Policy Contains 'unsafe-eval' Directive",
            severity: 'LOW',
            confidence: 'CONFIRMED',
            description: `The Content-Security-Policy header on ${page.url} allows 'unsafe-eval', enabling dynamic string-to-code execution (eval, Function constructor).`,
            remediation:
              "Refactor dynamic code execution and remove 'unsafe-eval' from the Content-Security-Policy.",
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              directiveMatched: "'unsafe-eval'",
              headerSnippet: cspHeader.slice(0, 300),
            }),
          })
        );
      }

      // Check wildcard * origins in sensitive directives
      const sensitiveTokens = this.getCspTokens(cspDirectives, [
        'default-src',
        'script-src',
        'connect-src',
        'object-src',
      ]);
      if (sensitiveTokens.has('*')) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'WEAK_CSP_HEADER',
            title: "Content-Security-Policy Uses Overly Permissive Wildcard Origin (*)",
            severity: 'LOW',
            confidence: 'CONFIRMED',
            description: `The Content-Security-Policy header on ${page.url} uses wildcard origin '*' in sensitive resource fetch/script directives, permitting content loading from any domain.`,
            remediation:
              "Replace wildcard '*' origins with explicit trusted domains or 'self'.",
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              directiveMatched: '*',
              headerSnippet: cspHeader.slice(0, 300),
            }),
          })
        );
      }
    }

    // 3. X-Frame-Options (Clickjacking defense)
    const xfoHeader = headers['x-frame-options'];
    const hasFrameAncestors =
      cspDirectives !== null && cspDirectives.has('frame-ancestors');

    if (!xfoHeader || xfoHeader.trim().length === 0) {
      if (!hasFrameAncestors) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'MISSING_FRAME_OPTIONS',
            title: 'Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            description: `The response from ${page.url} lacks both an X-Frame-Options header and a CSP frame-ancestors directive, exposing users to UI redressing and clickjacking.`,
            remediation:
              'Set "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN", or enforce a CSP "frame-ancestors \'none\'" directive.',
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              observation: 'X-Frame-Options and CSP frame-ancestors are absent.',
            }),
          })
        );
      }
    } else {
      const xfoVal = xfoHeader.trim().toUpperCase();
      if (xfoVal !== 'DENY' && xfoVal !== 'SAMEORIGIN') {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'INVALID_FRAME_OPTIONS',
            title: 'Invalid or Deprecated X-Frame-Options Header Value',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            description: `The X-Frame-Options header on ${page.url} is set to '${xfoHeader}', which is invalid or deprecated (only DENY and SAMEORIGIN are standard).`,
            remediation:
              'Update X-Frame-Options to strictly "DENY" or "SAMEORIGIN".',
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              headerValue: xfoHeader,
            }),
          })
        );
      }
    }

    // 4. X-Content-Type-Options (MIME-sniffing prevention)
    const xctoHeader = headers['x-content-type-options'];
    if (!xctoHeader || xctoHeader.trim().toLowerCase() !== 'nosniff') {
      findings.push(
        Object.freeze({
          ruleId: this.id,
          vulnerabilityType: 'MISSING_CONTENT_TYPE_OPTIONS',
          title: "Missing 'X-Content-Type-Options: nosniff' Header",
          severity: 'LOW',
          confidence: 'CONFIRMED',
          description: `The response from ${page.url} lacks 'X-Content-Type-Options: nosniff', which permits browsers to MIME-sniff responses away from the declared content-type.`,
          remediation:
            'Add "X-Content-Type-Options: nosniff" to all server HTTP responses.',
          url: page.url,
          evidence: Object.freeze({
            targetUrl: page.url,
            headerValue: xctoHeader || 'absent',
          }),
        })
      );
    }

    // 5. Referrer-Policy
    const referrerPolicyHeader = headers['referrer-policy'];
    if (!referrerPolicyHeader || referrerPolicyHeader.trim().length === 0) {
      findings.push(
        Object.freeze({
          ruleId: this.id,
          vulnerabilityType: 'MISSING_REFERRER_POLICY',
          title: 'Missing Referrer-Policy Header',
          severity: 'LOW',
          confidence: 'CONFIRMED',
          description: `The response from ${page.url} does not declare a Referrer-Policy header.`,
          remediation:
            'Set "Referrer-Policy: strict-origin-when-cross-origin" or "Referrer-Policy: no-referrer".',
          url: page.url,
          evidence: Object.freeze({
            targetUrl: page.url,
            observation: 'Referrer-Policy header is absent.',
          }),
        })
      );
    } else {
      const lowerPolicy = referrerPolicyHeader.trim().toLowerCase();
      if (lowerPolicy.includes('unsafe-url')) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'WEAK_REFERRER_POLICY',
            title: "Permissive Referrer-Policy ('unsafe-url')",
            severity: 'LOW',
            confidence: 'CONFIRMED',
            description: `The Referrer-Policy on ${page.url} is configured with 'unsafe-url', which transmits full URLs including sensitive path and query parameters to external origins.`,
            remediation:
              'Change Referrer-Policy to "strict-origin-when-cross-origin" or "no-referrer".',
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              headerValue: referrerPolicyHeader,
            }),
          })
        );
      }
    }

    // 6. Permissions-Policy
    const permissionsPolicyHeader =
      headers['permissions-policy'] || headers['feature-policy'];
    if (!permissionsPolicyHeader || permissionsPolicyHeader.trim().length === 0) {
      findings.push(
        Object.freeze({
          ruleId: this.id,
          vulnerabilityType: 'MISSING_PERMISSIONS_POLICY',
          title: 'Missing Permissions-Policy Header',
          severity: 'LOW',
          confidence: 'CONFIRMED',
          description: `The response from ${page.url} does not declare a Permissions-Policy header to control browser device APIs and features.`,
          remediation:
            'Configure "Permissions-Policy: camera=(), microphone=(), geolocation=()" to restrict sensitive device APIs.',
          url: page.url,
          evidence: Object.freeze({
            targetUrl: page.url,
            observation: 'Permissions-Policy header is absent.',
          }),
        })
      );
    } else {
      const rawPerms = permissionsPolicyHeader.trim().toLowerCase();
      // Check whether camera, microphone, and geolocation are restricted
      const hasCamera = rawPerms.includes('camera');
      const hasMicrophone = rawPerms.includes('microphone');
      const hasGeolocation = rawPerms.includes('geolocation');
      const hasWildcardFeature =
        rawPerms.includes('camera=*') ||
        rawPerms.includes('microphone=*') ||
        rawPerms.includes('geolocation=*');

      if (!hasCamera || !hasMicrophone || !hasGeolocation || hasWildcardFeature) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'WEAK_PERMISSIONS_POLICY',
            title: 'Unrestricted Sensitive Features in Permissions-Policy',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            description: `The Permissions-Policy header on ${page.url} does not restrict one or more sensitive browser capabilities (camera, microphone, or geolocation) or grants them wildcard access (*).`,
            remediation:
              'Explicitly restrict camera=(), microphone=(), and geolocation=() in Permissions-Policy.',
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              headerValue: permissionsPolicyHeader,
              missingOrWildcardFeatures: {
                cameraRestricted: hasCamera && !rawPerms.includes('camera=*'),
                microphoneRestricted: hasMicrophone && !rawPerms.includes('microphone=*'),
                geolocationRestricted: hasGeolocation && !rawPerms.includes('geolocation=*'),
              },
            }),
          })
        );
      }
    }

    return Object.freeze(findings);
  }

  /**
   * Parses CSP header into directive names and sets of distinct tokens.
   */
  private parseCspDirectives(cspHeader: string): Map<string, Set<string>> {
    const directives = new Map<string, Set<string>>();
    const rawDirectives = cspHeader.split(';');

    for (const rawDirective of rawDirectives) {
      const trimmed = rawDirective.trim();
      if (!trimmed) continue;

      const tokens = trimmed.split(/\s+/).filter(Boolean);
      const name = tokens[0]?.toLowerCase();
      if (!name) continue;

      const values = new Set<string>();
      for (let i = 1; i < tokens.length; i++) {
        const token = tokens[i];
        if (token) {
          values.add(token.toLowerCase());
        }
      }
      directives.set(name, values);
    }

    return directives;
  }

  /**
   * Collects tokens across multiple CSP directive names.
   */
  private getCspTokens(
    directives: Map<string, Set<string>>,
    directiveNames: readonly string[]
  ): Set<string> {
    const result = new Set<string>();
    for (const name of directiveNames) {
      const set = directives.get(name);
      if (set) {
        for (const token of set) {
          result.add(token);
        }
      }
    }
    return result;
  }
}
