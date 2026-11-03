/**
 * VELTRIX Passive Security Assessment Pipeline - PassiveAnalyzer (TASK-804)
 *
 * Implements the zero-intrusion, zero-extra-request passive security analysis engine.
 * Inspects server response data already collected by the crawler and SafeHttpClient.
 *
 * Invariants:
 * - Never makes additional network requests (0 calls to fetch, http, https, net, or SafeHttpClient).
 * - Never runs active vulnerability probes or executes JavaScript.
 * - Deterministically evaluates:
 *   1. TLS / SSL configuration (obsolete protocols, certificate validity, expiration, hostname matching).
 *   2. HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
 *   3. Cookie security attributes (Secure, HttpOnly, SameSite).
 *   4. Information disclosure (Server banner version, X-Powered-By, debug endpoint references, stack traces, sensitive files).
 * - Deduplicates findings deterministically.
 */

import type { CrawledPage, CrawlResult } from '../crawler/types.js';
import type {
  PassiveRuleInterface,
  ScannerFinding,
} from '../types.js';
import { TlsRule, type TlsRuleOptions } from '../rules/passive/tls-rule.js';
import { SecurityHeadersRule } from '../rules/passive/security-headers-rule.js';
import { CookieFlagsRule } from '../rules/passive/cookie-flags-rule.js';
import { BannerDisclosureRule } from '../rules/passive/banner-disclosure-rule.js';

export interface PassiveAnalyzerOptions {
  /**
   * Custom rule instances. If omitted, defaults to all 4 standard passive rules.
   */
  readonly rules?: readonly PassiveRuleInterface[];

  /**
   * Optional allowlist of rule IDs to execute. If omitted, all registered rules run.
   */
  readonly enabledRuleIds?: readonly string[];

  /**
   * Options passed to the TLS evaluation rule (e.g. mock current time for expiration checks).
   */
  readonly tlsRuleOptions?: TlsRuleOptions;
}

export class PassiveAnalyzer {
  private readonly rules: readonly PassiveRuleInterface[];

  constructor(options?: PassiveAnalyzerOptions) {
    if (options?.rules && options.rules.length > 0) {
      this.rules = Object.freeze([...options.rules]);
    } else {
      // Default to the 4 canonical passive assessment rules
      this.rules = Object.freeze([
        new TlsRule(options?.tlsRuleOptions),
        new SecurityHeadersRule(),
        new CookieFlagsRule(),
        new BannerDisclosureRule(),
      ]);
    }

    if (options?.enabledRuleIds && options.enabledRuleIds.length > 0) {
      const allowedSet = new Set(options.enabledRuleIds);
      this.rules = Object.freeze(this.rules.filter((r) => allowedSet.has(r.id)));
    }
  }

  /**
   * Returns all currently active rule identifiers.
   */
  public getActiveRuleIds(): readonly string[] {
    return Object.freeze(this.rules.map((r) => r.id));
  }

  /**
   * Performs passive security evaluation across crawled pages.
   *
   * @param input A single CrawledPage, an array of CrawledPages, or a CrawlResult.
   * @returns Deduplicated array of deterministic ScannerFindings.
   */
  public async analyze(
    input: CrawledPage | readonly CrawledPage[] | CrawlResult
  ): Promise<readonly ScannerFinding[]> {
    const pages: readonly CrawledPage[] = this.normalizeInput(input);
    const findings: ScannerFinding[] = [];
    const seenFindingKeys = new Set<string>();

    for (const page of pages) {
      for (const rule of this.rules) {
        const ruleFindings = await Promise.resolve(rule.evaluate(page, pages));

        for (const finding of ruleFindings) {
          const dedupeKey = this.computeDeduplicationKey(finding);
          if (!seenFindingKeys.has(dedupeKey)) {
            seenFindingKeys.add(dedupeKey);
            findings.push(finding);
          }
        }
      }
    }

    return Object.freeze(findings);
  }

  /**
   * Evaluates a single crawled page synchronously or asynchronously.
   */
  public async analyzePage(page: CrawledPage): Promise<readonly ScannerFinding[]> {
    return this.analyze(page);
  }

  private normalizeInput(
    input: CrawledPage | readonly CrawledPage[] | CrawlResult
  ): readonly CrawledPage[] {
    if (Array.isArray(input)) {
      return input;
    }
    if ('pages' in input && Array.isArray(input.pages)) {
      return input.pages;
    }
    return [input as CrawledPage];
  }

  private computeDeduplicationKey(finding: ScannerFinding): string {
    const ep = finding.endpoint || '';
    return `${finding.ruleId}:${finding.vulnerabilityType}:${finding.url}:${finding.title}:${ep}`;
  }
}
