/**
 * VELTRIX Crawler Scope Guard & Target Boundary Policy (TASK-803)
 *
 * Enforces strict tenant authorization boundaries during link discovery and crawling:
 * - Exact hostname matching against primaryDomain and approvedSubdomains (no wildcards).
 * - Categorical enforcement of excludedPaths and mandatory server exclusions.
 * - Rejection of out-of-scope schemes, non-standard unauthorized ports, and credentials.
 * - Direct integration with TASK-802 AuthorizedScanScopeGuard.
 */

import {
  type AuthorizedScanScopeContext,
  isBlockedInternalPort,
} from '../transport/types.js';
import {
  AuthorizedScanScopeGuard,
} from '../transport/scope-guard.js';
import { SERVER_MANDATORY_EXCLUDED_PATHS } from '../transport/context-authority.js';
import type { DiscoveredEndpoint } from './types.js';
import { normalizeUrl } from './url-normalizer.js';

export interface CrawlerScopeCheckResult {
  readonly inScope: boolean;
  readonly reason?: string;
  readonly normalizedUrl?: string;
}

export class CrawlerScopeGuard {
  /**
   * Derives the exact set of approved FQDN hostnames authorized for crawling.
   * Wildcards are strictly forbidden; each subdomain must be explicitly registered.
   */
  static getAllowedHosts(context: AuthorizedScanScopeContext): Set<string> {
    const allowed = new Set<string>();
    if (context.primaryDomain && typeof context.primaryDomain === 'string') {
      allowed.add(context.primaryDomain.trim().toLowerCase());
    }
    if (Array.isArray(context.approvedSubdomains)) {
      for (const sub of context.approvedSubdomains) {
        if (typeof sub === 'string' && sub.trim().length > 0) {
          allowed.add(sub.trim().toLowerCase());
        }
      }
    }
    return allowed;
  }

  /**
   * Evaluates whether a candidate URL is within the authorized crawl scope.
   *
   * @param rawUrl The URL string or URL instance to test.
   * @param context The authoritative scan scope context.
   * @returns Detailed scope check result.
   */
  static evaluate(
    rawUrl: string | URL,
    context: AuthorizedScanScopeContext
  ): CrawlerScopeCheckResult {
    let parsed: URL;
    try {
      parsed = typeof rawUrl === 'string' ? new URL(rawUrl) : rawUrl;
    } catch {
      return { inScope: false, reason: `Malformed or unparseable URL: '${String(rawUrl)}'` };
    }

    // 1. Credentials Check: Reject URLs with embedded credentials
    if (parsed.username || parsed.password) {
      return { inScope: false, reason: 'URL contains embedded user credentials.' };
    }

    // 2. Protocol Check: Only http: and https: are permitted
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { inScope: false, reason: `Protocol '${parsed.protocol}' is out of scope. Only HTTP/HTTPS allowed.` };
    }

    // 3. Exact Hostname Boundary Check (No Wildcards)
    const allowedHosts = CrawlerScopeGuard.getAllowedHosts(context);
    const targetHost = parsed.hostname.toLowerCase();
    if (!allowedHosts.has(targetHost)) {
      return {
        inScope: false,
        reason: `Target host '${targetHost}' is not in authorized scan scope [${Array.from(allowedHosts).join(', ')}].`,
      };
    }

    // 4. Port Validation & Internal Port Blocking
    const isHttps = parsed.protocol === 'https:';
    const defaultPort = isHttps ? 443 : 80;
    const port = parsed.port ? parseInt(parsed.port, 10) : defaultPort;

    if (isNaN(port) || port < 1 || port > 65535) {
      return { inScope: false, reason: `Invalid destination port '${parsed.port}'.` };
    }

    if (isBlockedInternalPort(port)) {
      return { inScope: false, reason: `Port ${port} is a prohibited internal infrastructure port.` };
    }

    const isStandardPort = (isHttps && port === 443) || (!isHttps && port === 80);
    const isWhitelistedPort = context.allowedPorts && context.allowedPorts.includes(port);
    if (!isStandardPort && !isWhitelistedPort) {
      return {
        inScope: false,
        reason: `Port ${port} is non-standard and has not been explicitly authorized for '${parsed.protocol}'.`,
      };
    }

    // 5. Excluded Paths Check
    const rawPath = parsed.pathname;
    const exclusions = [
      ...SERVER_MANDATORY_EXCLUDED_PATHS,
      ...(context.excludedPaths || []),
    ];

    for (const rule of exclusions) {
      if (typeof rule === 'string' && rule.length > 0) {
        if (rawPath.startsWith(rule)) {
          return {
            inScope: false,
            reason: `Path '${rawPath}' matches excluded path prefix '${rule}'.`,
          };
        }
      }
    }

    // 6. Verification with AuthorizedScanScopeGuard for transport-level invariants
    try {
      AuthorizedScanScopeGuard.validate(parsed, 'GET', context);
    } catch (guardErr) {
      const message = guardErr instanceof Error ? guardErr.message : String(guardErr);
      return { inScope: false, reason: `Scope guard rejected URL: ${message}` };
    }

    // 7. Canonical URL normalization check
    const normalized = normalizeUrl(parsed.toString());
    if (!normalized) {
      return { inScope: false, reason: 'URL failed canonical normalization.' };
    }

    return { inScope: true, normalizedUrl: normalized };
  }

  /**
   * Convenience boolean predicate testing whether a URL is in authorized scope.
   */
  static isUrlInScope(url: string | URL, context: AuthorizedScanScopeContext): boolean {
    return CrawlerScopeGuard.evaluate(url, context).inScope;
  }

  /**
   * Filters a list of discovered endpoints, retaining only those within authorized scope.
   */
  static filterInScopeEndpoints(
    endpoints: readonly DiscoveredEndpoint[],
    context: AuthorizedScanScopeContext
  ): DiscoveredEndpoint[] {
    const inScopeEndpoints: DiscoveredEndpoint[] = [];
    for (const ep of endpoints) {
      if (CrawlerScopeGuard.isUrlInScope(ep.url, context)) {
        inScopeEndpoints.push(ep);
      }
    }
    return inScopeEndpoints;
  }
}
