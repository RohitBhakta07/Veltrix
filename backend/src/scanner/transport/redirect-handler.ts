/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Hop-by-Hop Redirect Handler
 *
 * Enforces hop ceilings (max 5), canonical URL loop detection, HTTPS-to-HTTP downgrade
 * blocking, cross-origin credential/header stripping, and per-hop scope revalidation.
 */

import {
  type RequestAuthorizationContext,
  SafeTransportError,
  RESTRICTED_HOP_BY_HOP_HEADERS,
} from './types.js';
import { AuthorizedScanScopeGuard } from './scope-guard.js';

export interface RedirectEvaluationParams {
  currentUrl: URL;
  statusCode: number;
  locationHeader?: string;
  currentMethod: string;
  currentBody?: string | Buffer | Uint8Array;
  currentHeaders: Record<string, string | string[]>;
  currentHop: number;
  maxRedirects: number;
  visitedUrls: Set<string>;
  context: RequestAuthorizationContext;
}

export interface NextHopRequest {
  nextUrl: URL;
  nextMethod: string;
  nextBody?: string | Buffer | Uint8Array;
  nextHeaders: Record<string, string | string[]>;
  nextHop: number;
}

export class RedirectHandler {
  static evaluate(params: RedirectEvaluationParams): NextHopRequest | null {
    const {
      currentUrl,
      statusCode,
      locationHeader,
      currentMethod,
      currentBody,
      currentHeaders,
      currentHop,
      maxRedirects,
      visitedUrls,
      context,
    } = params;

    // Only 301, 302, 303, 307, 308 are redirects
    const isRedirectStatus = [301, 302, 303, 307, 308].includes(statusCode);
    if (!isRedirectStatus) {
      return null;
    }

    // 1. Inviolable Rule: Domain verification NEVER follows redirects
    if (context.purpose === 'DOMAIN_OWNERSHIP_VERIFICATION') {
      const targetLocation = locationHeader || 'unspecified';
      throw new SafeTransportError(
        'REDIRECT_PROHIBITED_FOR_VERIFICATION',
        `HTTP redirect (${statusCode}) to '${targetLocation}' blocked. Redirects are prohibited for domain verification.`
      );
    }

    if (!locationHeader) {
      throw new SafeTransportError(
        'MALFORMED_URL',
        `Redirect response HTTP ${statusCode} missing Location header.`
      );
    }

    // 2. Enforce Hop Ceiling (max 5 hops)
    const effectiveMaxHops = Math.min(5, Math.max(0, maxRedirects));
    if (currentHop >= effectiveMaxHops) {
      throw new SafeTransportError(
        'MAX_REDIRECTS_EXCEEDED',
        `Maximum redirect limit of ${effectiveMaxHops} hops exceeded on redirect to '${locationHeader}'.`
      );
    }

    // 3. Resolve Next URL
    let nextUrl: URL;
    try {
      nextUrl = new URL(locationHeader, currentUrl);
    } catch {
      throw new SafeTransportError(
        'MALFORMED_URL',
        `Invalid redirect Location URL: '${locationHeader}'.`
      );
    }

    // 4. Scheme validation & HTTPS-to-HTTP Downgrade Ban
    if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
      throw new SafeTransportError(
        'SSRF_BLOCKED',
        `Redirect to prohibited protocol '${nextUrl.protocol}'. Only HTTP and HTTPS are allowed.`
      );
    }

    if (currentUrl.protocol === 'https:' && nextUrl.protocol === 'http:') {
      throw new SafeTransportError(
        'PROTOCOL_DOWNGRADE_BLOCKED',
        `HTTPS-to-HTTP downgrade prohibited on redirect to '${nextUrl.href}'.`
      );
    }

    // 5. Canonical URL Loop Detection
    const canonicalNext = `${nextUrl.origin}${nextUrl.pathname}${nextUrl.search}`;
    if (visitedUrls.has(canonicalNext)) {
      throw new SafeTransportError(
        'REDIRECT_LOOP_DETECTED',
        `Redirect loop detected for URL '${canonicalNext}'.`
      );
    }
    visitedUrls.add(canonicalNext);

    // 6. Hop-by-Hop Scope Revalidation
    if (context.purpose === 'AUTHORIZED_SCAN') {
      AuthorizedScanScopeGuard.validate(nextUrl, currentMethod, context, { maxRedirects });
    }

    // 7. Method & Body Semantics per RFC 7231
    let nextMethod = currentMethod.toUpperCase();
    let nextBody = currentBody;

    if (statusCode === 303) {
      // 303 See Other forces GET and drops body
      nextMethod = 'GET';
      nextBody = undefined;
    } else if ((statusCode === 301 || statusCode === 302) && nextMethod !== 'HEAD') {
      // 301/302 conventionally converts to GET and drops body
      nextMethod = 'GET';
      nextBody = undefined;
    }

    // 8. Credential & Sensitive Header Hygiene on Cross-Origin Redirect
    const isCrossOrigin = currentUrl.origin !== nextUrl.origin;
    const nextHeaders: Record<string, string | string[]> = {};

    const nominatedRedirectHeaders = new Set<string>();
    for (const [key, value] of Object.entries(currentHeaders)) {
      if (key.toLowerCase() === 'connection') {
        const values = Array.isArray(value) ? value : [value];
        for (const v of values) {
          if (typeof v === 'string') {
            for (const token of v.split(',')) {
              const clean = token.trim().toLowerCase();
              if (clean.length > 0) nominatedRedirectHeaders.add(clean);
            }
          }
        }
      }
    }

    for (const [key, value] of Object.entries(currentHeaders)) {
      const lowerKey = key.toLowerCase();
      // Hop-by-hop and connection-nominated headers are NEVER forwarded across hops
      if (RESTRICTED_HOP_BY_HOP_HEADERS.has(lowerKey) || nominatedRedirectHeaders.has(lowerKey)) {
        continue;
      }
      if (isCrossOrigin) {
        if (
          lowerKey === 'authorization' ||
          lowerKey === 'cookie' ||
          lowerKey === 'cookie2' ||
          lowerKey === 'proxy-authorization' ||
          lowerKey.startsWith('x-org') ||
          lowerKey.startsWith('x-tenant') ||
          lowerKey.startsWith('x-veltrix') ||
          lowerKey.startsWith('x-api-key')
        ) {
          continue; // Strip on cross-origin
        }
      }
      nextHeaders[key] = value;
    }

    return {
      nextUrl,
      nextMethod,
      nextBody,
      nextHeaders,
      nextHop: currentHop + 1,
    };
  }
}
