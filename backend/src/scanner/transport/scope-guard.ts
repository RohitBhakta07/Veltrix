/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Scope & Authorization Guards
 *
 * Implements two strictly decoupled authorization guards:
 * 1. VerificationScopeGuard: Pre-verification domain ownership challenge verification.
 * 2. AuthorizedScanScopeGuard: Post-verification vulnerability assessment scanning.
 */

import path from 'node:path';
import {
  type RequestAuthorizationContext,
  type VerificationScopeContext,
  type AuthorizedScanScopeContext,
  SafeTransportError,
  isTrustedScopeContext,
  BLOCKED_INTERNAL_PORTS,
  isBlockedInternalPort,
} from './types.js';

export { BLOCKED_INTERNAL_PORTS, isBlockedInternalPort };

export interface ScopeValidationResult {
  allowed: boolean;
  normalizedUrl: URL;
  targetHost: string;
  targetPort: number;
  isHttps: boolean;
  maxRedirects: number;
}

export class VerificationScopeGuard {
  static validate(
    url: URL,
    method: string,
    context: VerificationScopeContext
  ): ScopeValidationResult {
    // 1. Validate Method
    const upperMethod = method.toUpperCase();
    if (upperMethod !== 'GET' && upperMethod !== 'HEAD') {
      throw new SafeTransportError(
        'METHOD_NOT_PERMITTED',
        `HTTP method '${method}' is not permitted for domain verification. Only GET and HEAD are allowed.`
      );
    }

    // 2. Validate Scheme
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new SafeTransportError(
        'SSRF_BLOCKED',
        `Prohibited protocol '${url.protocol}'. Verification permits only HTTP and HTTPS.`
      );
    }
    const isHttps = url.protocol === 'https:';

    // 3. Strict Identity Validation
    if (
      typeof context.primaryDomain !== 'string' ||
      context.primaryDomain.trim().length === 0 ||
      typeof context.activeToken !== 'string' ||
      context.activeToken.trim().length === 0
    ) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        'Verification rejected: Missing, empty, or whitespace-only verification challenge identity fields.'
      );
    }

    // 4. Protocol-Specific Standard Port Policy (Issue 5)
    const expectedPort = isHttps ? 443 : 80;
    const port = url.port ? parseInt(url.port, 10) : expectedPort;
    if (isNaN(port) || port !== expectedPort) {
      throw new SafeTransportError(
        'PORT_NOT_PERMITTED',
        `Port ${port} is prohibited for domain verification with protocol '${url.protocol}'. Only standard port ${expectedPort} is allowed.`
      );
    }

    // 5. Strict Host Matching (Case-insensitive primary domain only; subdomains barred)
    const reqHost = url.hostname.toLowerCase();
    const allowedPrimary = context.primaryDomain.toLowerCase();
    if (reqHost !== allowedPrimary) {
      throw new SafeTransportError(
        'SSRF_BLOCKED',
        `Verification target host '${reqHost}' does not match registered primary domain '${allowedPrimary}'. Subdomains are prohibited during primary domain verification.`
      );
    }

    // 6. Strict Permitted Path Whitelist & Anti-Traversal
    const allowedHttpChallengePath = `/.well-known/veltrix-challenge/${context.activeToken}`;
    const rawPath = url.pathname;

    // Check for encoded traversal sequences
    let decodedPath: string;
    try {
      decodedPath = decodeURIComponent(rawPath);
    } catch {
      throw new SafeTransportError(
        'VERIFICATION_PATH_UNAUTHORIZED',
        `Malformed path encoding detected in verification request: '${rawPath}'.`
      );
    }

    const posixNormalized = path.posix.normalize(decodedPath);

    // Permitted paths: strictly '/' or '/.well-known/veltrix-challenge/<token>'
    const isHttpChallenge =
      rawPath === allowedHttpChallengePath && posixNormalized === allowedHttpChallengePath;
    const isRootMetaTag = rawPath === '/' && posixNormalized === '/';

    if (!isHttpChallenge && !isRootMetaTag) {
      throw new SafeTransportError(
        'VERIFICATION_PATH_UNAUTHORIZED',
        `Verification request to path '${rawPath}' is unauthorized. Verification is strictly restricted to challenge paths ('${allowedHttpChallengePath}' or '/').`
      );
    }

    return {
      allowed: true,
      normalizedUrl: url,
      targetHost: reqHost,
      targetPort: port,
      isHttps,
      maxRedirects: 0, // Inviolable invariant: 0 redirects for verification
    };
  }
}

export class AuthorizedScanScopeGuard {
  static validate(
    url: URL,
    method: string,
    context: AuthorizedScanScopeContext,
    options?: { maxRedirects?: number }
  ): ScopeValidationResult {
    // 1. Authoritative Identity Validation
    if (
      typeof context.orgId !== 'string' || context.orgId.trim().length === 0 ||
      typeof context.scanId !== 'string' || context.scanId.trim().length === 0 ||
      typeof context.siteId !== 'string' || context.siteId.trim().length === 0 ||
      typeof context.primaryDomain !== 'string' || context.primaryDomain.trim().length === 0
    ) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        'Scan rejected: Missing, empty, or whitespace-only authoritative identity fields.'
      );
    }

    if (
      !Array.isArray(context.approvedSubdomains) ||
      context.approvedSubdomains.some((s) => typeof s !== 'string' || s.trim().length === 0)
    ) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        'Scan rejected: Malformed or invalid approved subdomains specification.'
      );
    }

    // 2. Inviolable Ownership & State Invariants
    if (context.status === 'GRACE_PERIOD' || context.status === 'SUSPENDED') {
      throw new SafeTransportError(
        'DOMAIN_VERIFICATION_SUSPENDED',
        `Scan rejected: Target domain verification status is '${context.status}'. Active scans are suspended.`
      );
    }

    if (context.status !== 'VERIFIED') {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        `Scan rejected: Target domain has not completed ownership verification (status: '${context.status}').`
      );
    }

    if (context.scanBlocked !== false) {
      throw new SafeTransportError(
        'DOMAIN_VERIFICATION_SUSPENDED',
        'Scan rejected: Target domain has scanBlocked set to true or undefined.'
      );
    }

    if (
      typeof context.expiresAt !== 'number' ||
      !Number.isFinite(context.expiresAt) ||
      context.expiresAt <= Date.now()
    ) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        `Scan rejected: Domain ownership verification expired or timestamp is invalid (${context.expiresAt}).`
      );
    }

    // 3. Validate Scheme
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new SafeTransportError(
        'SSRF_BLOCKED',
        `Prohibited protocol '${url.protocol}'. Scanning permits only HTTP and HTTPS.`
      );
    }
    const isHttps = url.protocol === 'https:';

    // 4. Port Policy & Inviolable Safety Precedence
    const defaultPort = isHttps ? 443 : 80;
    const port = url.port ? parseInt(url.port, 10) : defaultPort;
    if (isNaN(port) || port < 1 || port > 65535) {
      throw new SafeTransportError('PORT_NOT_PERMITTED', `Invalid destination port '${url.port}'.`);
    }

    // High-risk internal ports can NEVER be accessed
    if (BLOCKED_INTERNAL_PORTS.has(port)) {
      throw new SafeTransportError(
        'INTERNAL_PORT_BLOCKED',
        `Port ${port} is a prohibited internal infrastructure port. Scanner egress to this port is categorically blocked.`
      );
    }

    // Protocol-Specific Standard Port Acceptance (Issue 5)
    const isStandardPort = (isHttps && port === 443) || (!isHttps && port === 80);
    const isWhitelistedPort = context.allowedPorts && context.allowedPorts.includes(port);
    if (!isStandardPort && !isWhitelistedPort) {
      throw new SafeTransportError(
        'PORT_NOT_PERMITTED',
        `Port ${port} is non-standard and has not been explicitly authorized for protocol '${url.protocol}'.`
      );
    }

    // 5. Exact Approved Host Matching (No wildcards permitted)
    const reqHost = url.hostname.toLowerCase();
    const primaryDomain = context.primaryDomain.toLowerCase();
    const approvedSubdomains = (context.approvedSubdomains || []).map((s) => s.toLowerCase());

    const isPrimary = reqHost === primaryDomain;
    const isApprovedSub = approvedSubdomains.includes(reqHost);

    if (!isPrimary && !isApprovedSub) {
      throw new SafeTransportError(
        'SSRF_BLOCKED',
        `Host '${reqHost}' is out of authorized scan scope. Egress is permitted only to exact verified domains: [${[primaryDomain, ...approvedSubdomains].join(', ')}].`
      );
    }

    // 6. Excluded Paths Policy
    const rawPath = url.pathname;
    let decodedPath = rawPath;
    try {
      decodedPath = decodeURIComponent(rawPath);
    } catch {}

    const normalizedPath = path.posix.normalize(decodedPath);

    if (context.excludedPaths && context.excludedPaths.length > 0) {
      for (const pattern of context.excludedPaths) {
        if (typeof pattern === 'string') {
          if (rawPath.startsWith(pattern) || normalizedPath.startsWith(pattern)) {
            throw new SafeTransportError(
              'SSRF_BLOCKED',
              `Path '${rawPath}' matches excluded path rule '${pattern}'. Dispatch dropped.`
            );
          }
        } else if (pattern instanceof RegExp) {
          if (pattern.test(rawPath) || pattern.test(normalizedPath)) {
            throw new SafeTransportError(
              'SSRF_BLOCKED',
              `Path '${rawPath}' matches excluded path regex '${pattern.source}'. Dispatch dropped.`
            );
          }
        }
      }
    }

    // 7. HTTP Method Policy
    const upperMethod = method.toUpperCase();
    const allowedMethods = context.allowedMethods || ['GET', 'HEAD'];
    if (!allowedMethods.includes(upperMethod)) {
      throw new SafeTransportError(
        'METHOD_NOT_PERMITTED',
        `HTTP method '${method}' is not permitted by scan operation policy. Permitted methods: [${allowedMethods.join(', ')}].`
      );
    }

    // 8. Redirect Ceiling: Max 5 hops for authorized scanning
    const requestedRedirects = options?.maxRedirects ?? 0;
    const maxRedirects = Math.min(5, Math.max(0, requestedRedirects));

    return {
      allowed: true,
      normalizedUrl: url,
      targetHost: reqHost,
      targetPort: port,
      isHttps,
      maxRedirects,
    };
  }
}

export function validateRequestScope(
  url: URL,
  method: string,
  context: RequestAuthorizationContext,
  options?: { maxRedirects?: number }
): ScopeValidationResult {
  if (!context || typeof context !== 'object' || !isTrustedScopeContext(context)) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      'Untrusted or forged request authorization context rejected. Context must be created via trusted internal service.'
    );
  }

  if (context.purpose === 'DOMAIN_OWNERSHIP_VERIFICATION') {
    return VerificationScopeGuard.validate(url, method, context);
  }

  if (context.purpose === 'AUTHORIZED_SCAN') {
    return AuthorizedScanScopeGuard.validate(url, method, context, options);
  }

  throw new SafeTransportError(
    'DOMAIN_NOT_VERIFIED',
    `Unrecognized request authorization context purpose: '${(context as any).purpose}'.`
  );
}
