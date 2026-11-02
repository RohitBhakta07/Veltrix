/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Authoritative Context Authority
 *
 * Enforces unforgeable capability-based scope context creation using a module-private
 * WeakSet registry. External callers and request payloads cannot manufacture or forge
 * authorization contexts.
 */

import type { WebsiteAsset } from '@veltrix/shared';
import {
  type VerificationScopeContext,
  type AuthorizedScanScopeContext,
  type RequestAuthorizationContext,
  SafeTransportError,
} from './types.js';

/**
 * Module-private WeakSet capability registry.
 * Absolutely NEVER exported. Ordinary JSON or attacker-controlled objects
 * cannot obtain membership in this registry.
 */
const TRUSTED_CONTEXT_REGISTRY = new WeakSet<object>();

/**
 * Validates whether an unknown context reference was authoritatively minted by this module.
 */
export function isTrustedScopeContext(context: unknown): context is RequestAuthorizationContext {
  if (!context || typeof context !== 'object') {
    return false;
  }
  return TRUSTED_CONTEXT_REGISTRY.has(context);
}

export interface AuthoritativeScanDescriptor {
  scanId: string;
  allowedMethods?: string[];
  excludedPaths?: (string | RegExp)[];
  allowedPorts?: number[];
}

/**
 * Creates an authoritative VerificationScopeContext from a server-side WebsiteAsset.
 * Strictly decoupled from vulnerability scanning authorization.
 */
export function createAuthoritativeVerificationScopeContext(
  asset: Pick<WebsiteAsset, 'primaryDomain' | 'verificationToken' | 'orgId' | 'siteId'>
): VerificationScopeContext {
  if (!asset || typeof asset !== 'object') {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Authoritative asset record is required.');
  }

  const cleanDomain = typeof asset.primaryDomain === 'string' ? asset.primaryDomain.trim().toLowerCase() : '';
  const cleanToken = typeof asset.verificationToken === 'string' ? asset.verificationToken.trim() : '';

  if (!cleanDomain) {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Primary domain is required in authoritative asset.');
  }
  if (!cleanToken) {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Active verification token is required in authoritative asset.');
  }

  const context: VerificationScopeContext = Object.freeze({
    purpose: 'DOMAIN_OWNERSHIP_VERIFICATION' as const,
    primaryDomain: cleanDomain,
    activeToken: cleanToken,
    orgId: typeof asset.orgId === 'string' ? asset.orgId.trim() : undefined,
    siteId: typeof asset.siteId === 'string' ? asset.siteId.trim() : undefined,
  });

  TRUSTED_CONTEXT_REGISTRY.add(context);
  return context;
}

/**
 * Creates an authoritative AuthorizedScanScopeContext from a verified server-side WebsiteAsset.
 * Derives organization, site, primary domain, approved subdomains, and verification state
 * strictly from authoritative server records.
 */
export function createAuthoritativeScanScopeContext(
  asset: Readonly<WebsiteAsset>,
  scan: AuthoritativeScanDescriptor
): AuthorizedScanScopeContext {
  if (!asset || typeof asset !== 'object') {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Authoritative asset record is required.');
  }
  if (!scan || typeof scan !== 'object') {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Authoritative scan descriptor is required.');
  }

  const cleanOrgId = typeof asset.orgId === 'string' ? asset.orgId.trim() : '';
  const cleanSiteId = typeof asset.siteId === 'string' ? asset.siteId.trim() : '';
  const cleanScanId = typeof scan.scanId === 'string' ? scan.scanId.trim() : '';
  const cleanDomain = typeof asset.primaryDomain === 'string' ? asset.primaryDomain.trim().toLowerCase() : '';

  if (!cleanOrgId || !cleanSiteId || !cleanScanId || !cleanDomain) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      'Authoritative identity fields (orgId, scanId, siteId, primaryDomain) must be non-empty strings.'
    );
  }

  // State checks: status must be VERIFIED
  if (asset.status === 'GRACE_PERIOD' || asset.status === 'SUSPENDED') {
    throw new SafeTransportError(
      'DOMAIN_VERIFICATION_SUSPENDED',
      `Target domain verification status is '${asset.status}'. Active scans are suspended.`
    );
  }

  if (asset.status !== 'VERIFIED') {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      `Target domain has not completed ownership verification (status: '${asset.status}').`
    );
  }

  // scanBlocked must be strictly false (reject true, undefined, null)
  if (asset.scanBlocked !== false) {
    throw new SafeTransportError(
      'DOMAIN_VERIFICATION_SUSPENDED',
      'Target domain has scanBlocked set to true or undefined.'
    );
  }

  // Expiry validation: must be finite timestamp strictly in the future
  if (!asset.expiresAt || typeof asset.expiresAt !== 'string') {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      'Domain ownership verification timestamp is missing or malformed.'
    );
  }

  const expiresAtMs = Date.parse(asset.expiresAt);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      `Domain ownership verification expired at ${new Date(expiresAtMs).toISOString()}.`
    );
  }

  // Approved subdomains validation: must be array of non-empty strings
  const subdomainsRaw = Array.isArray(asset.approvedSubdomains) ? asset.approvedSubdomains : [];
  const cleanApprovedSubdomains: string[] = [];
  for (const sub of subdomainsRaw) {
    if (typeof sub !== 'string' || sub.trim().length === 0) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        'Approved subdomains contain invalid or empty domain strings.'
      );
    }
    cleanApprovedSubdomains.push(sub.trim().toLowerCase());
  }

  const context: AuthorizedScanScopeContext = Object.freeze({
    purpose: 'AUTHORIZED_SCAN' as const,
    orgId: cleanOrgId,
    scanId: cleanScanId,
    siteId: cleanSiteId,
    primaryDomain: cleanDomain,
    approvedSubdomains: cleanApprovedSubdomains,
    status: asset.status,
    scanBlocked: false,
    expiresAt: expiresAtMs,
    excludedPaths: scan.excludedPaths,
    allowedPorts: scan.allowedPorts,
    allowedMethods: scan.allowedMethods,
  });

  TRUSTED_CONTEXT_REGISTRY.add(context);
  return context;
}

/**
 * Strict internal builder for test harnesses and local mock contexts.
 * Applies the exact same runtime validations as the authoritative asset flow.
 */
export function createInternalScanContext(params: {
  orgId: string;
  scanId: string;
  siteId: string;
  primaryDomain: string;
  approvedSubdomains?: string[];
  status: 'VERIFIED' | 'PENDING_VERIFICATION' | 'GRACE_PERIOD' | 'EXPIRED' | 'SUSPENDED' | 'REVOKED';
  scanBlocked: boolean;
  expiresAt: number;
  excludedPaths?: (string | RegExp)[];
  allowedPorts?: number[];
  allowedMethods?: string[];
}): AuthorizedScanScopeContext {
  const cleanOrgId = typeof params.orgId === 'string' ? params.orgId.trim() : '';
  const cleanSiteId = typeof params.siteId === 'string' ? params.siteId.trim() : '';
  const cleanScanId = typeof params.scanId === 'string' ? params.scanId.trim() : '';
  const cleanDomain = typeof params.primaryDomain === 'string' ? params.primaryDomain.trim().toLowerCase() : '';

  if (!cleanOrgId || !cleanSiteId || !cleanScanId || !cleanDomain) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      'Authoritative identity fields (orgId, scanId, siteId, primaryDomain) must be non-empty strings.'
    );
  }

  if (params.status === 'GRACE_PERIOD' || params.status === 'SUSPENDED') {
    throw new SafeTransportError(
      'DOMAIN_VERIFICATION_SUSPENDED',
      `Target domain verification status is '${params.status}'. Active scans are suspended.`
    );
  }

  if (params.status !== 'VERIFIED') {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      `Target domain has not completed ownership verification (status: '${params.status}').`
    );
  }

  if (params.scanBlocked !== false) {
    throw new SafeTransportError(
      'DOMAIN_VERIFICATION_SUSPENDED',
      'Target domain has scanBlocked set to true or undefined.'
    );
  }

  if (typeof params.expiresAt !== 'number' || !Number.isFinite(params.expiresAt) || params.expiresAt <= Date.now()) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      `Domain ownership verification timestamp is invalid or expired (${params.expiresAt}).`
    );
  }

  const subdomainsRaw = Array.isArray(params.approvedSubdomains) ? params.approvedSubdomains : [];
  const cleanApprovedSubdomains: string[] = [];
  for (const sub of subdomainsRaw) {
    if (typeof sub !== 'string' || sub.trim().length === 0) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        'Approved subdomains contain invalid or empty domain strings.'
      );
    }
    cleanApprovedSubdomains.push(sub.trim().toLowerCase());
  }

  const context: AuthorizedScanScopeContext = Object.freeze({
    purpose: 'AUTHORIZED_SCAN' as const,
    orgId: cleanOrgId,
    scanId: cleanScanId,
    siteId: cleanSiteId,
    primaryDomain: cleanDomain,
    approvedSubdomains: cleanApprovedSubdomains,
    status: params.status,
    scanBlocked: false,
    expiresAt: params.expiresAt,
    excludedPaths: params.excludedPaths,
    allowedPorts: params.allowedPorts,
    allowedMethods: params.allowedMethods,
  });

  TRUSTED_CONTEXT_REGISTRY.add(context);
  return context;
}

/**
 * Strict internal builder for domain ownership verification challenge context.
 */
export function createInternalVerificationContext(params: {
  primaryDomain: string;
  activeToken: string;
  orgId?: string;
  siteId?: string;
}): VerificationScopeContext {
  const cleanDomain = typeof params.primaryDomain === 'string' ? params.primaryDomain.trim().toLowerCase() : '';
  const cleanToken = typeof params.activeToken === 'string' ? params.activeToken.trim() : '';

  if (!cleanDomain) {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Primary domain is required to create verification scope context.');
  }
  if (!cleanToken) {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Active token is required to create verification scope context.');
  }

  const context: VerificationScopeContext = Object.freeze({
    purpose: 'DOMAIN_OWNERSHIP_VERIFICATION' as const,
    primaryDomain: cleanDomain,
    activeToken: cleanToken,
    orgId: typeof params.orgId === 'string' ? params.orgId.trim() : undefined,
    siteId: typeof params.siteId === 'string' ? params.siteId.trim() : undefined,
  });

  TRUSTED_CONTEXT_REGISTRY.add(context);
  return context;
}

/**
 * Aliases for backwards compatibility in test harnesses.
 */
export const createAuthorizedScanScopeContext = createInternalScanContext;
export const createVerificationScopeContext = createInternalVerificationContext;
