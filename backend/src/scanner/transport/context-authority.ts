/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Authoritative Context Authority
 *
 * Enforces unforgeable capability-based scope context creation using a module-private
 * WeakSet registry. External callers and request payloads cannot manufacture or forge
 * authorization contexts.
 *
 * Inviolable Security Mandate:
 * - Authoritative contexts are exclusively minted by resolving genuinely stored WebsiteAsset
 *   records through trusted StorageInterface access.
 * - Test-only or arbitrary per-request builders are strictly excluded from production modules.
 * - The WeakSet capability registry is module-private and cannot be accessed or manipulated.
 */

import type { StorageInterface } from '../../storage/storage-interface.js';
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

export interface AuthoritativeScanParams {
  orgId: string;
  siteId: string;
  scanId: string;
  allowedMethods?: string[];
  excludedPaths?: (string | RegExp)[];
  allowedPorts?: number[];
}

export interface AuthoritativeVerificationParams {
  orgId: string;
  siteId: string;
}

/**
 * Creates an authoritative AuthorizedScanScopeContext by independently verifying database provenance
 * through trusted StorageInterface access using server-controlled organization/site identifiers.
 *
 * Derives tenant identity, primary domain, approved subdomains, verification state,
 * scan blocking state, and expiration timestamp strictly from the authoritative stored record.
 */
export async function createAuthoritativeScanScopeContext(
  storage: StorageInterface,
  params: AuthoritativeScanParams
): Promise<AuthorizedScanScopeContext> {
  if (!storage || typeof storage.getWebsiteById !== 'function') {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Authoritative storage interface is required.');
  }
  if (!params || typeof params !== 'object') {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Authoritative scan parameters are required.');
  }

  const cleanOrgId = typeof params.orgId === 'string' ? params.orgId.trim() : '';
  const cleanSiteId = typeof params.siteId === 'string' ? params.siteId.trim() : '';
  const cleanScanId = typeof params.scanId === 'string' ? params.scanId.trim() : '';

  if (!cleanOrgId || !cleanSiteId || !cleanScanId) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      'Authoritative identity identifiers (orgId, siteId, scanId) must be non-empty strings.'
    );
  }

  // Authoritatively establish database provenance: retrieve the stored asset
  const asset = await storage.getWebsiteById(cleanOrgId, cleanSiteId);
  if (!asset) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      `Target website asset '${cleanSiteId}' not found in authoritative storage for organization '${cleanOrgId}'.`
    );
  }

  const cleanDomain = typeof asset.primaryDomain === 'string' ? asset.primaryDomain.trim().toLowerCase() : '';
  if (!cleanDomain) {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Primary domain is missing in authoritative asset.');
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
    excludedPaths: params.excludedPaths,
    allowedPorts: params.allowedPorts,
    allowedMethods: params.allowedMethods,
  });

  TRUSTED_CONTEXT_REGISTRY.add(context);
  return context;
}

/**
 * Creates an authoritative VerificationScopeContext by independently verifying database provenance
 * through trusted StorageInterface access using server-controlled organization/site identifiers.
 *
 * Strictly decoupled from vulnerability scanning authorization.
 */
export async function createAuthoritativeVerificationScopeContext(
  storage: StorageInterface,
  params: AuthoritativeVerificationParams
): Promise<VerificationScopeContext> {
  if (!storage || typeof storage.getWebsiteById !== 'function') {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Authoritative storage interface is required.');
  }
  if (!params || typeof params !== 'object') {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Authoritative verification parameters are required.');
  }

  const cleanOrgId = typeof params.orgId === 'string' ? params.orgId.trim() : '';
  const cleanSiteId = typeof params.siteId === 'string' ? params.siteId.trim() : '';

  if (!cleanOrgId || !cleanSiteId) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      'Authoritative identity identifiers (orgId, siteId) must be non-empty strings.'
    );
  }

  // Authoritatively establish database provenance: retrieve the stored asset
  const asset = await storage.getWebsiteById(cleanOrgId, cleanSiteId);
  if (!asset) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      `Website asset '${cleanSiteId}' not found in authoritative storage for organization '${cleanOrgId}'.`
    );
  }

  const cleanDomain = typeof asset.primaryDomain === 'string' ? asset.primaryDomain.trim().toLowerCase() : '';
  const cleanToken = typeof asset.verificationToken === 'string' ? asset.verificationToken.trim() : '';

  if (!cleanDomain) {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Primary domain is missing in authoritative asset.');
  }
  if (!cleanToken) {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Active verification token is missing in authoritative asset.');
  }

  const context: VerificationScopeContext = Object.freeze({
    purpose: 'DOMAIN_OWNERSHIP_VERIFICATION' as const,
    primaryDomain: cleanDomain,
    activeToken: cleanToken,
    orgId: cleanOrgId,
    siteId: cleanSiteId,
  });

  TRUSTED_CONTEXT_REGISTRY.add(context);
  return context;
}
