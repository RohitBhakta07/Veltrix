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
  isBlockedInternalPort,
} from './types.js';

/**
 * SERVER-SIDE SCAN POLICY BOUNDARY & AUTHORIZATION PROFILE SPECIFICATION
 *
 * Current Architectural Boundary & Limitation Note (TASK-802):
 * In Phase 8 TASK-802, database-persisted scan configuration profiles (scheduled for TASK-803)
 * have not yet been implemented in the storage schema. To establish an uncompromised server-side
 * authorization boundary and prevent arbitrary client request parameters from granting extra
 * permissions or bypassing security controls:
 *
 * 1. HTTP Methods: Defaults strictly to ['GET', 'HEAD']. Caller-requested methods are validated
 *    against SERVER_CONTROLLED_ALLOWED_METHODS. High-risk methods (TRACE, CONNECT, TRACK) and
 *    arbitrary verbs are categorically rejected.
 * 2. Destination Ports: Barred internal infrastructure ports (BLOCKED_INTERNAL_PORTS) are rejected
 *    at context-minting time regardless of caller allowlist contents. Ports must be valid integers in 1..65535.
 * 3. Excluded Paths: Server-side mandatory excluded paths (e.g. /.env, /.git, /proc/) are unconditionally
 *    enforced on every context and cannot be removed or overridden by caller input.
 * 4. Policy Immutability: All policy arrays (methods, ports, excluded paths, approved subdomains)
 *    are defensively cloned and frozen (Object.freeze) before placing them into the trusted context.
 */

export const SERVER_CONTROLLED_ALLOWED_METHODS: ReadonlySet<string> = new Set([
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'DELETE',
  'PATCH',
  'OPTIONS',
]);

export const SERVER_MANDATORY_EXCLUDED_PATHS: readonly (string | RegExp)[] = Object.freeze([
  '/.env',
  '/.git',
  '/.aws',
  '/proc/',
  '/sys/',
  '/etc/',
]);

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
  const cleanApprovedSubdomainsList: string[] = [];
  for (const sub of subdomainsRaw) {
    if (typeof sub !== 'string' || sub.trim().length === 0) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        'Approved subdomains contain invalid or empty domain strings.'
      );
    }
    cleanApprovedSubdomainsList.push(sub.trim().toLowerCase());
  }
  const cleanApprovedSubdomains: readonly string[] = Object.freeze(cleanApprovedSubdomainsList);

  // 1. Server-controlled HTTP Methods Policy: Default to ['GET', 'HEAD'] unless explicitly authorized
  let cleanAllowedMethods: readonly string[];
  if (!params.allowedMethods || params.allowedMethods.length === 0) {
    cleanAllowedMethods = Object.freeze(['GET', 'HEAD']);
  } else {
    if (!Array.isArray(params.allowedMethods)) {
      throw new SafeTransportError('METHOD_NOT_PERMITTED', 'allowedMethods must be an array of HTTP method strings.');
    }
    const validatedMethods: string[] = [];
    for (const m of params.allowedMethods) {
      if (typeof m !== 'string' || m.trim().length === 0) {
        throw new SafeTransportError('METHOD_NOT_PERMITTED', 'HTTP method entries must be non-empty strings.');
      }
      const upperMethod = m.trim().toUpperCase();
      if (!SERVER_CONTROLLED_ALLOWED_METHODS.has(upperMethod)) {
        throw new SafeTransportError(
          'METHOD_NOT_PERMITTED',
          `HTTP method '${m}' is prohibited by server-side scan policy. Allowed methods: [${Array.from(SERVER_CONTROLLED_ALLOWED_METHODS).join(', ')}].`
        );
      }
      if (!validatedMethods.includes(upperMethod)) {
        validatedMethods.push(upperMethod);
      }
    }
    cleanAllowedMethods = Object.freeze(validatedMethods);
  }

  // 2. Server-controlled Destination Ports Policy: Reject blocked internal ports and validate integer range
  let cleanAllowedPorts: readonly number[] | undefined;
  if (params.allowedPorts !== undefined) {
    if (!Array.isArray(params.allowedPorts)) {
      throw new SafeTransportError('PORT_NOT_PERMITTED', 'allowedPorts must be an array of port numbers.');
    }
    const validatedPorts: number[] = [];
    for (const p of params.allowedPorts) {
      if (typeof p !== 'number' || !Number.isInteger(p) || p < 1 || p > 65535) {
        throw new SafeTransportError(
          'PORT_NOT_PERMITTED',
          `Invalid destination port '${p}'. Ports must be valid integers between 1 and 65535.`
        );
      }
      if (isBlockedInternalPort(p)) {
        throw new SafeTransportError(
          'INTERNAL_PORT_BLOCKED',
          `Port ${p} is a prohibited internal infrastructure port. Scanner egress to this port is categorically blocked.`
        );
      }
      if (!validatedPorts.includes(p)) {
        validatedPorts.push(p);
      }
    }
    cleanAllowedPorts = Object.freeze(validatedPorts);
  }

  // 3. Server-controlled Excluded Paths Policy: Mandatory security exclusions cannot be removed
  const callerExcluded: (string | RegExp)[] = [];
  if (params.excludedPaths !== undefined) {
    if (!Array.isArray(params.excludedPaths)) {
      throw new SafeTransportError('MALFORMED_URL', 'excludedPaths must be an array of strings or RegExp instances.');
    }
    for (const entry of params.excludedPaths) {
      if (typeof entry === 'string') {
        if (entry.trim().length === 0) {
          throw new SafeTransportError('MALFORMED_URL', 'Excluded path string entries must be non-empty.');
        }
        callerExcluded.push(entry.trim());
      } else if (entry instanceof RegExp) {
        callerExcluded.push(entry);
      } else {
        throw new SafeTransportError('MALFORMED_URL', 'Excluded path entries must be strings or RegExp instances.');
      }
    }
  }
  const cleanExcludedPaths: readonly (string | RegExp)[] = Object.freeze([
    ...SERVER_MANDATORY_EXCLUDED_PATHS,
    ...callerExcluded,
  ]);

  const context: AuthorizedScanScopeContext = Object.freeze({
    purpose: 'AUTHORIZED_SCAN' as const,
    orgId: cleanOrgId,
    scanId: cleanScanId,
    siteId: cleanSiteId,
    primaryDomain: cleanDomain,
    approvedSubdomains: cleanApprovedSubdomains as string[],
    status: asset.status,
    scanBlocked: false,
    expiresAt: expiresAtMs,
    excludedPaths: cleanExcludedPaths as (string | RegExp)[],
    allowedPorts: cleanAllowedPorts as number[] | undefined,
    allowedMethods: cleanAllowedMethods as string[],
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
