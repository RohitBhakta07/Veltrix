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
 * Current Architectural Limitation & Security Invariant Note (TASK-802):
 * In Phase 8 TASK-802, database-persisted scan configuration profiles (scheduled for TASK-803)
 * have not yet been implemented in the storage schema.
 *
 * IMPORTANT SECURITY HONESTY DISCLOSURE:
 * Merely validating HTTP method names against a permitted vocabulary ('GET', 'POST', etc.) does
 * NOT constitute operation-level authorization. An attacker or client passing 'allowedMethods: [POST]'
 * or 'allowedPorts: [8080]' in request parameters must NEVER be trusted to self-authorize expanded
 * scanner capabilities.
 *
 * Therefore, until persisted scan profiles are implemented in TASK-803:
 * 1. Default Authority: Scan authorization defaults strictly to safe, read-only HTTP methods ['GET', 'HEAD']
 *    and standard ports (80 for HTTP, 443 for HTTPS).
 * 2. Expansion Restriction: Client-controlled request parameters cannot expand methods (e.g. POST, PUT, DELETE)
 *    or grant non-standard destination ports. Any attempt to do so in raw parameters is rejected.
 * 3. Trusted Server Policy: Non-default methods or ports can ONLY be authorized by trusted backend orchestration
 *    code via a cryptographically/in-memory branded ServerScanPolicy (created via createServerScanPolicy).
 * 4. Immutable Exclusions: Excluded paths are strictly string-based prefixes. Mutable RegExp instances are
 *    categorically prohibited to prevent mutable object injection. Mandatory server-side exclusions
 *    (/.env, /.git, /proc/, etc.) are always prepended and cannot be bypassed or removed.
 */

const SERVER_CONTROLLED_ALLOWED_METHODS_SET: ReadonlySet<string> = new Set([
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'DELETE',
  'PATCH',
  'OPTIONS',
]);

/**
 * Validates whether an HTTP method is in the server-controlled allowed vocabulary.
 * Case-insensitive. Protects underlying policy collection from external mutation.
 */
export function isServerControlledAllowedMethod(method: string): boolean {
  if (typeof method !== 'string') return false;
  return SERVER_CONTROLLED_ALLOWED_METHODS_SET.has(method.trim().toUpperCase());
}

/**
 * Mandatory server-side security excluded path prefixes.
 * Categorically enforced on all authorized scans to prevent accessing sensitive local host/cloud endpoints.
 * Cannot be overridden, bypassed, or removed by caller input.
 */
export const SERVER_MANDATORY_EXCLUDED_PATHS: readonly string[] = Object.freeze([
  '/.env',
  '/.git',
  '/.aws',
  '/proc/',
  '/sys/',
  '/etc/',
]);

/**
 * Module-private WeakSet capability registries.
 * Absolutely NEVER exported. Ordinary JSON or attacker-controlled objects
 * cannot obtain membership in these registries.
 */
const TRUSTED_CONTEXT_REGISTRY = new WeakSet<object>();
const TRUSTED_SERVER_POLICY_REGISTRY = new WeakSet<object>();

/**
 * Validates whether an unknown context reference was authoritatively minted by this module.
 */
export function isTrustedScopeContext(context: unknown): context is RequestAuthorizationContext {
  if (!context || typeof context !== 'object') {
    return false;
  }
  return TRUSTED_CONTEXT_REGISTRY.has(context);
}

/**
 * Validates whether an unknown policy descriptor is a trusted ServerScanPolicy.
 */
export function isServerScanPolicy(policy: unknown): policy is ServerScanPolicy {
  if (!policy || typeof policy !== 'object') {
    return false;
  }
  return TRUSTED_SERVER_POLICY_REGISTRY.has(policy);
}

/**
 * Trusted server-owned scan policy descriptor.
 * Can only be minted by trusted backend orchestration code via createServerScanPolicy.
 */
export interface ServerScanPolicy {
  readonly allowedMethods?: readonly string[];
  readonly allowedPorts?: readonly number[];
  readonly additionalExcludedPaths?: readonly string[];
}

/**
 * Creates an authoritative ServerScanPolicy descriptor.
 * Strictly available to trusted backend orchestration code or verified profile loaders.
 */
export function createServerScanPolicy(policy: {
  allowedMethods?: string[];
  allowedPorts?: number[];
  additionalExcludedPaths?: string[];
}): ServerScanPolicy {
  if (!policy || typeof policy !== 'object') {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'ServerScanPolicy descriptor must be an object.');
  }

  // 1. Methods: Validate against server-controlled vocabulary
  let cleanMethods: readonly string[] | undefined;
  if (policy.allowedMethods !== undefined) {
    if (!Array.isArray(policy.allowedMethods)) {
      throw new SafeTransportError('METHOD_NOT_PERMITTED', 'allowedMethods must be an array of HTTP method strings.');
    }
    const validated: string[] = [];
    for (const m of policy.allowedMethods) {
      if (typeof m !== 'string' || m.trim().length === 0) {
        throw new SafeTransportError('METHOD_NOT_PERMITTED', 'HTTP method entries must be non-empty strings.');
      }
      const upper = m.trim().toUpperCase();
      if (!isServerControlledAllowedMethod(upper)) {
        throw new SafeTransportError(
          'METHOD_NOT_PERMITTED',
          `HTTP method '${m}' is prohibited by server-side scan policy. Allowed methods: [${Array.from(SERVER_CONTROLLED_ALLOWED_METHODS_SET).join(', ')}].`
        );
      }
      if (!validated.includes(upper)) validated.push(upper);
    }
    cleanMethods = Object.freeze(validated);
  }

  // 2. Ports: Validate 1..65535, reject blocked internal ports
  let cleanPorts: readonly number[] | undefined;
  if (policy.allowedPorts !== undefined) {
    if (!Array.isArray(policy.allowedPorts)) {
      throw new SafeTransportError('PORT_NOT_PERMITTED', 'allowedPorts must be an array of port numbers.');
    }
    const validatedPorts: number[] = [];
    for (const p of policy.allowedPorts) {
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
      if (!validatedPorts.includes(p)) validatedPorts.push(p);
    }
    cleanPorts = Object.freeze(validatedPorts);
  }

  // 3. Excluded Paths: String only, reject RegExp
  let cleanExcluded: readonly string[] | undefined;
  if (policy.additionalExcludedPaths !== undefined) {
    if (!Array.isArray(policy.additionalExcludedPaths)) {
      throw new SafeTransportError('MALFORMED_URL', 'additionalExcludedPaths must be an array of strings.');
    }
    const validatedPaths: string[] = [];
    for (const entry of policy.additionalExcludedPaths) {
      if (typeof entry !== 'string' || entry.trim().length === 0) {
        throw new SafeTransportError(
          'MALFORMED_URL',
          'Excluded path entries must be non-empty strings. RegExp instances are prohibited to prevent mutable object injection.'
        );
      }
      validatedPaths.push(entry.trim());
    }
    cleanExcluded = Object.freeze(validatedPaths);
  }

  const policyObj: ServerScanPolicy = Object.freeze({
    allowedMethods: cleanMethods,
    allowedPorts: cleanPorts,
    additionalExcludedPaths: cleanExcluded,
  });
  TRUSTED_SERVER_POLICY_REGISTRY.add(policyObj);
  return policyObj;
}

export interface AuthoritativeScanParams {
  orgId: string;
  siteId: string;
  scanId: string;
  serverPolicy?: ServerScanPolicy;
  /**
   * @deprecated Raw caller parameters cannot broaden scan permissions.
   * Supplying non-default methods, non-standard ports, or invalid exclusions directly
   * will be rejected by server policy.
   */
  allowedMethods?: string[];
  allowedPorts?: number[];
  excludedPaths?: string[];
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
  if (!asset.expiresAt || typeof asset.expiresAt !== 'string' || asset.expiresAt.trim().length === 0) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      'Domain ownership verification timestamp is missing or malformed.'
    );
  }

  const expiresAtMs = Date.parse(asset.expiresAt);
  if (!Number.isFinite(expiresAtMs) || Number.isNaN(expiresAtMs)) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      `Domain ownership verification timestamp '${asset.expiresAt}' is invalid or malformed.`
    );
  }

  if (expiresAtMs <= Date.now()) {
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

  // 1. Verify serverPolicy if provided
  if (params.serverPolicy !== undefined && !isServerScanPolicy(params.serverPolicy)) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      'Untrusted or forged server scan policy rejected. ServerScanPolicy must be minted via createServerScanPolicy.'
    );
  }

  const trustedPolicy = params.serverPolicy;

  // 2. Reject client-controlled permission expansion
  if (params.allowedMethods !== undefined && !trustedPolicy) {
    const rawMethods = Array.isArray(params.allowedMethods)
      ? params.allowedMethods.map((m) => (typeof m === 'string' ? m.trim().toUpperCase() : m))
      : [];
    const containsNonDefault = rawMethods.some((m) => m !== 'GET' && m !== 'HEAD');
    if (containsNonDefault) {
      throw new SafeTransportError(
        'METHOD_NOT_PERMITTED',
        'Arbitrary client request parameters cannot authorize non-default HTTP methods. Non-standard methods must originate from trusted server policy.'
      );
    }
  }

  if (params.allowedPorts !== undefined && !trustedPolicy) {
    const rawPorts = Array.isArray(params.allowedPorts) ? params.allowedPorts : [];
    const containsNonStandard = rawPorts.some((p) => p !== 80 && p !== 443);
    if (containsNonStandard) {
      throw new SafeTransportError(
        'PORT_NOT_PERMITTED',
        'Arbitrary client request parameters cannot authorize non-standard destination ports. Non-standard ports must originate from trusted server policy.'
      );
    }
  }

  if (params.excludedPaths !== undefined) {
    if (!Array.isArray(params.excludedPaths)) {
      throw new SafeTransportError('MALFORMED_URL', 'excludedPaths must be an array of strings.');
    }
    for (const entry of params.excludedPaths) {
      if (typeof entry !== 'string' || entry.trim().length === 0) {
        throw new SafeTransportError(
          'MALFORMED_URL',
          'Excluded path entries must be non-empty strings. RegExp instances are prohibited to prevent mutable object injection.'
        );
      }
    }
  }

  // 3. Resolve Effective HTTP Methods Policy: Defaults strictly to ['GET', 'HEAD'] unless server policy authorizes
  let cleanAllowedMethods: readonly string[];
  if (trustedPolicy?.allowedMethods && trustedPolicy.allowedMethods.length > 0) {
    cleanAllowedMethods = trustedPolicy.allowedMethods;
  } else {
    cleanAllowedMethods = Object.freeze(['GET', 'HEAD']);
  }

  // 4. Resolve Effective Destination Ports Policy: Defaults strictly to undefined (standard 80/443 only)
  let cleanAllowedPorts: readonly number[] | undefined;
  if (trustedPolicy?.allowedPorts && trustedPolicy.allowedPorts.length > 0) {
    cleanAllowedPorts = trustedPolicy.allowedPorts;
  } else {
    cleanAllowedPorts = undefined;
  }

  // 5. Resolve Effective Excluded Paths Policy: Mandatory security exclusions + server/caller string exclusions
  const additional: string[] = [
    ...(trustedPolicy?.additionalExcludedPaths || []),
    ...(Array.isArray(params.excludedPaths) ? params.excludedPaths.map((s) => s.trim()) : []),
  ];
  const cleanExcludedPaths: readonly string[] = Object.freeze([
    ...SERVER_MANDATORY_EXCLUDED_PATHS,
    ...Array.from(new Set(additional)),
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
    excludedPaths: cleanExcludedPaths as string[],
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
