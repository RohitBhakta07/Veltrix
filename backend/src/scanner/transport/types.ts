/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Types and Interfaces
 */

import type net from 'node:net';
import type tls from 'node:tls';

export type TransportErrorCode =
  | 'SSRF_BLOCKED'
  | 'VERIFICATION_PATH_UNAUTHORIZED'
  | 'DOMAIN_NOT_VERIFIED'
  | 'DOMAIN_VERIFICATION_SUSPENDED'
  | 'METHOD_NOT_PERMITTED'
  | 'PORT_NOT_PERMITTED'
  | 'MAX_REDIRECTS_EXCEEDED'
  | 'REDIRECT_LOOP_DETECTED'
  | 'PROTOCOL_DOWNGRADE_BLOCKED'
  | 'REDIRECT_PROHIBITED_FOR_VERIFICATION'
  | 'MAX_RESPONSE_SIZE_EXCEEDED'
  | 'DECOMPRESSION_BOMB_DETECTED'
  | 'REQUEST_TIMEOUT'
  | 'CONNECT_TIMEOUT'
  | 'HEADERS_TIMEOUT'
  | 'BODY_IDLE_TIMEOUT'
  | 'ABORTED'
  | 'UNSUPPORTED_ENCODING'
  | 'MALFORMED_URL'
  | 'DNS_RESOLUTION_FAILED'
  | 'TLS_VERIFICATION_FAILED'
  | 'INTERNAL_PORT_BLOCKED';

export class SafeTransportError extends Error {
  readonly code: TransportErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: TransportErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'SafeTransportError';
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, SafeTransportError.prototype);
  }
}

/**
 * Non-forgeable private symbol branding trusted authorization contexts.
 * Ordinary JSON objects cannot possess this branding.
 */
export const TRUSTED_SCOPE_BRAND: unique symbol = Symbol('VELTRIX_TRUSTED_SCOPE_CONTEXT');

/**
 * Pre-verification context for domain ownership challenges.
 * Used BEFORE the website asset achieves VERIFIED status.
 */
export interface VerificationScopeContext {
  readonly [TRUSTED_SCOPE_BRAND]: true;
  readonly purpose: 'DOMAIN_OWNERSHIP_VERIFICATION';
  readonly orgId?: string;
  readonly siteId?: string;
  readonly primaryDomain: string;
  readonly activeToken: string;
}

/**
 * Post-verification context for authorized vulnerability assessment scans.
 * Requires verified, unexpired, non-blocked status.
 */
export interface AuthorizedScanScopeContext {
  readonly [TRUSTED_SCOPE_BRAND]: true;
  readonly purpose: 'AUTHORIZED_SCAN';
  readonly orgId: string;
  readonly scanId: string;
  readonly siteId: string;
  readonly primaryDomain: string;
  readonly approvedSubdomains: string[];
  readonly status: 'VERIFIED' | 'PENDING_VERIFICATION' | 'GRACE_PERIOD' | 'EXPIRED' | 'SUSPENDED' | 'REVOKED';
  readonly scanBlocked: boolean;
  readonly expiresAt: number;
  readonly excludedPaths?: (string | RegExp)[];
  readonly allowedPorts?: number[];
  readonly allowedMethods?: string[];
}

export type RequestAuthorizationContext =
  | VerificationScopeContext
  | AuthorizedScanScopeContext;

export function isTrustedScopeContext(context: unknown): context is RequestAuthorizationContext {
  if (!context || typeof context !== 'object') return false;
  return (context as any)[TRUSTED_SCOPE_BRAND] === true;
}

export function createVerificationScopeContext(params: {
  primaryDomain: string;
  activeToken: string;
  orgId?: string;
  siteId?: string;
}): VerificationScopeContext {
  if (!params.primaryDomain || typeof params.primaryDomain !== 'string') {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Primary domain is required to create verification scope context.');
  }
  if (!params.activeToken || typeof params.activeToken !== 'string') {
    throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Active token is required to create verification scope context.');
  }

  const cleanDomain = params.primaryDomain.trim().toLowerCase();
  const cleanToken = params.activeToken.trim();

  return Object.freeze({
    [TRUSTED_SCOPE_BRAND]: true as const,
    purpose: 'DOMAIN_OWNERSHIP_VERIFICATION' as const,
    primaryDomain: cleanDomain,
    activeToken: cleanToken,
    orgId: params.orgId,
    siteId: params.siteId,
  });
}

export function createAuthorizedScanScopeContext(params: {
  orgId: string;
  scanId: string;
  siteId: string;
  primaryDomain: string;
  approvedSubdomains: string[];
  status: 'VERIFIED' | 'PENDING_VERIFICATION' | 'GRACE_PERIOD' | 'EXPIRED' | 'SUSPENDED' | 'REVOKED';
  scanBlocked: boolean;
  expiresAt: number;
  excludedPaths?: (string | RegExp)[];
  allowedPorts?: number[];
  allowedMethods?: string[];
}): AuthorizedScanScopeContext {
  if (!params.orgId || !params.scanId || !params.siteId || !params.primaryDomain) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      'Missing required identity fields (orgId, scanId, siteId, primaryDomain) for scan context.'
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

  if (params.scanBlocked) {
    throw new SafeTransportError(
      'DOMAIN_VERIFICATION_SUSPENDED',
      'Target domain has scanBlocked set to true.'
    );
  }

  if (params.expiresAt <= Date.now()) {
    throw new SafeTransportError(
      'DOMAIN_NOT_VERIFIED',
      `Domain ownership verification expired at ${new Date(params.expiresAt).toISOString()}.`
    );
  }

  const cleanPrimary = params.primaryDomain.trim().toLowerCase();
  const cleanApproved = (params.approvedSubdomains || []).map((s) => s.trim().toLowerCase());

  return Object.freeze({
    [TRUSTED_SCOPE_BRAND]: true as const,
    purpose: 'AUTHORIZED_SCAN' as const,
    orgId: params.orgId,
    scanId: params.scanId,
    siteId: params.siteId,
    primaryDomain: cleanPrimary,
    approvedSubdomains: cleanApproved,
    status: params.status,
    scanBlocked: params.scanBlocked,
    expiresAt: params.expiresAt,
    excludedPaths: params.excludedPaths,
    allowedPorts: params.allowedPorts,
    allowedMethods: params.allowedMethods,
  });
}

export interface DnsRecord {
  address: string;
  family: number;
}

export interface ValidatedDnsResolution {
  hostname: string;
  records: DnsRecord[];
  pinnedIp: string;
  family: number;
}

export interface DnsResolverInterface {
  resolve(hostname: string, options?: { timeoutMs?: number; signal?: AbortSignal }): Promise<ValidatedDnsResolution>;
}

export interface SocketConnectorInterface {
  connect(options: { host: string; port: number }): net.Socket;
  connectTls(options: tls.ConnectionOptions): tls.TLSSocket;
}

export interface SafeHttpRequestOptions {
  method?: string;
  headers?: Record<string, string | string[]>;
  body?: string | Buffer | Uint8Array;
  timeoutMs?: number;
  connectTimeoutMs?: number;
  headersTimeoutMs?: number;
  bodyIdleTimeoutMs?: number;
  signal?: AbortSignal;
  maxRedirects?: number;
  context: RequestAuthorizationContext;
  allowLoopbackForTesting?: boolean;
}

export interface SafeHttpResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  rawBody: Buffer;
  rawBuffer?: Buffer;
  text: string;
  data: unknown;
  remoteAddress: string;
  remotePort: number;
  wireBytesReceived: number;
  decompressedBytes: number;
  redirectHops: number;
}
