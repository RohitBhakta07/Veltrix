/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Type Definitions
 *
 * All core types, error structures, interfaces, and immutable data contracts
 * required for the hardened SafeHttpClient and ScopeGuards.
 */

import type net from 'node:net';
import type tls from 'node:tls';
export type TransportErrorCode =
  | 'SSRF_BLOCKED'
  | 'DNS_RESOLUTION_FAILED'
  | 'CONNECT_TIMEOUT'
  | 'HEADERS_TIMEOUT'
  | 'BODY_IDLE_TIMEOUT'
  | 'REQUEST_TIMEOUT'
  | 'ABORTED'
  | 'MAX_REDIRECTS_EXCEEDED'
  | 'REDIRECT_LOOP_DETECTED'
  | 'PROTOCOL_DOWNGRADE_BLOCKED'
  | 'MAX_RESPONSE_SIZE_EXCEEDED'
  | 'DECOMPRESSION_BOMB_DETECTED'
  | 'DECOMPRESSION_ERROR'
  | 'UNSUPPORTED_ENCODING'
  | 'PORT_NOT_PERMITTED'
  | 'INTERNAL_PORT_BLOCKED'
  | 'METHOD_NOT_PERMITTED'
  | 'DOMAIN_NOT_VERIFIED'
  | 'DOMAIN_VERIFICATION_SUSPENDED'
  | 'VERIFICATION_PATH_UNAUTHORIZED'
  | 'REDIRECT_PROHIBITED_FOR_VERIFICATION'
  | 'MALFORMED_URL'
  | 'TLS_VERIFICATION_FAILED';

export class SafeTransportError extends Error {
  public readonly code: TransportErrorCode;
  public readonly details?: Record<string, unknown>;

  constructor(code: TransportErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'SafeTransportError';
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, SafeTransportError.prototype);
  }
}

/**
 * Pre-verification context for domain ownership challenges.
 * Used BEFORE the website asset achieves VERIFIED status.
 */
export interface VerificationScopeContext {
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

export { isTrustedScopeContext } from './context-authority.js';

/**
 * Standard RFC 7230 / RFC 9110 hop-by-hop headers that must never be forwarded
 * or accepted from external caller configurations.
 */
export const RESTRICTED_HOP_BY_HOP_HEADERS: ReadonlySet<string> = Object.freeze(
  new Set([
    'host',
    ':authority',
    ':method',
    ':path',
    ':scheme',
    ':status',
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'proxy-connection',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
  ])
);

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
  timeoutMs?: number; // Global end-to-end request timeout (default: 30000)
  connectTimeoutMs?: number; // Connect and TLS handshake timeout (default: 5000)
  headersTimeoutMs?: number; // Header arrival timeout (default: 10000)
  bodyIdleTimeoutMs?: number; // Body streaming idle watchdog timeout (default: 15000)
  maxRedirects?: number; // 0 for verification; max 5 for scanning
  signal?: AbortSignal; // Cancellation / emergency abort signal
  context: RequestAuthorizationContext;
  allowLoopbackForTesting?: boolean; // Allowed strictly in unit test harnesses
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
