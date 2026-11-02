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
 * Pre-verification context for domain ownership challenges.
 * Used BEFORE the website asset achieves VERIFIED status.
 */
export interface VerificationScopeContext {
  readonly purpose: 'DOMAIN_OWNERSHIP_VERIFICATION';
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
  resolve(hostname: string, options?: { timeoutMs?: number }): Promise<ValidatedDnsResolution>;
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
  text: string;
  data: unknown;
  remoteAddress: string;
  remotePort: number;
  wireBytesReceived: number;
  decompressedBytes: number;
  redirectHops: number;
}
