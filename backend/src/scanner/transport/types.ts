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
  readonly excludedPaths?: string[];
  readonly allowedPorts?: number[];
  readonly allowedMethods?: string[];
}

export type RequestAuthorizationContext =
  | VerificationScopeContext
  | AuthorizedScanScopeContext;

export { isTrustedScopeContext } from './context-authority.js';

/**
 * Module-private set of standard RFC 7230 / RFC 9110 hop-by-hop headers
 * that must never be forwarded or accepted from external caller configurations.
 * Strictly non-exported to prevent runtime tampering with Set entries.
 */
const RESTRICTED_HOP_BY_HOP_HEADERS_SET: ReadonlySet<string> = new Set([
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
]);

/**
 * Validates whether a header name is a restricted hop-by-hop or pseudo-header.
 * Case-insensitive. Protects underlying policy collection from external mutation.
 */
export function isRestrictedHopByHopHeader(name: string): boolean {
  if (typeof name !== 'string') return false;
  return RESTRICTED_HOP_BY_HOP_HEADERS_SET.has(name.trim().toLowerCase());
}

/**
 * Categorically barred internal service ports that can NEVER be accessed by scanner requests,
 * even if explicitly requested in an asset port allowlist.
 */
const BLOCKED_INTERNAL_PORTS_SET = new Set<number>([
  20, 21, 22, 23, 25, 53, 69, 110, 111, 135, 137, 138, 139, 143, 389, 445, 636,
  1433, 1434, 1521, 2049, 2375, 2376, 2379, 2380, 3306, 3389, 5000, 5432, 5900,
  6379, 8500, 9000, 9200, 9300, 11211, 27017, 27018, 28017,
]);

/**
 * Validates whether a port is a prohibited internal infrastructure port.
 */
export function isBlockedInternalPort(port: number): boolean {
  return typeof port === 'number' && BLOCKED_INTERNAL_PORTS_SET.has(port);
}

/**
 * Genuinely immutable read-only view of blocked internal ports.
 * Mutating operations (add, delete, clear) throw TypeError.
 */
export const BLOCKED_INTERNAL_PORTS: ReadonlySet<number> = Object.freeze({
  has: (port: number) => isBlockedInternalPort(port),
  get size() {
    return BLOCKED_INTERNAL_PORTS_SET.size;
  },
  [Symbol.iterator]: () => BLOCKED_INTERNAL_PORTS_SET[Symbol.iterator](),
  entries: () => BLOCKED_INTERNAL_PORTS_SET.entries(),
  keys: () => BLOCKED_INTERNAL_PORTS_SET.keys(),
  values: () => BLOCKED_INTERNAL_PORTS_SET.values(),
  forEach: (cb: (value: number, value2: number, set: ReadonlySet<number>) => void, thisArg?: unknown) =>
    BLOCKED_INTERNAL_PORTS_SET.forEach((v) => cb.call(thisArg, v, v, BLOCKED_INTERNAL_PORTS)),
  add: () => {
    throw new TypeError('BLOCKED_INTERNAL_PORTS is immutable');
  },
  delete: () => {
    throw new TypeError('BLOCKED_INTERNAL_PORTS is immutable');
  },
  clear: () => {
    throw new TypeError('BLOCKED_INTERNAL_PORTS is immutable');
  },
}) as unknown as ReadonlySet<number>;

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

export interface SanitizedTlsCertificate {
  readonly subject: Record<string, string>;
  readonly issuer: Record<string, string>;
  readonly validFrom: string;
  readonly validTo: string;
  readonly subjectAltNames?: readonly string[];
  readonly serialNumber?: string;
  readonly fingerprint256?: string;
}

export interface SanitizedTlsMetadata {
  readonly protocol: string | null;
  readonly cipher?: { readonly name: string; readonly version: string };
  readonly authorized: boolean;
  readonly authorizationError?: string;
  readonly peerCertificate?: SanitizedTlsCertificate;
}

export interface SafeHttpResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  setCookies?: readonly string[];
  rawHeaders?: readonly string[];
  rawBody: Buffer;
  rawBuffer?: Buffer;
  text: string;
  data: unknown;
  remoteAddress: string;
  remotePort: number;
  wireBytesReceived: number;
  decompressedBytes: number;
  redirectHops: number;
  tls?: SanitizedTlsMetadata;
}
