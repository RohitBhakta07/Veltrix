import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

export interface HttpResponse {
  status: number;
  data: unknown;
  text?: string;
  headers?: Record<string, string>;
  remoteAddress?: string;
}

import type { VerificationScopeContext } from '../transport/types.js';

export interface HttpFetcherInterface {
  fetch(
    url: string,
    options?: {
      timeoutMs?: number;
      signal?: AbortSignal;
      token?: string;
      primaryDomain?: string;
      orgId?: string;
      siteId?: string;
      context?: VerificationScopeContext;
    }
  ): Promise<HttpResponse>;
}

export interface DnsLookupRecord {
  address: string;
  family: number;
}

export interface AddressResolverInterface {
  lookup(hostname: string): Promise<DnsLookupRecord[]>;
}

export class DefaultAddressResolver implements AddressResolverInterface {
  async lookup(hostname: string): Promise<DnsLookupRecord[]> {
    const results = await dns.lookup(hostname, { all: true });
    return results.map((r) => ({
      address: r.address,
      family: r.family,
    }));
  }
}

export interface SocketConnectorInterface {
  connect(options: { host: string; port: number }): net.Socket;
  connectTls(options: tls.ConnectionOptions): tls.TLSSocket;
}

export class DefaultSocketConnector implements SocketConnectorInterface {
  connect(options: { host: string; port: number }): net.Socket {
    return net.connect({
      host: options.host,
      port: options.port,
    });
  }

  connectTls(options: tls.ConnectionOptions): tls.TLSSocket {
    return tls.connect(options);
  }
}

import {
  parseIpv4ToNumber,
  normalizeIpv4,
  isProhibitedIpv4Bytes,
  isProhibitedIpv4,
  parseIpv6,
  isIpLiteral,
  isProhibitedIp,
} from '../transport/ip-validator.js';

export {
  parseIpv4ToNumber,
  normalizeIpv4,
  isProhibitedIpv4Bytes,
  isProhibitedIpv4,
  parseIpv6,
  isIpLiteral,
  isProhibitedIp,
};

import { SafeVerificationHttpFetcher } from '../transport/verification-fetcher.js';
export { SafeVerificationHttpFetcher };

export interface DefaultHttpFetcherOptions {
  addressResolver?: AddressResolverInterface;
  socketConnector?: SocketConnectorInterface;
  onSocketConnected?: (info: { remoteAddress: string; remotePort: number; servername?: string }) => void;
  allowLoopbackForTesting?: boolean;
}

/**
 * Legacy test adapter — strictly prohibited in production.
 *
 * Preserved for backward-compatible TASK-801 regression testing where tests directly
 * inspect DefaultSocketConnector.prototype.connect parameters and custom AddressResolverInterface.
 * In production (NODE_ENV === 'production'), this class unconditionally throws FATAL_SECURITY_ERROR.
 * All production domain ownership verification is authoritatively routed through SafeVerificationHttpFetcher
 * backed by SafeHttpClient.
 */
export class DefaultHttpFetcher implements HttpFetcherInterface {
  private readonly addressResolver: AddressResolverInterface;
  private readonly socketConnector: SocketConnectorInterface;
  private readonly onSocketConnected?: (info: { remoteAddress: string; remotePort: number; servername?: string }) => void;
  private readonly allowLoopbackForTesting: boolean;

  constructor(options?: DefaultHttpFetcherOptions) {
    if (process.env.NODE_ENV === 'production') {
      if (options?.socketConnector || options?.allowLoopbackForTesting) {
        throw new Error('FATAL_SECURITY_ERROR: Custom socket connectors and test loopback options are prohibited in production.');
      }
      throw new Error(
        'FATAL_SECURITY_ERROR: DefaultHttpFetcher is a legacy test adapter and is strictly prohibited in production. All verification must use SafeVerificationHttpFetcher.'
      );
    }

    this.addressResolver = options?.addressResolver || new DefaultAddressResolver();
    this.socketConnector = options?.socketConnector || new DefaultSocketConnector();
    this.onSocketConnected = options?.onSocketConnected;
    this.allowLoopbackForTesting = options?.allowLoopbackForTesting === true && process.env.NODE_ENV !== 'production';
  }

  async fetch(
    url: string,
    options?: { timeoutMs?: number; signal?: AbortSignal }
  ): Promise<HttpResponse> {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        'FATAL_SECURITY_ERROR: DefaultHttpFetcher is strictly prohibited in production. All verification must use SafeVerificationHttpFetcher.'
      );
    }

    const timeout = options?.timeoutMs || 5000;

    // 1. Strict protocol allowlist
    const parsedUrl = new URL(url);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new Error(`SSRF blocked: Prohibited protocol '${parsedUrl.protocol}'. Only HTTP/HTTPS allowed.`);
    }

    const isHttps = parsedUrl.protocol === 'https:';
    const defaultPort = isHttps ? 443 : 80;
    const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : defaultPort;
    if (isNaN(port) || port < 1 || port > 65535) {
      throw new Error(`Invalid port '${parsedUrl.port}'.`);
    }

    // 2. Reject prohibited literal hostnames
    const rawHostname = parsedUrl.hostname.toLowerCase();
    const cleanHostname = rawHostname.startsWith('[') && rawHostname.endsWith(']')
      ? rawHostname.slice(1, -1)
      : rawHostname;

    const isTestLoopbackAllowed = this.allowLoopbackForTesting &&
      process.env.NODE_ENV !== 'production' &&
      (cleanHostname === '127.0.0.1' || cleanHostname === '::1');

    if (
      !isTestLoopbackAllowed && (
        cleanHostname === 'localhost' ||
        cleanHostname.endsWith('.internal') ||
        cleanHostname.endsWith('.local') ||
        cleanHostname.endsWith('.arpa') ||
        cleanHostname === 'metadata.google.internal'
      )
    ) {
      throw new Error(`SSRF blocked: Prohibited destination host '${cleanHostname}'.`);
    }

    // Check if hostname itself is directly a prohibited IP literal
    if (isIpLiteral(cleanHostname)) {
      if (!isTestLoopbackAllowed && isProhibitedIp(cleanHostname)) {
        throw new Error(`SSRF blocked: Host '${rawHostname}' is a prohibited IP literal.`);
      }
    }

    // 3. DNS Resolution with timeout: Fail closed in every environment
    let resolvedAddresses: DnsLookupRecord[] = [];
    if (net.isIP(cleanHostname)) {
      resolvedAddresses = [{ address: cleanHostname, family: net.isIP(cleanHostname) }];
    } else {
      const dnsTimeoutMs = Math.min(3000, timeout);
      try {
        const dnsPromise = this.addressResolver.lookup(cleanHostname);
        let timer: NodeJS.Timeout;
        const timeoutPromise = new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            reject(new Error(`DNS resolution timed out after ${dnsTimeoutMs}ms for host '${cleanHostname}'.`));
          }, dnsTimeoutMs);
          timer.unref?.();
        });

        try {
          resolvedAddresses = await Promise.race([dnsPromise, timeoutPromise]);
        } finally {
          clearTimeout(timer!);
        }
      } catch (dnsErr: unknown) {
        const errMsg = (dnsErr as Error)?.message || 'Unknown DNS resolution error';
        throw new Error(`DNS resolution failed for verification target '${cleanHostname}': ${errMsg}`);
      }
    }

    if (!resolvedAddresses || resolvedAddresses.length === 0) {
      throw new Error(`DNS resolution returned no addresses for verification target '${cleanHostname}'.`);
    }

    // 4. Validate EVERY resolved address. Reject destination if ANY address is prohibited!
    for (const record of resolvedAddresses) {
      if (!record || !record.address) {
        throw new Error(`SSRF blocked: Host '${cleanHostname}' resolved to invalid address.`);
      }

      const recordLoopbackAllowed = this.allowLoopbackForTesting &&
        process.env.NODE_ENV !== 'production' &&
        (record.address === '127.0.0.1' || record.address === '::1');

      if (!recordLoopbackAllowed && isProhibitedIp(record.address)) {
        throw new Error(`SSRF blocked: Host '${cleanHostname}' resolved to prohibited IP address '${record.address}'.`);
      }
    }

    // 5. Select Pinned IP (Connection-level IP pinning)
    const pinnedRecord = resolvedAddresses[0]!;
    const pinnedIp = pinnedRecord.address.replace(/^\[|\]$/g, '');

    // 6. Execute HTTP/HTTPS Request over Pinned Socket Connection
    const clientModule = isHttps ? https : http;

    const agent = new (isHttps ? https.Agent : http.Agent)({
      keepAlive: false,
    });

    return new Promise<HttpResponse>((resolve, reject) => {
      let settled = false;
      let activeSocket: net.Socket | tls.TLSSocket | null = null;

      const safeReject = (err: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(requestTimer);
        if (activeSocket) {
          try {
            activeSocket.destroy();
          } catch {}
        }
        reject(err);
      };

      const safeResolve = (res: HttpResponse) => {
        if (settled) return;
        settled = true;
        clearTimeout(requestTimer);
        resolve(res);
      };

      const requestTimer = setTimeout(() => {
        safeReject(new Error(`Verification request timed out after ${timeout}ms.`));
      }, timeout);
      requestTimer.unref?.();

      if (options?.signal) {
        if (options.signal.aborted) {
          safeReject(new Error('Verification request was aborted.'));
          return;
        }
        options.signal.addEventListener('abort', () => {
          safeReject(new Error('Verification request was aborted.'));
        });
      }

      agent.createConnection = (connOpts: any) => {
        const targetPort = connOpts?.port || port;

        const tcpSocket = this.socketConnector.connect({
          host: pinnedIp,
          port: targetPort,
        });

        tcpSocket.on('connect', () => {
          this.onSocketConnected?.({
            remoteAddress: tcpSocket.remoteAddress || pinnedIp,
            remotePort: tcpSocket.remotePort || targetPort,
          });
        });

        if (isHttps) {
          const tlsSocket = this.socketConnector.connectTls({
            socket: tcpSocket,
            servername: parsedUrl.hostname,
            rejectUnauthorized: true,
          });

          tlsSocket.on('secureConnect', () => {
            this.onSocketConnected?.({
              remoteAddress: tlsSocket.remoteAddress || pinnedIp,
              remotePort: tlsSocket.remotePort || targetPort,
              servername: parsedUrl.hostname,
            });
          });

          activeSocket = tlsSocket;
          return tlsSocket;
        }

        activeSocket = tcpSocket;
        return tcpSocket;
      };

      const req = clientModule.request({
        protocol: parsedUrl.protocol,
        hostname: parsedUrl.hostname,
        port: port,
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        headers: {
          'Host': parsedUrl.host,
          'User-Agent': 'Veltrix-Domain-Verifier/1.0.0 (+https://veltrix.io)',
          'Accept': 'application/json, text/html, */*',
          'Connection': 'close',
        },
        agent: agent,
        // Fallback lookup: ensures Node never attempts unpinned DNS resolution
        lookup: (_host, lookupOpts, cb) => {
          const family = pinnedRecord.family || (pinnedIp.includes(':') ? 6 : 4);
          if (lookupOpts && lookupOpts.all) {
            cb(null, [{ address: pinnedIp, family }]);
          } else {
            cb(null, pinnedIp, family);
          }
        },
      }, (res) => {
        // 7. Strict Redirect Policy: Reject any 3xx redirect to prevent internal redirect attacks
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
          const location = res.headers.location || 'unspecified';
          safeReject(new Error(`HTTP redirect to '${location}' blocked. Redirects are disabled for domain verification.`));
          return;
        }

        // 8. Enforce 128KB Response Size Limit
        const MAX_RESPONSE_BYTES = 128 * 1024;
        const contentLength = res.headers['content-length'];
        if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
          safeReject(new Error(`Verification response exceeded maximum allowed size of 128KB (${contentLength} bytes).`));
          return;
        }

        let receivedBytes = 0;
        const chunks: Buffer[] = [];

        res.on('data', (chunk: Buffer) => {
          receivedBytes += chunk.length;
          if (receivedBytes > MAX_RESPONSE_BYTES) {
            try {
              res.destroy();
            } catch {}
            safeReject(new Error('Verification response exceeded maximum allowed size of 128KB.'));
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let data: unknown;
          try {
            data = JSON.parse(text);
          } catch {
            data = null;
          }

          const responseHeaders: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (v !== undefined) {
              responseHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
            }
          }

          safeResolve({
            status: res.statusCode || 200,
            data,
            text,
            headers: responseHeaders,
            remoteAddress: activeSocket?.remoteAddress || pinnedIp,
          });
        });

        res.on('error', (err) => {
          safeReject(err);
        });
      });

      req.on('error', (err) => {
        safeReject(err);
      });

      req.end();
    });
  }
}

export interface HttpVerificationResult {
  matched: boolean;
  statusReceived?: number;
  failureReason?: string;
}

export class HttpVerifier {
  private readonly fetcher: HttpFetcherInterface;

  constructor(fetcher?: HttpFetcherInterface) {
    if (process.env.NODE_ENV === 'production' && fetcher) {
      throw new Error('FATAL_SECURITY_ERROR: Injected HttpFetcher is prohibited in production.');
    }
    this.fetcher = fetcher || new SafeVerificationHttpFetcher();
  }

  async verify(
    url: string,
    expectedToken: string,
    expectedOrgId: string,
    context?: VerificationScopeContext
  ): Promise<HttpVerificationResult> {
    try {
      const { status, data } = await this.fetcher.fetch(url, {
        timeoutMs: 5000,
        token: expectedToken,
        orgId: expectedOrgId,
        context,
      });

      if (status !== 200) {
        return {
          matched: false,
          statusReceived: status,
          failureReason: `HTTP challenge endpoint returned HTTP status ${status} (expected 200 OK).`,
        };
      }

      if (
        typeof data === 'object' &&
        data !== null &&
        (data as { veltrixChallengeToken?: string }).veltrixChallengeToken === expectedToken &&
        (data as { orgId?: string }).orgId === expectedOrgId
      ) {
        return {
          matched: true,
          statusReceived: status,
        };
      }

      return {
        matched: false,
        statusReceived: status,
        failureReason: `HTTP challenge body did not match expected JSON { veltrixChallengeToken: "${expectedToken}", orgId: "${expectedOrgId}" }.`,
      };
    } catch (err: unknown) {
      const errMsg = (err as Error)?.message || 'HTTP request failed';
      return {
        matched: false,
        failureReason: `HTTP challenge fetch failed for '${url}': ${errMsg}`,
      };
    }
  }
}
