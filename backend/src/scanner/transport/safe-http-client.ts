/**
 * VELTRIX Hardened Safe HTTP Transport Layer - SafeHttpClient
 *
 * Implements hardened outbound HTTP transport with pre-flight authorization guards,
 * DNS rebinding protection, connection-level IP pinning, ambient proxy isolation,
 * hop-by-hop redirect validation, streaming decompression ceilings, and tenant-scoped emergency abort.
 */

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type tls from 'node:tls';
import {
  type DnsResolverInterface,
  type SocketConnectorInterface,
  type SafeHttpRequestOptions,
  type SafeHttpResponse,
  SafeTransportError,
  isRestrictedHopByHopHeader,
} from './types.js';
import { DnsResolver } from './dns-resolver.js';
import { DefaultSocketConnector } from './socket-connector.js';
import {
  ActiveSocketRegistry,
  defaultActiveSocketRegistry,
} from './active-socket-registry.js';
import { validateRequestScope } from './scope-guard.js';
import { RedirectHandler } from './redirect-handler.js';
import { StreamDecompressor } from './stream-decompressor.js';
import { isProhibitedIp } from './ip-validator.js';

export interface SafeHttpClientOptions {
  dnsResolver?: DnsResolverInterface;
  socketConnector?: SocketConnectorInterface;
  socketRegistry?: ActiveSocketRegistry;
  allowLoopbackForTesting?: boolean;
}

export class SafeHttpClient {
  private readonly dnsResolver: DnsResolverInterface;
  private readonly socketConnector: SocketConnectorInterface;
  private readonly socketRegistry: ActiveSocketRegistry;
  private readonly allowLoopbackForTesting: boolean;

  constructor(options?: SafeHttpClientOptions) {
    if (process.env.NODE_ENV === 'production') {
      if (options?.dnsResolver) {
        throw new Error('FATAL_SECURITY_ERROR: Injected DNS resolvers are prohibited in production.');
      }
      if (options?.socketConnector) {
        throw new Error('FATAL_SECURITY_ERROR: Custom socket connectors are prohibited in production.');
      }
      if (options?.socketRegistry) {
        throw new Error('FATAL_SECURITY_ERROR: Custom socket registries are prohibited in production.');
      }
      if (options?.allowLoopbackForTesting) {
        throw new Error('FATAL_SECURITY_ERROR: Test loopback options are prohibited in production.');
      }
    }

    this.allowLoopbackForTesting =
      options?.allowLoopbackForTesting === true && process.env.NODE_ENV !== 'production';

    this.dnsResolver =
      options?.dnsResolver ||
      new DnsResolver({ allowLoopbackForTesting: this.allowLoopbackForTesting });

    this.socketConnector = options?.socketConnector || new DefaultSocketConnector();
    this.socketRegistry = options?.socketRegistry || defaultActiveSocketRegistry;
  }

  async get(url: string, options: SafeHttpRequestOptions): Promise<SafeHttpResponse> {
    return this.request(url, { ...options, method: 'GET' });
  }

  async head(url: string, options: SafeHttpRequestOptions): Promise<SafeHttpResponse> {
    return this.request(url, { ...options, method: 'HEAD' });
  }

  async request(urlStr: string, options: SafeHttpRequestOptions): Promise<SafeHttpResponse> {
    if (!urlStr || typeof urlStr !== 'string') {
      throw new SafeTransportError('MALFORMED_URL', 'Empty or invalid URL string provided.');
    }

    let currentUrl: URL;
    try {
      currentUrl = new URL(urlStr);
    } catch {
      throw new SafeTransportError('MALFORMED_URL', `Failed to parse URL '${urlStr}'.`);
    }

    // 1. Strict URL Credentials Rejection
    if (currentUrl.username || currentUrl.password) {
      throw new SafeTransportError(
        'MALFORMED_URL',
        'Embedded user credentials in target URL are strictly prohibited.'
      );
    }

    let currentMethod = (options.method || 'GET').toUpperCase();
    let currentBody = options.body;
    let currentHeaders: Record<string, string | string[]> = { ...(options.headers || {}) };
    let currentHop = 0;

    const visitedUrls = new Set<string>();
    visitedUrls.add(`${currentUrl.origin}${currentUrl.pathname}${currentUrl.search}`);

    const maxRedirects = options.maxRedirects ?? 0;
    const totalTimeoutMs = options.timeoutMs ?? 30000;
    const requestDeadline = Date.now() + totalTimeoutMs;

    // Check pre-flight AbortSignal
    if (options.signal?.aborted) {
      throw new SafeTransportError('ABORTED', 'Request was cancelled by AbortSignal prior to dispatch.');
    }

    // Global Request Abort Controller to link parent signal and total timeout
    const globalTimeoutController = new AbortController();
    const globalTotalTimer = setTimeout(() => {
      globalTimeoutController.abort();
    }, totalTimeoutMs);
    globalTotalTimer.unref?.();

    const parentAbortHandler = () => {
      globalTimeoutController.abort();
    };

    if (options.signal) {
      options.signal.addEventListener('abort', parentAbortHandler, { once: true });
    }

    try {
      // Execute Request Loop (Handling Redirects)
      while (true) {
        const remainingTimeoutMs = Math.max(1, requestDeadline - Date.now());
        if (remainingTimeoutMs <= 1) {
          throw new SafeTransportError(
            'REQUEST_TIMEOUT',
            `Total request timed out after ${totalTimeoutMs}ms.`
          );
        }

        // 2. Pre-flight Request Scope & Authorization Guard
        validateRequestScope(currentUrl, currentMethod, options.context, { maxRedirects });

        const isHttps = currentUrl.protocol === 'https:';
        const defaultPort = isHttps ? 443 : 80;
        const targetPort = currentUrl.port ? parseInt(currentUrl.port, 10) : defaultPort;

        // 3. Pre-flight DNS Resolution & IP Pinning
        const dnsResolution = await this.dnsResolver.resolve(currentUrl.hostname, {
          timeoutMs: Math.min(3000, options.connectTimeoutMs ?? 5000, remainingTimeoutMs),
          signal: globalTimeoutController.signal,
        });

        // 4. Defense-in-depth DNS Resolution Revalidation
        if (!dnsResolution || !Array.isArray(dnsResolution.records) || dnsResolution.records.length === 0) {
          throw new SafeTransportError(
            'DNS_RESOLUTION_FAILED',
            `DNS resolution returned no valid records for host '${currentUrl.hostname}'.`
          );
        }

        const loopbackPermitted =
          (this.allowLoopbackForTesting === true || options.allowLoopbackForTesting === true) &&
          process.env.NODE_ENV !== 'production';

        for (const record of dnsResolution.records) {
          const isRecordLoopback = loopbackPermitted && (record?.address === '127.0.0.1' || record?.address === '::1');
          if (!record || !record.address || (!isRecordLoopback && isProhibitedIp(record.address))) {
            throw new SafeTransportError(
              'SSRF_BLOCKED',
              `SSRF blocked: Host '${currentUrl.hostname}' resolved to prohibited address '${record?.address}'.`
            );
          }
        }

        const pinnedIp = dnsResolution.pinnedIp;
        if (!pinnedIp || typeof pinnedIp !== 'string' || !net.isIP(pinnedIp)) {
          throw new SafeTransportError(
            'SSRF_BLOCKED',
            `SSRF blocked: Pinned IP '${pinnedIp}' is not a valid canonical IP address.`
          );
        }

        const matchesRecord = dnsResolution.records.some((r) => r.address === pinnedIp);
        if (!matchesRecord) {
          throw new SafeTransportError(
            'SSRF_BLOCKED',
            `SSRF blocked: Pinned IP '${pinnedIp}' does not match any validated DNS record.`
          );
        }

        const isPinnedLoopback = loopbackPermitted && (pinnedIp === '127.0.0.1' || pinnedIp === '::1');
        if (!isPinnedLoopback && isProhibitedIp(pinnedIp)) {
          throw new SafeTransportError(
            'SSRF_BLOCKED',
            `SSRF blocked: Pinned IP '${pinnedIp}' is a prohibited address.`
          );
        }

        const pinnedFamily = dnsResolution.family;

        // 5. Execute Single Safe HTTP Hop
        const hopResponse = await this.executeHop({
          url: currentUrl,
          method: currentMethod,
          body: currentBody,
          headers: currentHeaders,
          isHttps,
          targetPort,
          pinnedIp,
          pinnedFamily,
          options,
          remainingTimeoutMs,
          signal: globalTimeoutController.signal,
        });

        // 6. Evaluate Redirect
        const isRedirect = [301, 302, 303, 307, 308].includes(hopResponse.statusCode);
        if (isRedirect && options.context.purpose === 'DOMAIN_OWNERSHIP_VERIFICATION') {
          const loc = hopResponse.rawIncoming.headers.location || 'unspecified';
          throw new SafeTransportError(
            'REDIRECT_PROHIBITED_FOR_VERIFICATION',
            `HTTP redirect to '${loc}' blocked. Redirects are disabled for domain verification.`
          );
        }

        if (isRedirect && maxRedirects > 0) {
          const nextHop = RedirectHandler.evaluate({
            currentUrl,
            statusCode: hopResponse.statusCode,
            locationHeader: hopResponse.rawIncoming.headers.location,
            currentMethod,
            currentBody,
            currentHeaders,
            currentHop,
            maxRedirects,
            visitedUrls,
            context: options.context,
          });

          if (nextHop) {
            currentUrl = nextHop.nextUrl;
            currentMethod = nextHop.nextMethod;
            currentBody = nextHop.nextBody;
            currentHeaders = nextHop.nextHeaders;
            currentHop = nextHop.nextHop;
            continue; // Loop for next hop
          }
        }

        // Return completed response
        hopResponse.fullResponse.redirectHops = currentHop;
        return hopResponse.fullResponse;
      }
    } finally {
      clearTimeout(globalTotalTimer);
      if (options.signal) {
        options.signal.removeEventListener('abort', parentAbortHandler);
      }
    }
  }

  private executeHop(params: {
    url: URL;
    method: string;
    body?: string | Buffer | Uint8Array;
    headers: Record<string, string | string[]>;
    isHttps: boolean;
    targetPort: number;
    pinnedIp: string;
    pinnedFamily: number;
    options: SafeHttpRequestOptions;
    remainingTimeoutMs: number;
    signal: AbortSignal;
  }): Promise<{
    statusCode: number;
    rawIncoming: http.IncomingMessage;
    fullResponse: SafeHttpResponse;
  }> {
    const {
      url,
      method,
      body,
      headers,
      isHttps,
      targetPort,
      pinnedIp,
      pinnedFamily,
      options,
      remainingTimeoutMs,
      signal,
    } = params;

    const connectTimeoutMs = options.connectTimeoutMs ?? 5000;
    const headersTimeoutMs = options.headersTimeoutMs ?? 10000;
    const bodyIdleTimeoutMs = options.bodyIdleTimeoutMs ?? 15000;

    return new Promise((resolve, reject) => {
      let settled = false;
      let activeSocket: net.Socket | tls.TLSSocket | null = null;
      let rawIncomingRes: http.IncomingMessage | null = null;
      let unregisterSocket: (() => void) | null = null;
      let connectedRemoteAddress = pinnedIp;

      let connectTimer: NodeJS.Timeout | null = null;
      let headersTimer: NodeJS.Timeout | null = null;
      let bodyIdleTimer: NodeJS.Timeout | null = null;

      const clearAllTimers = () => {
        if (connectTimer) clearTimeout(connectTimer);
        if (headersTimer) clearTimeout(headersTimer);
        if (bodyIdleTimer) clearTimeout(bodyIdleTimer);
      };

      const cleanup = () => {
        clearAllTimers();
        if (unregisterSocket) {
          unregisterSocket();
          unregisterSocket = null;
        }
        signal.removeEventListener('abort', onAbort);
      };

      const safeReject = (err: SafeTransportError | Error) => {
        if (settled) return;
        settled = true;
        cleanup();

        if (rawIncomingRes) {
          try {
            rawIncomingRes.destroy();
          } catch {}
        }

        if (activeSocket) {
          try {
            activeSocket.destroy();
          } catch {}
        }

        if (err instanceof SafeTransportError) {
          reject(err);
        } else {
          const msg = err.message || 'Transport error';
          if (/timeout/i.test(msg)) {
            reject(new SafeTransportError('REQUEST_TIMEOUT', msg));
          } else if (/self-signed|certificate|tls/i.test(msg)) {
            reject(new SafeTransportError('TLS_VERIFICATION_FAILED', msg));
          } else {
            reject(new SafeTransportError('CONNECT_TIMEOUT', msg));
          }
        }
      };

      const onAbort = () => {
        if (options.signal?.aborted) {
          safeReject(new SafeTransportError('ABORTED', 'Request was cancelled by caller AbortSignal.'));
        } else {
          safeReject(new SafeTransportError('REQUEST_TIMEOUT', `Total request timed out after ${options.timeoutMs ?? 30000}ms.`));
        }
      };

      signal.addEventListener('abort', onAbort, { once: true });

      // Connection Timeout Watchdog (covers TCP connect + TLS handshake)
      connectTimer = setTimeout(() => {
        safeReject(
          new SafeTransportError(
            'CONNECT_TIMEOUT',
            `TCP/TLS connection timed out after ${connectTimeoutMs}ms.`
          )
        );
      }, Math.min(connectTimeoutMs, remainingTimeoutMs));
      connectTimer.unref?.();

      const startHeadersTimer = () => {
        headersTimer = setTimeout(() => {
          safeReject(
            new SafeTransportError(
              'HEADERS_TIMEOUT',
              `Response headers timed out after ${headersTimeoutMs}ms.`
            )
          );
        }, Math.min(headersTimeoutMs, remainingTimeoutMs));
        headersTimer.unref?.();
      };

      const resetBodyIdleTimer = () => {
        if (bodyIdleTimer) clearTimeout(bodyIdleTimer);
        bodyIdleTimer = setTimeout(() => {
          safeReject(
            new SafeTransportError(
              'BODY_IDLE_TIMEOUT',
              `Response body idle timeout: No data received for ${bodyIdleTimeoutMs}ms.`
            )
          );
        }, bodyIdleTimeoutMs);
        bodyIdleTimer.unref?.();
      };

      const clientModule = isHttps ? https : http;
      const agent = new (isHttps ? https.Agent : http.Agent)({
        keepAlive: false,
      });

      // Socket Creation with IP Pinning and Socket Registry
      agent.createConnection = (connOpts: any) => {
        const port = connOpts?.port || targetPort;

        const tcpSocket = this.socketConnector.connect({
          host: pinnedIp,
          port,
        });

        if (!isHttps) {
          tcpSocket.on('connect', () => {
            if (connectTimer) {
              clearTimeout(connectTimer);
              connectTimer = null;
            }
            connectedRemoteAddress = tcpSocket.remoteAddress || pinnedIp;
            startHeadersTimer();
          });
          activeSocket = tcpSocket;
        } else {
          // HTTPS: connectTimer continues until secureConnect (TLS handshake completion)
          tcpSocket.on('connect', () => {
            connectedRemoteAddress = tcpSocket.remoteAddress || pinnedIp;
          });

          const tlsSocket = this.socketConnector.connectTls({
            socket: tcpSocket,
            servername: url.hostname,
            rejectUnauthorized: true,
          });

          tlsSocket.on('secureConnect', () => {
            if (connectTimer) {
              clearTimeout(connectTimer);
              connectTimer = null;
            }
            connectedRemoteAddress = tlsSocket.remoteAddress || pinnedIp;
            startHeadersTimer();
          });

          activeSocket = tlsSocket;
        }

        // Register in Active Socket Registry for tenant-scoped abort
        if (options.context.purpose === 'AUTHORIZED_SCAN') {
          unregisterSocket = this.socketRegistry.register(
            options.context.orgId,
            options.context.scanId,
            activeSocket
          );
        }

        return activeSocket;
      };

      // Header Hygiene & Host Boundary
      const expectedHost = url.port ? `${url.hostname}:${url.port}` : url.hostname;
      const sanitizedHeaders: Record<string, string | string[]> = {};

      // Parse nominated headers from caller-supplied Connection header(s) case-insensitively
      const nominatedHeaders = new Set<string>();
      for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() === 'connection') {
          const valArr = Array.isArray(value) ? value : [value];
          for (const item of valArr) {
            if (typeof item === 'string') {
              for (const token of item.split(',')) {
                const clean = token.trim().toLowerCase();
                if (clean.length > 0) {
                  nominatedHeaders.add(clean);
                }
              }
            }
          }
        }
      }

      for (const [key, value] of Object.entries(headers)) {
        const lowerKey = key.toLowerCase();
        if (lowerKey === 'host' || lowerKey === ':authority') {
          const valStr = Array.isArray(value) ? value[0] : value;
          if (valStr && valStr.trim().toLowerCase() !== expectedHost.toLowerCase()) {
            safeReject(
              new SafeTransportError(
                'MALFORMED_URL',
                `Caller-supplied Host header '${valStr}' does not match target URL authority '${expectedHost}'.`
              )
            );
            return;
          }
          continue;
        }
        if (isRestrictedHopByHopHeader(lowerKey) || nominatedHeaders.has(lowerKey)) {
          continue; // Strip restricted hop-by-hop headers and connection-nominated headers
        }
        sanitizedHeaders[key] = value;
      }

      sanitizedHeaders['Host'] = expectedHost;
      sanitizedHeaders['Connection'] = 'close';
      sanitizedHeaders['Accept-Encoding'] = 'gzip, deflate, br';
      if (!sanitizedHeaders['User-Agent']) {
        sanitizedHeaders['User-Agent'] = 'Veltrix-Security-Scanner/1.0.0 (+https://veltrix.io)';
      }

      const req = clientModule.request({
        protocol: url.protocol,
        hostname: url.hostname,
        port: targetPort,
        path: url.pathname + url.search,
        method: method,
        headers: sanitizedHeaders,
        agent: agent,
        lookup: (_host, lookupOpts, cb) => {
          if (lookupOpts && (lookupOpts as any).all) {
            cb(null, [{ address: pinnedIp, family: pinnedFamily }]);
          } else {
            cb(null, pinnedIp, pinnedFamily);
          }
        },
      });

      req.on('response', async (res: http.IncomingMessage) => {
        if (headersTimer) {
          clearTimeout(headersTimer);
          headersTimer = null;
        }
        rawIncomingRes = res;

        // Check if redirect response
        const statusCode = res.statusCode || 200;
        const isRedirect = [301, 302, 303, 307, 308].includes(statusCode);

        if (isRedirect && (options.maxRedirects ?? 0) > 0) {
          // Bounded redirect response drain & socket teardown
          const redirectDrainTimeout = Math.min(
            options.bodyIdleTimeoutMs ?? 1000,
            options.timeoutMs ?? 1000,
            remainingTimeoutMs,
            1000
          );
          try {
            // Prevent teardown/reset events on old socket from triggering safeReject on req
            req.removeAllListeners('error');
            req.on('error', () => {});
            if (activeSocket) {
              activeSocket.removeAllListeners('error');
              activeSocket.on('error', () => {});
            }

            await this.drainAndDestroyRedirectResponse(res, activeSocket, {
              maxDrainBytes: 64 * 1024,
              timeoutMs: redirectDrainTimeout,
              signal,
            });
          } catch (drainErr) {
            safeReject(drainErr as Error);
            return;
          }

          if (settled) return;
          settled = true;
          cleanup();
          resolve({
            statusCode,
            rawIncoming: res,
            fullResponse: null as any,
          });
          return;
        }

        // Start Body Idle Timer
        resetBodyIdleTimer();

        // Stream and decompress response body
        try {
          const maxWire =
            options.context.purpose === 'DOMAIN_OWNERSHIP_VERIFICATION'
              ? 128 * 1024 // 128 KB limit for verification
              : undefined;

          const decompressResult = await StreamDecompressor.consumeStream(res, {
            maxWireBytes: maxWire,
            maxDecompressedBytes: maxWire,
            signal,
            onChunkReceived: resetBodyIdleTimer,
          });

          if (settled) return;
          settled = true;
          cleanup();

          const text = decompressResult.bodyBuffer.toString('utf8');
          let data: unknown = null;
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

          const fullResponse: SafeHttpResponse = {
            status: statusCode,
            statusText: res.statusMessage || 'OK',
            headers: responseHeaders,
            rawBody: decompressResult.bodyBuffer,
            rawBuffer: decompressResult.bodyBuffer,
            text,
            data,
            remoteAddress: connectedRemoteAddress,
            remotePort: targetPort,
            wireBytesReceived: decompressResult.wireBytesReceived,
            decompressedBytes: decompressResult.decompressedBytes,
            redirectHops: 0,
          };

          resolve({
            statusCode,
            rawIncoming: res,
            fullResponse,
          });
        } catch (streamErr) {
          safeReject(streamErr as Error);
        }
      });

      req.on('error', (err) => {
        safeReject(err);
      });

      if (body) {
        req.write(body);
      }
      req.end();
    });
  }

  private async drainAndDestroyRedirectResponse(
    res: http.IncomingMessage,
    socket: net.Socket | null,
    options: {
      maxDrainBytes: number;
      timeoutMs: number;
      signal: AbortSignal;
    }
  ): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let bytesDrained = 0;
      let timer: NodeJS.Timeout | null = null;
      let finished = false;

      const finish = (err?: Error) => {
        if (finished) return;
        finished = true;
        if (timer) clearTimeout(timer);
        options.signal.removeEventListener('abort', onAbort);
        res.removeListener('data', onData);
        res.removeListener('end', onEnd);
        res.removeListener('error', onError);

        // Explicitly destroy incoming stream and underlying socket
        try {
          res.destroy();
        } catch {}
        if (socket) {
          try {
            socket.destroy();
          } catch {}
        }

        if (err) {
          reject(err);
        } else {
          resolve();
        }
      };

      const onAbort = () => {
        finish(new SafeTransportError('ABORTED', 'Request was cancelled by caller AbortSignal.'));
      };

      if (options.signal.aborted) {
        onAbort();
        return;
      }

      options.signal.addEventListener('abort', onAbort, { once: true });

      timer = setTimeout(() => {
        finish(
          new SafeTransportError(
            'BODY_IDLE_TIMEOUT',
            'Redirect response body transmission timed out.'
          )
        );
      }, options.timeoutMs);
      timer.unref?.();

      const onData = (chunk: Buffer) => {
        bytesDrained += chunk.length;
        if (bytesDrained > options.maxDrainBytes) {
          // Exceeded bounded redirect wire limit -> terminate immediately and safely
          finish();
        }
      };

      const onEnd = () => {
        finish();
      };

      const onError = () => {
        finish();
      };

      res.on('data', onData);
      res.on('end', onEnd);
      res.on('error', onError);

      if (res.complete || res.readableEnded) {
        finish();
      } else {
        res.resume();
      }
    });
  }
}
