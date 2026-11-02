/**
 * VELTRIX Hardened Safe HTTP Transport Layer - SafeHttpClient
 *
 * Implements hardened outbound HTTP transport with pre-flight authorization guards,
 * DNS rebinding protection, connection-level IP pinning, ambient proxy isolation,
 * hop-by-hop redirect validation, streaming decompression ceilings, and tenant-scoped emergency abort.
 */

import http from 'node:http';
import https from 'node:https';
import type net from 'node:net';
import type tls from 'node:tls';
import {
  type DnsResolverInterface,
  type SocketConnectorInterface,
  type SafeHttpRequestOptions,
  type SafeHttpResponse,
  SafeTransportError,
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
    if (
      process.env.NODE_ENV === 'production' &&
      (options?.socketConnector || options?.allowLoopbackForTesting)
    ) {
      throw new Error(
        'FATAL_SECURITY_ERROR: Custom socket connectors and test loopback options are prohibited in production.'
      );
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

    let currentMethod = (options.method || 'GET').toUpperCase();
    let currentBody = options.body;
    let currentHeaders: Record<string, string | string[]> = { ...(options.headers || {}) };
    let currentHop = 0;

    const visitedUrls = new Set<string>();
    visitedUrls.add(`${currentUrl.origin}${currentUrl.pathname}${currentUrl.search}`);

    const maxRedirects = options.maxRedirects ?? 0;

    // Execute Request Loop (Handling Redirects)
    while (true) {
      // 1. Pre-flight Request Scope & Authorization Guard
      validateRequestScope(currentUrl, currentMethod, options.context, { maxRedirects });

      const isHttps = currentUrl.protocol === 'https:';
      const defaultPort = isHttps ? 443 : 80;
      const targetPort = currentUrl.port ? parseInt(currentUrl.port, 10) : defaultPort;

      // 2. Pre-flight DNS Resolution & IP Pinning
      const dnsResolution = await this.dnsResolver.resolve(currentUrl.hostname, {
        timeoutMs: Math.min(3000, options.connectTimeoutMs ?? 5000),
      });

      const pinnedIp = dnsResolution.pinnedIp;
      const pinnedFamily = dnsResolution.family;

      // 3. Execute Single Safe HTTP Hop
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
      });

      // 4. Evaluate Redirect
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

      // 5. Consume Response Stream through Streaming Decompression Guard
      const maxWire = options.context.purpose === 'DOMAIN_OWNERSHIP_VERIFICATION'
        ? 128 * 1024 // 128 KB limit for verification
        : undefined;

      const decompressResult = await StreamDecompressor.consumeStream(hopResponse.rawIncoming, {
        maxWireBytes: maxWire,
        maxDecompressedBytes: maxWire,
      });

      const text = decompressResult.bodyBuffer.toString('utf8');
      let data: unknown = null;
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }

      const responseHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(hopResponse.rawIncoming.headers)) {
        if (v !== undefined) {
          responseHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
        }
      }

      return {
        status: hopResponse.statusCode,
        statusText: hopResponse.rawIncoming.statusMessage || 'OK',
        headers: responseHeaders,
        rawBody: decompressResult.bodyBuffer,
        text,
        data,
        remoteAddress: hopResponse.remoteAddress || pinnedIp,
        remotePort: targetPort,
        wireBytesReceived: decompressResult.wireBytesReceived,
        decompressedBytes: decompressResult.decompressedBytes,
        redirectHops: currentHop,
      };
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
  }): Promise<{
    statusCode: number;
    rawIncoming: http.IncomingMessage;
    remoteAddress: string;
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
    } = params;

    const totalTimeoutMs = options.timeoutMs ?? 30000;
    const connectTimeoutMs = options.connectTimeoutMs ?? 5000;
    const headersTimeoutMs = options.headersTimeoutMs ?? 10000;

    return new Promise((resolve, reject) => {
      let settled = false;
      let activeSocket: net.Socket | tls.TLSSocket | null = null;
      let unregisterSocket: (() => void) | null = null;
      let connectedRemoteAddress = pinnedIp;

      let totalTimer: NodeJS.Timeout | null = null;
      let connectTimer: NodeJS.Timeout | null = null;
      let headersTimer: NodeJS.Timeout | null = null;

      const clearTimers = () => {
        if (totalTimer) clearTimeout(totalTimer);
        if (connectTimer) clearTimeout(connectTimer);
        if (headersTimer) clearTimeout(headersTimer);
      };

      const safeReject = (err: SafeTransportError | Error) => {
        if (settled) return;
        settled = true;
        clearTimers();

        if (unregisterSocket) {
          unregisterSocket();
        }

        if (activeSocket) {
          try {
            activeSocket.destroy();
          } catch {}
        }

        if (err instanceof SafeTransportError) {
          reject(err);
        } else {
          // Wrap in SafeTransportError
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

      // AbortSignal listener
      if (options.signal) {
        if (options.signal.aborted) {
          safeReject(new SafeTransportError('ABORTED', 'Request was cancelled by AbortSignal.'));
          return;
        }
        options.signal.addEventListener('abort', () => {
          safeReject(new SafeTransportError('ABORTED', 'Request was cancelled by AbortSignal.'));
        });
      }

      // Total Request Timeout Watchdog
      totalTimer = setTimeout(() => {
        safeReject(
          new SafeTransportError(
            'REQUEST_TIMEOUT',
            `Total request timed out after ${totalTimeoutMs}ms.`
          )
        );
      }, totalTimeoutMs);
      totalTimer.unref?.();

      // Connection Timeout Watchdog
      connectTimer = setTimeout(() => {
        safeReject(
          new SafeTransportError(
            'CONNECT_TIMEOUT',
            `TCP/TLS connection timed out after ${connectTimeoutMs}ms.`
          )
        );
      }, connectTimeoutMs);
      connectTimer.unref?.();

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

        tcpSocket.on('connect', () => {
          if (connectTimer) {
            clearTimeout(connectTimer);
            connectTimer = null;
          }
          connectedRemoteAddress = tcpSocket.remoteAddress || pinnedIp;

          // Start Response Headers Timeout watchdog
          headersTimer = setTimeout(() => {
            safeReject(
              new SafeTransportError(
                'HEADERS_TIMEOUT',
                `Response headers timed out after ${headersTimeoutMs}ms.`
              )
            );
          }, headersTimeoutMs);
          headersTimer.unref?.();
        });

        if (isHttps) {
          const tlsSocket = this.socketConnector.connectTls({
            socket: tcpSocket,
            servername: url.hostname,
            rejectUnauthorized: true,
          });

          tlsSocket.on('secureConnect', () => {
            connectedRemoteAddress = tlsSocket.remoteAddress || pinnedIp;
          });

          activeSocket = tlsSocket;
        } else {
          activeSocket = tcpSocket;
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

      const requestHeaders: Record<string, string | string[]> = {
        'Host': url.host,
        'User-Agent': 'Veltrix-Security-Scanner/1.0.0 (+https://veltrix.io)',
        'Accept': '*/*',
        'Connection': 'close',
        'Accept-Encoding': 'gzip, deflate, br',
        ...headers,
      };

      const req = clientModule.request({
        protocol: url.protocol,
        hostname: url.hostname,
        port: targetPort,
        path: url.pathname + url.search,
        method: method,
        headers: requestHeaders,
        agent: agent,
        lookup: (_host, lookupOpts, cb) => {
          if (lookupOpts && (lookupOpts as any).all) {
            cb(null, [{ address: pinnedIp, family: pinnedFamily }]);
          } else {
            cb(null, pinnedIp, pinnedFamily);
          }
        },
      });

      req.on('response', (res: http.IncomingMessage) => {
        if (headersTimer) {
          clearTimeout(headersTimer);
          headersTimer = null;
        }

        if (settled) return;
        settled = true;
        clearTimers();

        resolve({
          statusCode: res.statusCode || 200,
          rawIncoming: res,
          remoteAddress: connectedRemoteAddress,
        });
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
}
