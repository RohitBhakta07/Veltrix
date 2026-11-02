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

export interface HttpFetcherInterface {
  fetch(
    url: string,
    options?: { timeoutMs?: number; signal?: AbortSignal }
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

export function parseIpv4ToNumber(partStr: string): number {
  const s = partStr.trim().toLowerCase();
  if (s.startsWith('0x') || s.startsWith('0X')) {
    return parseInt(s, 16);
  }
  if (s.length > 1 && s.startsWith('0') && !s.includes('.')) {
    return parseInt(s, 8);
  }
  return parseInt(s, 10);
}

export function normalizeIpv4(ipStr: string): [number, number, number, number] | null {
  let clean = ipStr.trim().toLowerCase();
  if (clean.includes(':')) {
    const lastColon = clean.lastIndexOf(':');
    clean = clean.slice(0, lastColon);
  }

  // Handle single integer representations (hex, octal, decimal dword)
  if (/^0x[0-9a-f]+$/i.test(clean)) {
    const num = parseInt(clean, 16);
    if (isNaN(num) || num < 0 || num > 0xffffffff) return null;
    return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255];
  }
  if (/^0[0-7]+$/.test(clean)) {
    const num = parseInt(clean, 8);
    if (isNaN(num) || num < 0 || num > 0xffffffff) return null;
    return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255];
  }
  if (/^\d+$/.test(clean)) {
    const num = Number(clean);
    if (isNaN(num) || num < 0 || num > 0xffffffff) return null;
    return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255];
  }

  const rawParts = clean.split('.');
  if (rawParts.length < 1 || rawParts.length > 4) return null;

  const parts: number[] = [];
  for (const p of rawParts) {
    if (!p) return null;
    const n = parseIpv4ToNumber(p);
    if (isNaN(n) || n < 0) return null;
    parts.push(n);
  }

  if (parts.length === 1) {
    const num = parts[0]!;
    if (num > 0xffffffff) return null;
    return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255];
  }
  if (parts.length === 2) {
    // A.B: B is 24-bit
    if (parts[0]! > 255 || parts[1]! > 0xffffff) return null;
    return [parts[0]!, (parts[1]! >>> 16) & 255, (parts[1]! >>> 8) & 255, parts[1]! & 255];
  }
  if (parts.length === 3) {
    // A.B.C: C is 16-bit
    if (parts[0]! > 255 || parts[1]! > 255 || parts[2]! > 0xffff) return null;
    return [parts[0]!, parts[1]!, (parts[2]! >>> 8) & 255, parts[2]! & 255];
  }
  if (parts.length === 4) {
    if (parts.some((p) => p > 255)) return null;
    return parts as [number, number, number, number];
  }

  return null;
}

export function isProhibitedIpv4Bytes(parts: [number, number, number, number]): boolean {
  const [a, b, c] = parts;

  if (a === 0) return true; // 0.0.0.0/8 Current Network
  if (a === 127) return true; // 127.0.0.0/8 Loopback
  if (a === 10) return true; // 10.0.0.0/8 Private RFC 1918
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 Private RFC 1918
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 Private RFC 1918
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 Link-Local / AWS IMDS
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 Carrier-Grade NAT
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1 (RFC 5737)
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2 (RFC 5737)
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3 (RFC 5737)
  if (a === 198 && b >= 18 && b <= 19) return true; // Benchmark testing (RFC 2544)
  if (a === 192 && b === 0 && c === 0) return true; // IETF Protocol Assignments (RFC 6890)
  if (a === 192 && b === 88 && c === 99) return true; // 6to4 Relay Anycast (RFC 3068)
  if (a >= 224) return true; // 224.0.0.0/4 Multicast & Reserved (including 255.255.255.255 broadcast)

  return false;
}

export function isProhibitedIpv4(ip: string): boolean {
  const parts = normalizeIpv4(ip);
  if (!parts) {
    return true; // Malformed or invalid IPv4 fails closed as prohibited
  }
  return isProhibitedIpv4Bytes(parts);
}

export function parseIpv6(ip: string): number[] | null {
  let clean = ip.trim().toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  // Zone identifiers (%interface) are only valid for local scoped addresses (RFC 4007 / RFC 6874).
  // In public domain verification, zone identifiers MUST NOT be silently stripped; they must be rejected.
  if (clean.includes('%')) {
    return null;
  }

  // Handle embedded IPv4 at the end (e.g. ::ffff:192.168.1.1)
  let embeddedIpv4: [number, number, number, number] | null = null;
  const lastColon = clean.lastIndexOf(':');
  if (lastColon !== -1) {
    const afterColon = clean.slice(lastColon + 1);
    if (afterColon.includes('.')) {
      embeddedIpv4 = normalizeIpv4(afterColon);
      if (!embeddedIpv4) return null;
      clean = clean.slice(0, lastColon) + ':0:0';
    }
  }

  const parts = clean.split('::');
  if (parts.length > 2) return null; // Invalid multiple '::'

  const parseHexList = (s: string): number[] => {
    if (!s) return [];
    return s.split(':').map((h) => {
      if (!h || !/^[0-9a-f]{1,4}$/i.test(h)) return NaN;
      return parseInt(h, 16);
    });
  };

  const left = parseHexList(parts[0]!);
  const right = parts[1] !== undefined ? parseHexList(parts[1]) : [];
  if (left.some(isNaN) || right.some(isNaN)) return null;

  let words: number[];
  if (parts.length === 2) {
    const missing = 8 - (left.length + right.length);
    // When '::' is present, RFC 4291 requires at least one compressed zero hextet (missing >= 1).
    // An address containing 8 hextets plus '::' (e.g. 2001:4860:1:2:3:4:5:6::) is invalid syntax.
    if (missing < 1) return null;
    words = [...left, ...new Array(missing).fill(0), ...right];
  } else {
    if (left.length !== 8) return null;
    words = left;
  }

  if (embeddedIpv4) {
    words[6] = (embeddedIpv4[0] << 8) | embeddedIpv4[1];
    words[7] = (embeddedIpv4[2] << 8) | embeddedIpv4[3];
  }

  return words;
}

export function isIpLiteral(str: string): boolean {
  if (!str || typeof str !== 'string') return false;
  const clean = str.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (clean.includes(':')) return true; // IPv6 candidate
  if (/^0x[0-9a-f]+$/i.test(clean) || /^\d+$/.test(clean)) return true; // dword

  const parts = clean.split('.');
  if (parts.length >= 2 && parts.length <= 4) {
    return parts.every((p) => {
      if (!p) return false;
      if (/^0x[0-9a-f]+$/i.test(p)) return true;
      if (/^\d+$/.test(p)) return true;
      return false;
    });
  }
  return false;
}

export function isProhibitedIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return true;
  let clean = ip.trim().toLowerCase();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  // IPv6 format (contains colon)
  if (clean.includes(':')) {
    const words = parseIpv6(clean);
    if (!words) return true; // Malformed IPv6 fails closed

    const w0 = words[0]!;
    const w1 = words[1]!;

    // 1. Explicit assessment: ::0:0/96 (IPv4-compatible IPv6, deprecated RFC 4291 e.g. ::8.8.8.8)
    // Strictly prohibited to prevent SSRF filtering bypasses.
    if (words.slice(0, 6).every((w) => w === 0)) {
      return true;
    }

    // 2. Positive IPv6 Global-Unicast Policy (RFC 4291 section 2.4).
    // By default, only Global Unicast space (2000::/3) is routable on the public IPv6 internet.
    // In word 0, the top 3 bits must match 001 (0x2000). Any address outside 2000::/3 is prohibited:
    // - ::/128 (Unspecified)
    // - ::1/128 (Loopback)
    // - ::ffff:0:0/96 (IPv4-mapped IPv6, RFC 4291 / RFC 6890 Table 20 non-global)
    // - ::ffff:0:0:0/96 (SIIT IPv4-translated, RFC 7915)
    // - 64:ff9b::/96 & 64:ff9b:1::/48 (NAT64)
    // - 100::/64 (Discard-only)
    // - 4000::/3 through e000::/3 (Unallocated / Reserved e.g. 4000::1, f000::1, fe00::1)
    // - fc00::/7 (Unique Local Address - ULA e.g. fc00::1, fd00:ec2::254 IMDSv6)
    // - fe80::/10 (Link-Local Unicast)
    // - fec0::/10 (Site-Local Unicast, deprecated)
    // - ff00::/8 (Multicast)
    if ((w0 & 0xe000) !== 0x2000) {
      return true;
    }

    // 3. Preserved exclusions within 2000::/3:
    // - 2002::/16 (6to4, RFC 3056) - validate embedded IPv4 (bytes 2..5)
    // NOTE (6to4 Policy Assessment):
    // 6to4 anycast relays were deprecated by RFC 7526 due to operational and security limitations
    // (return-path asymmetry, lack of relay authentication, and high packet drop rates).
    // Current policy maintains backward compatibility for legitimate public 6to4 gateways by inspecting
    // embedded IPv4 bytes against the SSRF denylist, while blocking embedded private, loopback, and IMDS IPs.
    // In production hardening, this policy can be configured to reject the entire 2002::/16 range.
    if (w0 === 0x2002) {
      const v4: [number, number, number, number] = [
        (words[1]! >>> 8) & 255,
        words[1]! & 255,
        (words[2]! >>> 8) & 255,
        words[2]! & 255,
      ];
      return isProhibitedIpv4Bytes(v4);
    }

    // - 2001::/23 (IETF Special-Purpose Block, RFC 6890)
    // Covers:
    //   - 2001::/32 (Teredo, RFC 4380)
    //   - 2001:1::/32 (PCP Anycast, RFC 7723)
    //   - 2001:2::/48 (BMWG Benchmarking, RFC 5180)
    //   - 2001:3::/32 (AMT, RFC 7450)
    //   - 2001:4:112::/48 (AS112, RFC 7535)
    //   - 2001:10::/28 (ORCHID, RFC 4843)
    //   - 2001:20::/28 (ORCHIDv2, RFC 7343)
    //   - 2001:30::/28 (Drone ID DETs, RFC 9374)
    if (w0 === 0x2001 && (w1 & 0xfe00) === 0x0000) {
      return true;
    }

    // - 2001:db8::/32 (Documentation, RFC 3849)
    if (w0 === 0x2001 && w1 === 0x0db8) {
      return true;
    }

    // - 3fff::/20 (Documentation, RFC 9637)
    if (w0 === 0x3fff && (w1 & 0xf000) === 0x0000) {
      return true;
    }

    return false;
  }

  // IPv4 / Decimal / Hex / Octal numeric formats
  const v4Parts = normalizeIpv4(clean);
  if (!v4Parts) {
    return true; // Malformed address fails closed as prohibited
  }
  return isProhibitedIpv4Bytes(v4Parts);
}

export interface DefaultHttpFetcherOptions {
  addressResolver?: AddressResolverInterface;
  socketConnector?: SocketConnectorInterface;
  onSocketConnected?: (info: { remoteAddress: string; remotePort: number; servername?: string }) => void;
  allowLoopbackForTesting?: boolean;
}

export class DefaultHttpFetcher implements HttpFetcherInterface {
  private readonly addressResolver: AddressResolverInterface;
  private readonly socketConnector: SocketConnectorInterface;
  private readonly onSocketConnected?: (info: { remoteAddress: string; remotePort: number; servername?: string }) => void;
  private readonly allowLoopbackForTesting: boolean;

  constructor(options?: DefaultHttpFetcherOptions) {
    if (process.env.NODE_ENV === 'production' && (options?.socketConnector || options?.allowLoopbackForTesting)) {
      throw new Error('FATAL_SECURITY_ERROR: Custom socket connectors and test loopback options are prohibited in production.');
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
    this.fetcher = fetcher || new DefaultHttpFetcher();
  }

  async verify(url: string, expectedToken: string, expectedOrgId: string): Promise<HttpVerificationResult> {
    try {
      const { status, data } = await this.fetcher.fetch(url, { timeoutMs: 5000 });

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
