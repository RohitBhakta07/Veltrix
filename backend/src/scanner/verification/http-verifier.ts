import dns from 'node:dns/promises';

export interface HttpFetcherInterface {
  fetch(
    url: string,
    options?: { timeoutMs?: number }
  ): Promise<{ status: number; data: unknown; text?: string; headers?: Record<string, string> }>;
}

export function isProhibitedIpv4(ip: string): boolean {
  // Normalize potential octal/hex/dword formats
  let cleanIp = ip.trim();

  // If integer format (dword), e.g. 2130706433
  if (/^\d+$/.test(cleanIp)) {
    const num = Number(cleanIp);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      const b1 = (num >>> 24) & 255;
      const b2 = (num >>> 16) & 255;
      const b3 = (num >>> 8) & 255;
      const b4 = num & 255;
      cleanIp = `${b1}.${b2}.${b3}.${b4}`;
    }
  }

  const parts = cleanIp.split('.').map((p) => {
    // Handle octal (e.g. 0177) or hex (0x7f)
    if (p.startsWith('0x') || p.startsWith('0X')) {
      return parseInt(p, 16);
    }
    if (p.length > 1 && p.startsWith('0')) {
      return parseInt(p, 8);
    }
    return Number(p);
  });

  if (parts.length === 2) {
    // Zero-compressed, e.g. 127.1 -> 127.0.0.1
    parts.splice(1, 0, 0, 0);
  } else if (parts.length === 3) {
    // e.g. 127.0.1 -> 127.0.0.1
    parts.splice(2, 0, 0);
  }

  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return true; // Prohibit malformed or unparseable IPv4
  }

  const [a, b, c] = parts;
  if (a === 0) return true; // 0.0.0.0/8 Current Network
  if (a === 127) return true; // 127.0.0.0/8 Loopback
  if (a === 10) return true; // 10.0.0.0/8 Private
  if (a === 172 && b! >= 16 && b! <= 31) return true; // 172.16.0.0/12 Private
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 Private
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 Link-Local / AWS IMDS
  if (a === 100 && b! >= 64 && b! <= 127) return true; // 100.64.0.0/10 Carrier-Grade NAT
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  if (a === 198 && b! >= 18 && b! <= 19) return true; // Benchmark testing
  if (a! >= 224) return true; // 224.0.0.0/4 Multicast & Reserved
  if (a === 255 && b === 255 && c === 255 && parts[3] === 255) return true; // Broadcast

  return false;
}

export function isProhibitedIp(ip: string): boolean {
  const clean = ip.trim().toLowerCase();

  // IPv4, decimal dword, or IPv4-Mapped IPv6
  if (clean.includes('.') || /^\d+$/.test(clean)) {
    if (clean.startsWith('::ffff:')) {
      return isProhibitedIpv4(clean.slice(7));
    }
    return isProhibitedIpv4(clean);
  }

  // IPv6 checks
  if (clean === '::1' || clean === '::' || clean === '0:0:0:0:0:0:0:1' || clean === '0:0:0:0:0:0:0:0') {
    return true; // Loopback or Unspecified
  }
  if (clean.startsWith('fe80:') || clean.startsWith('fe9') || clean.startsWith('fea') || clean.startsWith('feb')) {
    return true; // fe80::/10 Link-Local
  }
  if (clean.startsWith('fc') || clean.startsWith('fd')) {
    return true; // fc00::/7 Unique Local (ULA) and AWS IMDSv6 [fd00:ec2::254]
  }
  if (clean.startsWith('64:ff9b:')) {
    return true; // NAT64
  }
  if (clean.startsWith('2001:db8:')) {
    return true; // Documentation
  }

  return false;
}

export class DefaultHttpFetcher implements HttpFetcherInterface {
  async fetch(
    url: string,
    options?: { timeoutMs?: number }
  ): Promise<{ status: number; data: unknown; text?: string; headers?: Record<string, string> }> {
    const timeout = options?.timeoutMs || 5000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const parsedUrl = new URL(url);

      // 1. Strict protocol allowlist
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        throw new Error(`SSRF blocked: Prohibited protocol '${parsedUrl.protocol}'. Only HTTP/HTTPS allowed.`);
      }

      const hostname = parsedUrl.hostname.toLowerCase();

      // 2. Reject prohibited literal hostnames
      if (
        hostname === 'localhost' ||
        hostname.endsWith('.internal') ||
        hostname.endsWith('.local') ||
        hostname.endsWith('.arpa') ||
        hostname === 'metadata.google.internal'
      ) {
        throw new Error(`SSRF blocked: Prohibited destination host '${hostname}'.`);
      }

      // Check if hostname itself is a prohibited IP literal
      if (isProhibitedIp(hostname)) {
        throw new Error(`SSRF blocked: Host '${hostname}' is a prohibited IP literal.`);
      }

      // 3. DNS Resolution & Pinning: Verify resolved IPs do not hit private/link-local/metadata
      try {
        const resolved = await dns.lookup(hostname, { all: true });
        for (const record of resolved) {
          if (isProhibitedIp(record.address)) {
            throw new Error(`SSRF blocked: Host '${hostname}' resolved to prohibited IP address '${record.address}'.`);
          }
        }
      } catch (dnsErr: unknown) {
        if ((dnsErr as Error).message.startsWith('SSRF blocked')) {
          throw dnsErr;
        }
        if (process.env.NODE_ENV === 'production') {
          throw new Error(`DNS resolution failed for verification target '${hostname}': ${(dnsErr as Error).message}`);
        }
      }

      // 4. Dispatch HTTP request with no-redirect policy to prevent redirect-based SSRF
      const res = await fetch(url, {
        signal: controller.signal,
        redirect: 'error',
        headers: {
          'User-Agent': 'Veltrix-Domain-Verifier/1.0.0 (+https://veltrix.io)',
          Accept: 'application/json, text/html, */*',
        },
      });

      // 5. Response size limit enforcement (max 128KB for HTML/JSON verification)
      const MAX_RESPONSE_BYTES = 128 * 1024;
      const contentLength = res.headers.get('content-length');
      if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
        throw new Error(`Verification response exceeded maximum allowed size of 128KB (${contentLength} bytes).`);
      }

      const text = await res.text();
      if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
        throw new Error('Verification response exceeded maximum allowed size of 128KB.');
      }

      let data: unknown;
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }

      const responseHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        responseHeaders[k.toLowerCase()] = v;
      });

      return { status: res.status, data, text, headers: responseHeaders };
    } finally {
      clearTimeout(timer);
    }
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
