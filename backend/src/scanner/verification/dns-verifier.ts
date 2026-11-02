import dns from 'node:dns/promises';

export interface DnsResolverInterface {
  resolveTxt(host: string): Promise<string[][]>;
}

export class DefaultDnsResolver implements DnsResolverInterface {
  async resolveTxt(host: string): Promise<string[][]> {
    return dns.resolveTxt(host);
  }
}

export interface DnsVerificationResult {
  matched: boolean;
  recordsFound: string[];
  failureReason?: string;
}

export class DnsVerifier {
  private readonly resolver: DnsResolverInterface;

  constructor(resolver?: DnsResolverInterface) {
    this.resolver = resolver || new DefaultDnsResolver();
  }

  async verify(expectedHost: string, expectedValue: string): Promise<DnsVerificationResult> {
    const cleanHost = expectedHost.trim().toLowerCase();
    const cleanExpected = expectedValue.trim();

    try {
      const rawRecords = await this.resolver.resolveTxt(cleanHost);
      // DNS TXT entries can be returned as arrays of chunks per RFC 1035; concatenate each record's chunks
      const flattened = rawRecords.map((chunks) => chunks.join(''));
      const matched = flattened.some((record) => record.trim() === cleanExpected);

      if (!matched) {
        return {
          matched: false,
          recordsFound: flattened,
          failureReason: `DNS TXT record '${cleanHost}' was found but did not match expected value '${cleanExpected}'. Found: [${flattened.join(', ')}]`,
        };
      }

      return {
        matched: true,
        recordsFound: flattened,
      };
    } catch (err: unknown) {
      const errMsg = (err as Error)?.message || 'DNS resolution failed';
      const code = (err as { code?: string })?.code;

      let reason = `DNS TXT query for '${cleanHost}' failed: ${errMsg}`;
      if (code === 'ENOTFOUND' || code === 'ENODATA') {
        reason = `DNS TXT record '${cleanHost}' was not found.`;
      } else if (code === 'ETIMEOUT') {
        reason = `DNS TXT query for '${cleanHost}' timed out.`;
      }

      return {
        matched: false,
        recordsFound: [],
        failureReason: reason,
      };
    }
  }
}
