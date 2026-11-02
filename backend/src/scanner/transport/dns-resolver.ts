/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Dedicated DNS Resolver
 *
 * Enforces pre-flight multi-record DNS resolution, strict timeout bounds,
 * fail-closed SSRF validation across all resolved records, and socket-level IP pinning.
 */

import dns from 'node:dns/promises';
import net from 'node:net';
import { isProhibitedIp, isIpLiteral } from './ip-validator.js';
import {
  type DnsRecord,
  type ValidatedDnsResolution,
  type DnsResolverInterface,
  SafeTransportError,
} from './types.js';

export interface DnsResolverOptions {
  lookupFn?: (hostname: string) => Promise<DnsRecord[]>;
  allowLoopbackForTesting?: boolean;
}

export class DnsResolver implements DnsResolverInterface {
  private readonly lookupFn: (hostname: string) => Promise<DnsRecord[]>;
  private readonly allowLoopbackForTesting: boolean;

  constructor(options?: DnsResolverOptions) {
    if (process.env.NODE_ENV === 'production') {
      if (options?.lookupFn) {
        throw new Error('FATAL_SECURITY_ERROR: Injected lookupFn is prohibited in production.');
      }
      if (options?.allowLoopbackForTesting) {
        throw new Error('FATAL_SECURITY_ERROR: Test loopback options are prohibited in production.');
      }
    }

    this.allowLoopbackForTesting = options?.allowLoopbackForTesting === true && process.env.NODE_ENV !== 'production';

    this.lookupFn = options?.lookupFn || (async (hostname: string): Promise<DnsRecord[]> => {
      const results = await dns.lookup(hostname, { all: true });
      return results.map((r) => ({
        address: r.address,
        family: r.family,
      }));
    });
  }

  async resolve(hostname: string, options?: { timeoutMs?: number; signal?: AbortSignal }): Promise<ValidatedDnsResolution> {
    if (!hostname || typeof hostname !== 'string') {
      throw new SafeTransportError('MALFORMED_URL', 'Invalid or empty hostname provided for DNS resolution.');
    }

    if (options?.signal?.aborted) {
      throw new SafeTransportError('ABORTED', 'DNS resolution was cancelled by AbortSignal.');
    }

    const rawHostname = hostname.trim().toLowerCase();
    const cleanHostname = rawHostname.startsWith('[') && rawHostname.endsWith(']')
      ? rawHostname.slice(1, -1)
      : rawHostname;

    const isTestLoopbackAllowed = this.allowLoopbackForTesting &&
      (cleanHostname === '127.0.0.1' || cleanHostname === '::1');

    // 1. Prohibited special-use and internal domain suffix checks
    if (
      !isTestLoopbackAllowed && (
        cleanHostname === 'localhost' ||
        cleanHostname.endsWith('.internal') ||
        cleanHostname.endsWith('.local') ||
        cleanHostname.endsWith('.arpa') ||
        cleanHostname === 'metadata.google.internal'
      )
    ) {
      throw new SafeTransportError('SSRF_BLOCKED', `SSRF blocked: Prohibited destination host '${cleanHostname}'.`);
    }

    // 2. Direct IP literal check (IPv4 or IPv6)
    if (net.isIP(cleanHostname) || isIpLiteral(cleanHostname)) {
      if (!isTestLoopbackAllowed && isProhibitedIp(cleanHostname)) {
        throw new SafeTransportError('SSRF_BLOCKED', `SSRF blocked: Host '${rawHostname}' is a prohibited IP literal.`);
      }
      const family = net.isIP(cleanHostname) || (cleanHostname.includes(':') ? 6 : 4);
      const record: DnsRecord = { address: cleanHostname, family };
      return {
        hostname: cleanHostname,
        records: [record],
        pinnedIp: cleanHostname,
        family,
      };
    }

    // 3. DNS Lookup with bounded timeout
    const timeoutMs = options?.timeoutMs && options.timeoutMs > 0 ? options.timeoutMs : 3000;
    let records: DnsRecord[];

    try {
      const lookupPromise = this.lookupFn(cleanHostname);
      let timer: NodeJS.Timeout;
      let abortHandler: (() => void) | null = null;

      const timeoutPromise = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(new SafeTransportError('DNS_RESOLUTION_FAILED', `DNS resolution timed out after ${timeoutMs}ms for host '${cleanHostname}'.`));
        }, timeoutMs);
        timer.unref?.();

        if (options?.signal) {
          abortHandler = () => {
            reject(new SafeTransportError('ABORTED', 'DNS resolution was cancelled by AbortSignal.'));
          };
          options.signal.addEventListener('abort', abortHandler, { once: true });
        }
      });

      try {
        records = await Promise.race([lookupPromise, timeoutPromise]);
      } finally {
        clearTimeout(timer!);
        if (options?.signal && abortHandler) {
          options.signal.removeEventListener('abort', abortHandler);
        }
      }
    } catch (err: unknown) {
      if (err instanceof SafeTransportError) {
        throw err;
      }
      const errMsg = (err as Error)?.message || 'Unknown DNS resolution error';
      throw new SafeTransportError('DNS_RESOLUTION_FAILED', `DNS resolution failed for host '${cleanHostname}': ${errMsg}`);
    }

    if (!records || records.length === 0) {
      throw new SafeTransportError('DNS_RESOLUTION_FAILED', `DNS resolution returned no addresses for host '${cleanHostname}'.`);
    }

    // 4. Validate EVERY resolved address - Fail closed if ANY address is prohibited!
    for (const record of records) {
      if (!record || !record.address) {
        throw new SafeTransportError('SSRF_BLOCKED', `SSRF blocked: Host '${cleanHostname}' resolved to invalid address.`);
      }

      const recordLoopbackAllowed = this.allowLoopbackForTesting &&
        (record.address === '127.0.0.1' || record.address === '::1');

      if (!recordLoopbackAllowed && isProhibitedIp(record.address)) {
        throw new SafeTransportError('SSRF_BLOCKED', `SSRF blocked: Host '${cleanHostname}' resolved to prohibited IP address '${record.address}'.`);
      }
    }

    // 5. Select Pinned IP
    const pinnedRecord = records[0]!;
    const pinnedIp = pinnedRecord.address.replace(/^\[|\]$/g, '');
    const family = pinnedRecord.family || (pinnedIp.includes(':') ? 6 : 4);

    return {
      hostname: cleanHostname,
      records,
      pinnedIp,
      family,
    };
  }
}
