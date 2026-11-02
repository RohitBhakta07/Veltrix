/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Verification HTTP Fetcher Adapter
 *
 * Implements HttpFetcherInterface backed by SafeHttpClient and VerificationScopeGuard
 * for domain ownership challenge resolution.
 */

import { SafeHttpClient } from './safe-http-client.js';
import type { HttpResponse, HttpFetcherInterface } from '../verification/http-verifier.js';

export interface SafeVerificationFetcherOptions {
  client?: SafeHttpClient;
  allowLoopbackForTesting?: boolean;
  defaultToken?: string;
}

export class SafeVerificationHttpFetcher implements HttpFetcherInterface {
  private readonly client: SafeHttpClient;
  private readonly defaultToken?: string;

  constructor(options?: SafeVerificationFetcherOptions) {
    this.client =
      options?.client ||
      new SafeHttpClient({
        allowLoopbackForTesting: options?.allowLoopbackForTesting,
      });
    this.defaultToken = options?.defaultToken;
  }

  async fetch(
    urlStr: string,
    options?: { timeoutMs?: number; signal?: AbortSignal; token?: string }
  ): Promise<HttpResponse> {
    const parsed = new URL(urlStr);

    let activeToken = options?.token || this.defaultToken || '';
    if (!activeToken && parsed.pathname.startsWith('/.well-known/veltrix-challenge/')) {
      activeToken = parsed.pathname.slice('/.well-known/veltrix-challenge/'.length);
    }

    const res = await this.client.get(urlStr, {
      timeoutMs: options?.timeoutMs || 5000,
      signal: options?.signal,
      maxRedirects: 0,
      allowLoopbackForTesting: (this.client as any).allowLoopbackForTesting,
      context: {
        purpose: 'DOMAIN_OWNERSHIP_VERIFICATION',
        primaryDomain: parsed.hostname,
        activeToken,
      },
    });

    return {
      status: res.status,
      data: res.data,
      text: res.text,
      headers: res.headers,
      remoteAddress: res.remoteAddress,
    };
  }
}
