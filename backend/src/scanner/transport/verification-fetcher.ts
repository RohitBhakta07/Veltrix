/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Verification HTTP Fetcher Adapter
 *
 * Implements HttpFetcherInterface backed by SafeHttpClient and VerificationScopeGuard
 * for domain ownership challenge resolution.
 */

import { SafeHttpClient } from './safe-http-client.js';
import type { HttpResponse, HttpFetcherInterface } from '../verification/http-verifier.js';
import {
  type VerificationScopeContext,
  SafeTransportError,
} from './types.js';
import {
  createInternalVerificationContext,
  isTrustedScopeContext,
} from './context-authority.js';

export interface SafeVerificationFetcherOptions {
  client?: SafeHttpClient;
  allowLoopbackForTesting?: boolean;
  defaultToken?: string;
  primaryDomain?: string;
  orgId?: string;
  siteId?: string;
}

export interface SafeVerificationFetchOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
  token?: string;
  primaryDomain?: string;
  orgId?: string;
  siteId?: string;
  context?: VerificationScopeContext;
}

export class SafeVerificationHttpFetcher implements HttpFetcherInterface {
  private readonly client: SafeHttpClient;
  private readonly defaultToken?: string;
  private readonly primaryDomain?: string;
  private readonly orgId?: string;
  private readonly siteId?: string;
  private readonly allowLoopbackForTesting: boolean;

  constructor(options?: SafeVerificationFetcherOptions) {
    this.allowLoopbackForTesting = options?.allowLoopbackForTesting === true;
    this.client =
      options?.client ||
      new SafeHttpClient({
        allowLoopbackForTesting: this.allowLoopbackForTesting,
      });
    this.defaultToken = options?.defaultToken;
    this.primaryDomain = options?.primaryDomain;
    this.orgId = options?.orgId;
    this.siteId = options?.siteId;
  }

  async fetch(
    urlStr: string,
    options?: SafeVerificationFetchOptions
  ): Promise<HttpResponse> {
    let context: VerificationScopeContext;

    if (options?.context) {
      if (!isTrustedScopeContext(options.context)) {
        throw new SafeTransportError(
          'DOMAIN_NOT_VERIFIED',
          'Untrusted or forged request authorization context rejected. Context must be created via trusted internal service.'
        );
      }
      context = options.context;
    } else {
      const primaryDomain = options?.primaryDomain || this.primaryDomain;
      const activeToken = options?.token || this.defaultToken;
      const orgId = options?.orgId || this.orgId;
      const siteId = options?.siteId || this.siteId;

      if (!primaryDomain || !activeToken) {
        throw new SafeTransportError(
          'DOMAIN_NOT_VERIFIED',
          'SafeVerificationHttpFetcher requires trusted asset context (primaryDomain and activeToken). Deriving verification context from arbitrary URLs is prohibited.'
        );
      }

      context = createInternalVerificationContext({
        primaryDomain,
        activeToken,
        orgId,
        siteId,
      });
    }

    const res = await this.client.get(urlStr, {
      timeoutMs: options?.timeoutMs || 5000,
      signal: options?.signal,
      maxRedirects: 0,
      allowLoopbackForTesting: this.allowLoopbackForTesting,
      context,
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
