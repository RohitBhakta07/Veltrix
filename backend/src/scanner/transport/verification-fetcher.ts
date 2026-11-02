/**
 * VELTRIX Hardened Safe HTTP Transport Layer - Verification HTTP Fetcher Adapter
 *
 * Implements HttpFetcherInterface backed by SafeHttpClient and VerificationScopeGuard
 * for domain ownership challenge resolution.
 *
 * Inviolable Security Mandate:
 * - Pre-request context minting is prohibited. Fetch requests must supply an authoritatively
 *   minted VerificationScopeContext created through database provenance.
 * - In production (process.env.NODE_ENV === 'production'), injected SafeHttpClient implementations
 *   and test loopback flags are strictly forbidden with FATAL_SECURITY_ERROR.
 */

import { SafeHttpClient } from './safe-http-client.js';
import type { HttpResponse, HttpFetcherInterface } from '../verification/http-verifier.js';
import {
  type VerificationScopeContext,
  SafeTransportError,
} from './types.js';
import { isTrustedScopeContext } from './context-authority.js';

export interface SafeVerificationFetcherOptions {
  client?: SafeHttpClient;
  allowLoopbackForTesting?: boolean;
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
  private readonly allowLoopbackForTesting: boolean;

  constructor(options?: SafeVerificationFetcherOptions) {
    if (process.env.NODE_ENV === 'production') {
      if (options?.client || options?.allowLoopbackForTesting) {
        throw new Error(
          'FATAL_SECURITY_ERROR: Injected SafeHttpClient and test loopback options are prohibited in production.'
        );
      }
    }

    this.allowLoopbackForTesting = options?.allowLoopbackForTesting === true;
    this.client =
      options?.client ||
      new SafeHttpClient({
        allowLoopbackForTesting: this.allowLoopbackForTesting,
      });
  }

  async fetch(
    urlStr: string,
    options?: SafeVerificationFetchOptions
  ): Promise<HttpResponse> {
    if (!options?.context) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        'SafeVerificationHttpFetcher requires a pre-validated authoritative VerificationScopeContext. Deriving or minting verification contexts from arbitrary per-request parameters is prohibited.'
      );
    }

    if (!isTrustedScopeContext(options.context)) {
      throw new SafeTransportError(
        'DOMAIN_NOT_VERIFIED',
        'Untrusted or forged request authorization context rejected. Context must be created via trusted internal service.'
      );
    }

    const context: VerificationScopeContext = options.context;

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
