import type { HttpFetcherInterface } from './http-verifier.js';
import { SafeVerificationHttpFetcher } from '../transport/verification-fetcher.js';
import type { VerificationScopeContext } from '../transport/types.js';

export interface MetaVerificationResult {
  matched: boolean;
  metaTagsFound?: string[];
  failureReason?: string;
}

export class MetaVerifier {
  private readonly fetcher: HttpFetcherInterface;

  constructor(fetcher?: HttpFetcherInterface) {
    this.fetcher = fetcher || new SafeVerificationHttpFetcher();
  }

  async verify(
    targetUrl: string,
    expectedToken: string,
    context?: VerificationScopeContext
  ): Promise<MetaVerificationResult> {
    const cleanExpected = expectedToken.trim();

    try {
      const { status, text } = await this.fetcher.fetch(targetUrl, {
        timeoutMs: 5000,
        token: cleanExpected,
        context,
      });

      if (status !== 200) {
        return {
          matched: false,
          failureReason: `Target page returned HTTP status ${status} (expected 200 OK).`,
        };
      }

      if (!text || typeof text !== 'string') {
        return {
          matched: false,
          failureReason: 'Target page returned empty or non-text response body.',
        };
      }

      // Regex matching <meta ... name="veltrix-site-verification" ... content="TOKEN" ...>
      // and <meta ... content="TOKEN" ... name="veltrix-site-verification" ...>
      const metaTagRegex = /<meta\s+[^>]*?(?:name|property)\s*=\s*["']?veltrix-site-verification["']?[^>]*?>/gi;
      const matches = text.match(metaTagRegex) || [];

      if (matches.length === 0) {
        return {
          matched: false,
          failureReason: `No '<meta name="veltrix-site-verification" content="${cleanExpected}" />' tag found in the HTML head.`,
        };
      }

      const foundTokens: string[] = [];

      for (const tag of matches) {
        const contentMatch = tag.match(/content\s*=\s*["']([^"']+)["']/i) || tag.match(/content\s*=\s*([^\s>]+)/i);
        if (contentMatch && contentMatch[1]) {
          const token = contentMatch[1].trim();
          foundTokens.push(token);
          if (token === cleanExpected) {
            return {
              matched: true,
              metaTagsFound: matches,
            };
          }
        }
      }

      return {
        matched: false,
        metaTagsFound: matches,
        failureReason: `Found veltrix-site-verification meta tag but content [${foundTokens.join(', ')}] did not match expected token '${cleanExpected}'.`,
      };
    } catch (err: unknown) {
      const errMsg = (err as Error)?.message || 'HTTP request failed';
      return {
        matched: false,
        failureReason: `Failed to fetch HTML document at '${targetUrl}': ${errMsg}`,
      };
    }
  }
}
