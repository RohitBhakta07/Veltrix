/**
 * VELTRIX Bounded Crawling & Endpoint Discovery Engine - Type Definitions (TASK-803)
 *
 * Defines data structures, options, results, and interfaces for the
 * bounded, deterministic BFS web crawler and link extraction pipeline.
 */

import type { SanitizedTlsMetadata } from '../transport/types.js';

export type CrawlStoppedReason =
  | 'COMPLETED'
  | 'MAX_PAGES_REACHED'
  | 'MAX_DEPTH_REACHED'
  | 'QUEUE_LIMIT_REACHED'
  | 'ABORTED';

export type LinkSource = 'seed' | 'a' | 'form' | 'script' | 'link';

export interface FormField {
  readonly name: string;
  readonly type?: string;
  readonly value?: string;
}

export interface DiscoveredEndpoint {
  readonly url: string;
  readonly rawUrl: string;
  readonly source: LinkSource;
  readonly depth: number;
  readonly parentUrl: string | null;
  readonly method?: string; // Form method (e.g. GET, POST) for passive awareness only; crawler NEVER submits
  readonly formFields?: readonly FormField[];
}

export interface CrawledPage {
  readonly url: string;
  readonly depth: number;
  readonly parentUrl: string | null;
  readonly source: LinkSource;
  readonly status: number;
  readonly statusText: string;
  readonly contentType: string;
  readonly title?: string;
  readonly discoveredEndpoints: readonly DiscoveredEndpoint[];
  readonly durationMs: number;
  readonly wireBytesReceived: number;
  readonly error?: string;
  readonly headers?: Record<string, string>;
  readonly setCookies?: readonly string[];
  readonly rawHeaders?: readonly string[];
  readonly bodyText?: string;
  readonly rawBody?: Buffer;
  readonly tls?: SanitizedTlsMetadata;
}

export interface CrawlerOptions {
  /**
   * Maximum crawl depth from seed URL (default: 3, max: 5).
   * Seed is depth 0. Links on seed are depth 1.
   */
  readonly maxDepth?: number;

  /**
   * Maximum number of pages to fetch and crawl (default: 250, max: 1000).
   */
  readonly maxPages?: number;

  /**
   * Maximum queue size to prevent unbounded memory growth (default: 2500, max: 10000).
   */
  readonly maxQueueSize?: number;

  /**
   * Maximum response body bytes to parse for HTML links (default: 2MB).
   * Responses exceeding SafeHttpClient's 10MB ceiling are dropped by transport.
   */
  readonly maxResponseSizeBytes?: number;

  /**
   * End-to-end request timeout per crawled page in milliseconds (default: 10000).
   */
  readonly timeoutMs?: number;

  /**
   * Custom User-Agent header (defaults to Veltrix-Security-Scanner).
   */
  readonly userAgent?: string;

  /**
   * Cancellation / emergency abort signal.
   */
  readonly signal?: AbortSignal;

  /**
   * Whether to skip known static media and binary file extensions (default: true).
   */
  readonly skipBinaryExtensions?: boolean;

  /**
   * Testing hook: permits loopback addresses in unit test environments.
   * Strictly prohibited in production by SafeHttpClient.
   */
  readonly allowLoopbackForTesting?: boolean;

  /**
   * Callback invoked whenever a page request finishes.
   */
  readonly onPageCrawled?: (page: CrawledPage) => void | Promise<void>;

  /**
   * Callback invoked whenever a new in-scope URL is discovered and enqueued.
   */
  readonly onPageDiscovered?: (url: string, depth: number, source: LinkSource) => void;

  /**
   * Callback invoked when a network or parsing failure occurs.
   */
  readonly onError?: (error: Error, url: string) => void;
}

export interface CrawlResult {
  readonly seedUrl: string;
  readonly pagesCrawled: number;
  readonly totalDiscovered: number;
  readonly pages: readonly CrawledPage[];
  readonly discoveredUrls: readonly string[];
  readonly durationMs: number;
  readonly stoppedReason: CrawlStoppedReason;
}
