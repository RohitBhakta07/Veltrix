/**
 * VELTRIX Bounded Crawling & Endpoint Discovery Engine (TASK-803)
 *
 * Implements deterministic Breadth-First Search (BFS) endpoint discovery
 * backed strictly by SafeHttpClient, AuthorizedScanScopeGuard, and robust URL canonicalization.
 *
 * Inviolable Security Mandates:
 * - Issues GET requests only; never submits forms, mutations, or probing payloads.
 * - Confined strictly to verified primaryDomain and approvedSubdomains (no wildcards).
 * - Enforces mandatory server-side excluded paths and configured exclusions.
 * - Strictly bounds traversal: default maxDepth = 3 (max 5), configurable maxPages (max 1000).
 * - Bounded queue and response processing to eliminate denial-of-service / memory exhaustion.
 * - Handles network and parsing failures resiliently without crashing the entire crawl.
 * - Respects tenant-scoped AbortSignal for emergency sub-500ms shutdown.
 */

import { StringDecoder } from 'node:string_decoder';
import { SafeHttpClient } from '../transport/safe-http-client.js';
import {
  type AuthorizedScanScopeContext,
  SafeTransportError,
} from '../transport/types.js';
import type {
  CrawledPage,
  CrawlerOptions,
  CrawlResult,
  CrawlStoppedReason,
  DiscoveredEndpoint,
  LinkSource,
} from './types.js';
import {
  normalizeUrl,
  isBinaryOrMediaUrl,
  isScriptResourceUrl,
} from './url-normalizer.js';
import { extractHtmlLinks } from './html-link-extractor.js';
import { CrawlerScopeGuard } from './scope-guard.js';

interface QueueItem {
  readonly url: string;
  readonly depth: number;
  readonly parentUrl: string | null;
  readonly source: LinkSource;
}

export class BoundedCrawler {
  public static readonly DEFAULT_MAX_DEPTH = 3;
  public static readonly ABSOLUTE_MAX_DEPTH = 5;
  public static readonly DEFAULT_MAX_PAGES = 250;
  public static readonly ABSOLUTE_MAX_PAGES = 1000;
  public static readonly DEFAULT_MAX_QUEUE_SIZE = 2500;
  public static readonly ABSOLUTE_MAX_QUEUE_SIZE = 10000;
  public static readonly DEFAULT_TIMEOUT_MS = 10000;
  public static readonly DEFAULT_MAX_RESPONSE_SIZE_BYTES = 2 * 1024 * 1024; // 2MB
  public static readonly ABSOLUTE_MAX_RESPONSE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB (SafeHttpClient ceiling)

  private readonly context: AuthorizedScanScopeContext;
  private readonly client: SafeHttpClient;
  private readonly options: CrawlerOptions;

  public readonly maxDepth: number;
  public readonly maxPages: number;
  public readonly maxQueueSize: number;
  public readonly timeoutMs: number;
  public readonly maxResponseSizeBytes: number;

  constructor(
    context: AuthorizedScanScopeContext,
    clientOrOptions?: SafeHttpClient | CrawlerOptions,
    maybeOptions?: CrawlerOptions
  ) {
    if (!context || typeof context !== 'object') {
      throw new SafeTransportError('DOMAIN_NOT_VERIFIED', 'Authoritative AuthorizedScanScopeContext is required.');
    }

    this.context = context;

    let client: SafeHttpClient | undefined;
    let options: CrawlerOptions | undefined;

    if (clientOrOptions instanceof SafeHttpClient) {
      client = clientOrOptions;
      options = maybeOptions;
    } else if (typeof clientOrOptions === 'object' && clientOrOptions !== null) {
      options = clientOrOptions;
      client = undefined;
    }

    this.options = options || {};

    // Validate and enforce maxDepth (default: 3, max: 5)
    const rawMaxDepth = this.options.maxDepth ?? BoundedCrawler.DEFAULT_MAX_DEPTH;
    if (!Number.isInteger(rawMaxDepth) || rawMaxDepth < 0 || rawMaxDepth > BoundedCrawler.ABSOLUTE_MAX_DEPTH) {
      throw new RangeError(
        `maxDepth must be an integer between 0 and ${BoundedCrawler.ABSOLUTE_MAX_DEPTH} (received ${rawMaxDepth}).`
      );
    }
    this.maxDepth = rawMaxDepth;

    // Validate and enforce maxPages (default: 250, max: 1000)
    const rawMaxPages = this.options.maxPages ?? BoundedCrawler.DEFAULT_MAX_PAGES;
    if (!Number.isInteger(rawMaxPages) || rawMaxPages < 1 || rawMaxPages > BoundedCrawler.ABSOLUTE_MAX_PAGES) {
      throw new RangeError(
        `maxPages must be an integer between 1 and ${BoundedCrawler.ABSOLUTE_MAX_PAGES} (received ${rawMaxPages}).`
      );
    }
    this.maxPages = rawMaxPages;

    // Validate and enforce maxQueueSize (default: 2500, max: 10000)
    const rawQueueSize = this.options.maxQueueSize ?? BoundedCrawler.DEFAULT_MAX_QUEUE_SIZE;
    if (!Number.isInteger(rawQueueSize) || rawQueueSize < 1 || rawQueueSize > BoundedCrawler.ABSOLUTE_MAX_QUEUE_SIZE) {
      throw new RangeError(
        `maxQueueSize must be an integer between 1 and ${BoundedCrawler.ABSOLUTE_MAX_QUEUE_SIZE} (received ${rawQueueSize}).`
      );
    }
    this.maxQueueSize = rawQueueSize;

    // Request Timeout
    const rawTimeout = this.options.timeoutMs ?? BoundedCrawler.DEFAULT_TIMEOUT_MS;
    if (!Number.isInteger(rawTimeout) || rawTimeout < 100) {
      throw new RangeError(`timeoutMs must be an integer >= 100ms (received ${rawTimeout}).`);
    }
    this.timeoutMs = rawTimeout;

    // Validate and enforce maxResponseSizeBytes (default: 2MB, max: 10MB)
    const rawMaxResponse =
      this.options.maxResponseSizeBytes ?? BoundedCrawler.DEFAULT_MAX_RESPONSE_SIZE_BYTES;
    if (
      !Number.isInteger(rawMaxResponse) ||
      rawMaxResponse < 1 ||
      rawMaxResponse > BoundedCrawler.ABSOLUTE_MAX_RESPONSE_SIZE_BYTES
    ) {
      throw new RangeError(
        `maxResponseSizeBytes must be an integer between 1 and ${BoundedCrawler.ABSOLUTE_MAX_RESPONSE_SIZE_BYTES} bytes (received ${rawMaxResponse}).`
      );
    }
    this.maxResponseSizeBytes = rawMaxResponse;

    // Initialize or assign SafeHttpClient
    this.client =
      client ||
      new SafeHttpClient({
        allowLoopbackForTesting: this.options.allowLoopbackForTesting,
      });
  }

  /**
   * Executes bounded breadth-first crawling starting from the specified seed URL.
   *
   * @param customSeedUrl Optional seed URL. Defaults to https://${context.primaryDomain}/.
   */
  async crawl(customSeedUrl?: string): Promise<CrawlResult> {
    const startTime = Date.now();

    // 1. Resolve and validate initial seed URL
    const rawSeed = customSeedUrl || `https://${this.context.primaryDomain}/`;
    const normalizedSeed = normalizeUrl(rawSeed);
    if (!normalizedSeed) {
      throw new SafeTransportError('MALFORMED_URL', `Invalid or unparseable crawl seed URL '${rawSeed}'.`);
    }

    const seedScopeCheck = CrawlerScopeGuard.evaluate(normalizedSeed, this.context);
    if (!seedScopeCheck.inScope) {
      throw new SafeTransportError(
        'SSRF_BLOCKED',
        `Crawl seed URL '${normalizedSeed}' is out of authorized scan scope: ${seedScopeCheck.reason}`
      );
    }

    // 2. Initialize BFS data structures
    const queue: QueueItem[] = [
      {
        url: normalizedSeed,
        depth: 0,
        parentUrl: null,
        source: 'seed',
      },
    ];

    const visitedUrls = new Set<string>();
    visitedUrls.add(normalizedSeed);

    const discoveredUrlsMap = new Map<string, DiscoveredEndpoint>();
    discoveredUrlsMap.set(normalizedSeed, {
      url: normalizedSeed,
      rawUrl: rawSeed,
      source: 'seed',
      depth: 0,
      parentUrl: null,
    });

    const pages: CrawledPage[] = [];
    let stoppedReason: CrawlStoppedReason = 'COMPLETED';

    // 3. BFS Execution Loop
    while (queue.length > 0) {
      // Check cancellation signal
      if (this.options.signal?.aborted) {
        stoppedReason = 'ABORTED';
        break;
      }

      // Check page count limit
      if (pages.length >= this.maxPages) {
        stoppedReason = 'MAX_PAGES_REACHED';
        break;
      }

      const currentItem = queue.shift()!;

      // Skip items that exceed maximum depth limit
      if (currentItem.depth > this.maxDepth) {
        continue;
      }

      // Fetch and process page
      const page = await this.crawlSinglePage(currentItem);
      pages.push(page);

      // Invoke onPageCrawled callback
      if (this.options.onPageCrawled) {
        try {
          await this.options.onPageCrawled(page);
        } catch {
          // Callback errors must not crash crawler execution
        }
      }

      // If page limit reached immediately after adding this page, stop
      if (pages.length >= this.maxPages) {
        stoppedReason = 'MAX_PAGES_REACHED';
        break;
      }

      // If next depth level exceeds maxDepth, don't enqueue newly discovered links
      if (currentItem.depth + 1 > this.maxDepth) {
        continue;
      }

      // Process newly discovered endpoints
      for (const ep of page.discoveredEndpoints) {
        // Record all discovered endpoints
        if (!discoveredUrlsMap.has(ep.url)) {
          discoveredUrlsMap.set(ep.url, ep);
        }

        // Never enqueue non-GET form actions (e.g. POST, PUT, DELETE)
        if (ep.source === 'form' && ep.method && ep.method !== 'GET') {
          continue;
        }

        // Skip static JavaScript resources from consuming HTML crawl page budget
        if (ep.source === 'script' || isScriptResourceUrl(ep.url)) {
          continue;
        }

        // Only enqueue unvisited HTML endpoints for further crawling
        if (!visitedUrls.has(ep.url)) {
          // Skip static binary / media extensions if configured
          if (this.options.skipBinaryExtensions !== false && isBinaryOrMediaUrl(ep.url)) {
            continue;
          }

          // Check queue capacity ceiling
          if (queue.length >= this.maxQueueSize) {
            stoppedReason = 'QUEUE_LIMIT_REACHED';
            break;
          }

          visitedUrls.add(ep.url);
          const queueItem: QueueItem = {
            url: ep.url,
            depth: currentItem.depth + 1,
            parentUrl: currentItem.url,
            source: ep.source,
          };
          queue.push(queueItem);

          if (this.options.onPageDiscovered) {
            try {
              this.options.onPageDiscovered(ep.url, queueItem.depth, ep.source);
            } catch {
              // Callback exceptions must not abort an otherwise valid crawl
            }
          }
        }
      }

      if (stoppedReason === 'QUEUE_LIMIT_REACHED') {
        break;
      }
    }

    if (queue.length === 0 && stoppedReason === 'COMPLETED') {
      stoppedReason = 'COMPLETED';
    }

    const durationMs = Date.now() - startTime;

    return Object.freeze({
      seedUrl: normalizedSeed,
      pagesCrawled: pages.length,
      totalDiscovered: discoveredUrlsMap.size,
      pages: Object.freeze(pages),
      discoveredUrls: Object.freeze(Array.from(discoveredUrlsMap.keys())),
      durationMs,
      stoppedReason,
    });
  }

  /**
   * Fetches a single page using SafeHttpClient, extracts in-scope HTML links, and records metrics.
   */
  private async crawlSinglePage(item: QueueItem): Promise<CrawledPage> {
    const pageStartTime = Date.now();

    try {
      // Dispatch safe HTTP GET request via SafeHttpClient
      const res = await this.client.get(item.url, {
        context: this.context,
        timeoutMs: this.timeoutMs,
        signal: this.options.signal,
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          ...(this.options.userAgent ? { 'User-Agent': this.options.userAgent } : {}),
        },
        allowLoopbackForTesting: this.options.allowLoopbackForTesting,
      });

      const durationMs = Date.now() - pageStartTime;
      const contentType = res.headers['content-type'] || 'text/html';
      const isHtml = /text\/html|application\/xhtml\+xml/i.test(contentType);

      let title: string | undefined;
      let discoveredEndpoints: DiscoveredEndpoint[] = [];

      // Extract links only from HTML responses
      if (isHtml && (res.rawBody || res.text)) {
        // Enforce parsing ceiling in actual UTF-8 bytes using res.rawBody
        const bodyBuffer = res.rawBody || Buffer.from(res.text || '', 'utf8');
        let htmlToParse = res.text || '';

        if (bodyBuffer.length > this.maxResponseSizeBytes) {
          const slicedBuffer = bodyBuffer.subarray(0, this.maxResponseSizeBytes);
          const decoder = new StringDecoder('utf8');
          htmlToParse = decoder.write(slicedBuffer);
        } else if (!htmlToParse && bodyBuffer.length > 0) {
          htmlToParse = bodyBuffer.toString('utf8');
        }

        const extractionResult = extractHtmlLinks(htmlToParse, item.url, item.depth);
        title = extractionResult.title;

        // Filter extracted endpoints to retain only in-scope endpoints
        discoveredEndpoints = CrawlerScopeGuard.filterInScopeEndpoints(
          extractionResult.endpoints,
          this.context
        );
      }

      return Object.freeze({
        url: item.url,
        depth: item.depth,
        parentUrl: item.parentUrl,
        source: item.source,
        status: res.status,
        statusText: res.statusText || 'OK',
        contentType,
        title,
        discoveredEndpoints: Object.freeze(discoveredEndpoints),
        durationMs,
        wireBytesReceived: res.wireBytesReceived || 0,
        headers: res.headers,
        setCookies: res.setCookies,
        rawHeaders: res.rawHeaders,
        bodyText: res.text,
        rawBody: res.rawBody,
        tls: res.tls,
      });
    } catch (err) {
      const durationMs = Date.now() - pageStartTime;
      const errorMsg = err instanceof Error ? err.message : String(err);

      if (this.options.onError) {
        try {
          this.options.onError(err instanceof Error ? err : new Error(errorMsg), item.url);
        } catch {
          // Callback exceptions must not abort an otherwise valid crawl
        }
      }

      return Object.freeze({
        url: item.url,
        depth: item.depth,
        parentUrl: item.parentUrl,
        source: item.source,
        status: 0,
        statusText: 'Request Failed',
        contentType: '',
        discoveredEndpoints: Object.freeze([]),
        durationMs,
        wireBytesReceived: 0,
        error: errorMsg,
      });
    }
  }
}
