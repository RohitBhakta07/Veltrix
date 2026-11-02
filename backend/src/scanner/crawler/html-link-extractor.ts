/**
 * VELTRIX Safe HTML Link & Endpoint Extractor (TASK-803)
 *
 * Extracts links, form action endpoints, scripts, and stylesheet links from
 * raw HTML without executing JavaScript or submitting forms.
 */

import type { DiscoveredEndpoint, FormField, LinkSource } from './types.js';
import { normalizeUrl } from './url-normalizer.js';

/**
 * Decodes standard HTML entities commonly found in URL attributes.
 */
export function decodeHtmlEntities(str: string): string {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => {
      try {
        return String.fromCharCode(parseInt(hex, 16));
      } catch {
        return '';
      }
    })
    .replace(/&#([0-9]+);/g, (_, dec) => {
      try {
        return String.fromCharCode(parseInt(dec, 10));
      } catch {
        return '';
      }
    });
}

/**
 * Extracts attribute value from an HTML tag string case-insensitively.
 * Handles double-quoted, single-quoted, and unquoted attribute formats.
 */
function extractAttribute(tagString: string, attributeName: string): string | null {
  const regex = new RegExp(`\\b${attributeName}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i');
  const match = regex.exec(tagString);
  if (!match) return null;
  const rawValue = match[1] ?? match[2] ?? match[3] ?? null;
  return rawValue !== null ? decodeHtmlEntities(rawValue).trim() : null;
}

export interface ExtractedHtmlResult {
  readonly title?: string;
  readonly baseUrl: string;
  readonly endpoints: readonly DiscoveredEndpoint[];
}

/**
 * Extracts discovered links and endpoints from raw HTML text.
 *
 * Security Mandates:
 * - Never executes JavaScript.
 * - Extracts form actions for endpoint awareness only; never submits forms.
 * - Resolves relative references against <base href> or page URL.
 * - Handles malformed HTML safely without throwing unhandled exceptions.
 *
 * @param html The raw HTML string response body.
 * @param pageUrl The URL of the page from which the HTML was fetched.
 * @param depth The current crawl depth of the page.
 */
export function extractHtmlLinks(
  html: string,
  pageUrl: string,
  depth: number = 0
): ExtractedHtmlResult {
  if (typeof html !== 'string' || html.length === 0) {
    return { baseUrl: pageUrl, endpoints: [] };
  }

  // 1. Strip HTML comments to avoid parsing commented-out code
  const sanitizedHtml = html.replace(/<!--[\s\S]*?-->/g, '');

  // 2. Extract Document Title (<title>...</title>)
  let title: string | undefined;
  const titleMatch = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(sanitizedHtml);
  if (titleMatch && titleMatch[1]) {
    title = decodeHtmlEntities(titleMatch[1].replace(/\s+/g, ' ').trim());
  }

  // 3. Determine Effective Base URL (<base href="...">)
  let effectiveBaseUrl = pageUrl;
  const baseMatch = /<base\b[^>]*>/i.exec(sanitizedHtml);
  if (baseMatch) {
    const baseHref = extractAttribute(baseMatch[0], 'href');
    if (baseHref) {
      try {
        const resolvedBase = new URL(baseHref, pageUrl).toString();
        effectiveBaseUrl = resolvedBase;
      } catch {
        // Fall back to pageUrl if base href is malformed
      }
    }
  }

  const endpoints: DiscoveredEndpoint[] = [];
  const seenRawEndpoints = new Set<string>();

  const addEndpoint = (
    rawUrl: string,
    source: LinkSource,
    method?: string,
    formFields?: FormField[]
  ) => {
    if (!rawUrl || typeof rawUrl !== 'string') return;
    const cleanRaw = rawUrl.trim();
    if (cleanRaw.length === 0) return;

    // Discard non-navigational pseudo schemes immediately
    const lower = cleanRaw.toLowerCase();
    if (
      lower.startsWith('javascript:') ||
      lower.startsWith('data:') ||
      lower.startsWith('mailto:') ||
      lower.startsWith('tel:')
    ) {
      return;
    }

    const normalized = normalizeUrl(cleanRaw, effectiveBaseUrl);
    if (!normalized) return;

    const dedupeKey = `${source}:${normalized}:${method || ''}`;
    if (seenRawEndpoints.has(dedupeKey)) return;
    seenRawEndpoints.add(dedupeKey);

    endpoints.push({
      url: normalized,
      rawUrl: cleanRaw,
      source,
      depth: depth + 1,
      parentUrl: pageUrl,
      method: method ? method.toUpperCase() : undefined,
      formFields: formFields && formFields.length > 0 ? Object.freeze(formFields) : undefined,
    });
  };

  // 4. Extract <a href="..."> links
  const anchorRegex = /<a\b([^>]*)>/gi;
  let match: RegExpExecArray | null;
  while ((match = anchorRegex.exec(sanitizedHtml)) !== null) {
    const rawTagAttrs = match[1];
    if (rawTagAttrs) {
      const href = extractAttribute(rawTagAttrs, 'href');
      if (href) {
        addEndpoint(href, 'a');
      }
    }
  }

  // 5. Extract <link href="..."> tags
  const linkTagRegex = /<link\b([^>]*)>/gi;
  while ((match = linkTagRegex.exec(sanitizedHtml)) !== null) {
    const rawTagAttrs = match[1];
    if (rawTagAttrs) {
      const href = extractAttribute(rawTagAttrs, 'href');
      if (href) {
        addEndpoint(href, 'link');
      }
    }
  }

  // 6. Extract <script src="..."> tags (endpoints only; never executes scripts)
  const scriptTagRegex = /<script\b([^>]*)>/gi;
  while ((match = scriptTagRegex.exec(sanitizedHtml)) !== null) {
    const rawTagAttrs = match[1];
    if (rawTagAttrs) {
      const src = extractAttribute(rawTagAttrs, 'src');
      if (src) {
        addEndpoint(src, 'script');
      }
    }
  }

  // 7. Extract <form action="..." method="..."> (endpoints only; NEVER submits forms)
  // Splits by <form to parse forms and their associated inputs
  const formBlocks = sanitizedHtml.split(/<form\b/i);
  // First element is before the first <form>, so skip it
  for (let i = 1; i < formBlocks.length; i++) {
    const block = formBlocks[i];
    if (!block) continue;
    const tagEndIdx = block.indexOf('>');
    if (tagEndIdx === -1) continue;

    const formTagAttributes = block.slice(0, tagEndIdx);
    const formInner = block.slice(tagEndIdx + 1);

    // Extract form action (if empty or omitted, defaults to current page URL)
    let action = extractAttribute(formTagAttributes, 'action');
    if (!action || action.length === 0) {
      action = pageUrl;
    }

    const method = extractAttribute(formTagAttributes, 'method') || 'GET';

    // Extract inputs within this form
    const formFields: FormField[] = [];
    const inputRegex = /<input\b([^>]*)>/gi;
    let inputMatch: RegExpExecArray | null;
    while ((inputMatch = inputRegex.exec(formInner)) !== null) {
      const rawInputAttrs = inputMatch[1];
      if (rawInputAttrs) {
        const name = extractAttribute(rawInputAttrs, 'name');
        if (name) {
          const type = extractAttribute(rawInputAttrs, 'type') || 'text';
          const value = extractAttribute(rawInputAttrs, 'value') || undefined;
          formFields.push({ name, type, value });
        }
      }
    }

    addEndpoint(action, 'form', method, formFields);
  }

  return {
    title,
    baseUrl: effectiveBaseUrl,
    endpoints: Object.freeze(endpoints),
  };
}
