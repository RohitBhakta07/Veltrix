/**
 * VELTRIX URL Canonicalization & Normalization Engine (TASK-803)
 *
 * Implements deterministic URL normalization, duplicate elimination,
 * session identifier stripping, and binary media filtering.
 */

import path from 'node:path';

/**
 * Standard session identifier parameter names stripped from URLs during normalization.
 * Case-insensitive comparison. Prevents session-specific crawl trap loops without
 * modifying legitimate application parameters.
 */
export const KNOWN_SESSION_QUERY_PARAMS: ReadonlySet<string> = new Set([
  'jsessionid',
  'phpsessid',
  'aspsessionid',
  'asp.net_sessionid',
  'sid',
  'sessionid',
  'session_id',
  's_id',
  'cfid',
  'cftoken',
  'zenid',
]);

/**
 * Static asset, media, and binary file extensions that should be bypassed
 * during HTML application crawling.
 */
export const BINARY_AND_MEDIA_EXTENSIONS: ReadonlySet<string> = new Set([
  // Images
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.svg',
  '.ico',
  '.webp',
  '.bmp',
  '.tiff',
  // Documents & Archives
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.7z',
  '.rar',
  '.exe',
  '.dll',
  '.dmg',
  '.iso',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx',
  '.ppt',
  '.pptx',
  // Audio & Video
  '.mp3',
  '.mp4',
  '.avi',
  '.mov',
  '.wmv',
  '.flv',
  '.mkv',
  '.webm',
  '.wav',
  '.ogg',
  // Fonts
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.otf',
  // Static stylesheets & source maps
  '.css',
  '.map',
]);

/**
 * Static JavaScript resource extensions that should be recorded as discovered endpoints,
 * but bypassed from consuming the HTML crawl page budget.
 */
export const SCRIPT_EXTENSIONS: ReadonlySet<string> = new Set([
  '.js',
  '.mjs',
  '.cjs',
]);

/**
 * Determines whether a URL points to a static JavaScript resource based on extension.
 */
export function isScriptResourceUrl(url: string | URL): boolean {
  try {
    const parsed = typeof url === 'string' ? new URL(url) : url;
    const pathname = parsed.pathname.toLowerCase();
    const ext = path.extname(pathname);
    return SCRIPT_EXTENSIONS.has(ext);
  } catch {
    return false;
  }
}

/**
 * Determines whether a URL points to a static media or binary asset based on extension.
 */
export function isBinaryOrMediaUrl(url: string | URL): boolean {
  try {
    const parsed = typeof url === 'string' ? new URL(url) : url;
    const pathname = parsed.pathname.toLowerCase();
    const ext = path.extname(pathname);
    return BINARY_AND_MEDIA_EXTENSIONS.has(ext);
  } catch {
    return false;
  }
}

/**
 * Normalizes and canonicalizes a URL string.
 *
 * Operations performed:
 * 1. Protocol validation: Accepts only 'http:' and 'https:'. Rejects all other schemes.
 * 2. Credential rejection: Rejects URLs with embedded username or password.
 * 3. Fragment removal: Strips URL fragments (#...).
 * 4. Host casing: Normalizes hostname to lowercase and trims trailing dot.
 * 5. Default port removal: Strips :80 for HTTP and :443 for HTTPS.
 * 6. Path normalization:
 *    - Collapses duplicate slashes (// -> /).
 *    - Strips path matrix session parameters (e.g. ;jsessionid=...).
 *    - Applies POSIX path normalization (resolving . and ..).
 *    - Preserves trailing slash semantics on non-root paths.
 * 7. Query parameter canonicalization:
 *    - Strips known session identifier parameters.
 *    - Sorts remaining parameters lexicographically by key, then by value.
 *    - Preserves duplicate parameter semantics (e.g. ?tag=a&tag=b).
 *
 * @param rawUrl The URL string to normalize (relative or absolute).
 * @param baseUrl Optional base URL for resolving relative references.
 * @returns Canonical URL string, or null if the URL is invalid, out-of-scheme, or contains credentials.
 */
export function normalizeUrl(rawUrl: string, baseUrl?: string): string | null {
  if (typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  if (trimmed.length === 0) return null;

  let parsed: URL;
  try {
    parsed = baseUrl ? new URL(trimmed, baseUrl) : new URL(trimmed);
  } catch {
    return null;
  }

  // 1. Strict Protocol Allowlist: Only http: and https:
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return null;
  }

  // 2. Strict Credential Rejection: Disallow embedded user:pass
  if (parsed.username || parsed.password) {
    return null;
  }

  // 3. Fragment Stripping
  parsed.hash = '';

  // 4. Host Casing & Trailing Dot Normalization
  let hostname = parsed.hostname.toLowerCase();
  if (hostname.endsWith('.')) {
    hostname = hostname.slice(0, -1);
  }
  parsed.hostname = hostname;

  // 5. Default Port Normalization
  if (parsed.protocol === 'http:' && parsed.port === '80') {
    parsed.port = '';
  } else if (parsed.protocol === 'https:' && parsed.port === '443') {
    parsed.port = '';
  }

  // 6. Path Normalization
  const rawPath = parsed.pathname;

  // Strip matrix parameters (e.g. ;jsessionid=... or ;sid=...)
  const pathWithoutMatrix = rawPath.replace(/;[a-zA-Z0-9_\-]+=[^/?#]*/gi, '');

  // Normalize duplicate slashes
  const collapsedPath = pathWithoutMatrix.replace(/\/+/g, '/');

  // POSIX normalization for traversal sequences
  let normalizedPath = path.posix.normalize(collapsedPath);
  if (!normalizedPath.startsWith('/')) {
    normalizedPath = '/' + normalizedPath;
  }

  // Preserve trailing slash if original path ended with slash and is not root
  const hadTrailingSlash = collapsedPath.endsWith('/') && collapsedPath.length > 1;
  if (hadTrailingSlash && !normalizedPath.endsWith('/')) {
    normalizedPath += '/';
  }
  parsed.pathname = normalizedPath;

  // 7. Query Parameter Canonicalization:
  // Sort distinct keys lexicographically, but preserve original relative order and count of duplicate parameter values.
  const searchParams = parsed.searchParams;
  const keyToValues = new Map<string, string[]>();

  for (const [key, value] of searchParams.entries()) {
    const lowerKey = key.trim().toLowerCase();
    // Strip known session parameters
    if (KNOWN_SESSION_QUERY_PARAMS.has(lowerKey)) {
      continue;
    }
    const existing = keyToValues.get(key);
    if (existing) {
      existing.push(value);
    } else {
      keyToValues.set(key, [value]);
    }
  }

  if (keyToValues.size === 0) {
    parsed.search = '';
  } else {
    const sortedKeys = Array.from(keyToValues.keys()).sort((a, b) => a.localeCompare(b));
    const newParams = new URLSearchParams();
    for (const key of sortedKeys) {
      const values = keyToValues.get(key)!;
      for (const val of values) {
        newParams.append(key, val);
      }
    }
    parsed.search = newParams.toString();
  }

  return parsed.toString();
}

/**
 * Normalizes a URL and throws a TypeError if the URL is invalid or malformed.
 */
export function normalizeUrlOrThrow(rawUrl: string, baseUrl?: string): string {
  const normalized = normalizeUrl(rawUrl, baseUrl);
  if (!normalized) {
    throw new TypeError(`Failed to normalize URL '${rawUrl}': Invalid, malformed, or prohibited scheme/credentials.`);
  }
  return normalized;
}
