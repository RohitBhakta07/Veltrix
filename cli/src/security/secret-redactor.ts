/**
 * VELTRIX CLI — Secret Redactor
 * Ensures secrets, tokens, passwords, and sensitive headers are never printed
 * to terminal stdout/stderr, debug logs, or error traces.
 */

type SecretReplacer = {
  pattern: RegExp;
  replacement: string | ((...args: string[]) => string);
};

const SECRET_PATTERNS: SecretReplacer[] = [
  // Bearer tokens (JWT or opaque)
  {
    pattern: /Bearer\s+[A-Za-z0-9_.-]+/gi,
    replacement: 'Bearer [REDACTED]',
  },
  // Standalone JWTs (header.payload.signature starting with eyJ)
  {
    pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    replacement: '[REDACTED_JWT]',
  },
  // Veltrix specific tokens & keys
  {
    pattern: /vltx_tok_[a-zA-Z0-9_-]+/g,
    replacement: 'vltx_tok_[REDACTED]',
  },
  {
    pattern: /vltx_key_[a-zA-Z0-9_-]+/g,
    replacement: 'vltx_key_[REDACTED]',
  },
  // AWS Keys
  {
    pattern: /AKIA[0-9A-Z]{16}/g,
    replacement: 'AKIA[REDACTED_AWS_KEY]',
  },
  // JSON key-values
  {
    pattern: /"(password|secret|clientSecret|client_secret|token|apiKey|refreshToken|accessToken|privateKey)":\s*"[^"]+"/gi,
    replacement: '"$1": "[REDACTED]"',
  },
  // Key=value pairs (with optional quotes)
  {
    pattern: /\b(password|secret|clientSecret|client_secret|token|apiKey|refreshToken|accessToken|privateKey)=("([^"]+)"|'([^']+)'|([^\s&,;]+))/gi,
    replacement: (_match: string, key: string, _val: string, q1?: string, q2?: string) => {
      const quote = q1 !== undefined ? '"' : (q2 !== undefined ? "'" : '');
      return `${key}=${quote}[REDACTED]${quote}`;
    },
  },
  // Basic Auth Credentials in URLs: https://user:password@hostname
  {
    pattern: /(https?:\/\/)([^:\/\s]+):([^\/\s]+)@([a-zA-Z0-9.-]+)/gi,
    replacement: '$1$2:[REDACTED]@$4',
  },
];

const SENSITIVE_KEY_NAMES = new Set([
  'password',
  'passwd',
  'secret',
  'secretkey',
  'clientsecret',
  'client_secret',
  'token',
  'accesstoken',
  'access_token',
  'refreshtoken',
  'refresh_token',
  'sessiontoken',
  'session_token',
  'signingkey',
  'signing_key',
  'signingsecret',
  'signing_secret',
  'apikey',
  'api_key',
  'x-api-key',
  'x-integration-key',
  'authorization',
  'cookie',
  'set-cookie',
  'privatekey',
  'private_key',
  'verificationtoken',
  'tokenhash',
]);

/**
 * Sanitizes a string by replacing known secret patterns with redaction markers.
 */
export function redactSecrets(input: string): string {
  if (!input || typeof input !== 'string') {
    return input;
  }

  let sanitized = input;
  for (const { pattern, replacement } of SECRET_PATTERNS) {
    if (typeof replacement === 'function') {
      sanitized = sanitized.replace(pattern, replacement as (...args: any[]) => string);
    } else {
      sanitized = sanitized.replace(pattern, replacement);
    }
  }
  return sanitized;
}

/**
 * Recursively deep-redacts sensitive object fields for safe serialization.
 */
export function sanitizeObject<T>(obj: T): T {
  if (obj === null || obj === undefined) {
    return obj;
  }

  if (typeof obj === 'string') {
    return redactSecrets(obj) as unknown as T;
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeObject(item)) as unknown as T;
  }

  if (typeof obj === 'object') {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const lowerKey = key.toLowerCase();
      if (SENSITIVE_KEY_NAMES.has(lowerKey)) {
        sanitizedObj[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        sanitizedObj[key] = sanitizeObject(value);
      } else if (typeof value === 'string') {
        sanitizedObj[key] = redactSecrets(value);
      } else {
        sanitizedObj[key] = value;
      }
    }
    return sanitizedObj as T;
  }

  return obj;
}
