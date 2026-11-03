/**
 * VELTRIX CLI — Target Scope & SSRF Security Validator
 * Validates scan targets and domains against client-side SSRF and boundary bypass vectors.
 * Note: Server-side verification remains the authoritative boundary.
 */

import { ValidationError, ScopePolicyError } from '../client/errors.js';

export interface TargetValidationResult {
  valid: boolean;
  normalizedUrl: string;
  domain: string;
  port?: number;
  protocol: 'http:' | 'https:';
  error?: string;
  errorCode?: 'INVALID_SCHEME' | 'PROHIBITED_DESTINATION' | 'INVALID_PORT' | 'INVALID_DOMAIN' | 'USERINFO_PROHIBITED';
}

const DISALLOWED_PORTS = new Set([
  20, 21,    // FTP
  22,        // SSH
  23,        // Telnet
  25, 465,   // SMTP
  53,        // DNS
  110, 995,  // POP3
  143, 993,  // IMAP
  3306,      // MySQL
  5432,      // PostgreSQL
  6379,      // Redis
  11211,     // Memcached
  27017,     // MongoDB
  9200,      // Elasticsearch
  2375, 2376 // Docker daemon
]);

const LOCAL_HOST_NAMES = new Set([
  'localhost',
  'local',
  'internal',
  'intranet',
  'lan',
  'home.arpa',
  'corp',
  'metadata',
  'instance-data',
]);

/**
 * Checks if an IPv4 octet string represents an IPv4 address.
 */
function isIpv4(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d+$/.test(p)) return false;
    const n = parseInt(p, 10);
    return n >= 0 && n <= 255;
  });
}

/**
 * Checks if an IPv4 address is in private, loopback, link-local, or metadata ranges.
 */
function isProhibitedIpv4(host: string): boolean {
  const parts = host.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(isNaN)) return false;

  const [a, b] = parts;
  if (a === undefined || b === undefined) return false;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;
  // 10.0.0.0/8 (RFC 1918 Private)
  if (a === 10) return true;
  // 172.16.0.0/12 (RFC 1918 Private)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 (RFC 1918 Private)
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 (Link-local & AWS/GCP/Azure Metadata 169.254.169.254)
  if (a === 169 && b === 254) return true;
  // 100.64.0.0/10 (Carrier-grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 224.0.0.0/4 (Multicast)
  if (a >= 224 && a <= 239) return true;
  // 240.0.0.0/4 (Reserved / Future Use & Broadcast 255.255.255.255)
  if (a >= 240) return true;
  // 198.18.0.0/15 (Network Benchmark Testing)
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
  if (a === 192 && b === 0 && parts[2] === 2) return true;
  if (a === 198 && b === 51 && parts[2] === 100) return true;
  if (a === 203 && b === 0 && parts[2] === 113) return true;

  return false;
}

/**
 * Checks if a host is an IPv6 prohibited address.
 */
function isProhibitedIpv6(host: string): boolean {
  const raw = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  const lower = raw.toLowerCase();

  // Loopback ::1
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
  // Unspecified ::
  if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true;
  // Link-local fe80::/10
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;
  // Unique local fc00::/7 (fc00:: and fd00::)
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  // Multicast ff00::/8
  if (lower.startsWith('ff')) return true;
  // Documentation 2001:db8::/32
  if (lower.startsWith('2001:db8:') || lower.startsWith('2001:0db8:')) return true;
  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (lower.startsWith('::ffff:')) {
    const embeddedIpv4 = lower.slice(7);
    if (isIpv4(embeddedIpv4) && isProhibitedIpv4(embeddedIpv4)) return true;
    if (embeddedIpv4.includes(':')) {
      const parts = embeddedIpv4.split(':');
      if (parts[0]) {
        const hexWord = parseInt(parts[0], 16);
        if (!isNaN(hexWord)) {
          const highByte = (hexWord >> 8) & 0xff;
          const lowByte = hexWord & 0xff;
          if (
            highByte === 127 ||
            highByte === 0 ||
            highByte === 10 ||
            (highByte === 172 && lowByte >= 16 && lowByte <= 31) ||
            (highByte === 192 && lowByte === 168) ||
            (highByte === 169 && lowByte === 254) ||
            (highByte >= 224 && highByte <= 239) ||
            highByte >= 240
          ) {
            return true;
          }
        }
      }
    }
  }
  // IPv4-compatible IPv6 (e.g. ::10.0.0.1)
  if (lower.startsWith('::') && lower.includes('.')) {
    const embeddedIpv4 = lower.slice(2);
    if (isIpv4(embeddedIpv4) && isProhibitedIpv4(embeddedIpv4)) return true;
  }

  return false;
}

/**
 * Checks if string is purely numeric or hexadecimal (DWORD / Hex / Octal bypass attempt)
 */
function isObfuscatedIpFormat(host: string): boolean {
  // Pure decimal integer (e.g. 2130706433 = 127.0.0.1)
  if (/^\d{8,10}$/.test(host)) return true;
  // Hexadecimal notation (e.g. 0x7f000001)
  if (/^0x[0-9a-fA-F]+$/i.test(host)) return true;
  // Octal dotted notation (e.g. 0177.0.0.1)
  if (/^0\d+(\.0\d+)+$/.test(host)) return true;
  return false;
}

/**
 * Checks if a host/IP is in a private, loopback, or reserved IP space.
 */
export function isPrivateOrReservedIp(host: string): boolean {
  if (LOCAL_HOST_NAMES.has(host.toLowerCase())) return true;
  if (isIpv4(host)) return isProhibitedIpv4(host);
  if (isProhibitedIpv6(host)) return true;
  return false;
}

/**
 * Prepares canonical URL from raw string, prepending https:// if missing.
 */
export function canonicalizeTarget(rawInput: string): string {
  const trimmed = rawInput.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

/**
 * Validates a target URL or domain string.
 */
export function validateTarget(rawInput: string): TargetValidationResult {
  if (!rawInput || typeof rawInput !== 'string') {
    return {
      valid: false,
      normalizedUrl: '',
      domain: '',
      protocol: 'https:',
      error: 'Target URL or domain cannot be empty.',
      errorCode: 'INVALID_DOMAIN',
    };
  }

  const trimmed = rawInput.trim();

  // Reject zone IDs in IPv6
  if (trimmed.includes('%')) {
    return {
      valid: false,
      normalizedUrl: '',
      domain: '',
      protocol: 'https:',
      error: 'IPv6 zone identifiers (%) are strictly prohibited.',
      errorCode: 'PROHIBITED_DESTINATION',
    };
  }

  // Prepend scheme if missing
  let urlString = trimmed;
  if (!/^https?:\/\//i.test(urlString)) {
    urlString = `https://${urlString}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return {
      valid: false,
      normalizedUrl: '',
      domain: '',
      protocol: 'https:',
      error: `Malformed target URL: '${rawInput}'. Must be a valid URL or FQDN.`,
      errorCode: 'INVALID_DOMAIN',
    };
  }

  // Scheme validation
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      normalizedUrl: '',
      domain: '',
      protocol: 'https:',
      error: `Unsupported scheme '${parsed.protocol}'. Only 'http:' and 'https:' are permitted.`,
      errorCode: 'INVALID_SCHEME',
    };
  }

  // Reject credentials in URL
  if (parsed.username || parsed.password) {
    return {
      valid: false,
      normalizedUrl: '',
      domain: '',
      protocol: parsed.protocol as 'http:' | 'https:',
      error: 'Embedded userinfo credentials (user:pass@host) are prohibited in target URLs.',
      errorCode: 'USERINFO_PROHIBITED',
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Port validation
  if (parsed.port) {
    const portNum = parseInt(parsed.port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      return {
        valid: false,
        normalizedUrl: '',
        domain: '',
        protocol: parsed.protocol as 'http:' | 'https:',
        error: `Invalid port number: '${parsed.port}'.`,
        errorCode: 'INVALID_PORT',
      };
    }
    if (DISALLOWED_PORTS.has(portNum)) {
      return {
        valid: false,
        normalizedUrl: '',
        domain: '',
        protocol: parsed.protocol as 'http:' | 'https:',
        error: `Port ${portNum} is a restricted administrative/database port and cannot be targeted.`,
        errorCode: 'INVALID_PORT',
      };
    }
  }

  // Obfuscated IP check
  if (isObfuscatedIpFormat(hostname)) {
    return {
      valid: false,
      normalizedUrl: '',
      domain: '',
      protocol: parsed.protocol as 'http:' | 'https:',
      error: `Obfuscated numeric/hexadecimal IP notation '${hostname}' is prohibited.`,
      errorCode: 'PROHIBITED_DESTINATION',
    };
  }

  // Check IPv4 prohibited ranges
  if (isIpv4(hostname)) {
    if (isProhibitedIpv4(hostname)) {
      return {
        valid: false,
        normalizedUrl: '',
        domain: '',
        protocol: parsed.protocol as 'http:' | 'https:',
        error: `IP address '${hostname}' is in a private, loopback, or cloud-metadata range.`,
        errorCode: 'PROHIBITED_DESTINATION',
      };
    }
  }

  // Check IPv6 prohibited ranges
  if (isProhibitedIpv6(hostname)) {
    return {
      valid: false,
      normalizedUrl: '',
      domain: '',
      protocol: parsed.protocol as 'http:' | 'https:',
      error: `IPv6 address '${hostname}' is in a loopback, link-local, or private range.`,
      errorCode: 'PROHIBITED_DESTINATION',
    };
  }

  const INTERNAL_SUFFIXES = [
    '.local',
    '.internal',
    '.intranet',
    '.lan',
    '.localhost',
    '.corp',
    '.home.arpa',
    '.test',
    '.example',
    '.invalid',
  ];

  // Check localhost & internal names
  if (
    LOCAL_HOST_NAMES.has(hostname) ||
    INTERNAL_SUFFIXES.some((suffix) => hostname.endsWith(suffix))
  ) {
    return {
      valid: false,
      normalizedUrl: '',
      domain: '',
      protocol: parsed.protocol as 'http:' | 'https:',
      error: `Target host '${hostname}' resolves to a local or internal network boundary.`,
      errorCode: 'PROHIBITED_DESTINATION',
    };
  }

  // Domain structure validation (must be at least domain.tld or valid public IP)
  const isIpv6Host = hostname.includes(':') || (hostname.startsWith('[') && hostname.endsWith(']'));
  if (!isIpv4(hostname) && !isIpv6Host && !hostname.includes('.')) {
    return {
      valid: false,
      normalizedUrl: '',
      domain: '',
      protocol: parsed.protocol as 'http:' | 'https:',
      error: `Target '${hostname}' is not a valid fully qualified domain name (FQDN).`,
      errorCode: 'INVALID_DOMAIN',
    };
  }

  const normalizedUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`;
  const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);

  return {
    valid: true,
    normalizedUrl,
    domain: hostname,
    port,
    protocol: parsed.protocol as 'http:' | 'https:',
  };
}

/**
 * Validates scan target on client side, throwing ScopePolicyError or ValidationError if unsafe.
 */
export function validateScanTargetClient(rawInput: string): {
  isValid: boolean;
  normalizedUrl: string;
  hostname: string;
  scheme: string;
  port: number;
} {
  const result = validateTarget(rawInput);
  if (!result.valid) {
    if (result.errorCode === 'INVALID_PORT') {
      throw new ScopePolicyError(result.error || 'Disallowed target port', 'DISALLOWED_PORT');
    }
    if (result.errorCode === 'PROHIBITED_DESTINATION') {
      throw new ScopePolicyError(result.error || 'Prohibited destination boundary', 'PROHIBITED_DESTINATION');
    }
    throw new ValidationError(result.error || 'Invalid target URL', result.errorCode || 'VALIDATION_FAILED');
  }

  return {
    isValid: true,
    normalizedUrl: result.normalizedUrl,
    hostname: result.domain,
    scheme: result.protocol.replace(':', ''),
    port: result.port ?? (result.protocol === 'https:' ? 443 : 80),
  };
}
