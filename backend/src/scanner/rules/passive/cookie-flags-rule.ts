/**
 * VELTRIX Passive Security Rule: Cookie Security Attributes Assessment (TASK-804)
 *
 * Inspects all Set-Cookie directives independently to ensure proper configuration of:
 * - Secure attribute (prevents transmission over unencrypted HTTP).
 * - HttpOnly attribute (prevents theft via client-side JavaScript / XSS).
 * - SameSite attribute (Lax or Strict; mitigates CSRF).
 *
 * Invariants:
 * - Operates on individual raw Set-Cookie strings.
 * - Never naively splits on commas, preserving Expires dates containing commas.
 * - Handles malformed attributes, duplicate attributes, and multiple cookies safely.
 */

import type { CrawledPage } from '../../crawler/types.js';
import {
  type PassiveRuleInterface,
  type ScannerFinding,
  RULE_PASSIVE_COOKIES,
} from '../../types.js';

const VALID_SAMESITE_VALUES: ReadonlySet<string> = new Set(['strict', 'lax', 'none']);

export interface ParsedCookie {
  readonly name: string;
  readonly value: string;
  readonly secure: boolean;
  readonly httpOnly: boolean;
  readonly sameSite: string | null;
  readonly expires?: string;
  readonly maxAge?: string;
  readonly path?: string;
  readonly domain?: string;
  readonly raw: string;
  readonly duplicateAttributes?: readonly string[];
}

export class CookieFlagsRule implements PassiveRuleInterface {
  public readonly id = RULE_PASSIVE_COOKIES;
  public readonly name = 'Passive Cookie Security Attributes Rule';
  public readonly description =
    'Inspects every Set-Cookie header independently for Secure, HttpOnly, and SameSite attributes.';

  public evaluate(page: CrawledPage): readonly ScannerFinding[] {
    const findings: ScannerFinding[] = [];
    const isHttps = page.url.startsWith('https://');

    // Retrieve unjoined cookie strings from page.setCookies or fallback to headers
    const rawCookies = this.extractCookieStrings(page);
    if (rawCookies.length === 0) {
      return Object.freeze(findings);
    }

    for (const rawCookie of rawCookies) {
      const parsed = this.parseSetCookieString(rawCookie);
      if (!parsed || !parsed.name) {
        continue; // Skip malformed empty cookies
      }

      // 1. Missing Secure flag
      if (!parsed.secure) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'INSECURE_COOKIE_ATTRIBUTES',
            title: `Cookie '${parsed.name}' Missing 'Secure' Attribute`,
            severity: isHttps ? 'MEDIUM' : 'LOW',
            confidence: 'CONFIRMED',
            description: `Cookie '${parsed.name}' set by ${page.url} does not declare the 'Secure' attribute, allowing it to be transmitted over unencrypted HTTP connections.`,
            remediation: `Add the 'Secure' attribute to the Set-Cookie header: 'Set-Cookie: ${parsed.name}=...; Secure; ...'.`,
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              cookieName: parsed.name,
              missingFlag: 'Secure',
              rawCookie: this.sanitizeRawCookie(rawCookie),
            }),
          })
        );
      }

      // 2. Missing HttpOnly flag
      if (!parsed.httpOnly) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'INSECURE_COOKIE_ATTRIBUTES',
            title: `Cookie '${parsed.name}' Missing 'HttpOnly' Attribute`,
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            description: `Cookie '${parsed.name}' set by ${page.url} does not declare the 'HttpOnly' attribute, making it accessible to client-side scripts via document.cookie and increasing XSS token theft risk.`,
            remediation: `Add the 'HttpOnly' attribute to prevent script access: 'Set-Cookie: ${parsed.name}=...; HttpOnly; ...'.`,
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              cookieName: parsed.name,
              missingFlag: 'HttpOnly',
              rawCookie: this.sanitizeRawCookie(rawCookie),
            }),
          })
        );
      }

      // 3. SameSite Attribute Validation (Strict, Lax, None)
      if (parsed.sameSite === null) {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'INSECURE_COOKIE_ATTRIBUTES',
            title: `Cookie '${parsed.name}' Missing 'SameSite' Attribute`,
            severity: 'LOW',
            confidence: 'CONFIRMED',
            description: `Cookie '${parsed.name}' set by ${page.url} does not specify a 'SameSite' attribute, increasing susceptibility to Cross-Site Request Forgery (CSRF).`,
            remediation: `Configure 'SameSite=Lax' (recommended for navigation) or 'SameSite=Strict' (for sensitive sessions) on the Set-Cookie header.`,
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              cookieName: parsed.name,
              sameSiteValue: 'absent',
              rawCookie: this.sanitizeRawCookie(rawCookie),
            }),
          })
        );
      } else {
        const lowerSameSite = parsed.sameSite.toLowerCase();
        if (lowerSameSite === '' || !VALID_SAMESITE_VALUES.has(lowerSameSite)) {
          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'INVALID_SAMESITE_ATTRIBUTE',
              title: `Cookie '${parsed.name}' Has Invalid 'SameSite' Attribute Value '${parsed.sameSite}'`,
              severity: 'MEDIUM',
              confidence: 'CONFIRMED',
              description: `Cookie '${parsed.name}' set by ${page.url} declares an invalid 'SameSite' value '${parsed.sameSite}'. Valid values per RFC 6265bis are 'Strict', 'Lax', or 'None'.`,
              remediation: `Update the 'SameSite' attribute to one of 'Strict', 'Lax', or 'None'.`,
              url: page.url,
              evidence: Object.freeze({
                targetUrl: page.url,
                cookieName: parsed.name,
                invalidSameSiteValue: parsed.sameSite,
                rawCookie: this.sanitizeRawCookie(rawCookie),
              }),
            })
          );
        } else if (lowerSameSite === 'none') {
          if (!parsed.secure) {
            findings.push(
              Object.freeze({
                ruleId: this.id,
                vulnerabilityType: 'INSECURE_COOKIE_ATTRIBUTES',
                title: `Cookie '${parsed.name}' Uses 'SameSite=None' Without 'Secure' Attribute`,
                severity: 'MEDIUM',
                confidence: 'CONFIRMED',
                description: `Cookie '${parsed.name}' set by ${page.url} declares 'SameSite=None' but omits the 'Secure' attribute. Modern browsers will reject this cookie per RFC 6265bis.`,
                remediation: `Add the 'Secure' attribute whenever 'SameSite=None' is declared: 'Set-Cookie: ${parsed.name}=...; SameSite=None; Secure'.`,
                url: page.url,
                evidence: Object.freeze({
                  targetUrl: page.url,
                  cookieName: parsed.name,
                  sameSiteValue: parsed.sameSite,
                  missingFlag: 'Secure',
                  rawCookie: this.sanitizeRawCookie(rawCookie),
                }),
              })
            );
          }
          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'INSECURE_COOKIE_ATTRIBUTES',
              title: `Cookie '${parsed.name}' Configured with Insecure 'SameSite=None'`,
              severity: 'LOW',
              confidence: 'CONFIRMED',
              description: `Cookie '${parsed.name}' set by ${page.url} is configured with 'SameSite=None', allowing cross-site requests to include the cookie and increasing CSRF exposure.`,
              remediation: `Configure 'SameSite=Lax' (recommended for navigation) or 'SameSite=Strict' (for sensitive sessions) unless cross-site sharing is explicitly required.`,
              url: page.url,
              evidence: Object.freeze({
                targetUrl: page.url,
                cookieName: parsed.name,
                sameSiteValue: parsed.sameSite,
                rawCookie: this.sanitizeRawCookie(rawCookie),
              }),
            })
          );
        }
      }
    }

    return Object.freeze(findings);
  }

  /**
   * Safely extracts raw cookie strings from page without comma splitting.
   */
  private extractCookieStrings(page: CrawledPage): readonly string[] {
    if (page.setCookies && Array.isArray(page.setCookies) && page.setCookies.length > 0) {
      return page.setCookies;
    }
    // Fallback if headers contains a single set-cookie string
    const fallback = page.headers?.['set-cookie'];
    if (typeof fallback === 'string' && fallback.trim().length > 0) {
      return [fallback.trim()];
    }
    return [];
  }

  /**
   * Parses an individual raw Set-Cookie string without naive comma splitting.
   */
  public parseSetCookieString(rawCookie: string): ParsedCookie | null {
    if (!rawCookie || typeof rawCookie !== 'string') return null;
    const trimmed = rawCookie.trim();
    if (trimmed.length === 0) return null;

    // Semicolon divides name=val and attributes
    const parts = trimmed.split(';');
    const firstPart = parts[0]?.trim();
    if (!firstPart) return null;

    const eqIdx = firstPart.indexOf('=');
    const name = eqIdx !== -1 ? firstPart.slice(0, eqIdx).trim() : firstPart;
    const value = eqIdx !== -1 ? firstPart.slice(eqIdx + 1).trim() : '';

    if (!name) return null;

    let secure = false;
    let httpOnly = false;
    let sameSite: string | null = null;
    let expires: string | undefined = undefined;
    let maxAge: string | undefined = undefined;
    let cookiePath: string | undefined = undefined;
    let domain: string | undefined = undefined;

        const seenAttrs = new Set<string>();
    const duplicateAttributes: string[] = [];

    for (let i = 1; i < parts.length; i++) {
      const part = parts[i]?.trim();
      if (!part) continue;

      const attrEqIdx = part.indexOf('=');
      const attrName = (attrEqIdx !== -1 ? part.slice(0, attrEqIdx) : part)
        .trim()
        .toLowerCase();
      const attrValue = attrEqIdx !== -1 ? part.slice(attrEqIdx + 1).trim() : '';

      if (seenAttrs.has(attrName)) {
        duplicateAttributes.push(attrName);
      } else {
        seenAttrs.add(attrName);
      }

      switch (attrName) {
        case 'secure':
          secure = true;
          break;
        case 'httponly':
          httpOnly = true;
          break;
        case 'samesite':
          // Preserve declared SameSite (Lax, Strict, None)
          sameSite = attrValue.trim();
          break;
        case 'expires':
          expires = attrValue;
          break;
        case 'max-age':
          maxAge = attrValue;
          break;
        case 'path':
          cookiePath = attrValue;
          break;
        case 'domain':
          domain = attrValue;
          break;
        default:
          break;
      }
    }

    return {
      name,
      value,
      secure,
      httpOnly,
      sameSite,
      expires,
      maxAge,
      path: cookiePath,
      domain,
      raw: trimmed,
      duplicateAttributes: duplicateAttributes.length > 0 ? Object.freeze(duplicateAttributes) : undefined,
    };
  }

  /**
   * Sanitizes cookie value for evidence to avoid sensitive token leaks.
   */
  private sanitizeRawCookie(rawCookie: string): string {
    const parts = rawCookie.split(';');
    const firstPart = parts[0]?.trim() || '';
    const eqIdx = firstPart.indexOf('=');
    const name = eqIdx !== -1 ? firstPart.slice(0, eqIdx).trim() : firstPart;
    const rest = parts.slice(1).map((p) => p.trim()).filter(Boolean).join('; ');
    return `${name}=[REDACTED]${rest ? '; ' + rest : ''}`;
  }
}
