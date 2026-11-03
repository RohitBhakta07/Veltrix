/**
 * VELTRIX Passive Security Rule: TLS / SSL Configuration Assessment (TASK-804)
 *
 * Evaluates TLS metadata captured during SafeHttpClient connection establishment.
 *
 * Invariants:
 * - Operates strictly on existing TLS metadata from the initial request; never initiates
 *   a second connection or HTTP request.
 * - Evaluates negotiated protocol (flags TLS 1.0 and 1.1; notes TLS 1.2/1.3 without false claims).
 * - Verifies certificate expiration (expired or expiring within 14 days).
 * - Verifies hostname matching against subject CN and Subject Alternative Names (SAN).
 * - Verifies certificate chain trust verification status.
 */

import type { CrawledPage } from '../../crawler/types.js';
import {
  type PassiveRuleInterface,
  type ScannerFinding,
  RULE_PASSIVE_TLS,
} from '../../types.js';

export interface TlsRuleOptions {
  readonly currentTimeMs?: number;
}

export class TlsRule implements PassiveRuleInterface {
  public readonly id = RULE_PASSIVE_TLS;
  public readonly name = 'Passive TLS / SSL Configuration Rule';
  public readonly description =
    'Evaluates negotiated TLS protocol version, certificate expiration, hostname matching, and trust status from existing connection metadata.';

  private readonly currentTimeMs?: number;

  constructor(options?: TlsRuleOptions) {
    this.currentTimeMs = options?.currentTimeMs;
  }

  public evaluate(page: CrawledPage): readonly ScannerFinding[] {
    const findings: ScannerFinding[] = [];

    // Skip unencrypted HTTP endpoints or pages without TLS metadata
    if (!page.url.startsWith('https://') || !page.tls) {
      return Object.freeze(findings);
    }

    const tls = page.tls;
    const now = this.currentTimeMs ?? Date.now();

    // 1. Evaluate Negotiated Protocol
    if (tls.protocol) {
      const lowerProto = tls.protocol.toLowerCase();
      if (lowerProto === 'tlsv1' || lowerProto === 'tlsv1.0') {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'TLS_WEAK_PROTOCOL',
            title: 'Obsolete TLS 1.0 Protocol Negotiated',
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            description: `The server negotiated deprecated TLS 1.0 (${tls.protocol}) on ${page.url}. TLS 1.0 was formally deprecated by RFC 8996 and contains known architectural vulnerabilities.`,
            remediation:
              'Disable TLS 1.0 on the web server or load balancer. Configure TLS 1.2 and TLS 1.3 as the minimum acceptable protocol versions.',
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              negotiatedProtocol: tls.protocol,
              cipher: tls.cipher,
              observation: 'Server accepted and negotiated TLS 1.0 connection.',
            }),
          })
        );
      } else if (lowerProto === 'tlsv1.1') {
        findings.push(
          Object.freeze({
            ruleId: this.id,
            vulnerabilityType: 'TLS_WEAK_PROTOCOL',
            title: 'Obsolete TLS 1.1 Protocol Negotiated',
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            description: `The server negotiated deprecated TLS 1.1 (${tls.protocol}) on ${page.url}. TLS 1.1 was formally deprecated by RFC 8996 and lacks modern AEAD cipher suites.`,
            remediation:
              'Disable TLS 1.1 on the web server or load balancer. Configure TLS 1.2 and TLS 1.3 as the minimum acceptable protocol versions.',
            url: page.url,
            evidence: Object.freeze({
              targetUrl: page.url,
              negotiatedProtocol: tls.protocol,
              cipher: tls.cipher,
              observation: 'Server accepted and negotiated TLS 1.1 connection.',
            }),
          })
        );
      }
      // Note: TLS 1.2 and TLS 1.3 are secure and valid. Per specification:
      // A connection negotiating TLS 1.2 or 1.3 does not prove TLS 1.0/1.1 is disabled.
      // We report only what handshake evidence supports without making unsubstantiated claims.
    }

    // 2. Evaluate Certificate Chain Trust Verification
    if (tls.authorized === false) {
      findings.push(
        Object.freeze({
          ruleId: this.id,
          vulnerabilityType: 'TLS_CERTIFICATE_UNTRUSTED',
          title: 'Untrusted TLS Certificate or Chain Verification Failure',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          description: `The TLS certificate chain presented by ${page.url} failed trust validation: ${
            tls.authorizationError || 'Self-signed or untrusted certificate authority'
          }.`,
          remediation:
            'Install a valid, non-self-signed TLS certificate issued by a trusted public Certificate Authority (CA) with a complete intermediate chain.',
          url: page.url,
          evidence: Object.freeze({
            targetUrl: page.url,
            authorizationError: tls.authorizationError || 'UNTRUSTED_ROOT_OR_SELF_SIGNED',
            issuer: tls.peerCertificate?.issuer,
            subject: tls.peerCertificate?.subject,
          }),
        })
      );
    }

    // 3. Evaluate Certificate Expiration
    if (tls.peerCertificate && tls.peerCertificate.validTo) {
      const validToMs = Date.parse(tls.peerCertificate.validTo);
      if (!Number.isNaN(validToMs)) {
        if (validToMs < now) {
          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'TLS_CERTIFICATE_EXPIRED',
              title: 'Expired TLS Certificate',
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              description: `The TLS certificate for ${page.url} expired on ${tls.peerCertificate.validTo}. Browsers and automated clients will reject connections to this host.`,
              remediation:
                'Renew and deploy a valid, active TLS certificate from an authorized CA immediately.',
              url: page.url,
              evidence: Object.freeze({
                targetUrl: page.url,
                validTo: tls.peerCertificate.validTo,
                expiredAt: new Date(validToMs).toISOString(),
                currentEvaluationTime: new Date(now).toISOString(),
              }),
            })
          );
        } else {
          const msUntilExpiry = validToMs - now;
          const daysRemaining = Math.floor(msUntilExpiry / (24 * 60 * 60 * 1000));
          if (daysRemaining <= 14) {
            findings.push(
              Object.freeze({
                ruleId: this.id,
                vulnerabilityType: 'TLS_CERTIFICATE_EXPIRING_SOON',
                title: 'TLS Certificate Expiring Within 14 Days',
                severity: 'MEDIUM',
                confidence: 'CONFIRMED',
                description: `The TLS certificate for ${page.url} expires in ${daysRemaining} day(s) on ${tls.peerCertificate.validTo}.`,
                remediation:
                  'Renew the certificate before it expires to prevent service disruption and client security errors.',
                url: page.url,
                evidence: Object.freeze({
                  targetUrl: page.url,
                  validTo: tls.peerCertificate.validTo,
                  daysRemaining,
                  currentEvaluationTime: new Date(now).toISOString(),
                }),
              })
            );
          }
        }
      }
    }

    // 4. Evaluate Hostname Matching (RFC 6125 SAN Precedence)
    if (tls.peerCertificate) {
      let hostname = '';
      try {
        hostname = new URL(page.url).hostname.toLowerCase();
      } catch {
        hostname = '';
      }

      if (hostname) {
        const sans: string[] = [];
        if (tls.peerCertificate.subjectAltNames) {
          for (const san of tls.peerCertificate.subjectAltNames) {
            const cleanSan = san.replace(/^DNS:\s*/i, '').toLowerCase().trim();
            if (cleanSan) {
              sans.push(cleanSan);
            }
          }
        }

        const cn = tls.peerCertificate.subject?.CN
          ? tls.peerCertificate.subject.CN.toLowerCase().trim()
          : '';

        let matched = false;
        let identitySource: 'SAN' | 'CN' | 'NONE' = 'NONE';
        let evaluatedCandidates: readonly string[] = [];

        if (sans.length > 0) {
          // RFC 6125: If SAN dNSName entries exist, MUST NOT fall back to CN
          identitySource = 'SAN';
          evaluatedCandidates = sans;
          matched = sans.some((p) => this.isHostnameMatched(hostname, p));
        } else if (cn) {
          // Fall back to Common Name ONLY when SAN is absent
          identitySource = 'CN';
          evaluatedCandidates = [cn];
          matched = this.isHostnameMatched(hostname, cn);
        } else {
          identitySource = 'NONE';
          evaluatedCandidates = [];
          matched = false;
        }

        if (identitySource === 'NONE') {
          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'TLS_CERTIFICATE_NO_IDENTITY',
              title: 'TLS Certificate Missing Valid Identity (SAN / CN Absent)',
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              description: `The TLS certificate presented by ${page.url} does not contain any Subject Alternative Names (SAN) or Subject Common Name (CN).`,
              remediation:
                'Reissue the TLS certificate with valid Subject Alternative Names (SAN dNSName entries) matching the website domain.',
              url: page.url,
              evidence: Object.freeze({
                targetUrl: page.url,
                targetHostname: hostname,
                subject: tls.peerCertificate.subject,
              }),
            })
          );
        } else if (!matched) {
          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'TLS_CERTIFICATE_HOSTNAME_MISMATCH',
              title: 'TLS Certificate Hostname Mismatch',
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              description: `The TLS certificate presented by ${page.url} does not match target hostname '${hostname}'. Identity source evaluated: ${identitySource} (candidates: [${evaluatedCandidates.join(
                ', '
              )}]).${
                sans.length > 0 && cn && cn === hostname
                  ? ' Note: Subject Common Name (CN) matches but was disregarded per RFC 6125 SAN precedence.'
                  : ''
              }`,
              remediation:
                'Reissue the TLS certificate ensuring the target hostname is included in the Subject Alternative Names (SAN dNSName entries).',
              url: page.url,
              evidence: Object.freeze({
                targetUrl: page.url,
                targetHostname: hostname,
                identitySource,
                evaluatedCandidates,
                sanPrecedenceEnforced: sans.length > 0,
                cnIgnoredDueToSanPrecedence: sans.length > 0 && Boolean(cn),
              }),
            })
          );
        }
      }
    }

    return Object.freeze(findings);
  }

  private isHostnameMatched(targetHost: string, pattern: string): boolean {
    if (pattern === targetHost) {
      return true;
    }
    // Single-label wildcard matching per RFC 6125 Section 6.4.3:
    // Wildcard MUST be leftmost label, e.g. '*.example.com'.
    // Multi-label wildcards (*.*.com), partial wildcards (*test.com, test*.com),
    // and apex domain matches are strictly prohibited.
    if (pattern.startsWith('*.') && !pattern.slice(2).includes('*')) {
      const suffix = pattern.slice(2);
      // Suffix must have at least one dot (e.g. not '*.com')
      if (suffix.includes('.')) {
        if (targetHost.endsWith('.' + suffix)) {
          const prefix = targetHost.slice(0, -(suffix.length + 1));
          // Single-label only: prefix must not be empty and must not contain any '.'
          if (prefix.length > 0 && !prefix.includes('.')) {
            return true;
          }
        }
      }
    }
    return false;
  }
}
