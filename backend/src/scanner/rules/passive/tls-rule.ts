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

    // 4. Evaluate Hostname Matching
    if (tls.peerCertificate && tls.peerCertificate.subject) {
      let hostname = '';
      try {
        hostname = new URL(page.url).hostname.toLowerCase();
      } catch {
        hostname = '';
      }

      if (hostname) {
        const candidates: string[] = [];
        if (tls.peerCertificate.subject.CN) {
          candidates.push(tls.peerCertificate.subject.CN.toLowerCase().trim());
        }
        if (tls.peerCertificate.subjectAltNames) {
          for (const san of tls.peerCertificate.subjectAltNames) {
            const cleanSan = san.replace(/^DNS:\s*/i, '').toLowerCase().trim();
            if (cleanSan) {
              candidates.push(cleanSan);
            }
          }
        }

        if (candidates.length > 0 && !this.isHostnameMatched(hostname, candidates)) {
          findings.push(
            Object.freeze({
              ruleId: this.id,
              vulnerabilityType: 'TLS_CERTIFICATE_HOSTNAME_MISMATCH',
              title: 'TLS Certificate Hostname Mismatch',
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              description: `The TLS certificate presented by ${page.url} does not match target hostname '${hostname}'. Certificate identity candidates: [${candidates.join(
                ', '
              )}].`,
              remediation:
                'Reissue the TLS certificate ensuring the target hostname matches the Subject Common Name (CN) or is included in the Subject Alternative Names (SAN).',
              url: page.url,
              evidence: Object.freeze({
                targetUrl: page.url,
                targetHostname: hostname,
                certificateCandidates: candidates,
              }),
            })
          );
        }
      }
    }

    return Object.freeze(findings);
  }

  private isHostnameMatched(targetHost: string, candidates: readonly string[]): boolean {
    for (const pattern of candidates) {
      if (pattern === targetHost) {
        return true;
      }
      if (pattern.startsWith('*.')) {
        const suffix = pattern.slice(2);
        if (targetHost.endsWith('.' + suffix)) {
          const prefix = targetHost.slice(0, -(suffix.length + 1));
          if (prefix.length > 0 && !prefix.includes('.')) {
            return true;
          }
        }
      }
    }
    return false;
  }
}
