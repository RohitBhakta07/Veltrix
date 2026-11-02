import { randomBytes, createHash } from 'node:crypto';
import type { WebsiteAsset, VerificationMethod } from '@veltrix/shared';
import type { StorageInterface } from '../../storage/storage-interface.js';
import { DnsVerifier, type DnsResolverInterface, DefaultDnsResolver } from './dns-verifier.js';
import { HttpVerifier, type HttpFetcherInterface, isProhibitedIp, isProhibitedIpv4 } from './http-verifier.js';
import { MetaVerifier } from './meta-verifier.js';
import { SafeVerificationHttpFetcher } from '../transport/verification-fetcher.js';
import { createAuthoritativeVerificationScopeContext } from '../transport/context-authority.js';

export { isProhibitedIp, isProhibitedIpv4 };

export interface VerificationResult {
  verified: boolean;
  status: 'VERIFIED' | 'FAILED' | 'RATE_LIMITED';
  method: VerificationMethod;
  verifiedAt?: string;
  expiresAt?: string;
  message?: string;
  error?: {
    code: string;
    message: string;
  };
}

export interface ScanAuthorizationCheckResult {
  authorized: boolean;
  code?: 'DOMAIN_NOT_VERIFIED' | 'DOMAIN_VERIFICATION_SUSPENDED' | 'VERIFICATION_EXPIRED';
  message?: string;
}

export class DomainOwnershipVerifier {
  private readonly storage: StorageInterface;
  private readonly dnsVerifier: DnsVerifier;
  private readonly httpVerifier: HttpVerifier;
  private readonly metaVerifier: MetaVerifier;

  // Rate limiting map: siteId -> array of attempt timestamps (ms)
  private attemptTimestamps: Map<string, number[]> = new Map();
  public static readonly MAX_ATTEMPTS = 5;
  public static readonly WINDOW_MS = 15 * 60 * 1000; // 15 minutes
  public static readonly TOKEN_VALIDITY_DAYS = 90;
  public static readonly GRACE_PERIOD_DAYS = 7;
  public static readonly MAX_CHALLENGE_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

  constructor(
    storage: StorageInterface,
    dnsResolverOrOptions?:
      | DnsResolverInterface
      | {
          dnsResolver?: DnsResolverInterface;
          httpFetcher?: HttpFetcherInterface;
        },
    httpFetcherArg?: HttpFetcherInterface
  ) {
    this.storage = storage;

    let resolver: DnsResolverInterface | undefined;
    let fetcher: HttpFetcherInterface | undefined;

    if (dnsResolverOrOptions && 'resolveTxt' in dnsResolverOrOptions) {
      resolver = dnsResolverOrOptions;
      fetcher = httpFetcherArg;
    } else if (dnsResolverOrOptions && typeof dnsResolverOrOptions === 'object') {
      resolver = dnsResolverOrOptions.dnsResolver;
      fetcher = dnsResolverOrOptions.httpFetcher || httpFetcherArg;
    }

    this.dnsVerifier = new DnsVerifier(resolver || new DefaultDnsResolver());
    const finalFetcher = fetcher || new SafeVerificationHttpFetcher();
    this.httpVerifier = new HttpVerifier(finalFetcher);
    this.metaVerifier = new MetaVerifier(finalFetcher);
  }

  /**
   * Generates a cryptographically random challenge token and constructs TXT/HTTP/Meta challenge structures.
   */
  static generateChallenge(
    orgId: string,
    primaryDomain: string
  ): {
    token: string;
    tokenHash: string;
    dnsTxtRecord: { host: string; value: string };
    httpChallenge: { url: string; expectedBody: { veltrixChallengeToken: string; orgId: string } };
    metaTag: { tag: string; name: string; content: string };
  } {
    const rawBytes = randomBytes(16).toString('hex');
    const token = `vltx_tok_${rawBytes}`;
    const tokenHash = createHash('sha256').update(token).digest('hex');

    const cleanDomain = primaryDomain.toLowerCase().trim();
    const host = `_veltrix-challenge.${cleanDomain}`;
    const value = `veltrix-verify=${orgId}.${token}`;
    const url = `https://${cleanDomain}/.well-known/veltrix-challenge/${token}`;
    const tag = `<meta name="veltrix-site-verification" content="${token}" />`;

    return {
      token,
      tokenHash,
      dnsTxtRecord: { host, value },
      httpChallenge: {
        url,
        expectedBody: {
          veltrixChallengeToken: token,
          orgId,
        },
      },
      metaTag: {
        tag,
        name: 'veltrix-site-verification',
        content: token,
      },
    };
  }

  /**
   * Evaluates whether a website asset is currently authorized to initiate or execute scans.
   * Safety Mandate: Under no circumstances will VELTRIX initiate or run a scan without valid, unexpired authorization.
   */
  static isScanAuthorized(site: WebsiteAsset): ScanAuthorizationCheckResult {
    // 1. Status must be VERIFIED
    if (site.status !== 'VERIFIED') {
      if (site.status === 'GRACE_PERIOD') {
        return {
          authorized: false,
          code: 'DOMAIN_VERIFICATION_SUSPENDED',
          message: `Site '${site.primaryDomain}' is in GRACE_PERIOD. New scans are blocked until re-verification completes.`,
        };
      }
      return {
        authorized: false,
        code: 'DOMAIN_NOT_VERIFIED',
        message: `Site '${site.primaryDomain}' has status '${site.status}'. Only VERIFIED sites can be scanned.`,
      };
    }

    // 2. scanBlocked flag must be false
    if (site.scanBlocked) {
      return {
        authorized: false,
        code: 'DOMAIN_VERIFICATION_SUSPENDED',
        message: `Scanning is blocked for site '${site.primaryDomain}'. Verification must be refreshed.`,
      };
    }

    // 3. Expiration check: expiresAt must be in the future
    if (!site.expiresAt) {
      return {
        authorized: false,
        code: 'DOMAIN_NOT_VERIFIED',
        message: `Site '${site.primaryDomain}' is missing verification expiration timestamp.`,
      };
    }

    const expiryEpoch = new Date(site.expiresAt).getTime();
    if (isNaN(expiryEpoch) || expiryEpoch <= Date.now()) {
      return {
        authorized: false,
        code: 'VERIFICATION_EXPIRED',
        message: `Verification authorization for site '${site.primaryDomain}' expired at ${site.expiresAt}. Re-verification required.`,
      };
    }

    return { authorized: true };
  }

  /**
   * Verifies domain ownership via DNS TXT, HTTP Challenge, or HTML Meta Tag.
   */
  async verifyDomain(
    orgId: string,
    siteId: string,
    method: VerificationMethod
  ): Promise<VerificationResult> {
    const site = await this.storage.getWebsiteById(orgId, siteId);
    if (!site) {
      return {
        verified: false,
        status: 'FAILED',
        method,
        error: {
          code: 'WEBSITE_NOT_FOUND',
          message: `Website asset '${siteId}' not found for organization '${orgId}'.`,
        },
      };
    }

    const now = Date.now();

    // 1. Token expiration check (max 30 days challenge token validity)
    if (site.tokenCreatedAt) {
      const tokenAgeMs = now - new Date(site.tokenCreatedAt).getTime();
      if (tokenAgeMs > DomainOwnershipVerifier.MAX_CHALLENGE_AGE_MS) {
        return {
          verified: false,
          status: 'FAILED',
          method,
          error: {
            code: 'CHALLENGE_EXPIRED',
            message: 'Verification challenge token has expired (valid for 30 days). Please regenerate challenge.',
          },
        };
      }
    }

    // 2. Rate limit check: max 5 attempts per 15 minutes
    const attempts = this.attemptTimestamps.get(siteId) || [];
    const validAttempts = attempts.filter((t) => now - t < DomainOwnershipVerifier.WINDOW_MS);
    if (validAttempts.length >= DomainOwnershipVerifier.MAX_ATTEMPTS) {
      return {
        verified: false,
        status: 'RATE_LIMITED',
        method,
        error: {
          code: 'VERIFICATION_RATE_LIMITED',
          message: `Too many verification attempts for site '${site.name}'. Maximum ${DomainOwnershipVerifier.MAX_ATTEMPTS} attempts per 15 minutes.`,
        },
      };
    }
    validAttempts.push(now);
    this.attemptTimestamps.set(siteId, validAttempts);

    // 3. Prevent cross-tenant domain takeover
    // If the domain is already VERIFIED under another organization, reject
    const existingDomainAsset = await this.storage.getWebsiteByDomain(site.primaryDomain);
    if (
      existingDomainAsset &&
      existingDomainAsset.orgId !== orgId &&
      existingDomainAsset.status === 'VERIFIED'
    ) {
      return {
        verified: false,
        status: 'FAILED',
        method,
        error: {
          code: 'DOMAIN_ALREADY_CLAIMED',
          message: `Domain '${site.primaryDomain}' is already claimed and verified by another organization. Verification blocked.`,
        },
      };
    }

    let isMatch = false;
    let failureReason = '';

    // 4. Dispatch verification method
    if (method === 'DNS_TXT') {
      const expectedHost = site.dnsTxtRecord.host;
      const expectedValue = site.dnsTxtRecord.value;
      const res = await this.dnsVerifier.verify(expectedHost, expectedValue);
      isMatch = res.matched;
      failureReason = res.failureReason || '';
    } else if (method === 'HTTP_CHALLENGE') {
      const expectedUrl = site.httpChallenge.url;
      const expectedToken = site.httpChallenge.expectedBody.veltrixChallengeToken;
      const expectedOrgId = site.httpChallenge.expectedBody.orgId;
      const verificationContext = createAuthoritativeVerificationScopeContext(site);
      const res = await this.httpVerifier.verify(expectedUrl, expectedToken, expectedOrgId, verificationContext);
      isMatch = res.matched;
      failureReason = res.failureReason || '';
    } else if (method === 'META_TAG') {
      const targetUrl = `https://${site.primaryDomain.toLowerCase().trim()}/`;
      const expectedToken = site.verificationToken;
      const verificationContext = createAuthoritativeVerificationScopeContext(site);
      const res = await this.metaVerifier.verify(targetUrl, expectedToken, verificationContext);
      isMatch = res.matched;
      failureReason = res.failureReason || '';
    }

    const nowIso = new Date(now).toISOString();

    if (isMatch) {
      const expiresAt = new Date(
        now + DomainOwnershipVerifier.TOKEN_VALIDITY_DAYS * 24 * 60 * 60 * 1000
      ).toISOString();

      await this.storage.updateWebsite(orgId, siteId, {
        status: 'VERIFIED',
        verifiedAt: nowIso,
        expiresAt,
        scanBlocked: false,
        verifiedMethod: method,
        lastVerificationAttemptAt: nowIso,
        verificationAttempts: (site.verificationAttempts || 0) + 1,
      });

      // Append immutable audit log
      await this.storage.appendAuditLog({
        logId: `audit-verify-${Date.now()}-${randomBytes(4).toString('hex')}`,
        orgId,
        timestamp: nowIso,
        action: 'WEBSITE_VERIFIED',
        actor: {
          userId: 'system-verifier',
          role: 'ORG_ADMIN',
        },
        details: {
          siteId,
          primaryDomain: site.primaryDomain,
          method,
          verifiedAt: nowIso,
          expiresAt,
        },
      });

      return {
        verified: true,
        status: 'VERIFIED',
        method,
        verifiedAt: nowIso,
        expiresAt,
        message: `Domain '${site.primaryDomain}' successfully verified via ${method}. Authorization valid for 90 days.`,
      };
    } else {
      await this.storage.updateWebsite(orgId, siteId, {
        lastVerificationAttemptAt: nowIso,
        verificationAttempts: (site.verificationAttempts || 0) + 1,
      });

      return {
        verified: false,
        status: 'FAILED',
        method,
        error: {
          code: 'CHALLENGE_VERIFICATION_FAILED',
          message: failureReason || `Verification failed for domain '${site.primaryDomain}' using ${method}.`,
        },
      };
    }
  }

  /**
   * Revokes domain verification and places the asset into GRACE_PERIOD.
   * Safety Invariant: GRACE_PERIOD immediately sets scanBlocked: true and halts scanning.
   */
  async revokeVerification(
    orgId: string,
    siteId: string,
    reason: string,
    actorId = 'user-admin'
  ): Promise<WebsiteAsset | null> {
    const site = await this.storage.getWebsiteById(orgId, siteId);
    if (!site) return null;

    const now = Date.now();
    const nowIso = new Date(now).toISOString();
    const gracePeriodEndsAt = new Date(
      now + DomainOwnershipVerifier.GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000
    ).toISOString();

    const updated = await this.storage.updateWebsite(orgId, siteId, {
      status: 'GRACE_PERIOD',
      gracePeriodEndsAt,
      scanBlocked: true, // Immediate scan freeze!
    });

    await this.storage.appendAuditLog({
      logId: `audit-revoke-${now}-${randomBytes(4).toString('hex')}`,
      orgId,
      timestamp: nowIso,
      action: 'WEBSITE_REVOKED',
      actor: {
        userId: actorId,
        role: 'ORG_ADMIN',
      },
      details: {
        siteId,
        primaryDomain: site.primaryDomain,
        reason,
        gracePeriodEndsAt,
        scanBlocked: true,
      },
    });

    return updated;
  }

  /**
   * Checks expiration of a website asset and transitions status to EXPIRED with scanBlocked: true if past expiresAt.
   */
  async checkAndEnforceExpiry(orgId: string, siteId: string): Promise<WebsiteAsset | null> {
    const site = await this.storage.getWebsiteById(orgId, siteId);
    if (!site) return null;

    if (site.status === 'VERIFIED' && site.expiresAt) {
      const expiryEpoch = new Date(site.expiresAt).getTime();
      if (!isNaN(expiryEpoch) && expiryEpoch <= Date.now()) {
        const nowIso = new Date().toISOString();
        const updated = await this.storage.updateWebsite(orgId, siteId, {
          status: 'EXPIRED',
          scanBlocked: true,
        });

        await this.storage.appendAuditLog({
          logId: `audit-expire-${Date.now()}-${randomBytes(4).toString('hex')}`,
          orgId,
          timestamp: nowIso,
          action: 'WEBSITE_EXPIRED',
          actor: {
            userId: 'system-expiry-watchdog',
            role: 'ORG_ADMIN',
          },
          details: {
            siteId,
            primaryDomain: site.primaryDomain,
            expiredAt: site.expiresAt,
            scanBlocked: true,
          },
        });

        return updated;
      }
    }

    return site;
  }
}
