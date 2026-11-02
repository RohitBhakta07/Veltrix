/**
 * Domain Verification Service
 * Re-exports unified Domain Ownership Verification modules for backward compatibility and integration.
 */

export {
  DnsResolverInterface,
  DefaultDnsResolver,
  DnsVerifier,
  DnsVerificationResult,
} from '../scanner/verification/dns-verifier.js';

export {
  HttpFetcherInterface,
  DefaultHttpFetcher,
  HttpVerifier,
  HttpVerificationResult,
  isProhibitedIpv4,
  isProhibitedIp,
} from '../scanner/verification/http-verifier.js';

export {
  MetaVerifier,
  MetaVerificationResult,
} from '../scanner/verification/meta-verifier.js';

export {
  DomainOwnershipVerifier,
  DomainOwnershipVerifier as DomainVerificationService,
  VerificationResult,
  ScanAuthorizationCheckResult,
} from '../scanner/verification/verifier.js';
