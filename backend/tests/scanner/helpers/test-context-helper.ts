/**
 * VELTRIX Test-Only Context Helper
 *
 * Dedicated test helper for generating authoritative request contexts backed by a MemoryStore.
 * Strictly located under backend/tests/ and excluded from production distribution builds.
 */

import { MemoryStore } from '../../../src/storage/memory-store.js';
import {
  createAuthoritativeScanScopeContext,
  createAuthoritativeVerificationScopeContext,
  createServerScanPolicy,
} from '../../../src/scanner/transport/context-authority.js';
import type {
  AuthorizedScanScopeContext,
  VerificationScopeContext,
} from '../../../src/scanner/transport/types.js';
import type { WebsiteAsset } from '@veltrix/shared';

export interface TestScanContextParams {
  orgId?: string;
  scanId?: string;
  siteId?: string;
  primaryDomain?: string;
  approvedSubdomains?: string[];
  status?: WebsiteAsset['status'];
  scanBlocked?: boolean;
  expiresAt?: number | string;
  allowedPorts?: number[];
  allowedMethods?: string[];
  excludedPaths?: string[];
}

export async function createTestScanContext(
  params?: TestScanContextParams
): Promise<AuthorizedScanScopeContext> {
  const store = new MemoryStore();
  const orgId = params?.orgId ?? 'org-test-default';
  const siteId = params?.siteId ?? 'site-test-default';
  const scanId = params?.scanId ?? 'scan-test-default';
  const primaryDomain = params?.primaryDomain ?? 'example.com';

  const asset: WebsiteAsset = {
    orgId,
    siteId,
    name: 'Test Target Website',
    primaryDomain,
    approvedSubdomains: params?.approvedSubdomains ?? [],
    status: params?.status ?? 'VERIFIED',
    scanBlocked: params?.scanBlocked ?? false,
    expiresAt:
      typeof params?.expiresAt === 'number'
        ? new Date(params.expiresAt).toISOString()
        : params?.expiresAt ?? new Date(Date.now() + 86400000).toISOString(),
    environment: 'PRODUCTION',
    riskTier: 'LOW',
    tags: [],
    verificationToken: 'vltx_tok_test_1234567890abcdef',
    tokenCreatedAt: new Date().toISOString(),
    dnsTxtRecord: { host: `_veltrix-challenge.${primaryDomain}`, value: 'vltx-verify' },
    httpChallenge: { url: `http://${primaryDomain}/test`, expectedBody: { veltrixChallengeToken: 'test', orgId } },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    health: 'HEALTHY',
  };

  await store.saveWebsite(asset);

  const serverPolicy =
    params?.allowedPorts !== undefined ||
    params?.allowedMethods !== undefined ||
    params?.excludedPaths !== undefined
      ? createServerScanPolicy({
          allowedPorts: params?.allowedPorts,
          allowedMethods: params?.allowedMethods,
          additionalExcludedPaths: params?.excludedPaths,
        })
      : undefined;

  return createAuthoritativeScanScopeContext(store, {
    orgId,
    siteId,
    scanId,
    serverPolicy,
  });
}

export interface TestVerificationContextParams {
  orgId?: string;
  siteId?: string;
  primaryDomain?: string;
  activeToken?: string;
}

export async function createTestVerificationContext(
  params?: TestVerificationContextParams
): Promise<VerificationScopeContext> {
  const store = new MemoryStore();
  const orgId = params?.orgId ?? 'org-test-default';
  const siteId = params?.siteId ?? 'site-test-default';
  const primaryDomain = params?.primaryDomain ?? 'example.com';
  const verificationToken = params?.activeToken ?? 'vltx_tok_test_1234567890abcdef';

  const asset: WebsiteAsset = {
    orgId,
    siteId,
    name: 'Test Verification Website',
    primaryDomain,
    approvedSubdomains: [],
    status: 'PENDING_VERIFICATION',
    scanBlocked: false,
    environment: 'PRODUCTION',
    riskTier: 'LOW',
    tags: [],
    verificationToken,
    tokenCreatedAt: new Date().toISOString(),
    dnsTxtRecord: { host: `_veltrix-challenge.${primaryDomain}`, value: 'vltx-verify' },
    httpChallenge: { url: `http://${primaryDomain}/test`, expectedBody: { veltrixChallengeToken: 'test', orgId } },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    health: 'HEALTHY',
  };

  await store.saveWebsite(asset);

  return createAuthoritativeVerificationScopeContext(store, {
    orgId,
    siteId,
  });
}

// Aliases for tests that use the old signature
export const createAuthorizedScanScopeContext = createTestScanContext;
export const createVerificationScopeContext = createTestVerificationContext;
