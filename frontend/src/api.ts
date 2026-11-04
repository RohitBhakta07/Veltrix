/**
 * Backwards-compatible API surface for the Phase 6/7 feature components.
 * New code should import from `lib/api/endpoints` directly.
 */
import type { WebsiteAsset, Integration } from '@veltrix/shared';
import {
  createIntegration as createIntegrationRequest,
  createWebsite as createWebsiteRequest,
  deleteIntegration as deleteIntegrationRequest,
  deleteWebsite as deleteWebsiteRequest,
  fetchIntegrations as fetchIntegrationsRequest,
  fetchIncidents,
  fetchSiteRiskSummary as fetchSiteRiskSummaryRequest,
  fetchSiteTimeline as fetchSiteTimelineRequest,
  fetchWebDetections as fetchWebDetectionsRequest,
  fetchWebsites as fetchWebsitesRequest,
  revokeDomainVerification as revokeDomainVerificationRequest,
  revokeIntegration as revokeIntegrationRequest,
  rotateIntegrationKey as rotateIntegrationKeyRequest,
  updateIncident as updateIncidentRequest,
  verifyDomainOwnership as verifyDomainOwnershipRequest,
} from './lib/api/endpoints';
import type { RiskSummary, SiteTimeline } from './lib/api/types';

export async function fetchWebsites(): Promise<{ total: number; sites: WebsiteAsset[] }> {
  return fetchWebsitesRequest();
}

export async function createWebsite(data: {
  name: string;
  primaryDomain: string;
  approvedSubdomains?: string[];
  environment?: 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT';
  riskTier?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  tags?: string[];
}): Promise<WebsiteAsset> {
  const response = await createWebsiteRequest(data);
  return response.site;
}

export async function verifyDomainOwnership(
  siteId: string,
  method: 'DNS_TXT' | 'HTTP_CHALLENGE' | 'META_TAG'
): Promise<{ verified: boolean; message: string; expiresAt?: string }> {
  return verifyDomainOwnershipRequest(siteId, method);
}

export async function revokeDomainVerification(
  siteId: string,
  reason?: string
): Promise<WebsiteAsset> {
  const response = await revokeDomainVerificationRequest(siteId, reason);
  return response.site;
}

export async function deleteWebsite(siteId: string): Promise<void> {
  await deleteWebsiteRequest(siteId);
}

export async function fetchIntegrations(): Promise<{
  total: number;
  integrations: Integration[];
}> {
  return fetchIntegrationsRequest();
}

export async function createIntegration(data: {
  name: string;
  type: string;
  siteId?: string;
  description?: string;
}): Promise<{ integration: Integration; secretKey: string }> {
  return createIntegrationRequest(data);
}

export async function rotateIntegrationKey(
  integrationId: string
): Promise<{ secretKey: string; apiKeyPrefix: string }> {
  return rotateIntegrationKeyRequest(integrationId);
}

export async function revokeIntegration(integrationId: string): Promise<Integration> {
  return revokeIntegrationRequest(integrationId);
}

export async function deleteIntegration(integrationId: string): Promise<void> {
  await deleteIntegrationRequest(integrationId);
}

export async function fetchWebDetections(siteId?: string) {
  const response = await fetchWebDetectionsRequest(siteId);
  return { items: response.data.items, total: response.data.total };
}

export async function fetchWebIncidents(siteId?: string) {
  const response = await fetchIncidents({ siteId, limit: 100 });
  return { items: response.data.items, total: response.data.total };
}

export async function fetchSiteRiskSummary(siteId: string): Promise<RiskSummary> {
  const response = await fetchSiteRiskSummaryRequest(siteId);
  return response.data;
}

export async function fetchSiteTimeline(siteId: string): Promise<SiteTimeline> {
  const response = await fetchSiteTimelineRequest(siteId);
  return response.data;
}

export async function updateIncidentStatus(
  incidentId: string,
  status: string,
  note?: string
) {
  const response = await updateIncidentRequest(incidentId, { status, note });
  return response.data;
}
