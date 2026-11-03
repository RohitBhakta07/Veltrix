import { Router, type Request, type Response } from 'express';
import type {
  ApiResponse,
  ApiErrorResponse,
  Incident,
  SecurityEvent,
  Severity,
  WebsiteAsset,
} from '@veltrix/shared';
import { authenticate } from '../middleware/auth.js';
import { enforceTenantIsolation } from '../middleware/tenant.js';
import { getStorage } from '../storage/index.js';

interface VelocityBucket {
  timestamp: string;
  events: number;
  attacks: number;
}

interface BreakdownEntry {
  key: string;
  count: number;
}

function emptySeverityCounts(): Record<Severity, number> {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
}

function riskBandFor(score: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'LOW';
}

function isAttackEvent(event: SecurityEvent): boolean {
  return (
    event.eventType.startsWith('web.attack') ||
    event.eventType === 'auth.credential_stuffing' ||
    event.eventType === 'recon.account.probe'
  );
}

/**
 * GET /api/v1/dashboard/summary?range=24h
 * Single read model for the SOC Overview page. Composes the existing
 * tenant-scoped stores so the browser does not have to fan out six queries.
 */
export function createDashboardRouter(): Router {
  const router = Router();
  const storage = getStorage();

  router.use(authenticate);
  router.use(enforceTenantIsolation);

  router.get('/summary', async (req: Request, res: Response) => {
    try {
      const orgId = req.tenantOrgId!;
      const rangeHours = Math.min(
        24 * 30,
        Math.max(1, Number.parseInt(String(req.query.rangeHours || '24'), 10) || 24)
      );
      const windowStart = new Date(Date.now() - rangeHours * 60 * 60 * 1000).toISOString();
      const nowIso = new Date().toISOString();

      const [eventsResult, detectionsResult, incidentsResult, websitesResult] = await Promise.all([
        storage.getEvents(orgId, { startTime: windowStart, endTime: nowIso, limit: 2000 }),
        storage.getDetections(orgId, { startTime: windowStart, endTime: nowIso, limit: 1000 }),
        storage.getIncidents(orgId, { limit: 200 }),
        storage.getWebsites(orgId, { limit: 200 }),
      ]);

      const events = eventsResult.items;
      const detections = detectionsResult.items;
      const incidents = incidentsResult.items;
      const websites = websitesResult.items;

      // --- Hourly velocity buckets -----------------------------------------
      const bucketCount = Math.min(rangeHours, 24 * 7);
      const bucketMs = (rangeHours * 60 * 60 * 1000) / bucketCount;
      const velocity: VelocityBucket[] = Array.from({ length: bucketCount }, (_, index) => ({
        timestamp: new Date(Date.parse(windowStart) + index * bucketMs).toISOString(),
        events: 0,
        attacks: 0,
      }));

      for (const event of events) {
        const index = Math.floor(
          (Date.parse(event.timestamp) - Date.parse(windowStart)) / bucketMs
        );
        const bucket = velocity[Math.max(0, Math.min(bucketCount - 1, index))];
        if (bucket) {
          bucket.events += 1;
          if (isAttackEvent(event)) bucket.attacks += 1;
        }
      }

      // --- Severity / MITRE / risk-band breakdowns -------------------------
      const detectionSeverity = emptySeverityCounts();
      const incidentSeverity = emptySeverityCounts();
      const mitreCounts = new Map<string, number>();
      const ruleCounts = new Map<string, number>();

      for (const detection of detections) {
        detectionSeverity[detection.severity] = (detectionSeverity[detection.severity] || 0) + 1;
        ruleCounts.set(detection.ruleId, (ruleCounts.get(detection.ruleId) || 0) + 1);
        const tactic = detection.mitreAttack?.tactic;
        if (tactic) mitreCounts.set(tactic, (mitreCounts.get(tactic) || 0) + 1);
      }
      for (const incident of incidents) {
        incidentSeverity[incident.severity] = (incidentSeverity[incident.severity] || 0) + 1;
      }

      const severity: BreakdownEntry[] = (Object.keys(detectionSeverity) as Severity[]).map((key) => ({
        key,
        count: detectionSeverity[key],
      }));

      const mitre: BreakdownEntry[] = Array.from(mitreCounts.entries())
        .map(([key, count]) => ({ key, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8);

      const rules: BreakdownEntry[] = Array.from(ruleCounts.entries())
        .map(([key, count]) => ({ key, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8);

      const riskBandCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
      for (const incident of incidents) {
        const band = incident.riskBand || riskBandFor(incident.riskScore);
        riskBandCounts[band] += 1;
      }
      const riskBands: BreakdownEntry[] = Object.entries(riskBandCounts).map(([key, count]) => ({
        key,
        count,
      }));

      // --- Top source IPs ---------------------------------------------------
      const sourceMap = new Map<string, { count: number; riskScore: number }>();
      for (const incident of incidents) {
        if (!incident.sourceIp) continue;
        const current = sourceMap.get(incident.sourceIp) || { count: 0, riskScore: 0 };
        current.count += 1;
        current.riskScore = Math.max(current.riskScore, incident.riskScore);
        sourceMap.set(incident.sourceIp, current);
      }
      for (const detection of detections) {
        const ip =
          detection.evidence?.targetEntity?.type === 'IP'
            ? detection.evidence.targetEntity.value
            : undefined;
        if (!ip) continue;
        const current = sourceMap.get(ip) || { count: 0, riskScore: 0 };
        current.count += 1;
        sourceMap.set(ip, current);
      }
      const topSources = Array.from(sourceMap.entries())
        .map(([ip, value]) => ({ ip, ...value }))
        .sort((a, b) => b.riskScore - a.riskScore || b.count - a.count)
        .slice(0, 5);

      // --- Asset posture ----------------------------------------------------
      const incidentsBySite = new Map<string, Incident[]>();
      for (const incident of incidents) {
        if (!incident.siteId) continue;
        const list = incidentsBySite.get(incident.siteId) || [];
        list.push(incident);
        incidentsBySite.set(incident.siteId, list);
      }

      const assets = websites.map((site: WebsiteAsset) => {
        const siteIncidents = incidentsBySite.get(site.siteId) || [];
        const highest = siteIncidents.reduce(
          (max, incident) => Math.max(max, incident.riskScore),
          0
        );
        return {
          siteId: site.siteId,
          name: site.name,
          domain: site.primaryDomain,
          environment: site.environment,
          status: site.status,
          verified: site.status === 'VERIFIED',
          scanBlocked: site.scanBlocked,
          telemetryStatus: site.health?.telemetryStatus || 'INACTIVE',
          lastEventReceivedAt: site.health?.lastEventReceivedAt,
          riskScore: highest,
          riskBand: riskBandFor(highest),
          openIncidents: siteIncidents.filter(
            (incident) => incident.status !== 'RESOLVED' && incident.status !== 'FALSE_POSITIVE'
          ).length,
        };
      });

      const openIncidents = incidents.filter(
        (incident) => incident.status !== 'RESOLVED' && incident.status !== 'FALSE_POSITIVE'
      );
      const criticalIncidents = openIncidents.filter(
        (incident) => (incident.riskBand || riskBandFor(incident.riskScore)) === 'CRITICAL'
      );
      const avgRiskScore =
        incidents.length === 0
          ? 0
          : Math.round(
              incidents.reduce((sum, incident) => sum + incident.riskScore, 0) / incidents.length
            );

      const payload = {
        generatedAt: nowIso,
        rangeHours,
        kpis: {
          eventsInWindow: events.length,
          attacksInWindow: events.filter(isAttackEvent).length,
          detectionsInWindow: detections.length,
          openIncidents: openIncidents.length,
          criticalIncidents: criticalIncidents.length,
          resolvedIncidents: incidents.filter((i) => i.status === 'RESOLVED').length,
          totalAssets: websites.length,
          verifiedAssets: websites.filter((site) => site.status === 'VERIFIED').length,
          assetsWithTelemetry: websites.filter(
            (site) => site.health?.telemetryStatus === 'HEALTHY'
          ).length,
          avgRiskScore,
          activeScans: 0,
        },
        velocity,
        severity,
        incidentSeverity: (Object.keys(incidentSeverity) as Severity[]).map((key) => ({
          key,
          count: incidentSeverity[key],
        })),
        mitre,
        rules,
        riskBands,
        topSources,
        assets,
        recentIncidents: incidents.slice(0, 6),
        latestDetections: detections.slice(0, 8),
      };

      const response: ApiResponse<typeof payload> = {
        success: true,
        data: payload,
        meta: { timestamp: nowIso },
      };
      res.status(200).json(response);
    } catch (err: unknown) {
      console.error('[VELTRIX] Dashboard summary error:', err);
      const errorResponse: ApiErrorResponse = {
        success: false,
        error: {
          code: 'DASHBOARD_SUMMARY_ERROR',
          message: 'Failed to build the dashboard summary',
        },
      };
      res.status(500).json(errorResponse);
    }
  });

  return router;
}
