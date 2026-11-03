import type {
  Detection,
  Incident,
  Severity,
  WebConfidenceTier,
  WebRiskFactors,
  WebsiteEnvironment,
  WebsiteStatus,
} from '@veltrix/shared';

export interface BreakdownEntry {
  key: string;
  count: number;
}

export interface VelocityPoint {
  timestamp: string;
  events: number;
  attacks: number;
}

export interface DashboardAsset {
  siteId: string;
  name: string;
  domain: string;
  environment: WebsiteEnvironment;
  status: WebsiteStatus;
  verified: boolean;
  scanBlocked: boolean;
  telemetryStatus: 'HEALTHY' | 'DEGRADED' | 'INACTIVE';
  lastEventReceivedAt?: string;
  riskScore: number;
  riskBand: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  openIncidents: number;
}

export interface DashboardSummary {
  generatedAt: string;
  rangeHours: number;
  kpis: {
    eventsInWindow: number;
    attacksInWindow: number;
    detectionsInWindow: number;
    openIncidents: number;
    criticalIncidents: number;
    resolvedIncidents: number;
    totalAssets: number;
    verifiedAssets: number;
    assetsWithTelemetry: number;
    avgRiskScore: number;
    activeScans: number;
  };
  velocity: VelocityPoint[];
  severity: BreakdownEntry[];
  incidentSeverity: BreakdownEntry[];
  mitre: BreakdownEntry[];
  rules: BreakdownEntry[];
  riskBands: BreakdownEntry[];
  topSources: Array<{ ip: string; count: number; riskScore: number }>;
  assets: DashboardAsset[];
  recentIncidents: Incident[];
  latestDetections: Detection[];
}

export interface RiskSummary {
  siteId: string;
  domain: string;
  environment: WebsiteEnvironment;
  riskTier: string;
  currentRiskScore: number;
  currentRiskBand: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: WebRiskFactors;
  detectedAttackTypes: string[];
  totalIncidentsCount: number;
  totalDetectionsCount: number;
  latestIncidents: Incident[];
  latestDetections: Detection[];
}

export interface TimelineItem {
  timestamp: string;
  type: 'INCIDENT' | 'DETECTION';
  title: string;
  description: string;
  severity: Severity;
  sourceIp?: string;
  details?: Record<string, unknown>;
}

export interface SiteTimeline {
  siteId: string;
  domain: string;
  items: TimelineItem[];
  total: number;
}

export type ConfidenceTier = WebConfidenceTier;

export interface DemoSeedResult {
  alreadySeeded: boolean;
  sites: number;
  events?: number;
  detections?: number;
  incidents: number;
  topologyIncident?: string | null;
}
