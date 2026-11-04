import type { WebRiskFactors } from '@veltrix/shared';

/**
 * Normalizes legacy or partial risk factor payloads from backend into standard WebRiskFactors.
 */
export function normalizeRiskFactors(raw: any): WebRiskFactors {
  if (!raw || typeof raw !== 'object') {
    return {
      baseSeverity: 0,
      frequencyMultiplier: 1.0,
      assetCriticalityMultiplier: 1.0,
      threatIntelMultiplier: 1.0,
      attackSequenceBonus: 0,
      finalScore: 0,
      vulnerabilityMatchTerm: 0,
      riskBand: 'LOW',
      calculationExplanation: 'No risk factor calculation available.',
      contributingFactors: {
        eventCount: 0,
        detectedAttackTypes: [],
        highestConfidence: 'SUSPICIOUS_ATTEMPT',
        assetEnvironment: 'PRODUCTION',
        threatIntelStatus: 'NONE',
      },
    };
  }

  return {
    baseSeverity: Number(raw.baseSeverity ?? 0),
    frequencyMultiplier: Number(raw.frequencyMultiplier ?? 1.0),
    assetCriticalityMultiplier: Number(raw.assetCriticalityMultiplier ?? raw.assetMultiplier ?? 1.0),
    threatIntelMultiplier: Number(raw.threatIntelMultiplier ?? raw.threatMultiplier ?? 1.0),
    attackSequenceBonus: Number(raw.attackSequenceBonus ?? raw.sequenceBonus ?? 0),
    finalScore: Number(raw.finalScore ?? raw.score ?? 0),
    vulnerabilityMatchTerm: Number(raw.vulnerabilityMatchTerm ?? raw.vulnerabilityTerm ?? 0),
    riskBand: raw.riskBand || 'LOW',
    calculationExplanation: String(raw.calculationExplanation ?? raw.explanation ?? 'Calculated risk score based on correlated telemetry.'),
    contributingFactors: raw.contributingFactors || {
      eventCount: raw.eventCount ?? 0,
      detectedAttackTypes: raw.detectedAttackTypes ?? [],
      highestConfidence: raw.highestConfidence ?? 'SUSPICIOUS_ATTEMPT',
      assetEnvironment: raw.assetEnvironment ?? 'PRODUCTION',
      threatIntelStatus: raw.threatIntelStatus ?? 'NONE',
    },
  };
}

/**
 * Normalizes varied list response envelopes ({ sites: [] }, { integrations: [] }, { data: { items: [] } }, etc.)
 */
export function normalizeListResponse<T = any>(res: any): T[] {
  if (!res || typeof res !== 'object') return [];
  if (Array.isArray(res)) return res;
  if (Array.isArray(res.sites)) return res.sites;
  if (Array.isArray(res.integrations)) return res.integrations;
  if (Array.isArray(res.data?.items)) return res.data.items;
  if (Array.isArray(res.data?.events)) return res.data.events;
  if (Array.isArray(res.items)) return res.items;
  if (Array.isArray(res.events)) return res.events;
  if (Array.isArray(res.data)) return res.data;
  return [];
}
