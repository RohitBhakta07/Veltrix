import { describe, it, expect } from 'vitest';
import { normalizeRiskFactors, normalizeListResponse } from '../src/lib/api/normalize';

describe('API Contract Normalization', () => {
  it('normalizes legacy and updated risk factor payload keys', () => {
    const rawBackend = {
      assetMultiplier: 1.5,
      threatMultiplier: 2.0,
      vulnerabilityTerm: 15,
      sequenceBonus: 10,
      explanation: 'Targeted attack chain detected',
    };
    const normalized = normalizeRiskFactors(rawBackend);
    expect(normalized.assetCriticalityMultiplier).toBe(1.5);
    expect(normalized.threatIntelMultiplier).toBe(2.0);
    expect(normalized.vulnerabilityMatchTerm).toBe(15);
    expect(normalized.attackSequenceBonus).toBe(10);
    expect(normalized.calculationExplanation).toBe('Targeted attack chain detected');
  });

  it('normalizes already updated risk factor payload keys directly', () => {
    const updated = {
      assetCriticalityMultiplier: 1.2,
      threatIntelMultiplier: 1.8,
      vulnerabilityMatchTerm: 25,
      attackSequenceBonus: 15,
      calculationExplanation: 'Critical SQLi correlated with high asset',
    };
    const normalized = normalizeRiskFactors(updated);
    expect(normalized.assetCriticalityMultiplier).toBe(1.2);
    expect(normalized.threatIntelMultiplier).toBe(1.8);
    expect(normalized.vulnerabilityMatchTerm).toBe(25);
    expect(normalized.attackSequenceBonus).toBe(15);
    expect(normalized.calculationExplanation).toBe('Critical SQLi correlated with high asset');
  });

  it('normalizes heterogeneous list envelopes (sites, integrations, items, events)', () => {
    expect(normalizeListResponse({ sites: [{ siteId: '1' }] })).toEqual([{ siteId: '1' }]);
    expect(normalizeListResponse({ integrations: [{ id: '2' }] })).toEqual([{ id: '2' }]);
    expect(normalizeListResponse({ data: { items: [{ id: '3' }] } })).toEqual([{ id: '3' }]);
    expect(normalizeListResponse({ data: { events: [{ id: '4' }] } })).toEqual([{ id: '4' }]);
  });
});

