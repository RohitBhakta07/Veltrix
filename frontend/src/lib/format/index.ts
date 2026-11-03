import type { Severity, WebConfidenceTier } from '@veltrix/shared';

export function formatNumber(value: number | undefined | null): string {
  if (value === undefined || value === null || Number.isNaN(value)) return '—';
  return new Intl.NumberFormat('en-US').format(value);
}

export function formatCompact(value: number | undefined | null): string {
  if (value === undefined || value === null || Number.isNaN(value)) return '—';
  return new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(
    value
  );
}

export function formatPercent(value: number, digits = 0): string {
  return `${value.toFixed(digits)}%`;
}

export function formatDateTime(value?: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}

export function formatDate(value?: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
  }).format(date);
}

export function timeAgo(value?: string | null): string {
  if (!value) return '—';
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return '—';
  const seconds = Math.round((Date.now() - then) / 1000);
  if (Math.abs(seconds) < 45) return `${Math.max(1, Math.abs(seconds))}s ago`;
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return `${Math.abs(minutes)}m ago`;
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return `${Math.abs(hours)}h ago`;
  const days = Math.round(hours / 24);
  return `${Math.abs(days)}d ago`;
}

export function shortId(value?: string | null, length = 8): string {
  if (!value) return '—';
  return value.length <= length ? value : value.slice(0, length);
}

export function initials(name?: string | null): string {
  if (!name) return 'VT';
  return name
    .replace(/[^a-zA-Z0-9 ]/g, ' ')
    .split(' ')
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('');
}

export type Tone = 'critical' | 'high' | 'medium' | 'low' | 'success' | 'neutral' | 'info';

export function severityTone(severity?: Severity | string): Tone {
  switch (severity) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'neutral';
  }
}

export function riskTone(band?: string): Tone {
  switch (band) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'neutral';
  }
}

export function confidenceTone(confidence?: WebConfidenceTier | string | number): Tone {
  if (typeof confidence === 'number') {
    if (confidence >= 80) return 'critical';
    if (confidence >= 60) return 'high';
    if (confidence >= 40) return 'medium';
    return 'low';
  }
  switch (confidence?.toUpperCase()) {
    case 'CONFIRMED_EXPLOITATION':
    case 'CRITICAL':
      return 'critical';
    case 'POTENTIAL_EXPLOITATION':
    case 'HIGH':
      return 'high';
    case 'SUSPICIOUS_ATTEMPT':
    case 'MEDIUM':
      return 'medium';
    case 'BLOCKED_ATTEMPT':
    case 'LOW':
      return 'low';
    default:
      return 'neutral';
  }
}

export function confidenceLabel(confidence?: WebConfidenceTier | string | number): string {
  if (typeof confidence === 'number') {
    return `${confidence}% confidence`;
  }
  switch (confidence?.toUpperCase()) {
    case 'CONFIRMED_EXPLOITATION':
      return 'Confirmed exploitation';
    case 'POTENTIAL_EXPLOITATION':
      return 'Potential exploitation';
    case 'BLOCKED_ATTEMPT':
      return 'Blocked attempt';
    case 'SUSPICIOUS_ATTEMPT':
      return 'Suspicious attempt';
    case 'CRITICAL':
      return 'Critical confidence';
    case 'HIGH':
      return 'High confidence';
    case 'MEDIUM':
      return 'Medium confidence';
    case 'LOW':
      return 'Low confidence';
    default:
      return 'Unclassified';
  }
}

export function titleCase(value?: string | null): string {
  if (!value) return '—';
  return value
    .toLowerCase()
    .split(/[_\s.-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

export function scoreColor(score: number): string {
  // Theme-aware severity channels: readable on graphite and on paper.
  if (score >= 75) return 'rgb(var(--dp-sev-critical))';
  if (score >= 50) return 'rgb(var(--dp-sev-high))';
  if (score >= 25) return 'rgb(var(--dp-sev-medium))';
  return 'rgb(var(--dp-sev-low))';
}
