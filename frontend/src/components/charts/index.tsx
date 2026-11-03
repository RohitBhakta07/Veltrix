import { useMemo } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { BreakdownEntry, VelocityPoint } from '../../lib/api/types';
import { formatCompact, formatNumber } from '../../lib/format';
import { useTheme } from '../../theme/ThemeProvider';
import { Card, SectionHeader } from '../ui/primitives';

/**
 * Charts read their colours from the live theme tokens, so a theme switch is
 * reflected immediately without duplicating a palette per component.
 */
function useChartPalette() {
  const { resolved } = useTheme();
  return useMemo(() => {
    const read = (name: string, fallback: string) => {
      if (typeof window === 'undefined' || typeof document === 'undefined') return fallback;
      const raw = window.getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      if (!raw) return fallback;
      const parts = raw.split(/\s+/);
      return parts.length === 3 ? `rgb(${parts.join(', ')})` : raw;
    };
    return {
      axis: read('--dp-ink-muted', '#8a8d91'),
      grid: read('--dp-line', 'rgba(255,255,255,0.08)'),
      signal: read('--dp-signal', '#38ff8e'),
      critical: read('--dp-sev-critical', '#ff4d6d'),
      high: read('--dp-sev-high', '#ff8a3d'),
      medium: read('--dp-sev-medium', '#ffc857'),
      low: read('--dp-sev-low', '#38bdf8'),
      live: read('--dp-live', '#3fd6c6'),
    };
  }, [resolved]);
}

type Palette = ReturnType<typeof useChartPalette>;

function bandColor(palette: Palette, score: number): string {
  if (score >= 75) return palette.critical;
  if (score >= 50) return palette.high;
  if (score >= 25) return palette.medium;
  return palette.low;
}

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; color?: string }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-control border border-veltrix-border bg-veltrix-elevated px-3 py-2 shadow-card">
      {label ? (
        <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.1em] text-veltrix-textMeta">
          {label}
        </div>
      ) : null}
      {payload.map((entry, index) => (
        <div key={index} className="flex items-center gap-2 text-xs text-slate-200">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: entry.color }} />
          <span className="capitalize text-veltrix-textMuted">{entry.name}</span>
          <span className="ml-auto font-mono font-medium tabular-nums">
            {formatNumber(entry.value)}
          </span>
        </div>
      ))}
    </div>
  );
}

export function VelocityChart({ data }: { data: VelocityPoint[] }) {
  const palette = useChartPalette();
  const formatted = data.map((point) => ({
    ...point,
    label: new Date(point.timestamp).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }),
  }));

  return (
    <Card className="p-5">
      <SectionHeader
        title="Telemetry velocity"
        description="Normalized events versus web attacks in the selected window"
        action={
          <div className="flex items-center gap-3 font-mono text-[10px] uppercase tracking-[0.08em] text-veltrix-textMeta">
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-veltrix-cyan" /> Events
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-rose-400" /> Attacks
            </span>
          </div>
        }
      />
      <div className="mt-4 h-[240px] w-full">
        {formatted.length === 0 ? (
          <div className="flex h-full items-center justify-center text-xs text-veltrix-textMeta">
            No telemetry in this window
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={formatted} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="eventsFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={palette.signal} stopOpacity={0.16} />
                  <stop offset="100%" stopColor={palette.signal} stopOpacity={0.01} />
                </linearGradient>
                <linearGradient id="attacksFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={palette.critical} stopOpacity={0.16} />
                  <stop offset="100%" stopColor={palette.critical} stopOpacity={0.01} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke={palette.grid} strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="label"
                stroke={palette.axis}
                tick={{ fontSize: 10, fill: palette.axis }}
                tickLine={false}
                axisLine={false}
                minTickGap={24}
              />
              <YAxis
                stroke={palette.axis}
                tick={{ fontSize: 10, fill: palette.axis }}
                tickLine={false}
                axisLine={false}
                width={52}
              />
              <Tooltip content={<ChartTooltip />} cursor={{ stroke: palette.grid }} />
              <Area
                type="monotone"
                dataKey="events"
                stroke={palette.signal}
                strokeWidth={1.75}
                fill="url(#eventsFill)"
                name="Events"
              />
              <Area
                type="monotone"
                dataKey="attacks"
                stroke={palette.critical}
                strokeWidth={1.75}
                fill="url(#attacksFill)"
                name="Attacks"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  );
}

export function SeverityDonut({
  data,
  title = 'Detection severity',
  description = 'Share of detections by severity',
}: {
  data: BreakdownEntry[];
  title?: string;
  description?: string;
}) {
  const palette = useChartPalette();
  const colors: Record<string, string> = {
    CRITICAL: palette.critical,
    HIGH: palette.high,
    MEDIUM: palette.medium,
    LOW: palette.low,
  };
  const ordered = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    .map((key) => ({ key, count: data.find((entry) => entry.key === key)?.count || 0 }))
    .filter((entry) => entry.count > 0);
  const total = ordered.reduce((sum, entry) => sum + entry.count, 0);

  return (
    <Card className="p-5">
      <SectionHeader title={title} description={description} />
      <div className="relative mt-2 h-[220px]">
        {total === 0 ? (
          <div className="flex h-full items-center justify-center text-xs text-veltrix-textMeta">
            No detections yet
          </div>
        ) : (
          <>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={ordered}
                  dataKey="count"
                  nameKey="key"
                  innerRadius={64}
                  outerRadius={88}
                  paddingAngle={3}
                  stroke="none"
                >
                  {ordered.map((entry) => (
                    <Cell key={entry.key} fill={colors[entry.key]} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="font-mono text-[24px] font-medium tabular-nums text-slate-100">
                {formatNumber(total)}
              </span>
              <span className="text-[10px] uppercase tracking-[0.12em] text-veltrix-textMeta">
                Detections
              </span>
            </div>
          </>
        )}
      </div>
      <div className="mt-2 grid grid-cols-2 gap-2">
        {ordered.map((entry) => (
          <div
            key={entry.key}
            className="flex items-center gap-2 text-[11px] text-veltrix-textMuted"
          >
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: colors[entry.key] }} />
            <span className="flex-1">{entry.key}</span>
            <span className="font-mono tabular-nums text-slate-200">
              {formatNumber(entry.count)}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
}

export function MitreBars({ data }: { data: BreakdownEntry[] }) {
  const palette = useChartPalette();

  return (
    <Card className="p-5">
      <SectionHeader
        title="MITRE ATT&CK coverage"
        description="Detections mapped to adversary tactics"
      />
      <div className="mt-4 h-[240px]">
        {data.length === 0 ? (
          <div className="flex h-full items-center justify-center text-xs text-veltrix-textMeta">
            No mapped techniques in this window
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={data}
              layout="vertical"
              margin={{ left: 8, right: 16, top: 0, bottom: 0 }}
            >
              <CartesianGrid stroke={palette.grid} strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="key"
                width={118}
                tick={{ fontSize: 10, fill: palette.axis }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<ChartTooltip />} cursor={{ fill: palette.grid }} />
              <Bar dataKey="count" name="Detections" radius={[0, 2, 2, 0]} barSize={12}>
                {data.map((entry, index) => (
                  <Cell
                    key={entry.key}
                    fill={palette.signal}
                    fillOpacity={Math.max(0.2, 0.72 - index * 0.1)}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  );
}

export function RiskGauge({
  score,
  band,
  size = 168,
  label = 'Risk score',
}: {
  score: number;
  band?: string;
  size?: number;
  label?: string;
}) {
  const palette = useChartPalette();
  const clamped = Math.max(0, Math.min(100, score));
  const radius = size / 2 - 14;
  const circumference = Math.PI * radius;
  const offset = circumference * (1 - clamped / 100);
  const color = bandColor(palette, clamped);
  const height = size / 2 + 28;

  return (
    <div className="flex flex-col items-center" style={{ width: size }}>
      <svg
        width={size}
        height={height}
        viewBox={`0 0 ${size} ${height}`}
        role="img"
        aria-label={`${label}: ${clamped} out of 100`}
      >
        <path
          d={`M 14 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 14} ${size / 2}`}
          fill="none"
          stroke={palette.grid}
          strokeWidth="12"
          strokeLinecap="round"
        />
        <path
          d={`M 14 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 14} ${size / 2}`}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 400ms ease-out' }}
        />
      </svg>
      <div className="-mt-10 text-center">
        <div className="font-mono text-[28px] font-medium tabular-nums" style={{ color }}>
          {clamped}
        </div>
        <div className="text-[10px] uppercase tracking-[0.12em] text-veltrix-textMeta">{label}</div>
        {band ? (
          <div
            className="mt-1 text-[10px] font-medium uppercase tracking-[0.1em]"
            style={{ color }}
          >
            {band}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function Sparkline({
  values,
  color,
  width = 120,
  height = 32,
}: {
  values: number[];
  color?: string;
  width?: number;
  height?: number;
}) {
  const palette = useChartPalette();
  const stroke = color ?? palette.signal;

  if (values.length < 2) {
    return <div className="h-8 w-full rounded-control bg-veltrix-subtle" />;
  }
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const range = max - min || 1;
  const points = values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * width;
      const y = height - ((value - min) / range) * (height - 4) - 2;
      return `${x},${y}`;
    })
    .join(' ');

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="w-full">
      <polyline
        points={points}
        fill="none"
        stroke={stroke}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.9"
      />
    </svg>
  );
}

export function RiskWaterfall({
  factors,
}: {
  factors: {
    baseSeverity: number;
    frequencyMultiplier: number;
    assetCriticalityMultiplier: number;
    threatIntelMultiplier: number;
    attackSequenceBonus: number;
    vulnerabilityMatchTerm: number;
    finalScore: number;
  };
}) {
  const palette = useChartPalette();
  const base = factors.baseSeverity;
  const frequency = base * (factors.frequencyMultiplier - 1);
  const asset = base * factors.frequencyMultiplier * (factors.assetCriticalityMultiplier - 1);
  const threat =
    base *
    factors.frequencyMultiplier *
    factors.assetCriticalityMultiplier *
    (factors.threatIntelMultiplier - 1);
  const rows = [
    { label: 'Base severity', value: base, kind: 'base' as const },
    { label: 'Frequency', value: frequency, kind: 'mul' as const },
    { label: 'Asset criticality', value: asset, kind: 'mul' as const },
    { label: 'Threat intel', value: threat, kind: 'mul' as const },
    { label: 'Vulnerability match', value: factors.vulnerabilityMatchTerm, kind: 'add' as const },
    { label: 'Attack sequence', value: factors.attackSequenceBonus, kind: 'add' as const },
  ];
  const max = Math.max(factors.finalScore, ...rows.map((row) => Math.abs(row.value)), 1);

  return (
    <div className="space-y-2.5">
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[140px_1fr_56px] items-center gap-3">
          <span className="truncate text-[11px] text-veltrix-textMuted">{row.label}</span>
          <div className="h-2 overflow-hidden rounded-[1px] bg-veltrix-subtle">
            <div
              className={
                row.kind === 'base'
                  ? 'h-full rounded-[1px] bg-veltrix-cyan'
                  : row.value >= 0
                    ? 'h-full rounded-[1px] bg-sky-400/70'
                    : 'h-full rounded-[1px] bg-emerald-400/70'
              }
              style={{ width: `${Math.max(2, (Math.abs(row.value) / max) * 100)}%` }}
            />
          </div>
          <span className="text-right font-mono text-[11px] tabular-nums text-slate-200">
            {row.value >= 0 ? '+' : ''}
            {row.value.toFixed(1)}
          </span>
        </div>
      ))}
      <div className="mt-3 flex items-center justify-between rounded-control border border-veltrix-border bg-veltrix-elevated px-3 py-2">
        <span className="text-[10px] font-medium uppercase tracking-[0.12em] text-veltrix-textMeta">
          Final score
        </span>
        <span
          className="font-mono text-lg font-medium tabular-nums"
          style={{ color: bandColor(palette, factors.finalScore) }}
        >
          {factors.finalScore}
        </span>
      </div>
      <p className="text-[10px] leading-relaxed text-veltrix-textMeta">
        score = min(100, base × frequency × asset × threat intel + vulnerability + sequence)
      </p>
    </div>
  );
}

export function ConfidenceFunnel({ data }: { data: BreakdownEntry[] }) {
  const palette = useChartPalette();
  const order = [
    'SUSPICIOUS_ATTEMPT',
    'BLOCKED_ATTEMPT',
    'POTENTIAL_EXPLOITATION',
    'CONFIRMED_EXPLOITATION',
  ];
  const colors = [palette.low, palette.low, palette.high, palette.critical];
  const total = data.reduce((sum, item) => sum + item.count, 0);

  return (
    <div className="space-y-2">
      {order.map((tier, index) => {
        const count = data.find((entry) => entry.key === tier)?.count || 0;
        const percent = total ? (count / total) * 100 : 0;
        return (
          <div key={tier} className="space-y-1">
            <div className="flex items-center justify-between text-[10px]">
              <span className="uppercase tracking-[0.08em] text-veltrix-textMeta">
                {tier.replaceAll('_', ' ')}
              </span>
              <span className="font-mono tabular-nums text-slate-200">{formatCompact(count)}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-[1px] bg-veltrix-subtle">
              <div
                className="h-full rounded-[1px]"
                style={{ width: `${percent}%`, background: colors[index] }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
