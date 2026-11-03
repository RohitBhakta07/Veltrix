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
import { formatCompact, formatNumber, scoreColor } from '../../lib/format';
import { Card, SectionHeader } from '../ui/primitives';

const AXIS = '#64748b';
const GRID = 'rgba(30,43,69,0.65)';

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
    <div className="rounded-lg border border-veltrix-border bg-veltrix-card/95 px-3 py-2 shadow-card backdrop-blur">
      {label ? <div className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">{label}</div> : null}
      {payload.map((entry, index) => (
        <div key={index} className="flex items-center gap-2 text-xs text-slate-200">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: entry.color }} />
          <span className="capitalize text-slate-400">{entry.name}</span>
          <span className="ml-auto font-mono font-semibold">{formatNumber(entry.value)}</span>
        </div>
      ))}
    </div>
  );
}

export function VelocityChart({ data }: { data: VelocityPoint[] }) {
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
          <div className="flex items-center gap-3 text-[10px] uppercase tracking-wider text-slate-500">
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> Events
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-rose-400" /> Attacks
            </span>
          </div>
        }
      />
      <div className="mt-4 h-[240px] w-full">
        {formatted.length === 0 ? (
          <div className="flex h-full items-center justify-center text-xs text-slate-500">
            No telemetry in this window
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={formatted} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="eventsFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00F2FE" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#00F2FE" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="attacksFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#FF4D6D" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#FF4D6D" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="label"
                stroke={AXIS}
                tick={{ fontSize: 10, fill: AXIS }}
                tickLine={false}
                axisLine={false}
                minTickGap={24}
              />
              <YAxis
                stroke={AXIS}
                tick={{ fontSize: 10, fill: AXIS }}
                tickLine={false}
                axisLine={false}
                width={52}
              />
              <Tooltip content={<ChartTooltip />} />
              <Area
                type="monotone"
                dataKey="events"
                stroke="#00F2FE"
                strokeWidth={2}
                fill="url(#eventsFill)"
                name="Events"
              />
              <Area
                type="monotone"
                dataKey="attacks"
                stroke="#FF4D6D"
                strokeWidth={2}
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
  const colors: Record<string, string> = {
    CRITICAL: '#FF4D6D',
    HIGH: '#FF8A3D',
    MEDIUM: '#FFC857',
    LOW: '#38BDF8',
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
          <div className="flex h-full items-center justify-center text-xs text-slate-500">
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
              <span className="text-2xl font-bold tabular-nums text-white">{formatNumber(total)}</span>
              <span className="text-[10px] uppercase tracking-widest text-slate-500">Detections</span>
            </div>
          </>
        )}
      </div>
      <div className="mt-2 grid grid-cols-2 gap-2">
        {ordered.map((entry) => (
          <div key={entry.key} className="flex items-center gap-2 text-[11px] text-slate-400">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ background: colors[entry.key] }}
            />
            <span className="flex-1">{entry.key}</span>
            <span className="font-mono text-slate-300">{formatNumber(entry.count)}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}

export function MitreBars({ data }: { data: BreakdownEntry[] }) {
  return (
    <Card className="p-5">
      <SectionHeader
        title="MITRE ATT&CK coverage"
        description="Detections mapped to adversary tactics"
      />
      <div className="mt-4 h-[240px]">
        {data.length === 0 ? (
          <div className="flex h-full items-center justify-center text-xs text-slate-500">
            No mapped techniques in this window
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 0, bottom: 0 }}>
              <CartesianGrid stroke={GRID} strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="key"
                width={118}
                tick={{ fontSize: 10, fill: '#94a3b8' }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="count" name="Detections" radius={[0, 4, 4, 0]} barSize={12}>
                {data.map((entry, index) => (
                  <Cell
                    key={entry.key}
                    fill={index === 0 ? '#00F2FE' : `rgba(0,242,254,${Math.max(0.22, 0.72 - index * 0.09)})`}
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
  const clamped = Math.max(0, Math.min(100, score));
  const radius = size / 2 - 14;
  const circumference = Math.PI * radius;
  const offset = circumference * (1 - clamped / 100);
  const color = scoreColor(clamped);
  const height = size / 2 + 28;

  return (
    <div className="flex flex-col items-center" style={{ width: size }}>
      <svg width={size} height={height} viewBox={`0 0 ${size} ${height}`} role="img" aria-label={`${label}: ${clamped} out of 100`}>
        <path
          d={`M 14 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 14} ${size / 2}`}
          fill="none"
          stroke="rgba(255,255,255,0.07)"
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
          style={{ filter: `drop-shadow(0 0 8px ${color}55)`, transition: 'stroke-dashoffset 700ms ease' }}
        />
      </svg>
      <div className="-mt-10 text-center">
        <div className="text-3xl font-bold tabular-nums text-white" style={{ color }}>
          {clamped}
        </div>
        <div className="text-[10px] uppercase tracking-widest text-slate-500">{label}</div>
        {band ? (
          <div className="mt-1 text-[10px] font-semibold uppercase tracking-wider" style={{ color }}>
            {band}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function Sparkline({
  values,
  color = '#00F2FE',
  width = 120,
  height = 32,
}: {
  values: number[];
  color?: string;
  width?: number;
  height?: number;
}) {
  if (values.length < 2) {
    return <div className="h-8 w-full rounded bg-white/[0.03]" />;
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
        stroke={color}
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
  const max = Math.max(
    factors.finalScore,
    ...rows.map((row) => Math.abs(row.value)),
    1
  );

  return (
    <div className="space-y-2.5">
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[140px_1fr_56px] items-center gap-3">
          <span className="truncate text-[11px] text-slate-400">{row.label}</span>
          <div className="h-2 overflow-hidden rounded-full bg-white/5">
            <div
              className={
                row.kind === 'base'
                  ? 'h-full rounded-full bg-cyan-400'
                  : row.value >= 0
                    ? 'h-full rounded-full bg-sky-400/70'
                    : 'h-full rounded-full bg-emerald-400/70'
              }
              style={{ width: `${Math.max(2, (Math.abs(row.value) / max) * 100)}%` }}
            />
          </div>
          <span className="text-right font-mono text-[11px] text-slate-300">
            {row.value >= 0 ? '+' : ''}
            {row.value.toFixed(1)}
          </span>
        </div>
      ))}
      <div className="mt-3 flex items-center justify-between rounded-lg border border-cyan-500/25 bg-cyan-500/5 px-3 py-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-cyan-300">
          Final score
        </span>
        <span className="text-lg font-bold tabular-nums" style={{ color: scoreColor(factors.finalScore) }}>
          {factors.finalScore}
        </span>
      </div>
      <p className="text-[10px] leading-relaxed text-slate-500">
        score = min(100, base × frequency × asset × threat intel + vulnerability + sequence)
      </p>
    </div>
  );
}

export function ConfidenceFunnel({ data }: { data: BreakdownEntry[] }) {
  const order = [
    'SUSPICIOUS_ATTEMPT',
    'BLOCKED_ATTEMPT',
    'POTENTIAL_EXPLOITATION',
    'CONFIRMED_EXPLOITATION',
  ];
  const colors = ['#38BDF8', '#7DD3FC', '#FF8A3D', '#FF4D6D'];
  const total = data.reduce((sum, item) => sum + item.count, 0);
  return (
    <div className="space-y-2">
      {order.map((tier, index) => {
        const count = data.find((entry) => entry.key === tier)?.count || 0;
        const percent = total ? (count / total) * 100 : 0;
        return (
          <div key={tier} className="space-y-1">
            <div className="flex items-center justify-between text-[10px]">
              <span className="uppercase tracking-wider text-slate-500">{tier.replaceAll('_', ' ')}</span>
              <span className="font-mono text-slate-300">{formatCompact(count)}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-white/5">
              <div
                className="h-full rounded-full"
                style={{ width: `${percent}%`, background: colors[index] }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
