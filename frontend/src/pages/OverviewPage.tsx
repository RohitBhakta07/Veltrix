import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Crosshair,
  DatabaseZap,
  Globe2,
  Radar,
  RefreshCw,
  Siren,
  Timer,
} from 'lucide-react';
import { fetchDashboardSummary, seedDemoData } from '../lib/api/endpoints';
import { MitreBars, SeverityDonut, VelocityChart } from '../components/charts';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  KpiTile,
  LoadingPanel,
  PageHeader,
  ProgressBar,
  RiskBadge,
  SectionHeader,
  SeverityBadge,
  StatusBadge,
  Tabs,
} from '../components/ui/primitives';
import { formatCompact, formatNumber, riskTone, scoreColor, timeAgo, titleCase } from '../lib/format';
import { useAuth } from '../features/auth/AuthProvider';

const RANGES = [
  { id: '1', label: '1h' },
  { id: '24', label: '24h' },
  { id: '168', label: '7d' },
  { id: '720', label: '30d' },
];

export function OverviewPage() {
  const [range, setRange] = useState('24');
  const queryClient = useQueryClient();
  const { can } = useAuth();

  const summary = useQuery({
    queryKey: ['dashboard', 'summary', Number(range)],
    queryFn: () => fetchDashboardSummary(Number(range)),
    refetchInterval: 30_000,
  });

  const seed = useMutation({
    mutationFn: seedDemoData,
    onSuccess: () => queryClient.invalidateQueries(),
  });

  const data = summary.data?.data;
  const kpis = data?.kpis;

  const assets = useMemo(
    () => [...(data?.assets || [])].sort((a, b) => b.riskScore - a.riskScore),
    [data?.assets]
  );

  const incidentBreakdown = data?.incidentSeverity || [];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Command"
        title="Security posture overview"
        description="Tenant-wide telemetry, detection and response posture for authorized website assets."
        actions={
          <>
            <Tabs tabs={RANGES} value={range} onChange={setRange} />
            <Button
              variant="secondary"
              size="sm"
              icon={RefreshCw}
              onClick={() => summary.refetch()}
              disabled={summary.isFetching}
            >
              {summary.isFetching ? 'Refreshing…' : 'Refresh'}
            </Button>
            {can(['ORG_ADMIN', 'SUPER_ADMIN']) ? (
              <Button
                variant="primary"
                size="sm"
                icon={DatabaseZap}
                disabled={seed.isPending}
                onClick={() => seed.mutate()}
              >
                {seed.isPending ? 'Seeding…' : 'Load demo data'}
              </Button>
            ) : null}
          </>
        }
      />

      {seed.data ? (
        <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/[0.07] px-4 py-2.5 text-[11px] text-emerald-200">
          {seed.data.data.alreadySeeded
            ? `Demo dataset already present — ${seed.data.data.sites} assets, ${seed.data.data.incidents} incidents.`
            : `Seeded ${seed.data.data.sites} assets, ${seed.data.data.events ?? 0} events and ${seed.data.data.incidents} incidents through the live detection pipeline.`}
        </div>
      ) : null}

      {seed.error ? (
        <div className="rounded-xl border border-rose-500/25 bg-rose-500/[0.07] px-4 py-2.5 text-[11px] text-rose-200">
          {seed.error instanceof Error ? seed.error.message : 'Demo seeding failed.'}
        </div>
      ) : null}

      {summary.isError ? (
        <Card>
          <ErrorState
            message={
              summary.error instanceof Error
                ? summary.error.message
                : 'The dashboard read model could not be loaded.'
            }
            onRetry={() => summary.refetch()}
          />
        </Card>
      ) : null}

      {summary.isLoading ? (
        <Card>
          <LoadingPanel rows={6} />
        </Card>
      ) : null}

      {data && kpis ? (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
            <KpiTile
              label="Events in window"
              value={formatCompact(kpis.eventsInWindow)}
              hint={`last ${data.rangeHours}h · all sources`}
              icon={Activity}
              tone="info"
            />
            <KpiTile
              label="Attack events"
              value={formatCompact(kpis.attacksInWindow)}
              hint="web.attack.* + credential stuffing"
              icon={Crosshair}
              tone="high"
            />
            <KpiTile
              label="Detections"
              value={formatCompact(kpis.detectionsInWindow)}
              hint="rule matches with evidence"
              icon={Radar}
              tone="medium"
            />
            <KpiTile
              label="Open incidents"
              value={formatNumber(kpis.openIncidents)}
              hint={`${kpis.criticalIncidents} critical unresolved`}
              icon={Siren}
              tone={kpis.criticalIncidents > 0 ? 'critical' : 'low'}
            />
            <KpiTile
              label="Verified assets"
              value={`${kpis.verifiedAssets}/${kpis.totalAssets}`}
              hint={`${kpis.assetsWithTelemetry} reporting telemetry`}
              icon={Globe2}
              tone={kpis.verifiedAssets === kpis.totalAssets ? 'success' : 'medium'}
            />
            <KpiTile
              label="Mean asset risk"
              value={kpis.avgRiskScore}
              hint="0-100 weighted exposure score"
              icon={AlertTriangle}
              tone={kpis.avgRiskScore >= 50 ? 'critical' : 'low'}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <div className="xl:col-span-2">
              <VelocityChart data={data.velocity} />
            </div>
            <SeverityDonut data={data.severity} />
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <MitreBars data={data.mitre} />
            <Card className="p-5">
              <SectionHeader
                title="Risk distribution"
                description="Assets bucketed by composite exposure score"
              />
              <div className="mt-4 space-y-3">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((band) => {
                  const count = data.riskBands.find((entry) => entry.key === band)?.count || 0;
                  const total = data.riskBands.reduce((sum, entry) => sum + entry.count, 0) || 1;
                  return (
                    <div key={band} className="space-y-1.5">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="flex items-center gap-1.5 text-slate-400">
                          <span
                            className="h-1.5 w-1.5 rounded-full"
                            style={{ background: scoreColor(band === 'CRITICAL' ? 90 : band === 'HIGH' ? 60 : band === 'MEDIUM' ? 35 : 10) }}
                          />
                          {titleCase(band)}
                        </span>
                        <span className="font-mono text-slate-300">{formatNumber(count)}</span>
                      </div>
                      <ProgressBar
                        value={(count / total) * 100}
                        tone={riskTone(band)}
                      />
                    </div>
                  );
                })}
              </div>
              <div className="mt-5 rounded-lg border border-veltrix-border/70 bg-veltrix-chrome/50 p-3">
                <div className="vx-label">Incident severity mix</div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {incidentBreakdown.length === 0 ? (
                    <span className="text-[11px] text-slate-500">No incidents recorded.</span>
                  ) : (
                    incidentBreakdown.map((entry) => (
                      <span key={entry.key} className="flex items-center gap-1.5">
                        <SeverityBadge severity={entry.key} />
                        <span className="font-mono text-[11px] text-slate-400">
                          {formatNumber(entry.count)}
                        </span>
                      </span>
                    ))
                  )}
                </div>
              </div>
            </Card>
            <Card className="p-5">
              <SectionHeader
                title="Top hostile sources"
                description="Ranked by event volume in window"
              />
              <div className="mt-3 divide-y divide-veltrix-border/50">
                {(data.topSources || []).length === 0 ? (
                  <p className="py-6 text-center text-[11px] text-slate-500">
                    No hostile sources observed.
                  </p>
                ) : (
                  data.topSources.slice(0, 6).map((source, index) => (
                    <div key={source.ip} className="flex items-center gap-3 py-2">
                      <span className="font-mono text-[10px] text-slate-600">
                        {String(index + 1).padStart(2, '0')}
                      </span>
                      <Link
                        to={`/events?sourceIp=${encodeURIComponent(source.ip)}`}
                        className="min-w-0 flex-1 truncate font-mono text-[11px] text-slate-200 hover:text-cyan-300"
                      >
                        {source.ip}
                      </Link>
                      <Badge tone="neutral">{formatCompact(source.count)} evt</Badge>
                      <span
                        className="w-8 text-right font-mono text-[11px] font-semibold"
                        style={{ color: scoreColor(source.riskScore) }}
                      >
                        {source.riskScore}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </div>

          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-veltrix-border/70 px-5 py-4">
              <SectionHeader
                title="Asset exposure"
                description="Verified websites ranked by composite risk"
              />
              <Link
                to="/websites"
                className="flex items-center gap-1 text-[11px] font-semibold text-cyan-300 hover:text-cyan-200"
              >
                Manage assets <ArrowUpRight className="h-3 w-3" />
              </Link>
            </div>
            {assets.length === 0 ? (
              <EmptyState
                icon={Globe2}
                title="No authorized assets yet"
                description="Register a website and verify domain ownership to begin ingesting telemetry."
                action={
                  <Button variant="primary" size="sm" onClick={() => (window.location.href = '/websites')}>
                    Register website
                  </Button>
                }
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="vx-table">
                  <thead>
                    <tr>
                      <th>Asset</th>
                      <th>Environment</th>
                      <th>Status</th>
                      <th>Telemetry</th>
                      <th className="w-40">Risk</th>
                      <th>Open</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {assets.slice(0, 8).map((asset) => (
                      <tr key={asset.siteId}>
                        <td>
                          <div className="font-medium text-slate-100">{asset.name}</div>
                          <div className="font-mono text-[10px] text-slate-500">{asset.domain}</div>
                        </td>
                        <td>
                          <Badge tone="neutral">{titleCase(asset.environment)}</Badge>
                        </td>
                        <td>
                          <StatusBadge status={asset.status} />
                        </td>
                        <td>
                          <span className="flex items-center gap-1.5 text-[11px] text-slate-400">
                            <span
                              className={`h-1.5 w-1.5 rounded-full ${
                                asset.telemetryStatus === 'HEALTHY'
                                  ? 'bg-emerald-400'
                                  : asset.telemetryStatus === 'DEGRADED'
                                    ? 'bg-amber-400'
                                    : 'bg-slate-600'
                              }`}
                            />
                            {titleCase(asset.telemetryStatus)}
                          </span>
                          <span className="text-[10px] text-slate-600">
                            {asset.lastEventReceivedAt ? timeAgo(asset.lastEventReceivedAt) : 'no events'}
                          </span>
                        </td>
                        <td>
                          <div className="flex items-center gap-2">
                            <ProgressBar value={asset.riskScore} tone={riskTone(asset.riskBand)} />
                            <RiskBadge band={asset.riskBand} score={asset.riskScore} />
                          </div>
                        </td>
                        <td className="font-mono text-[11px]">{asset.openIncidents}</td>
                        <td className="text-right">
                          <Link
                            to={`/websites/${asset.siteId}`}
                            className="text-[11px] font-semibold text-cyan-300 hover:text-cyan-200"
                          >
                            Open
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Card>
              <div className="flex items-center justify-between border-b border-veltrix-border/70 px-5 py-4">
                <SectionHeader title="Latest detections" description="Highest-signal rule matches" />
                <Link
                  to="/detections"
                  className="text-[11px] font-semibold text-cyan-300 hover:text-cyan-200"
                >
                  All detections
                </Link>
              </div>
              <div className="divide-y divide-veltrix-border/50">
                {(data.latestDetections || []).length === 0 ? (
                  <p className="px-5 py-10 text-center text-[11px] text-slate-500">
                    No detections in this window.
                  </p>
                ) : (
                  data.latestDetections.slice(0, 5).map((detection) => (
                    <Link
                      key={detection.detectionId}
                      to={`/detections?focus=${detection.detectionId}`}
                      className="flex items-start gap-3 px-5 py-3 transition hover:bg-white/[0.025]"
                    >
                      <SeverityBadge severity={detection.severity} />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[12px] font-medium text-slate-100">
                          {detection.title}
                        </div>
                        <div className="mt-0.5 flex items-center gap-2 text-[10px] text-slate-500">
                          <span className="font-mono">{detection.ruleId}</span>
                          <span className="h-2 w-px bg-slate-700" />
                          <span>{timeAgo(detection.detectedAt)}</span>
                          <span className="h-2 w-px bg-slate-700" />
                          <span>confidence {detection.confidence}</span>
                        </div>
                      </div>
                      <Timer className="mt-1 h-3 w-3 shrink-0 text-slate-600" />
                    </Link>
                  ))
                )}
              </div>
            </Card>

            <Card>
              <div className="flex items-center justify-between border-b border-veltrix-border/70 px-5 py-4">
                <SectionHeader title="Recent incidents" description="Correlated multi-stage activity" />
                <Link
                  to="/incidents"
                  className="text-[11px] font-semibold text-cyan-300 hover:text-cyan-200"
                >
                  Triage queue
                </Link>
              </div>
              <div className="divide-y divide-veltrix-border/50">
                {(data.recentIncidents || []).length === 0 ? (
                  <p className="px-5 py-10 text-center text-[11px] text-slate-500">
                    No correlated incidents yet.
                  </p>
                ) : (
                  data.recentIncidents.slice(0, 5).map((incident) => (
                    <Link
                      key={incident.incidentId}
                      to={`/incidents?focus=${incident.incidentId}`}
                      className="flex items-start gap-3 px-5 py-3 transition hover:bg-white/[0.025]"
                    >
                      <SeverityBadge severity={incident.severity} />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[12px] font-medium text-slate-100">
                          {incident.title}
                        </div>
                        <div className="mt-0.5 flex items-center gap-2 text-[10px] text-slate-500">
                          <StatusBadge status={incident.status} />
                          <span>{timeAgo(incident.createdAt)}</span>
                          <span className="h-2 w-px bg-slate-700" />
                          <span>risk {incident.riskScore}</span>
                        </div>
                      </div>
                    </Link>
                  ))
                )}
              </div>
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
}
