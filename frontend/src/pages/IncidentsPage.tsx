import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Siren, ArrowRight, ShieldAlert } from 'lucide-react';
import { fetchIncidents } from '../lib/api/endpoints';
import { Card, Badge, LoadingPanel, SeverityBadge, EmptyState } from '../components/ui/primitives';

export function IncidentsPage() {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const { data: incidentsRes, isLoading } = useQuery({
    queryKey: ['incidents', statusFilter],
    queryFn: () => fetchIncidents({ limit: 100 }),
  });

  const incidents = incidentsRes?.data?.items || [];
  const filtered = statusFilter === 'ALL'
    ? incidents
    : incidents.filter((i) => i.status === statusFilter);

  if (isLoading) return <LoadingPanel rows={6} />;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Siren className="h-5 w-5 text-rose-400" />
            Security Incidents & Kill-Chain Triage
          </h1>
          <p className="text-xs text-slate-400">
            Correlated attack sequences, multi-stage kill chains, and explainable risk scores
          </p>
        </div>

        <div className="flex items-center gap-2">
          {['ALL', 'OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].map((status) => (
            <button
              key={status}
              onClick={() => setStatusFilter(status)}
              className={`px-3 py-1 text-xs font-semibold rounded-lg border transition-colors ${
                statusFilter === status
                  ? 'bg-cyan-500/10 border-cyan-500 text-cyan-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
              }`}
            >
              {status}
            </button>
          ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="No incidents found"
          description="No security incidents match the current filter criteria."
        />
      ) : (
        <div className="space-y-3">
          {filtered.map((inc) => (
            <Card key={inc.incidentId} className="p-4 hover:border-slate-700 transition-colors">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="flex flex-col items-center justify-center h-12 w-12 rounded-lg bg-rose-500/10 border border-rose-500/20 font-bold text-rose-400">
                    <span className="text-xs">RISK</span>
                    <span className="text-sm">{(inc as any).riskScore ?? 75}</span>
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-slate-400">{inc.incidentId}</span>
                      <SeverityBadge severity={inc.severity} />
                      <Badge tone="neutral">{inc.status}</Badge>
                    </div>
                    <h3 className="text-sm font-semibold text-white mt-1">{inc.title}</h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Target: {(inc as any).siteId || (inc as any).primaryDomain || 'Tenant Asset'} • Created {new Date(inc.createdAt).toLocaleString()}
                    </p>
                  </div>
                </div>

                <Link
                  to={`/incidents/${inc.incidentId}`}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 text-xs font-semibold transition-colors"
                >
                  Inspect Triage <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
