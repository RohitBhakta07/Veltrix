import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Siren, ArrowRight, ShieldAlert, Filter, Search } from 'lucide-react';
import { fetchIncidents } from '../lib/api/endpoints';
import { Card, LoadingPanel, SeverityBadge, StatusBadge, EmptyState } from '../components/ui/primitives';

const STATUS_FILTERS = ['ALL', 'NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'] as const;

export function IncidentsPage() {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const { data: incidentsRes, isLoading } = useQuery({
    queryKey: ['incidents', statusFilter],
    queryFn: () => fetchIncidents({ limit: 100 }),
  });

  const incidents = incidentsRes?.data?.items || [];
  
  const filtered = incidents.filter((inc) => {
    if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
    if (severityFilter !== 'ALL' && inc.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = inc.incidentId.toLowerCase().includes(q);
      const matchTitle = inc.title.toLowerCase().includes(q);
      const matchDesc = inc.description?.toLowerCase().includes(q) ?? false;
      if (!matchId && !matchTitle && !matchDesc) return false;
    }
    return true;
  });

  const criticalCount = incidents.filter((i) => i.severity === 'CRITICAL').length;
  const activeCount = incidents.filter((i) => i.status === 'NEW' || i.status === 'INVESTIGATING').length;
  const resolvedCount = incidents.filter((i) => i.status === 'RESOLVED').length;

  if (isLoading) return <LoadingPanel rows={6} />;

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Siren className="h-5 w-5 text-rose-400" />
            Security Incidents & Kill-Chain Triage
          </h1>
          <p className="text-xs text-slate-400">
            Correlated attack sequences, multi-stage kill chains, and explainable risk scores
          </p>
        </div>

        {/* Status quick filters */}
        <div className="flex flex-wrap items-center gap-1.5">
          {STATUS_FILTERS.map((status) => (
            <button
              key={status}
              onClick={() => setStatusFilter(status)}
              className={`px-2.5 py-1 text-xs font-semibold rounded-lg border transition-colors ${
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

      {/* KPI stats banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-3">
          <div className="text-slate-400 text-xs">Total Incidents</div>
          <div className="text-xl font-bold font-mono text-white mt-0.5">{incidents.length}</div>
        </Card>
        <Card className="p-3">
          <div className="text-rose-400 text-xs">Active / In-Flight</div>
          <div className="text-xl font-bold font-mono text-rose-300 mt-0.5">{activeCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-amber-400 text-xs">Critical Severity</div>
          <div className="text-xl font-bold font-mono text-amber-300 mt-0.5">{criticalCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-emerald-400 text-xs">Resolved</div>
          <div className="text-xl font-bold font-mono text-emerald-300 mt-0.5">{resolvedCount}</div>
        </Card>
      </div>

      {/* Filter toolbar */}
      <div className="flex flex-col sm:row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search incident ID, title, description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-500" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="No incidents found"
          description="No security incidents match the current filter and search criteria."
        />
      ) : (
        <div className="space-y-3">
          {filtered.map((inc) => (
            <Card key={inc.incidentId} className="p-4 hover:border-slate-700 transition-colors">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center justify-center h-12 w-12 rounded-lg bg-rose-500/10 border border-rose-500/20 font-bold text-rose-400 shrink-0">
                    <span className="text-[10px] tracking-wider uppercase font-semibold text-rose-400">RISK</span>
                    <span className="text-sm font-mono">{inc.riskScore ?? 75}</span>
                  </div>

                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs font-bold text-slate-400">{inc.incidentId}</span>
                      <SeverityBadge severity={inc.severity} />
                      <StatusBadge status={inc.status} />
                      {inc.assignedTo && (
                        <span className="text-[11px] text-slate-400 font-mono">
                          Assignee: {inc.assignedTo}
                        </span>
                      )}
                    </div>
                    <h3 className="text-sm font-semibold text-white mt-1">{inc.title}</h3>
                    <p className="text-xs text-slate-400 mt-0.5 line-clamp-1">{inc.description}</p>
                    <p className="text-[11px] text-slate-500 mt-1 font-mono">
                      Events: {inc.associatedEventIds?.length || 0} • Created {new Date(inc.createdAt).toLocaleString()}
                    </p>
                  </div>
                </div>

                <Link
                  to={`/incidents/${inc.incidentId}`}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 text-xs font-semibold transition-colors shrink-0 self-start sm:self-center"
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
