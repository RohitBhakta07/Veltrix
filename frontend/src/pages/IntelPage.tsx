import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Crosshair,
  Search,
  RefreshCw,
  Plus,
  ShieldAlert,
  ExternalLink,
  Copy,
  Check,
  X,
  Clock,
  Radio,
  FileSearch,
} from 'lucide-react';
import type { ThreatIndicator, Severity } from '@veltrix/shared';
import { fetchIndicators, createIndicator } from '../lib/api/endpoints';
import {
  Card,
  SeverityBadge,
  ConfidenceBadge,
  Badge,
  LoadingPanel,
  Button,
  EmptyState,
} from '../components/ui/primitives';

const TYPE_FILTERS = ['ALL', 'IP', 'DOMAIN', 'USER_AGENT', 'HASH'] as const;
const PROVENANCE_FILTERS = ['ALL', 'VERIFIED_FEED', 'MANUAL_ANALYST'] as const;

export function IntelPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [provenanceFilter, setProvenanceFilter] = useState<string>('ALL');
  const [selectedIndicator, setSelectedIndicator] = useState<ThreatIndicator | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [copied, setCopied] = useState(false);

  // New indicator form state
  const [newType, setNewType] = useState<'IP' | 'DOMAIN' | 'HASH' | 'USER_AGENT'>('IP');
  const [newValue, setNewValue] = useState('');
  const [newThreatType, setNewThreatType] = useState('');
  const [newSeverity, setNewSeverity] = useState<Severity>('HIGH');
  const [newConfidence, setNewConfidence] = useState(85);
  const [newSource, setNewSource] = useState('Manual Analyst');
  const [submitting, setSubmitting] = useState(false);

  const { data: indicatorsRes, isLoading, refetch } = useQuery({
    queryKey: ['threat-intel', typeFilter, provenanceFilter],
    queryFn: () => fetchIndicators(100),
  });

  const indicators: ThreatIndicator[] = indicatorsRes?.data?.indicators || [];

  const filtered = indicators.filter((ind: ThreatIndicator) => {
    if (typeFilter !== 'ALL' && ind.type !== typeFilter) return false;
    if (provenanceFilter !== 'ALL' && ind.provenance !== provenanceFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchVal = ind.value.toLowerCase().includes(q);
      const matchThreat = ind.threatType?.toLowerCase().includes(q) ?? false;
      const matchSource = ind.source?.toLowerCase().includes(q) ?? false;
      const matchSubmit = ind.submittedBy?.toLowerCase().includes(q) ?? false;
      if (!matchVal && !matchThreat && !matchSource && !matchSubmit) return false;
    }
    return true;
  });

  // KPI Calculations
  const totalCount = indicators.length;
  const ipCount = indicators.filter((i) => i.type === 'IP').length;
  const feedCount = indicators.filter((i) => i.provenance === 'VERIFIED_FEED').length;
  const highConfidenceCount = indicators.filter((i) => i.confidence >= 80).length;

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newValue.trim() || !newThreatType.trim()) return;

    try {
      setSubmitting(true);
      await createIndicator({
        type: newType,
        value: newValue.trim(),
        threatType: newThreatType.trim(),
        severity: newSeverity,
        confidence: newConfidence,
        description: newSource.trim(),
      });
      setShowAddModal(false);
      setNewValue('');
      setNewThreatType('');
      refetch();
    } catch (err: any) {
      alert(`Failed to add indicator: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-white">
            <Crosshair className="h-5 w-5 text-rose-400" />
            Threat Intelligence & IOC Dossiers
          </h1>
          <p className="text-xs text-slate-400">
            Known malicious IP addresses, scanner signatures, and reputation feeds
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" icon={RefreshCw} onClick={() => refetch()}>
            Sync Feeds
          </Button>
          <Button variant="primary" size="sm" icon={Plus} onClick={() => setShowAddModal(true)}>
            Add Indicator
          </Button>
        </div>
      </div>

      {/* KPI Stats Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-3">
          <div className="text-slate-400 text-xs">Total Indicators</div>
          <div className="text-xl font-bold font-mono text-white mt-0.5">{totalCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-rose-400 text-xs">Malicious IPs</div>
          <div className="text-xl font-bold font-mono text-rose-300 mt-0.5">{ipCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-cyan-400 text-xs">Verified Feeds</div>
          <div className="text-xl font-bold font-mono text-cyan-300 mt-0.5">{feedCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-emerald-400 text-xs">High Confidence (≥80)</div>
          <div className="text-xl font-bold font-mono text-emerald-300 mt-0.5">{highConfidenceCount}</div>
        </Card>
      </div>

      {/* Filters and Search Toolbar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Type:</span>
          {TYPE_FILTERS.map((type) => (
            <button
              key={type}
              onClick={() => setTypeFilter(type)}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold border transition ${
                typeFilter === type
                  ? 'bg-cyan-500/10 border-cyan-500 text-cyan-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
              }`}
            >
              {type}
            </button>
          ))}

          <span className="ml-2 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Provenance:</span>
          {PROVENANCE_FILTERS.map((prov) => (
            <button
              key={prov}
              onClick={() => setProvenanceFilter(prov)}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold border transition ${
                provenanceFilter === prov
                  ? 'bg-cyan-500/10 border-cyan-500 text-cyan-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
              }`}
            >
              {prov === 'ALL' ? 'ALL' : prov === 'VERIFIED_FEED' ? 'VERIFIED_FEED' : 'MANUAL_ANALYST'}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search indicator, source, threat type..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full sm:w-72 rounded-lg border border-slate-800 bg-slate-900/60 pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Content Table */}
      {isLoading ? (
        <LoadingPanel rows={6} />
      ) : filtered.length === 0 ? (
        <Card className="p-8">
          <EmptyState
            icon={Crosshair}
            title="No Threat Indicators Found"
            description="No indicators match the search or filter criteria. Sync feeds or add manual IOCs."
          />
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 bg-slate-900/50 text-[10px] uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Indicator Value</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Provenance</th>
                  <th className="px-4 py-3">Source / Feed</th>
                  <th className="px-4 py-3">Threat Type</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {filtered.map((ind: ThreatIndicator) => (
                  <tr
                    key={ind.indicatorId}
                    className="hover:bg-slate-800/30 transition cursor-pointer"
                    onClick={() => setSelectedIndicator(ind)}
                  >
                    <td className="px-4 py-3">
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-bold text-cyan-400">
                        {ind.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold text-white">
                      <div className="flex items-center gap-1.5">
                        <span>{ind.value}</span>
                        {ind.isFlagged && (
                          <span className="h-1.5 w-1.5 rounded-full bg-rose-500" title="Actively Flagged" />
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-sans">
                      <SeverityBadge severity={ind.severity || 'HIGH'} />
                    </td>
                    <td className="px-4 py-3 font-sans">
                      <ConfidenceBadge confidence={ind.confidence ?? 80} />
                    </td>
                    <td className="px-4 py-3 font-sans">
                      <Badge
                        tone={ind.provenance === 'VERIFIED_FEED' ? 'info' : 'medium'}
                      >
                        {ind.provenance}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 font-sans text-slate-300">
                      {ind.source || 'External Feed'}
                    </td>
                    <td className="px-4 py-3 font-sans text-slate-400 truncate max-w-xs">
                      {ind.threatType || 'Malicious Actor Signature'}
                    </td>
                    <td className="px-4 py-3 text-right font-sans">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedIndicator(ind);
                        }}
                        className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
                      >
                        Inspect Dossier →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* IP Dossier Drawer / Modal */}
      {selectedIndicator && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <Card className="w-full max-w-2xl border-slate-700 bg-slate-900 shadow-2xl overflow-hidden animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
              <div className="flex items-center gap-2">
                <Crosshair className="h-5 w-5 text-rose-400" />
                <h2 className="text-base font-bold text-white">IOC Threat Dossier</h2>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-mono text-cyan-400">
                  {selectedIndicator.type}
                </span>
              </div>
              <button
                onClick={() => setSelectedIndicator(null)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Value and Copy Bar */}
              <div className="flex items-center justify-between rounded-lg bg-slate-950 p-3.5 border border-slate-800">
                <div>
                  <div className="text-[10px] uppercase font-semibold text-slate-500">Indicator Target</div>
                  <div className="text-base font-mono font-bold text-white mt-0.5">
                    {selectedIndicator.value}
                  </div>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={copied ? Check : Copy}
                  onClick={() => handleCopy(selectedIndicator.value)}
                >
                  {copied ? 'Copied' : 'Copy IOC'}
                </Button>
              </div>

              {/* Threat Classification & Provenance */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <div className="text-slate-500 text-[10px] uppercase font-semibold">Severity</div>
                  <div className="mt-1">
                    <SeverityBadge severity={selectedIndicator.severity} />
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <div className="text-slate-500 text-[10px] uppercase font-semibold">Confidence Rating</div>
                  <div className="mt-1">
                    <ConfidenceBadge confidence={selectedIndicator.confidence} />
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <div className="text-slate-500 text-[10px] uppercase font-semibold">Provenance</div>
                  <div className="mt-1">
                    <Badge tone={selectedIndicator.provenance === 'VERIFIED_FEED' ? 'info' : 'medium'}>
                      {selectedIndicator.provenance}
                    </Badge>
                  </div>
                </div>
              </div>

              {/* Provenance Details */}
              <div className="space-y-3 rounded-lg bg-slate-950/40 p-4 border border-slate-800">
                <h3 className="text-xs font-bold text-white flex items-center gap-1.5">
                  <Radio className="h-3.5 w-3.5 text-cyan-400" />
                  Provenance & Attribution
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                  <div>
                    <span className="text-slate-500">Source: </span>
                    <span className="text-slate-200">{selectedIndicator.source || 'Global Feed'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Threat Type: </span>
                    <span className="text-slate-200">{selectedIndicator.threatType}</span>
                  </div>
                  {selectedIndicator.submittedBy && (
                    <div>
                      <span className="text-slate-500">Analyst: </span>
                      <span className="text-cyan-400">{selectedIndicator.submittedBy}</span>
                    </div>
                  )}
                  {selectedIndicator.retrievedAt && (
                    <div>
                      <span className="text-slate-500">Feed Sync: </span>
                      <span className="text-slate-300">{new Date(selectedIndicator.retrievedAt).toLocaleString()}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Timestamps */}
              <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                <div className="flex items-center gap-2 p-2.5 rounded bg-slate-950 border border-slate-800">
                  <Clock className="h-4 w-4 text-slate-500" />
                  <div>
                    <div className="text-[10px] text-slate-500">First Observed</div>
                    <div className="text-slate-300">{new Date(selectedIndicator.firstSeen).toLocaleString()}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2 p-2.5 rounded bg-slate-950 border border-slate-800">
                  <Clock className="h-4 w-4 text-slate-500" />
                  <div>
                    <div className="text-[10px] text-slate-500">Last Seen</div>
                    <div className="text-slate-300">{new Date(selectedIndicator.lastSeen).toLocaleString()}</div>
                  </div>
                </div>
              </div>

              {/* Quick SOC Pivots */}
              <div className="border-t border-slate-800 pt-4 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Link
                    to={`/events?sourceIp=${encodeURIComponent(selectedIndicator.value)}`}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 transition"
                  >
                    <FileSearch className="h-3.5 w-3.5" />
                    Query Log Explorer
                  </Link>
                  <Link
                    to="/detections"
                    className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700 transition"
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                    Correlated Detections
                  </Link>
                </div>
                <Button variant="ghost" size="sm" onClick={() => setSelectedIndicator(null)}>
                  Close Dossier
                </Button>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Add Indicator Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <Card className="w-full max-w-md border-slate-700 bg-slate-900 shadow-2xl p-6 space-y-4 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-cyan-400" />
                Add Threat Indicator (IOC)
              </h2>
              <button
                onClick={() => setShowAddModal(false)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleCreate} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Indicator Type</label>
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value as any)}
                  className="w-full rounded bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="IP">IP Address</option>
                  <option value="DOMAIN">Domain Name</option>
                  <option value="USER_AGENT">User Agent</option>
                  <option value="HASH">File Hash</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Indicator Value</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.42 or evil-c2.example.com"
                  value={newValue}
                  onChange={(e) => setNewValue(e.target.value)}
                  className="w-full rounded bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-white font-mono placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Threat Type / Classification</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Web Exploit Scanner or Botnet C2"
                  value={newThreatType}
                  onChange={(e) => setNewThreatType(e.target.value)}
                  className="w-full rounded bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as any)}
                    className="w-full rounded bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Confidence (0-100)</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={newConfidence}
                    onChange={(e) => setNewConfidence(Number(e.target.value))}
                    className="w-full rounded bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-white font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Provenance Source</label>
                <input
                  type="text"
                  value={newSource}
                  onChange={(e) => setNewSource(e.target.value)}
                  className="w-full rounded bg-slate-950 border border-slate-800 px-2.5 py-1.5 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <Button variant="ghost" size="sm" type="button" onClick={() => setShowAddModal(false)}>
                  Cancel
                </Button>
                <Button variant="primary" size="sm" type="submit" disabled={submitting}>
                  {submitting ? 'Adding...' : 'Add Indicator'}
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}
    </div>
  );
}
