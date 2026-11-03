import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Crosshair, Search, RefreshCw } from 'lucide-react';
import type { ThreatIndicator } from '@veltrix/shared';
import { fetchIndicators } from '../lib/api/endpoints';
import { Card, SeverityBadge, LoadingPanel, Button, EmptyState } from '../components/ui/primitives';

export function IntelPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [indicatorType, setIndicatorType] = useState<string>('ALL');

  const { data: indicatorsRes, isLoading, refetch } = useQuery({
    queryKey: ['threat-intel', indicatorType],
    queryFn: () => fetchIndicators(),
  });

  const indicators: ThreatIndicator[] = indicatorsRes?.data?.indicators || [];
  const filtered = indicators.filter((ind: ThreatIndicator) => {
    const matchesSearch = ind.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ind.threatType.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = indicatorType === 'ALL' || ind.type === indicatorType;
    return matchesSearch && matchesType;
  });

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
        </div>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          {['ALL', 'IP', 'DOMAIN', 'USER_AGENT', 'HASH'].map((type) => (
            <button
              key={type}
              onClick={() => setIndicatorType(type)}
              className={`rounded-lg px-3 py-1 text-xs font-semibold border transition ${
                indicatorType === type
                  ? 'bg-cyan-500/10 border-cyan-500 text-cyan-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
              }`}
            >
              {type}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search indicator or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full sm:w-64 rounded-lg border border-slate-800 bg-slate-900/60 pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Content */}
      {isLoading ? (
        <LoadingPanel rows={6} />
      ) : filtered.length === 0 ? (
        <Card className="p-8">
          <EmptyState
            icon={Crosshair}
            title="No Threat Indicators Found"
            description="No indicators match the search criteria or feed has not synced yet."
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
                  <th className="px-4 py-3">Confidence / Severity</th>
                  <th className="px-4 py-3">Description</th>
                  <th className="px-4 py-3 text-right">Added</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {filtered.map((ind: ThreatIndicator) => (
                  <tr key={ind.indicatorId} className="hover:bg-slate-800/30 transition">
                    <td className="px-4 py-3">
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-cyan-400">
                        {ind.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold text-white">{ind.value}</td>
                    <td className="px-4 py-3 font-sans">
                      <SeverityBadge severity={ind.severity || 'HIGH'} />
                    </td>
                    <td className="px-4 py-3 font-sans text-slate-400 truncate max-w-xs">
                      {ind.threatType || 'Known scanner / malicious host'}
                    </td>
                    <td className="px-4 py-3 text-right font-sans text-slate-500">
                      {new Date(ind.firstSeen || Date.now()).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
