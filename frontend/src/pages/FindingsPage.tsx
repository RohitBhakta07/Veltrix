import { useState } from 'react';
import { Bug, Filter, Search, ShieldAlert } from 'lucide-react';
import { Card, Button, EmptyState } from '../components/ui/primitives';

export function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-white">
            <Bug className="h-5 w-5 text-rose-400" />
            Vulnerability Findings & Evidence Ledger
          </h1>
          <p className="text-xs text-slate-400">
            Detected security flaws, CWE/OWASP mappings, and reproducible evidence logs
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" icon={Filter}>
            Export CSV
          </Button>
        </div>
      </div>

      {/* Contract Notice Banner */}
      <div className="flex items-start gap-3 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 text-cyan-200">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-cyan-400" />
        <div className="text-xs">
          <span className="font-semibold text-cyan-300">Phase 8 Vulnerability Catalog Ready:</span>{' '}
          Findings generated during deep scans and correlation engine triage will be aggregated here with CVE ratings and reproduction steps.
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`rounded-lg px-3 py-1 text-xs font-semibold border transition ${
                severityFilter === sev
                  ? 'bg-cyan-500/10 border-cyan-500 text-cyan-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search CVE, endpoint, title..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full sm:w-64 rounded-lg border border-slate-800 bg-slate-900/60 pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Empty State / Findings Table */}
      <Card className="p-8">
        <EmptyState
          icon={Bug}
          title="No Security Findings Recorded"
          description="Verified findings from active vulnerability scans and correlation detections will appear here."
        />
      </Card>
    </div>
  );
}
