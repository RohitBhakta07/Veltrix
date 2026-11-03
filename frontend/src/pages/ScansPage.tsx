import { useState } from 'react';
import { ScanLine, AlertTriangle, ShieldCheck, Play, RefreshCw } from 'lucide-react';
import { Card, Button, EmptyState } from '../components/ui/primitives';

export function ScansPage() {
  const [activeTab, setActiveTab] = useState<'all' | 'running' | 'completed'>('all');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-white">
            <ScanLine className="h-5 w-5 text-cyan-400" />
            Vulnerability Scans & Scope Verification
          </h1>
          <p className="text-xs text-slate-400">
            Authorized automated web security audits, SSRF-safe crawlers, and vulnerability probes
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" icon={RefreshCw}>
            Refresh
          </Button>
          <Button variant="primary" size="sm" icon={Play}>
            Launch Scan
          </Button>
        </div>
      </div>

      {/* Contract Notice Banner */}
      <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-amber-200">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
        <div className="text-xs">
          <span className="font-semibold text-amber-300">Awaiting Phase 8 Backend Scan Engine:</span>{' '}
          The CLI supports local scan commands (`veltrix scan start`), which validate domain ownership before initiating requests. The backend orchestration worker endpoint (`/api/v1/scans`) will populate this table upon deployment.
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        {(['all', 'running', 'completed'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`rounded-lg px-3 py-1.5 text-xs font-semibold capitalize transition ${
              activeTab === tab
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            {tab} Scans
          </button>
        ))}
      </div>

      {/* Content / Empty state */}
      <Card className="p-8">
        <EmptyState
          icon={ShieldCheck}
          title="No Active Scans Running"
          description="Initiate an authorized vulnerability assessment against a verified target website or run `veltrix scan start --target <URL>` from the CLI."
          action={
            <Button variant="primary" size="sm" icon={Play}>
              Start Authorized Scan
            </Button>
          }
        />
      </Card>
    </div>
  );
}
