import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ScanLine,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Play,
  RefreshCw,
  StopCircle,
  Globe,
  X,
  Lock,
} from 'lucide-react';
import { fetchWebsites } from '../lib/api/endpoints';
import {
  Card,
  Button,
  Badge,
  LoadingPanel,
  EmptyState,
} from '../components/ui/primitives';

export interface ScanJob {
  scanId: string;
  siteId: string;
  targetDomain: string;
  profile: 'PASSIVE_BASELINE' | 'STANDARD_ACTIVE' | 'FULL_AUDIT';
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'ABORTED' | 'FAILED';
  currentStage: 'DISCOVERY' | 'CRAWL' | 'FUZZ_INJECTION' | 'VERIFY_EVIDENCE' | 'REPORT_GENERATION';
  progressPercent: number;
  findingsCount: number;
  startedAt: string;
  durationSeconds?: number;
}

const DEFAULT_DEMO_SCANS: ScanJob[] = [
  {
    scanId: 'scan-act-901',
    siteId: 'site-shop-01',
    targetDomain: 'shop.veltrix.io',
    profile: 'STANDARD_ACTIVE',
    status: 'RUNNING',
    currentStage: 'FUZZ_INJECTION',
    progressPercent: 65,
    findingsCount: 3,
    startedAt: new Date(Date.now() - 1000 * 60 * 4).toISOString(),
  },
  {
    scanId: 'scan-pas-902',
    siteId: 'site-shop-01',
    targetDomain: 'shop.veltrix.io',
    profile: 'PASSIVE_BASELINE',
    status: 'COMPLETED',
    currentStage: 'REPORT_GENERATION',
    progressPercent: 100,
    findingsCount: 1,
    startedAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
    durationSeconds: 142,
  },
];

export function ScansPage() {
  const [activeTab, setActiveTab] = useState<'all' | 'running' | 'completed'>('all');
  const [showLaunchModal, setShowLaunchModal] = useState(false);
  const [scans, setScans] = useState<ScanJob[]>(DEFAULT_DEMO_SCANS);

  // Form state
  const [selectedSiteId, setSelectedSiteId] = useState('');
  const [selectedProfile, setSelectedProfile] = useState<'PASSIVE_BASELINE' | 'STANDARD_ACTIVE' | 'FULL_AUDIT'>('STANDARD_ACTIVE');
  const [rateLimitRps, setRateLimitRps] = useState(10);
  const [launching, setLaunching] = useState(false);

  const { data: websitesRes, isLoading: sitesLoading, refetch: refetchSites } = useQuery({
    queryKey: ['websites'],
    queryFn: () => fetchWebsites(),
  });

  const sites = websitesRes?.sites || [];
  const selectedSite = sites.find((s) => s.siteId === selectedSiteId);
  const isSiteVerified = selectedSite ? selectedSite.status === 'VERIFIED' && !selectedSite.scanBlocked : false;

  const filteredScans = scans.filter((scan) => {
    if (activeTab === 'running') return scan.status === 'RUNNING';
    if (activeTab === 'completed') return scan.status === 'COMPLETED' || scan.status === 'ABORTED';
    return true;
  });

  const runningCount = scans.filter((s) => s.status === 'RUNNING').length;
  const verifiedSitesCount = sites.filter((s) => s.status === 'VERIFIED').length;
  const blockedSitesCount = sites.filter((s) => s.status !== 'VERIFIED' || s.scanBlocked).length;

  const handleAbort = (scanId: string) => {
    setScans((prev) =>
      prev.map((s) =>
        s.scanId === scanId
          ? { ...s, status: 'ABORTED', durationSeconds: 45 }
          : s
      )
    );
  };

  const handleLaunch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSite || !isSiteVerified) return;

    setLaunching(true);
    setTimeout(() => {
      const newScan: ScanJob = {
        scanId: `scan-${Date.now().toString().slice(-4)}`,
        siteId: selectedSite.siteId,
        targetDomain: selectedSite.primaryDomain,
        profile: selectedProfile,
        status: 'RUNNING',
        currentStage: 'DISCOVERY',
        progressPercent: 10,
        findingsCount: 0,
        startedAt: new Date().toISOString(),
      };
      setScans([newScan, ...scans]);
      setLaunching(false);
      setShowLaunchModal(false);
    }, 400);
  };

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
          <Button variant="secondary" size="sm" icon={RefreshCw} onClick={() => refetchSites()}>
            Refresh
          </Button>
          <Button variant="primary" size="sm" icon={Play} onClick={() => setShowLaunchModal(true)}>
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

      {/* KPI Stats Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-3">
          <div className="text-slate-400 text-xs">Total Scan Audits</div>
          <div className="text-xl font-bold font-mono text-white mt-0.5">{scans.length}</div>
        </Card>
        <Card className="p-3">
          <div className="text-cyan-400 text-xs">Active / In-Flight</div>
          <div className="text-xl font-bold font-mono text-cyan-300 mt-0.5">{runningCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-emerald-400 text-xs">Scope-Verified Targets</div>
          <div className="text-xl font-bold font-mono text-emerald-300 mt-0.5">{verifiedSitesCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-rose-400 text-xs">Blocked / Unverified Scope</div>
          <div className="text-xl font-bold font-mono text-rose-300 mt-0.5">{blockedSitesCount}</div>
        </Card>
      </div>

      {/* Target Asset Scope & Verification Gate Section */}
      <Card className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Globe className="h-4 w-4 text-cyan-400" />
            Target Asset Scope & Authorization Gate
          </h2>
          <span className="text-[11px] font-mono text-slate-500">
            Strict SSRF Scope Enforcement Active
          </span>
        </div>
        <p className="text-xs text-slate-400">
          Scans may only target assets in <strong className="text-emerald-300">VERIFIED</strong> status. Any target pending ownership confirmation is strictly blocked from crawler dispatch.
        </p>

        {sitesLoading ? (
          <LoadingPanel rows={3} />
        ) : sites.length === 0 ? (
          <div className="text-xs text-slate-500 italic py-2">No website assets registered in this organization.</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            {sites.map((site) => {
              const eligible = site.status === 'VERIFIED' && !site.scanBlocked;
              return (
                <div
                  key={site.siteId}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white text-xs">{site.name}</span>
                      <span className="font-mono text-[11px] text-cyan-400">{site.primaryDomain}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[10px] text-slate-500 font-mono">{site.environment}</span>
                      <Badge tone={eligible ? 'success' : 'critical'}>
                        {site.status}
                      </Badge>
                    </div>
                  </div>

                  <div>
                    {eligible ? (
                      <button
                        onClick={() => {
                          setSelectedSiteId(site.siteId);
                          setShowLaunchModal(true);
                        }}
                        className="px-2.5 py-1 text-xs rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 font-semibold transition"
                      >
                        Target
                      </button>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[11px] text-rose-400 font-semibold" title="Domain verification required">
                        <Lock className="h-3 w-3" /> Blocked
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Scans Queue & Execution Progress */}
      <div className="space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div className="flex items-center gap-2">
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
          <span className="text-xs text-slate-500 font-mono">
            Emergency Abort SLO: &lt;500ms
          </span>
        </div>

        {filteredScans.length === 0 ? (
          <Card className="p-8">
            <EmptyState
              icon={ShieldCheck}
              title="No Scans in Selected View"
              description="Initiate an authorized vulnerability assessment against a verified target website or run `veltrix scan start --target <URL>` from the CLI."
              action={
                <Button variant="primary" size="sm" icon={Play} onClick={() => setShowLaunchModal(true)}>
                  Start Authorized Scan
                </Button>
              }
            />
          </Card>
        ) : (
          <div className="space-y-3">
            {filteredScans.map((scan) => (
              <Card key={scan.scanId} className="p-4 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="flex flex-col items-center justify-center h-10 w-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 font-mono font-bold text-cyan-400">
                      <ScanLine className="h-5 w-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 font-mono text-xs">
                        <span className="font-bold text-white">{scan.scanId}</span>
                        <Badge tone={scan.status === 'RUNNING' ? 'info' : scan.status === 'COMPLETED' ? 'success' : 'critical'}>
                          {scan.status}
                        </Badge>
                        <span className="text-slate-400">Profile: {scan.profile}</span>
                      </div>
                      <div className="text-sm font-semibold text-slate-200 mt-0.5">
                        Target: <span className="font-mono text-cyan-300">{scan.targetDomain}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {scan.status === 'RUNNING' && (
                      <Button
                        variant="danger"
                        size="sm"
                        icon={StopCircle}
                        onClick={() => handleAbort(scan.scanId)}
                      >
                        Abort (500ms SLO)
                      </Button>
                    )}
                    <span className="text-xs font-mono text-slate-400">
                      Findings: <strong className="text-amber-400">{scan.findingsCount}</strong>
                    </span>
                  </div>
                </div>

                {/* Scan Pipeline Stepper */}
                <div className="space-y-1.5 pt-1 font-mono text-[11px]">
                  <div className="flex justify-between text-slate-400">
                    <span>Stage: <strong className="text-white">{scan.currentStage}</strong></span>
                    <span>{scan.progressPercent}%</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-950 overflow-hidden border border-slate-800">
                    <div
                      className={`h-full transition-all duration-500 ${
                        scan.status === 'RUNNING' ? 'bg-cyan-400' : scan.status === 'COMPLETED' ? 'bg-emerald-400' : 'bg-rose-500'
                      }`}
                      style={{ width: `${scan.progressPercent}%` }}
                    />
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Launch Scan Modal */}
      {showLaunchModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <Card className="w-full max-w-lg border-slate-700 bg-slate-900 shadow-2xl p-6 space-y-4 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Play className="h-4 w-4 text-cyan-400" />
                Launch Authorized Vulnerability Scan
              </h2>
              <button
                onClick={() => setShowLaunchModal(false)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleLaunch} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Select Target Asset</label>
                <select
                  value={selectedSiteId}
                  onChange={(e) => setSelectedSiteId(e.target.value)}
                  className="w-full rounded bg-slate-950 border border-slate-800 px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
                  required
                >
                  <option value="">-- Choose verified asset --</option>
                  {sites.map((site) => (
                    <option key={site.siteId} value={site.siteId}>
                      {site.primaryDomain} ({site.name}) — {site.status}
                    </option>
                  ))}
                </select>
              </div>

              {selectedSite && !isSiteVerified && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-start gap-2">
                  <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5 text-rose-400" />
                  <div className="text-[11px] leading-relaxed">
                    <strong>SSRF Scope Violation Prevented:</strong> Target <code className="font-mono">{selectedSite.primaryDomain}</code> is in <strong className="uppercase">{selectedSite.status}</strong> status. Only VERIFIED domain assets are authorized for scanning.
                  </div>
                </div>
              )}

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Scan Profile</label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  {[
                    { id: 'PASSIVE_BASELINE', name: 'Passive', desc: 'Headers & TLS audit' },
                    { id: 'STANDARD_ACTIVE', name: 'Standard Active', desc: 'OWASP crawler & injection' },
                    { id: 'FULL_AUDIT', name: 'Full Audit', desc: 'Deep fuzzing & API probe' },
                  ].map((p) => (
                    <button
                      type="button"
                      key={p.id}
                      onClick={() => setSelectedProfile(p.id as any)}
                      className={`p-2.5 rounded-lg border text-left transition ${
                        selectedProfile === p.id
                          ? 'bg-cyan-500/15 border-cyan-500 text-cyan-200'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="font-bold text-white text-xs">{p.name}</div>
                      <div className="text-[10px] text-slate-400 mt-0.5">{p.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="text-slate-400 font-semibold">Max Crawler Rate Limit</label>
                  <span className="font-mono text-cyan-400">{rateLimitRps} RPS</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="50"
                  value={rateLimitRps}
                  onChange={(e) => setRateLimitRps(Number(e.target.value))}
                  className="w-full accent-cyan-400 cursor-pointer"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <Button variant="ghost" size="sm" type="button" onClick={() => setShowLaunchModal(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  type="submit"
                  disabled={!selectedSiteId || !isSiteVerified || launching}
                >
                  {launching ? 'Initializing...' : 'Start Authorized Scan'}
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}
    </div>
  );
}
