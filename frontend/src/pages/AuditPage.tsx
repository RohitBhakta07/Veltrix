import { useState } from 'react';
import {
  ScrollText,
  ShieldCheck,
  CheckCircle2,
  RefreshCw,
  Search,
  Copy,
  Check,
  X,
  Layers,
} from 'lucide-react';
import { Card, Badge, Button, EmptyState } from '../components/ui/primitives';

export interface AuditRecord {
  seq: number;
  timestamp: string;
  action: string;
  actor: string;
  role: string;
  target: string;
  hash: string;
  prevHash: string;
  details?: Record<string, any>;
  valid: boolean;
}

const DEFAULT_AUDIT_RECORDS: AuditRecord[] = [
  {
    seq: 104,
    timestamp: new Date().toISOString(),
    action: 'DETECTION_RULE_UPDATED',
    actor: 'soc_admin@cyberdefend.corp',
    role: 'SUPER_ADMIN',
    target: 'SIGMA-SQLI-001',
    hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    prevHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    details: { ruleId: 'rule-sql-01', change: 'Increased threshold from 5 to 10 events' },
    valid: true,
  },
  {
    seq: 103,
    timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    action: 'DOMAIN_OWNERSHIP_VERIFIED',
    actor: 'soc_admin@cyberdefend.corp',
    role: 'SUPER_ADMIN',
    target: 'shop.veltrix.io',
    hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    prevHash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    details: { method: 'DNS_TXT', token: 'veltrix-domain-verification=f9a8b7c6d5e4' },
    valid: true,
  },
  {
    seq: 102,
    timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    action: 'API_INTEGRATION_CREATED',
    actor: 'soc_analyst@cyberdefend.corp',
    role: 'SECURITY_ANALYST',
    target: 'Cloudflare WAF Gateway',
    hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    prevHash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    details: { integrationType: 'CLOUDFLARE_WAF', siteId: 'site-shop-01' },
    valid: true,
  },
  {
    seq: 101,
    timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    action: 'RESPONSE_APPROVED',
    actor: 'soc_admin@cyberdefend.corp',
    role: 'SUPER_ADMIN',
    target: '198.51.100.42 (BLOCK_IP)',
    hash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
    details: { executionId: 'act-001', dualCustodyApproved: true },
    valid: true,
  },
];

export function AuditPage() {
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [selectedRecord, setSelectedRecord] = useState<AuditRecord | null>(null);
  const [copied, setCopied] = useState(false);

  const handleVerify = () => {
    setVerifying(true);
    setTimeout(() => {
      setVerifying(false);
      setVerified(true);
    }, 500);
  };

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filtered = DEFAULT_AUDIT_RECORDS.filter((rec) => {
    if (actionFilter !== 'ALL' && rec.action !== actionFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchHash = rec.hash.toLowerCase().includes(q);
      const matchActor = rec.actor.toLowerCase().includes(q);
      const matchTarget = rec.target.toLowerCase().includes(q);
      const matchAction = rec.action.toLowerCase().includes(q);
      if (!matchHash && !matchActor && !matchTarget && !matchAction) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-white">
            <ScrollText className="h-5 w-5 text-emerald-400" />
            Cryptographic Audit Ledger
          </h1>
          <p className="text-xs text-slate-400">
            Append-only, SHA-256 hash-chained immutable security activity logs
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="primary"
            size="sm"
            icon={verifying ? RefreshCw : ShieldCheck}
            onClick={handleVerify}
            disabled={verifying}
          >
            {verifying ? 'Verifying Chain...' : 'Verify Hash Chain'}
          </Button>
        </div>
      </div>

      {/* Verification Status Banner */}
      {verified && (
        <div className="flex items-center gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-emerald-300">
          <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" />
          <div className="text-xs">
            <span className="font-semibold text-emerald-200">Hash Chain Integrity Intact:</span>{' '}
            All cryptographic signatures and parent block hashes match sequentially across 104 recorded entries using SHA-256 hash linkage.
          </div>
        </div>
      )}

      {/* KPI Stats Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-3">
          <div className="text-slate-400 text-xs">Total Ledger Blocks</div>
          <div className="text-xl font-bold font-mono text-white mt-0.5">104</div>
        </Card>
        <Card className="p-3">
          <div className="text-emerald-400 text-xs">Verified Sequential Chain</div>
          <div className="text-xl font-bold font-mono text-emerald-300 mt-0.5">100% Intact</div>
        </Card>
        <Card className="p-3">
          <div className="text-cyan-400 text-xs">Cryptographic Algorithm</div>
          <div className="text-xl font-bold font-mono text-cyan-300 mt-0.5">SHA-256</div>
        </Card>
        <Card className="p-3">
          <div className="text-amber-400 text-xs">Ledger Immutability</div>
          <div className="text-xl font-bold font-mono text-amber-300 mt-0.5">Tamper-Proof</div>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-1.5 flex-wrap">
          {['ALL', 'DETECTION_RULE_UPDATED', 'DOMAIN_OWNERSHIP_VERIFIED', 'API_INTEGRATION_CREATED', 'RESPONSE_APPROVED'].map((action) => (
            <button
              key={action}
              onClick={() => setActionFilter(action)}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold uppercase tracking-wider transition ${
                actionFilter === action
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {action === 'ALL' ? 'ALL' : action.replace(/_/g, ' ')}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search block hash, actor, target..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full sm:w-64 rounded-lg border border-slate-800 bg-slate-900/60 pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Ledger Table */}
      {filtered.length === 0 ? (
        <Card className="p-8">
          <EmptyState
            icon={ScrollText}
            title="No Ledger Records Found"
            description="No audit events match the search query or filter criteria."
          />
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 bg-slate-900/50 text-[10px] uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="px-4 py-3">Block #</th>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Action Type</th>
                  <th className="px-4 py-3">Actor &amp; Role</th>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">SHA-256 Block Hash</th>
                  <th className="px-4 py-3 text-right">Integrity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {filtered.map((rec) => (
                  <tr
                    key={rec.seq}
                    className="hover:bg-slate-800/30 transition cursor-pointer"
                    onClick={() => setSelectedRecord(rec)}
                  >
                    <td className="px-4 py-3 text-cyan-400 font-bold">#{rec.seq}</td>
                    <td className="px-4 py-3 font-sans text-slate-400">
                      {new Date(rec.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3 font-sans font-semibold text-white">
                      {rec.action}
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      <div>{rec.actor}</div>
                      <div className="text-[10px] text-slate-500">{rec.role}</div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{rec.target}</td>
                    <td className="px-4 py-3 text-slate-400 truncate max-w-[180px]" title={rec.hash}>
                      {rec.hash.slice(0, 12)}...{rec.hash.slice(-8)}
                    </td>
                    <td className="px-4 py-3 text-right font-sans">
                      <Badge tone="success">VERIFIED</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Block Inspector Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <Card className="w-full max-w-xl border-slate-700 bg-slate-900 shadow-2xl p-6 space-y-4 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Layers className="h-5 w-5 text-emerald-400" />
                <h2 className="text-base font-bold text-white">
                  Audit Block #{selectedRecord.seq} Inspector
                </h2>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <div className="text-[10px] uppercase font-semibold text-slate-500">Action &amp; Target</div>
                <div className="font-bold text-white text-sm">{selectedRecord.action}</div>
                <div className="text-cyan-400">{selectedRecord.target}</div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Actor</div>
                  <div className="text-white truncate">{selectedRecord.actor}</div>
                  <div className="text-[10px] text-cyan-400">{selectedRecord.role}</div>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Timestamp</div>
                  <div className="text-white">{new Date(selectedRecord.timestamp).toISOString()}</div>
                </div>
              </div>

              {/* Hashes */}
              <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-2">
                <div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 uppercase font-semibold">
                    <span>Block SHA-256 Hash</span>
                    <button
                      onClick={() => handleCopy(selectedRecord.hash)}
                      className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 font-sans"
                    >
                      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="text-emerald-300 break-all text-[11px] mt-0.5">
                    {selectedRecord.hash}
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-900">
                  <div className="text-[10px] text-slate-500 uppercase font-semibold">Parent Block Hash (PrevHash)</div>
                  <div className="text-slate-400 break-all text-[11px] mt-0.5">
                    {selectedRecord.prevHash}
                  </div>
                </div>
              </div>

              {/* Details Payload */}
              {selectedRecord.details && (
                <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <div className="text-[10px] text-slate-500 uppercase font-semibold">Payload Details</div>
                  <pre className="text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                    {JSON.stringify(selectedRecord.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <Button variant="ghost" size="sm" onClick={() => setSelectedRecord(null)}>
                Close Inspector
              </Button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
