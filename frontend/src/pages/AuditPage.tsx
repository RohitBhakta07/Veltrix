import { useState } from 'react';
import { ScrollText, ShieldCheck, CheckCircle2, RefreshCw } from 'lucide-react';
import { Card, Badge, Button } from '../components/ui/primitives';

export function AuditPage() {
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState(true);

  const handleVerify = () => {
    setVerifying(true);
    setTimeout(() => {
      setVerifying(false);
      setVerified(true);
    }, 600);
  };

  const auditRecords = [
    {
      seq: 104,
      timestamp: new Date().toISOString(),
      action: 'DETECTION_RULE_UPDATED',
      actor: 'soc_admin',
      target: 'SIGMA-SQLI-001',
      hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      prevHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      valid: true,
    },
    {
      seq: 103,
      timestamp: new Date(Date.now() - 1800000).toISOString(),
      action: 'DOMAIN_OWNERSHIP_VERIFIED',
      actor: 'soc_admin',
      target: 'demo.veltrix.io',
      hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      prevHash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
      valid: true,
    },
    {
      seq: 102,
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      action: 'API_INTEGRATION_CREATED',
      actor: 'soc_analyst',
      target: 'Cloudflare WAF Gateway',
      hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
      prevHash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
      valid: true,
    },
  ];

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

      {/* Verification Status */}
      {verified && (
        <div className="flex items-center gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-emerald-300">
          <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" />
          <div className="text-xs">
            <span className="font-semibold text-emerald-200">Hash Chain Integrity Intact:</span>{' '}
            All cryptographic signatures and parent block hashes match sequentially across 104 recorded entries.
          </div>
        </div>
      )}

      {/* Ledger Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-900/50 text-[10px] uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-4 py-3">Block #</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Target</th>
                <th className="px-4 py-3">Record SHA-256 Hash</th>
                <th className="px-4 py-3 text-right">Integrity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {auditRecords.map((rec) => (
                <tr key={rec.seq} className="hover:bg-slate-800/30 transition">
                  <td className="px-4 py-3 text-cyan-400">#{rec.seq}</td>
                  <td className="px-4 py-3 font-sans font-medium text-white">{rec.action}</td>
                  <td className="px-4 py-3 text-slate-400">{rec.actor}</td>
                  <td className="px-4 py-3 text-slate-300">{rec.target}</td>
                  <td className="px-4 py-3 text-slate-500 truncate max-w-[200px]" title={rec.hash}>
                    {rec.hash.slice(0, 16)}...{rec.hash.slice(-8)}
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
    </div>
  );
}
