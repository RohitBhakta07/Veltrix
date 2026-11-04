import { useState } from 'react';
import {
  Zap,
  CheckCircle2,
  XCircle,
  RotateCcw,
  Plus,
  Search,
  ShieldAlert,
  ShieldCheck,
  Lock,
  X,
} from 'lucide-react';
import type { ResponseActionType, ResponseExecutionStatus } from '@veltrix/shared';
import { Card, Badge, Button, EmptyState } from '../components/ui/primitives';

export interface ProposedAction {
  id: string;
  type: ResponseActionType;
  target: string;
  reason: string;
  status: ResponseExecutionStatus;
  confidence: number;
  requestedBy: string;
  approvedBy?: string;
  executedAt?: string;
  createdAt: string;
}

const DEFAULT_ACTIONS: ProposedAction[] = [
  {
    id: 'act-001',
    type: 'BLOCK_IP',
    target: '198.51.100.42',
    reason: 'Automated SQLi and Path Traversal detected on /api/v1/auth/login',
    status: 'PENDING_APPROVAL',
    confidence: 0.95,
    requestedBy: 'Sigma Correlation Engine',
    createdAt: new Date().toISOString(),
  },
  {
    id: 'act-002',
    type: 'REVOKE_SESSION',
    target: 'usr-sess-98213',
    reason: 'Credential stuffing attack pattern observed from multiple geographic IPs',
    status: 'PENDING_APPROVAL',
    confidence: 0.88,
    requestedBy: 'Behavioral Anomaly Detector',
    createdAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
  },
  {
    id: 'act-003',
    type: 'BLOCK_IP',
    target: '203.0.113.195',
    reason: 'High-frequency brute-force attack against WordPress XML-RPC endpoint',
    status: 'EXECUTED',
    confidence: 0.99,
    requestedBy: 'WAF Rate Limiter',
    approvedBy: 'soc_admin@cyberdefend.corp',
    executedAt: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    createdAt: new Date(Date.now() - 1000 * 60 * 130).toISOString(),
  },
];

export function ResponsePage() {
  const [filter, setFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [actions, setActions] = useState<ProposedAction[]>(DEFAULT_ACTIONS);
  const [showDispatchModal, setShowDispatchModal] = useState(false);

  // New action modal state
  const [newType, setNewType] = useState<ResponseActionType>('BLOCK_IP');
  const [newTarget, setNewTarget] = useState('');
  const [newReason, setNewReason] = useState('');

  const filtered = actions.filter((a) => {
    if (filter !== 'ALL' && a.status !== filter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTarget = a.target.toLowerCase().includes(q);
      const matchReason = a.reason.toLowerCase().includes(q);
      const matchType = a.type.toLowerCase().includes(q);
      if (!matchTarget && !matchReason && !matchType) return false;
    }
    return true;
  });

  const pendingCount = actions.filter((a) => a.status === 'PENDING_APPROVAL').length;
  const executedCount = actions.filter((a) => a.status === 'EXECUTED').length;
  const rolledBackCount = actions.filter((a) => a.status === 'ROLLED_BACK').length;

  const handleApprove = (id: string) => {
    setActions((prev) =>
      prev.map((a) =>
        a.id === id
          ? {
              ...a,
              status: 'EXECUTED',
              approvedBy: 'soc_analyst@cyberdefend.corp',
              executedAt: new Date().toISOString(),
            }
          : a
      )
    );
  };

  const handleReject = (id: string) => {
    setActions((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status: 'REJECTED' } : a))
    );
  };

  const handleRollback = (id: string) => {
    setActions((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status: 'ROLLED_BACK' } : a))
    );
  };

  const handleCreateAction = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim() || !newReason.trim()) return;

    const newAction: ProposedAction = {
      id: `act-${Date.now().toString().slice(-3)}`,
      type: newType,
      target: newTarget.trim(),
      reason: newReason.trim(),
      status: 'PENDING_APPROVAL',
      confidence: 1.0,
      requestedBy: 'Manual SOC Operator',
      createdAt: new Date().toISOString(),
    };

    setActions([newAction, ...actions]);
    setShowDispatchModal(false);
    setNewTarget('');
    setNewReason('');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-white">
            <Zap className="h-5 w-5 text-amber-400" />
            Defensive SOAR Response Queue
          </h1>
          <p className="text-xs text-slate-400">
            Approval-gated automated containment actions, firewall rules, and session mitigations
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge tone={pendingCount > 0 ? 'medium' : 'success'}>
            {pendingCount} Pending Approvals
          </Badge>
          <Button variant="primary" size="sm" icon={Plus} onClick={() => setShowDispatchModal(true)}>
            Propose Action
          </Button>
        </div>
      </div>

      {/* Contract Notice Banner */}
      <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-amber-200">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
        <div className="text-xs">
          <span className="font-semibold text-amber-300">Phase 10 Defensive SOAR & Auto-Containment Ready:</span>{' '}
          Automated playbooks enforce strict dual-custody authorization. Containment actions dispatch web firewall IP blocks, terminate active session tokens, and append cryptographic signatures directly into the audit ledger.
        </div>
      </div>

      {/* KPI Stats Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-3">
          <div className="text-slate-400 text-xs">Total Containments</div>
          <div className="text-xl font-bold font-mono text-white mt-0.5">{actions.length}</div>
        </Card>
        <Card className="p-3">
          <div className="text-amber-400 text-xs">Pending Dual-Custody</div>
          <div className="text-xl font-bold font-mono text-amber-300 mt-0.5">{pendingCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-emerald-400 text-xs">Active Mitigations</div>
          <div className="text-xl font-bold font-mono text-emerald-300 mt-0.5">{executedCount}</div>
        </Card>
        <Card className="p-3">
          <div className="text-slate-400 text-xs">Rolled Back / Reverted</div>
          <div className="text-xl font-bold font-mono text-slate-300 mt-0.5">{rolledBackCount}</div>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-1.5 flex-wrap">
          {['ALL', 'PENDING_APPROVAL', 'EXECUTED', 'ROLLED_BACK', 'REJECTED'].map((tab) => (
            <button
              key={tab}
              onClick={() => setFilter(tab)}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold uppercase tracking-wider transition ${
                filter === tab
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {tab.replace('_', ' ')}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search target IP, session, reason..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full sm:w-64 rounded-lg border border-slate-800 bg-slate-900/60 pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Action Cards */}
      {filtered.length === 0 ? (
        <Card className="p-8">
          <EmptyState
            icon={ShieldCheck}
            title="No Actions in Selected View"
            description="All automated playbooks have been processed or no mitigations match the filter criteria."
          />
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((action) => (
            <Card key={action.id} className="p-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-amber-300 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded">
                    {action.type}
                  </span>
                  <span className="font-mono text-xs text-slate-200 font-semibold">{action.target}</span>
                  <Badge
                    tone={
                      action.status === 'PENDING_APPROVAL'
                        ? 'medium'
                        : action.status === 'EXECUTED'
                        ? 'success'
                        : 'critical'
                    }
                  >
                    {action.status}
                  </Badge>
                </div>
                <p className="text-xs text-slate-300">{action.reason}</p>
                <div className="flex items-center gap-3 text-[10px] text-slate-500 font-mono">
                  <span>Confidence: {(action.confidence * 100).toFixed(0)}%</span>
                  <span>Requested by: {action.requestedBy}</span>
                  {action.approvedBy && (
                    <span className="text-cyan-400">Approved by: {action.approvedBy}</span>
                  )}
                  <span>Proposed: {new Date(action.createdAt).toLocaleTimeString()}</span>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {action.status === 'PENDING_APPROVAL' && (
                  <>
                    <Button
                      variant="danger"
                      size="sm"
                      icon={XCircle}
                      onClick={() => handleReject(action.id)}
                    >
                      Reject
                    </Button>
                    <Button
                      variant="primary"
                      size="sm"
                      icon={CheckCircle2}
                      onClick={() => handleApprove(action.id)}
                    >
                      Approve &amp; Execute
                    </Button>
                  </>
                )}

                {action.status === 'EXECUTED' && (
                  <Button
                    variant="secondary"
                    size="sm"
                    icon={RotateCcw}
                    onClick={() => handleRollback(action.id)}
                  >
                    Rollback Mitigation
                  </Button>
                )}

                {action.status === 'ROLLED_BACK' && (
                  <span className="text-xs font-mono text-slate-500 italic">
                    Action Reverted
                  </span>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Propose Action Modal */}
      {showDispatchModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <Card className="w-full max-w-md border-slate-700 bg-slate-900 shadow-2xl p-6 space-y-4 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Lock className="h-4 w-4 text-amber-400" />
                Propose Defensive Action
              </h2>
              <button
                onClick={() => setShowDispatchModal(false)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateAction} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Action Playbook</label>
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value as any)}
                  className="w-full rounded bg-slate-950 border border-slate-800 px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-500"
                >
                  <option value="BLOCK_IP">BLOCK_IP (Edge WAF Firewall Drop)</option>
                  <option value="REVOKE_SESSION">REVOKE_SESSION (Terminate JWT Token)</option>
                  <option value="SUSPEND_USER">SUSPEND_USER (Lock User Account)</option>
                  <option value="STEP_UP_AUTH">STEP_UP_AUTH (Enforce MFA Challenge)</option>
                  <option value="ESCALATE_ALERT">ESCALATE_ALERT (Page SOC Tier-3)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Target Identifier</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.42 or usr-sess-87213"
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  className="w-full rounded bg-slate-950 border border-slate-800 px-3 py-2 text-white font-mono placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Defensive Justification</label>
                <textarea
                  required
                  placeholder="Provide forensic reason and trigger detection id..."
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                  className="w-full h-20 rounded bg-slate-950 border border-slate-800 p-2 text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <Button variant="ghost" size="sm" type="button" onClick={() => setShowDispatchModal(false)}>
                  Cancel
                </Button>
                <Button variant="primary" size="sm" type="submit">
                  Queue for Approval
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}
    </div>
  );
}
