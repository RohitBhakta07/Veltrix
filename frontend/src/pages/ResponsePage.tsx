import { useState } from 'react';
import { CheckCircle2, XCircle, Zap } from 'lucide-react';
import { Card, Badge, Button } from '../components/ui/primitives';

interface ProposedAction {
  id: string;
  type: 'BLOCK_IP' | 'REVOKE_SESSION' | 'RATE_LIMIT' | 'DISABLE_KEY';
  target: string;
  reason: string;
  status: 'PENDING_APPROVAL' | 'EXECUTED' | 'REJECTED';
  confidence: number;
  createdAt: string;
}

export function ResponsePage() {
  const [filter, setFilter] = useState<'ALL' | 'PENDING' | 'EXECUTED'>('ALL');

  // Placeholder actions representing defensive SOAR capabilities
  const actions: ProposedAction[] = [
    {
      id: 'act-001',
      type: 'BLOCK_IP',
      target: '198.51.100.42',
      reason: 'Automated SQLi and Path Traversal detected on /api/v1/users',
      status: 'PENDING_APPROVAL',
      confidence: 0.95,
      createdAt: new Date().toISOString(),
    },
    {
      id: 'act-002',
      type: 'REVOKE_SESSION',
      target: 'usr-sess-98213',
      reason: 'Credential stuffing attack pattern observed from multiple endpoints',
      status: 'PENDING_APPROVAL',
      confidence: 0.88,
      createdAt: new Date(Date.now() - 3600000).toISOString(),
    },
  ];

  const filtered = filter === 'ALL'
    ? actions
    : actions.filter((a) => (filter === 'PENDING' ? a.status === 'PENDING_APPROVAL' : a.status === 'EXECUTED'));

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
          <Badge tone="medium">2 Pending Approvals</Badge>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        {(['ALL', 'PENDING', 'EXECUTED'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setFilter(tab)}
            className={`rounded-lg px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition ${
              filter === tab
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            {tab} Actions
          </button>
        ))}
      </div>

      {/* Action Cards */}
      <div className="space-y-3">
        {filtered.map((action) => (
          <Card key={action.id} className="p-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-amber-300 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded">
                  {action.type}
                </span>
                <span className="font-mono text-xs text-slate-300 font-semibold">{action.target}</span>
                <Badge tone={action.status === 'PENDING_APPROVAL' ? 'medium' : 'success'}>
                  {action.status}
                </Badge>
              </div>
              <p className="text-xs text-slate-400">{action.reason}</p>
              <div className="text-[10px] text-slate-500">
                Confidence: {(action.confidence * 100).toFixed(0)}% · Proposed {new Date(action.createdAt).toLocaleTimeString()}
              </div>
            </div>

            {action.status === 'PENDING_APPROVAL' && (
              <div className="flex items-center gap-2 shrink-0">
                <Button variant="danger" size="sm" icon={XCircle}>
                  Reject
                </Button>
                <Button variant="primary" size="sm" icon={CheckCircle2}>
                  Approve & Execute
                </Button>
              </div>
            )}
          </Card>
        ))}
      </div>
    </div>
  );
}
