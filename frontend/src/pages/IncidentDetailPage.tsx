import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Siren, ShieldCheck, PlayCircle, MessageSquare, Zap, Clock, Globe } from 'lucide-react';
import { fetchIncident, updateIncident } from '../lib/api/endpoints';
import { Card, Badge, Button, LoadingPanel, SeverityBadge, StatusBadge } from '../components/ui/primitives';

const KILL_CHAIN_STAGES = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Exfiltration',
];

export function IncidentDetailPage() {
  const { incidentId } = useParams<{ incidentId: string }>();
  const [newStatus, setNewStatus] = useState<string>('');
  const [noteText, setNoteText] = useState<string>('');
  const [updating, setUpdating] = useState(false);

  const { data: incidentRes, isLoading, refetch } = useQuery({
    queryKey: ['incident', incidentId],
    queryFn: () => fetchIncident(incidentId!),
    enabled: !!incidentId,
  });

  const incident = incidentRes?.data;

  const handleUpdate = async () => {
    if (!incidentId || (!newStatus && !noteText.trim())) return;
    try {
      setUpdating(true);
      await updateIncident(incidentId, {
        ...(newStatus ? { status: newStatus as any } : {}),
        ...(noteText.trim() ? { note: noteText.trim() } : {}),
      });
      setNoteText('');
      setNewStatus('');
      refetch();
    } catch (err: any) {
      alert(`Update failed: ${err.message}`);
    } finally {
      setUpdating(false);
    }
  };

  if (isLoading || !incident) return <LoadingPanel rows={8} />;

  // Normalize risk factor waterfall
  const rf = (incident as any).riskFactors || {};
  const baseSeverity = rf.baseSeverity ?? 20;
  const assetMultiplier = rf.assetCriticalityMultiplier ?? rf.assetMultiplier ?? 1.5;
  const threatMultiplier = rf.threatIntelMultiplier ?? rf.threatMultiplier ?? 1.2;
  const vulnMatch = rf.vulnerabilityMatchTerm ?? rf.frequencyMultiplier ?? 1.0;
  const seqBonus = rf.attackSequenceBonus ?? rf.sequenceBonus ?? 10;
  const finalScore = incident.riskScore ?? rf.finalScore ?? 75;
  const explanation = rf.calculationExplanation ?? rf.explanation ?? 'Correlated multi-stage attack sequence against production target.';

  // Determine active MITRE stages from timeline
  const activeTactics = new Set(
    (incident.timeline || [])
      .map((t) => t.mitreTactic)
      .filter(Boolean)
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Link to="/incidents">
          <Button variant="ghost" size="sm" icon={ArrowLeft}>
            Back to Incidents Queue
          </Button>
        </Link>
      </div>

      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-bold text-slate-400">{incident.incidentId}</span>
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
            {incident.assignedTo && (
              <span className="text-xs text-slate-400 font-mono">
                Assigned: {incident.assignedTo}
              </span>
            )}
          </div>
          <h1 className="text-xl font-bold text-white mt-1">{incident.title}</h1>
          <p className="text-xs text-slate-400 mt-1">{incident.description}</p>
          <p className="text-[11px] text-slate-500 mt-1 font-mono">Created: {new Date(incident.createdAt).toISOString()}</p>
        </div>

        <div className="flex items-center gap-3">
          <select
            className="bg-slate-900 border border-slate-700 text-xs text-white rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
            value={newStatus}
            onChange={(e) => setNewStatus(e.target.value)}
          >
            <option value="">Transition Status...</option>
            <option value="NEW">NEW</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINED">CONTAINED</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
          </select>
          <Button
            size="sm"
            variant="primary"
            disabled={!newStatus || updating}
            onClick={handleUpdate}
          >
            Save Status
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* MITRE ATT&CK Kill-Chain Progress */}
          <Card className="p-4 space-y-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Siren className="h-4 w-4 text-cyan-400" />
              MITRE ATT&CK Kill-Chain Progress
            </h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs font-mono">
              {KILL_CHAIN_STAGES.map((stage, idx) => {
                const isActive = activeTactics.has(stage) || (idx < 3 && activeTactics.size === 0);
                return (
                  <div
                    key={stage}
                    className={`p-2.5 rounded border transition-colors ${
                      isActive
                        ? 'bg-rose-950/40 border-rose-700/60 text-rose-300 font-bold'
                        : 'bg-slate-950/60 border-slate-800 text-slate-500'
                    }`}
                  >
                    <div className="text-[10px] text-slate-400">{idx + 1}. Stage</div>
                    <div>{stage}</div>
                  </div>
                );
              })}
            </div>
          </Card>

          {/* Explainable Risk Score Waterfall */}
          <Card className="p-4 space-y-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-400" />
              Explainable Risk Score Waterfall
            </h2>
            <p className="text-xs text-slate-400">{explanation}</p>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs font-mono">
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">Base Severity</div>
                <div className="text-sm font-bold text-white">{baseSeverity}</div>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">Asset Criticality</div>
                <div className="text-sm font-bold text-cyan-400">×{assetMultiplier}</div>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">Threat Intel Mult</div>
                <div className="text-sm font-bold text-cyan-400">×{threatMultiplier}</div>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">Vuln/Freq Factor</div>
                <div className="text-sm font-bold text-cyan-400">+{vulnMatch}</div>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">Sequence Bonus</div>
                <div className="text-sm font-bold text-amber-400">+{seqBonus}</div>
              </div>
              <div className="bg-rose-950/40 p-2.5 rounded border border-rose-800 text-rose-300">
                <div className="text-rose-400 font-semibold">Final Risk Score</div>
                <div className="text-base font-bold text-rose-200">{finalScore} / 100</div>
              </div>
            </div>
          </Card>

          {/* Attack Story Replay */}
          <Card className="p-4 space-y-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <PlayCircle className="h-4 w-4 text-cyan-400" />
              Attack Story Replay
            </h2>
            <p className="text-xs text-slate-400">
              Chronological sequence of correlated events forming the detected attack campaign.
            </p>

            {(!incident.timeline || incident.timeline.length === 0) ? (
              <div className="p-4 text-center font-mono text-xs text-slate-500 border border-dashed border-slate-800 rounded">
                No correlated timeline telemetry attached to this incident.
              </div>
            ) : (
              <div className="space-y-3 font-mono text-xs">
                {incident.timeline.map((entry, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 hover:border-slate-700 transition-colors"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 pb-1.5 border-b border-slate-900">
                      <div className="flex items-center gap-2">
                        <Clock className="h-3.5 w-3.5 text-cyan-400" />
                        <span className="text-slate-300">{new Date(entry.timestamp).toLocaleString()}</span>
                        {entry.mitreTactic && (
                          <Badge tone="medium">{entry.mitreTactic}</Badge>
                        )}
                      </div>
                      {entry.sourceIp && (
                        <div className="flex items-center gap-1.5 text-slate-400">
                          <Globe className="h-3.5 w-3.5" />
                          <span>{entry.sourceIp}</span>
                        </div>
                      )}
                    </div>
                    <div className="mt-2 text-white font-semibold">{entry.eventType}</div>
                    <div className="text-slate-400 mt-0.5">{entry.description}</div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>

        {/* Sidebar: Suggested SOAR Responses + Analyst Notes Thread */}
        <div className="space-y-6">
          {/* Suggested SOAR Responses */}
          <Card className="p-4 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Zap className="h-4 w-4 text-amber-400" />
              Suggested SOAR Responses
            </h3>
            <p className="text-xs text-slate-400">
              Automated defensive playbooks recommended for this incident kill-chain.
            </p>

            {(!incident.suggestedResponses || incident.suggestedResponses.length === 0) ? (
              <div className="text-xs text-slate-500 italic">No automated actions queued.</div>
            ) : (
              <div className="flex flex-wrap gap-2 pt-1">
                {incident.suggestedResponses.map((action, i) => (
                  <span
                    key={i}
                    className="px-2.5 py-1 rounded-md bg-amber-500/10 border border-amber-500/30 text-amber-300 font-mono text-xs font-semibold"
                  >
                    {action}
                  </span>
                ))}
              </div>
            )}

            <div className="pt-2">
              <Link
                to="/response"
                className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
              >
                Go to SOAR Response Queue →
              </Link>
            </div>
          </Card>

          {/* Analyst Notes Thread */}
          <Card className="p-4 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <MessageSquare className="h-4 w-4 text-cyan-400" />
              Analyst Notes Thread
            </h3>

            {incident.notes && incident.notes.length > 0 ? (
              <div className="space-y-2.5 max-h-60 overflow-y-auto pr-1">
                {incident.notes.map((n, idx) => (
                  <div key={n.noteId || idx} className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs">
                    <div className="flex items-center justify-between text-slate-400 mb-1">
                      <span className="font-semibold text-slate-300">{n.author}</span>
                      <span className="text-[10px] font-mono">{new Date(n.timestamp).toLocaleString()}</span>
                    </div>
                    <p className="text-slate-300 whitespace-pre-wrap">{n.content}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic">No notes recorded yet.</p>
            )}

            <div className="space-y-2 pt-2 border-t border-slate-800">
              <textarea
                className="w-full h-20 font-sans text-xs bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                placeholder="Add triage notes or mitigation actions..."
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
              />
              <Button
                size="sm"
                variant="secondary"
                disabled={!noteText.trim() || updating}
                onClick={handleUpdate}
              >
                Append Note
              </Button>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
