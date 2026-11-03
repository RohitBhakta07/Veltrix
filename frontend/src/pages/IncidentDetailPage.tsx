import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Siren, ShieldCheck } from 'lucide-react';
import { fetchIncident, updateIncident } from '../lib/api/endpoints';
import { Card, Badge, Button, LoadingPanel, SeverityBadge } from '../components/ui/primitives';

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
    if (!incidentId || !newStatus) return;
    try {
      setUpdating(true);
      await updateIncident(incidentId, { status: newStatus as any, note: noteText });
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

  const factors = (incident as any).factors || {
    baseSeverity: 20,
    frequencyMultiplier: 1.5,
    assetCriticalityMultiplier: 1.5,
    threatIntelMultiplier: 1.2,
    attackSequenceBonus: 10,
    finalScore: (incident as any).riskScore || 75,
    calculationExplanation: 'Correlated multi-stage attack sequence against production target.',
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Link to="/incidents">
          <Button variant="ghost" size="sm" icon={ArrowLeft}>
            Back to Incidents Queue
          </Button>
        </Link>
      </div>

      <div className="flex items-start justify-between border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-bold text-slate-400">{incident.incidentId}</span>
            <SeverityBadge severity={incident.severity} />
            <Badge tone="neutral">{incident.status}</Badge>
          </div>
          <h1 className="text-xl font-bold text-white mt-1">{incident.title}</h1>
          <p className="text-xs text-slate-400">Created: {new Date(incident.createdAt).toISOString()}</p>
        </div>

        <div className="flex items-center gap-3">
          <select
            className="bg-slate-900 border border-slate-700 text-xs text-white rounded-lg px-2.5 py-1.5"
            value={newStatus}
            onChange={(e) => setNewStatus(e.target.value)}
          >
            <option value="">Transition Status...</option>
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
          <Card className="p-4 space-y-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Siren className="h-4 w-4 text-cyan-400" />
              MITRE ATT&CK Kill-Chain Progress
            </h2>
            <div className="grid grid-cols-4 gap-2 text-center text-xs font-mono">
              <div className="p-2 rounded bg-cyan-950/60 border border-cyan-800 text-cyan-300">
                1. Initial Access
              </div>
              <div className="p-2 rounded bg-cyan-950/60 border border-cyan-800 text-cyan-300">
                2. Execution
              </div>
              <div className="p-2 rounded bg-cyan-950/60 border border-cyan-800 text-cyan-300">
                3. Persistence
              </div>
              <div className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-500">
                4. Exfiltration
              </div>
            </div>
          </Card>

          <Card className="p-4 space-y-4">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-400" />
              Explainable Risk Score Waterfall
            </h2>
            <p className="text-xs text-slate-400">{factors.calculationExplanation}</p>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs font-mono">
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">Base Severity</div>
                <div className="text-sm font-bold text-white">{factors.baseSeverity}</div>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">Frequency Mult</div>
                <div className="text-sm font-bold text-cyan-400">×{factors.frequencyMultiplier}</div>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">Asset Mult</div>
                <div className="text-sm font-bold text-cyan-400">×{factors.assetCriticalityMultiplier}</div>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">Threat Intel Mult</div>
                <div className="text-sm font-bold text-cyan-400">×{factors.threatIntelMultiplier}</div>
              </div>
              <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                <div className="text-slate-500">Sequence Bonus</div>
                <div className="text-sm font-bold text-amber-400">+{factors.attackSequenceBonus}</div>
              </div>
              <div className="bg-rose-950/40 p-2.5 rounded border border-rose-800 text-rose-300">
                <div className="text-rose-400">Final Risk Score</div>
                <div className="text-base font-bold text-rose-200">{factors.finalScore} / 100</div>
              </div>
            </div>
          </Card>
        </div>

        <div className="space-y-4">
          <Card className="p-4 space-y-3">
            <h3 className="text-sm font-bold text-white">Analyst Notes Thread</h3>
            <textarea
              className="w-full h-24 font-mono text-xs bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
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
          </Card>
        </div>
      </div>
    </div>
  );
}
