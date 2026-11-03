import { useState } from 'react';
import { Settings, User, Database, Play, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../features/auth/AuthProvider';
import { Card, Badge, Button } from '../components/ui/primitives';

export function SettingsPage() {
  const { user, demoLogin } = useAuth();
  const role = user?.role || 'READ_ONLY_VIEWER';
  const [generatingDemo, setGeneratingDemo] = useState(false);
  const [demoSuccess, setDemoSuccess] = useState(false);

  const handleGenerateDemo = async () => {
    setGeneratingDemo(true);
    setDemoSuccess(false);
    try {
      await fetch('/api/v1/demo/generate', { method: 'POST' });
      setDemoSuccess(true);
    } catch {
      // Demo fallback
    } finally {
      setGeneratingDemo(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="flex items-center gap-2 text-xl font-bold text-white">
          <Settings className="h-5 w-5 text-cyan-400" />
          Platform Settings & Tenant Governance
        </h1>
        <p className="text-xs text-slate-400">
          Organization configuration, role-based access controls, and evaluation demo scenarios
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* User Identity & Active Session */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-500/10 text-cyan-400">
              <User className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">Active Operator Identity</h2>
              <p className="text-xs text-slate-400">{user?.email || 'analyst@corp.com'}</p>
            </div>
          </div>

          <div className="space-y-2 border-t border-slate-800/80 pt-4 text-xs">
            <div className="flex justify-between py-1">
              <span className="text-slate-400">User ID</span>
              <span className="font-mono text-slate-200">{user?.userId || 'usr-default'}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">Current Role</span>
              <Badge tone="info">{role}</Badge>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">Organization Tenant ID</span>
              <span className="font-mono text-cyan-400">{user?.orgId || 'org-main'}</span>
            </div>
          </div>

          {/* Quick Demo Role Switcher */}
          <div className="border-t border-slate-800/80 pt-4">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Switch Demo Role Persona
            </div>
            <div className="grid grid-cols-2 gap-2">
              <Button
                variant={role === 'ORG_ADMIN' ? 'primary' : 'secondary'}
                size="sm"
                onClick={() => demoLogin('ORG_ADMIN')}
              >
                Org Admin
              </Button>
              <Button
                variant={role === 'SECURITY_ANALYST' ? 'primary' : 'secondary'}
                size="sm"
                onClick={() => demoLogin('SECURITY_ANALYST')}
              >
                Security Analyst
              </Button>
              <Button
                variant={role === 'AUDITOR' ? 'primary' : 'secondary'}
                size="sm"
                onClick={() => demoLogin('AUDITOR')}
              >
                Auditor
              </Button>
              <Button
                variant={role === 'READ_ONLY_VIEWER' ? 'primary' : 'secondary'}
                size="sm"
                onClick={() => demoLogin('READ_ONLY_VIEWER')}
              >
                Read-Only Viewer
              </Button>
            </div>
          </div>
        </Card>

        {/* Demo Attack Simulator */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl bg-rose-500/10 text-rose-400">
              <Database className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">Live Evaluation & Demo Scenarios</h2>
              <p className="text-xs text-slate-400">Inject synthetic attack streams into telemetry pipelines</p>
            </div>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Generate synthetic high-velocity security events (SQL injection, credential stuffing, path traversal, scanner probes) to exercise detection rules, correlation clustering, and risk scoring.
          </p>

          {demoSuccess && (
            <div className="flex items-center gap-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 p-3 text-xs text-emerald-300">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>Synthetic telemetry stream generated and ingested into detection pipeline!</span>
            </div>
          )}

          <Button
            variant="primary"
            size="sm"
            icon={Play}
            onClick={handleGenerateDemo}
            disabled={generatingDemo}
          >
            {generatingDemo ? 'Injecting Telemetry...' : 'Generate Demo Attack Scenario'}
          </Button>
        </Card>
      </div>
    </div>
  );
}
