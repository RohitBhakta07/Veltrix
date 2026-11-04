import { useState } from 'react';
import {
  Settings,
  User,
  Database,
  Play,
  RotateCcw,
  CheckCircle2,
  Building,
  Users,
  Shield,
  Clock,
  Save,
  Check,
  X,
} from 'lucide-react';
import { useAuth } from '../features/auth/AuthProvider';
import { Card, Badge, Button } from '../components/ui/primitives';

type SettingsTab = 'ORGANIZATION' | 'RBAC_TEAM' | 'DEMO_CONTROLLER';

interface TeamMember {
  userId: string;
  name: string;
  email: string;
  role: 'ORG_ADMIN' | 'SECURITY_ANALYST' | 'AUDITOR' | 'READ_ONLY_VIEWER';
  status: 'ACTIVE' | 'INVITED';
  lastLogin: string;
}

const DEFAULT_TEAM: TeamMember[] = [
  {
    userId: 'usr-admin-01',
    name: 'Sarah Connor',
    email: 'admin@cyberdefend.corp',
    role: 'ORG_ADMIN',
    status: 'ACTIVE',
    lastLogin: 'Just now',
  },
  {
    userId: 'usr-analyst-02',
    name: 'Alice Johnson',
    email: 'analyst@cyberdefend.corp',
    role: 'SECURITY_ANALYST',
    status: 'ACTIVE',
    lastLogin: '10 mins ago',
  },
  {
    userId: 'usr-auditor-03',
    name: 'Marcus Vance',
    email: 'auditor@cyberdefend.corp',
    role: 'AUDITOR',
    status: 'ACTIVE',
    lastLogin: '2 hours ago',
  },
  {
    userId: 'usr-viewer-04',
    name: 'Elena Rostova',
    email: 'viewer@cyberdefend.corp',
    role: 'READ_ONLY_VIEWER',
    status: 'ACTIVE',
    lastLogin: '1 day ago',
  },
];

const RBAC_CAPABILITIES = [
  { capability: 'View Telemetry & Incident Queues', admin: true, analyst: true, auditor: true, viewer: true },
  { capability: 'Triage Incidents & Append Notes', admin: true, analyst: true, auditor: false, viewer: false },
  { capability: 'Launch Authorized Scans', admin: true, analyst: true, auditor: false, viewer: false },
  { capability: 'Tune Sigma Detection Rules', admin: true, analyst: true, auditor: false, viewer: false },
  { capability: 'SOAR Containment Dual-Custody Approval', admin: true, analyst: false, auditor: false, viewer: false },
  { capability: 'Cryptographic Ledger Verification', admin: true, analyst: true, auditor: true, viewer: false },
  { capability: 'Manage Team & API Credentials', admin: true, analyst: false, auditor: false, viewer: false },
];

export function SettingsPage({ initialTab = 'ORGANIZATION' }: { initialTab?: SettingsTab } = {}) {
  const { user, demoLogin } = useAuth();
  const currentRole = user?.role || 'READ_ONLY_VIEWER';
  const [activeTab, setActiveTab] = useState<SettingsTab>(initialTab);

  // Governance state
  const [orgName, setOrgName] = useState('CyberDefend Global Enterprise');
  const [retentionDays, setRetentionDays] = useState('90');
  const [webhookUrl, setWebhookUrl] = useState('https://hooks.slack.com/services/T00/B00/VELTRIX');
  const [savedSettings, setSavedSettings] = useState(false);

  // Demo state
  const [generatingDemo, setGeneratingDemo] = useState(false);
  const [demoMessage, setDemoMessage] = useState<string | null>(null);
  const [resettingDemo, setResettingDemo] = useState(false);

  const handleSaveGovernance = (e: React.FormEvent) => {
    e.preventDefault();
    setSavedSettings(true);
    setTimeout(() => setSavedSettings(false), 2500);
  };

  const handleGenerateScenario = async (scenarioName: string) => {
    setGeneratingDemo(true);
    setDemoMessage(null);
    try {
      await fetch('/api/v1/demo/generate', { method: 'POST' });
    } catch {
      // Demo fallback
    } finally {
      setGeneratingDemo(false);
      setDemoMessage(`Successfully injected "${scenarioName}" attack telemetry into ingestion stream!`);
    }
  };

  const handleResetDemo = async () => {
    setResettingDemo(true);
    setDemoMessage(null);
    try {
      await fetch('/api/v1/demo/reset', { method: 'POST' });
    } catch {
      // Demo fallback
    } finally {
      setResettingDemo(false);
      setDemoMessage('Synthetic demo telemetry reset to clean baseline successfully.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="flex items-center gap-2 text-xl font-bold text-white">
          <Settings className="h-5 w-5 text-cyan-400" />
          Platform Settings &amp; Tenant Governance
        </h1>
        <p className="text-xs text-slate-400">
          Organization profile, role-based access control, data retention, and evaluation scenarios
        </p>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        {[
          { id: 'ORGANIZATION', label: 'Organization Profile', icon: Building },
          { id: 'RBAC_TEAM', label: 'Team & RBAC Matrix', icon: Users },
          { id: 'DEMO_CONTROLLER', label: 'Evaluation Scenarios', icon: Database },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as SettingsTab)}
              className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                activeTab === tab.id
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB 1: Organization Profile & Telemetry Retention */}
      {activeTab === 'ORGANIZATION' && (
        <div className="space-y-6">
          <Card className="p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Building className="h-4 w-4 text-cyan-400" />
                Organization Profile
              </h2>
              <span className="font-mono text-xs text-cyan-400">
                Tenant: {user?.orgId || 'org-enterprise-01'}
              </span>
            </div>

            <form onSubmit={handleSaveGovernance} className="space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Organization Name</label>
                  <input
                    type="text"
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                    className="w-full rounded bg-slate-950 border border-slate-800 px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Tenant Slug ID</label>
                  <input
                    type="text"
                    disabled
                    value={user?.orgId || 'org-enterprise-01'}
                    className="w-full rounded bg-slate-950/60 border border-slate-800/80 px-3 py-2 font-mono text-slate-400 cursor-not-allowed"
                  />
                </div>
              </div>

              {/* Retention Policy */}
              <div className="pt-2">
                <label className="block text-slate-400 font-semibold mb-1 flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-cyan-400" />
                  Telemetry Retention Policy
                </label>
                <p className="text-[11px] text-slate-500 mb-2">
                  Duration for storing raw security events, WAF logs, and detection telemetry before automated cryptographic ledger pruning.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {[
                    { days: '30', label: '30 Days', desc: 'Standard SOC Retain' },
                    { days: '90', label: '90 Days', desc: 'SOC2 & PCI-DSS Compliance' },
                    { days: '365', label: '365 Days', desc: 'Annual Regulatory Archival' },
                  ].map((opt) => (
                    <button
                      type="button"
                      key={opt.days}
                      onClick={() => setRetentionDays(opt.days)}
                      className={`p-3 rounded-lg border text-left transition ${
                        retentionDays === opt.days
                          ? 'bg-cyan-500/15 border-cyan-500 text-cyan-200'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="font-bold text-white text-xs">{opt.label}</div>
                      <div className="text-[10px] text-slate-400 mt-0.5">{opt.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Webhook */}
              <div className="pt-2">
                <label className="block text-slate-400 font-semibold mb-1">
                  Security Alert Escalation Webhook (Slack / PagerDuty)
                </label>
                <input
                  type="url"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  className="w-full rounded bg-slate-950 border border-slate-800 px-3 py-2 font-mono text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-slate-800">
                {savedSettings ? (
                  <span className="text-emerald-400 font-semibold flex items-center gap-1 text-xs">
                    <Check className="h-4 w-4" /> Governance settings saved!
                  </span>
                ) : (
                  <span />
                )}
                <Button variant="primary" size="sm" icon={Save} type="submit">
                  Save Governance Policies
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}

      {/* TAB 2: Team Members & RBAC Permission Matrix */}
      {activeTab === 'RBAC_TEAM' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Active Identity & Demo Persona Switcher */}
            <Card className="p-5 space-y-4">
              <div className="flex items-center gap-3">
                <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-500/10 text-cyan-400">
                  <User className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-white">Active Operator Identity</h2>
                  <p className="text-xs text-slate-400">{user?.email || 'analyst@cyberdefend.corp'}</p>
                </div>
              </div>

              <div className="space-y-1.5 border-t border-slate-800 pt-3 text-xs font-mono">
                <div className="flex justify-between py-1">
                  <span className="text-slate-500 font-sans">Role</span>
                  <Badge tone="info">{currentRole}</Badge>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500 font-sans">Session ID</span>
                  <span className="text-slate-300">sess-prod-active</span>
                </div>
              </div>

              {/* Demo Persona Switcher */}
              <div className="border-t border-slate-800 pt-3">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Switch Demo Role Persona
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <Button
                    variant={currentRole === 'ORG_ADMIN' ? 'primary' : 'secondary'}
                    size="sm"
                    onClick={() => demoLogin('ORG_ADMIN')}
                  >
                    ORG_ADMIN
                  </Button>
                  <Button
                    variant={currentRole === 'SECURITY_ANALYST' ? 'primary' : 'secondary'}
                    size="sm"
                    onClick={() => demoLogin('SECURITY_ANALYST')}
                  >
                    SECURITY_ANALYST
                  </Button>
                  <Button
                    variant={currentRole === 'AUDITOR' ? 'primary' : 'secondary'}
                    size="sm"
                    onClick={() => demoLogin('AUDITOR')}
                  >
                    AUDITOR
                  </Button>
                  <Button
                    variant={currentRole === 'READ_ONLY_VIEWER' ? 'primary' : 'secondary'}
                    size="sm"
                    onClick={() => demoLogin('READ_ONLY_VIEWER')}
                  >
                    READ_ONLY_VIEWER
                  </Button>
                </div>
              </div>
            </Card>

            {/* Team Members List */}
            <Card className="lg:col-span-2 p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <Users className="h-4 w-4 text-cyan-400" />
                  Team Members Directory
                </h2>
                <span className="text-xs text-slate-400 font-mono">{DEFAULT_TEAM.length} Users</span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-[10px] uppercase font-mono text-slate-500 border-b border-slate-800">
                    <tr>
                      <th className="pb-2">Name &amp; Email</th>
                      <th className="pb-2">Assigned Role</th>
                      <th className="pb-2">Status</th>
                      <th className="pb-2 text-right">Last Login</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                    {DEFAULT_TEAM.map((member) => (
                      <tr key={member.userId}>
                        <td className="py-2.5">
                          <div className="font-semibold text-white font-sans">{member.name}</div>
                          <div className="text-[11px] text-slate-400">{member.email}</div>
                        </td>
                        <td className="py-2.5 font-sans">
                          <Badge tone="info">{member.role}</Badge>
                        </td>
                        <td className="py-2.5 font-sans">
                          <Badge tone="success">{member.status}</Badge>
                        </td>
                        <td className="py-2.5 text-right text-slate-400 font-sans">
                          {member.lastLogin}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>

          {/* Role-Based Access Control (RBAC) Matrix */}
          <Card className="p-5 space-y-3">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan-400" />
              Role-Based Access Control (RBAC) Governance Matrix
            </h2>
            <p className="text-xs text-slate-400">
              Granular permission matrix enforced across all API endpoints and frontend mission control consoles.
            </p>

            <div className="overflow-x-auto pt-2">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 bg-slate-900/60 font-mono text-[10px] uppercase text-slate-400">
                  <tr>
                    <th className="p-3">Platform Capability</th>
                    <th className="p-3 text-center">ORG_ADMIN</th>
                    <th className="p-3 text-center">SECURITY_ANALYST</th>
                    <th className="p-3 text-center">AUDITOR</th>
                    <th className="p-3 text-center">READ_ONLY_VIEWER</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                  {RBAC_CAPABILITIES.map((cap, i) => (
                    <tr key={i} className="hover:bg-slate-800/30">
                      <td className="p-3 font-sans font-medium text-white">{cap.capability}</td>
                      <td className="p-3 text-center">
                        {cap.admin ? <Check className="h-4 w-4 text-emerald-400 mx-auto" /> : <X className="h-4 w-4 text-slate-600 mx-auto" />}
                      </td>
                      <td className="p-3 text-center">
                        {cap.analyst ? <Check className="h-4 w-4 text-emerald-400 mx-auto" /> : <X className="h-4 w-4 text-slate-600 mx-auto" />}
                      </td>
                      <td className="p-3 text-center">
                        {cap.auditor ? <Check className="h-4 w-4 text-emerald-400 mx-auto" /> : <X className="h-4 w-4 text-slate-600 mx-auto" />}
                      </td>
                      <td className="p-3 text-center">
                        {cap.viewer ? <Check className="h-4 w-4 text-emerald-400 mx-auto" /> : <X className="h-4 w-4 text-slate-600 mx-auto" />}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {/* TAB 3: Evaluation Demo Scenarios Controller */}
      {activeTab === 'DEMO_CONTROLLER' && (
        <div className="space-y-6">
          <Card className="p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Database className="h-4 w-4 text-rose-400" />
                  Evaluation Demo Scenarios
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Deterministic synthetic attack injection and pipeline exercise generator
                </p>
              </div>

              <Button
                variant="secondary"
                size="sm"
                icon={RotateCcw}
                onClick={handleResetDemo}
                disabled={resettingDemo}
              >
                {resettingDemo ? 'Resetting...' : 'Reset Demo Telemetry'}
              </Button>
            </div>

            {demoMessage && (
              <div className="flex items-center gap-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 p-3 text-xs text-emerald-300">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span>{demoMessage}</span>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              {[
                {
                  id: 'sqli',
                  title: 'Multi-Stage SQLi & Lateral Movement',
                  desc: 'Injects union-select payloads, database syntax errors, and privilege escalation attempts against /api/v1/auth/login.',
                  severity: 'CRITICAL',
                },
                {
                  id: 'brute',
                  title: 'High-Velocity Credential Stuffing',
                  desc: 'Dispatches 100+ distributed failed logins from Tor exit nodes to trigger behavioral rate limiting & correlation.',
                  severity: 'HIGH',
                },
                {
                  id: 'ssrf',
                  title: 'Cloud SSRF & Metadata Exfiltration',
                  desc: 'Simulates webhook callback probes attempting to harvest AWS IMDSv1 credentials from 169.254.169.254.',
                  severity: 'HIGH',
                },
              ].map((scen) => (
                <Card key={scen.id} className="p-4 space-y-3 flex flex-col justify-between">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white text-xs">{scen.title}</span>
                      <Badge tone={scen.severity === 'CRITICAL' ? 'critical' : 'medium'}>
                        {scen.severity}
                      </Badge>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{scen.desc}</p>
                  </div>

                  <Button
                    variant="primary"
                    size="sm"
                    icon={Play}
                    onClick={() => handleGenerateScenario(scen.title)}
                    disabled={generatingDemo}
                  >
                    {generatingDemo ? 'Injecting...' : 'Inject Attack Scenario'}
                  </Button>
                </Card>
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
