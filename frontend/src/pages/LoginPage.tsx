import { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowRight,
  Fingerprint,
  KeyRound,
  Loader2,
  Lock,
  Radar,
  ShieldCheck,
  Siren,
  Sparkles,
  Workflow,
} from 'lucide-react';
import { useAuth } from '../features/auth/AuthProvider';
import { fetchPlatformStatus } from '../lib/api/endpoints';
import { Button, Input } from '../components/ui/primitives';
import { titleCase } from '../lib/format';

const DEMO_ROLES = [
  {
    role: 'ORG_ADMIN' as const,
    label: 'Org admin',
    hint: 'Full tenant control · seeding · approvals',
  },
  {
    role: 'SECURITY_ANALYST' as const,
    label: 'Analyst',
    hint: 'Triage, detections and response requests',
  },
  {
    role: 'READ_ONLY_VIEWER' as const,
    label: 'Auditor',
    hint: 'Read-only posture and audit evidence',
  },
];

const CAPABILITIES = [
  { icon: Radar, title: 'Detection engine', copy: 'Sigma-inspired rules with confidence tiers' },
  { icon: Workflow, title: 'Correlation', copy: 'Multi-stage attacks folded into incidents' },
  { icon: ShieldCheck, title: 'Response queue', copy: 'Human-approved, fully auditable actions' },
  { icon: Fingerprint, title: 'Audit ledger', copy: 'SHA-256 hash-chain, tamper evident' },
];

export function LoginPage() {
  const { isAuthenticated, isLoggingIn, error, login, demoLogin, clearError } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [orgId, setOrgId] = useState('org-enterprise-01');

  const platform = useQuery({
    queryKey: ['platform', 'status'],
    queryFn: fetchPlatformStatus,
    retry: 0,
  });

  useEffect(() => {
    clearError();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (isAuthenticated) {
    const from = (location.state as { from?: string } | null)?.from || '/';
    return <Navigate to={from} replace />;
  }

  const destination = (location.state as { from?: string } | null)?.from || '/';

  return (
    <div className="relative grid min-h-screen lg:grid-cols-[1.1fr_0.9fr]">
      {/* Narrative panel */}
      <div className="relative hidden flex-col justify-between overflow-hidden border-r border-veltrix-border/70 bg-veltrix-chrome p-10 lg:flex">
        <div className="pointer-events-none absolute inset-0 bg-vx-grid opacity-25" aria-hidden />

        <div className="relative">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-control border border-veltrix-border bg-veltrix-elevated">
              <ShieldCheck className="h-[18px] w-[18px] text-veltrix-cyan" />
            </div>
            <div>
              <div className="text-[13px] font-semibold tracking-[0.28em] text-white">VELTRIX</div>
              <div className="text-[10px] uppercase tracking-[0.22em] text-slate-500">
                Autonomous threat detection
              </div>
            </div>
          </div>

          <h1 className="mt-14 max-w-lg text-[40px] font-medium leading-[1.06] tracking-[-0.025em] text-white">
            See the attack
            <span className="block text-veltrix-cyan">before it lands.</span>
          </h1>
          <p className="mt-4 max-w-md text-[14px] leading-relaxed text-veltrix-textMuted">
            A unified SOC console for authorized website telemetry: ingest, detect, correlate,
            respond and prove it happened — end to end, in one tenant-scoped surface.
          </p>

          <div className="mt-10 grid max-w-lg grid-cols-2 gap-3">
            {CAPABILITIES.map((capability) => {
              const Icon = capability.icon;
              return (
                <div
                  key={capability.title}
                  className="rounded-panel border border-veltrix-border bg-veltrix-card p-3.5"
                >
                  <Icon className="h-4 w-4 text-veltrix-cyan" />
                  <div className="mt-2 text-[12px] font-semibold text-slate-100">
                    {capability.title}
                  </div>
                  <div className="mt-0.5 text-[10px] leading-relaxed text-slate-500">
                    {capability.copy}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="relative mt-10 flex items-center gap-4 text-[10px] text-slate-600">
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden />
            {platform.data ? `${platform.data.data.storageMode} engine online` : 'engine status pending'}
          </span>
          <span className="h-3 w-px bg-slate-800" />
          <span>{platform.data?.data.platform.tagline || 'Detect · Correlate · Respond'}</span>
        </div>
      </div>

      {/* Auth panel */}
      <div className="vx-stage relative flex items-center justify-center px-5 py-12 sm:px-10">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <div className="grid h-9 w-9 place-items-center rounded-control border border-veltrix-border bg-veltrix-elevated">
              <ShieldCheck className="h-4 w-4 text-veltrix-cyan" />
            </div>
            <div className="text-[13px] font-semibold tracking-[0.28em] text-white">VELTRIX</div>
          </div>

          <div className="vx-card p-6">
            <div className="flex items-center gap-2">
              <Lock className="h-3.5 w-3.5 text-veltrix-cyan" />
              <span className="vx-label">Analyst access</span>
            </div>
            <h2 className="mt-2 text-[20px] font-medium tracking-[-0.01em] text-white">
              Sign in to console
            </h2>
            <p className="mt-1 text-xs text-slate-500">
              Tenant-scoped session with role-based permissions.
            </p>

            <form
              className="mt-6 space-y-3.5"
              onSubmit={async (event) => {
                event.preventDefault();
                try {
                  await login(email, password, orgId || undefined);
                  navigate(destination, { replace: true });
                } catch {
                  // Error is surfaced through the auth context banner.
                }
              }}
            >
              <label className="block space-y-1.5">
                <span className="vx-label">Work email</span>
                <Input
                  type="email"
                  autoComplete="username"
                  required
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="analyst@cyberdefend.corp"
                />
              </label>
              <label className="block space-y-1.5">
                <span className="vx-label">Password</span>
                <Input
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="••••••••••••"
                />
              </label>
              <label className="block space-y-1.5">
                <span className="vx-label">Organization</span>
                <Input
                  value={orgId}
                  onChange={(event) => setOrgId(event.target.value)}
                  placeholder="org-enterprise-01"
                />
              </label>

              {error ? (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-200">
                  {error}
                </div>
              ) : null}

              <Button
                type="submit"
                variant="primary"
                className="w-full"
                disabled={isLoggingIn}
              >
                {isLoggingIn ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <KeyRound className="h-4 w-4" />
                )}
                {isLoggingIn ? 'Authenticating…' : 'Enter console'}
              </Button>
            </form>

            <div className="my-5 flex items-center gap-3">
              <span className="h-px flex-1 bg-veltrix-border" />
              <span className="text-[10px] uppercase tracking-widest text-slate-600">or demo</span>
              <span className="h-px flex-1 bg-veltrix-border" />
            </div>

            <div className="space-y-2">
              {DEMO_ROLES.map((role) => (
                <button
                  key={role.role}
                  type="button"
                  disabled={isLoggingIn}
                  onClick={async () => {
                    try {
                      await demoLogin(role.role);
                      navigate(destination, { replace: true });
                    } catch {
                      // Handled by the auth banner.
                    }
                  }}
                  className="group flex w-full items-center gap-3 rounded-control border border-veltrix-border bg-veltrix-chrome px-3 py-2.5 text-left transition-colors hover:border-veltrix-borderStrong hover:bg-veltrix-elevated disabled:opacity-60"
                >
                  <Sparkles className="h-3.5 w-3.5 text-slate-500 transition-colors group-hover:text-veltrix-cyan" />
                  <span className="min-w-0 flex-1">
                    <span className="block text-[12px] font-semibold text-slate-100">
                      {role.label}
                    </span>
                    <span className="block truncate text-[10px] text-slate-500">{role.hint}</span>
                  </span>
                  <ArrowRight className="h-3.5 w-3.5 text-slate-600 transition-colors group-hover:text-veltrix-cyan" />
                </button>
              ))}
            </div>

            <p className="mt-5 flex items-start gap-1.5 text-[10px] leading-relaxed text-slate-600">
              <Siren className="mt-0.5 h-3 w-3 shrink-0 text-amber-400/70" />
              Demo identities are development-only and are rejected when the API runs in production
              or against Cognito.
            </p>
          </div>

          <p className="mt-6 text-center text-[10px] text-slate-600">
            {platform.data
              ? `${titleCase(platform.data.data.environment)} · v${platform.data.data.platform.version}`
              : 'VELTRIX console'}
          </p>
        </div>
      </div>
    </div>
  );
}
