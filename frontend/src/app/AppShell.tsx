import { useEffect, useMemo, useState } from 'react';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  Bell,
  ChevronRight,
  Command,
  LogOut,
  Menu,
  Search,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react';
import { NAV_GROUPS, findNavItem } from './nav';
import { CommandPalette } from './CommandPalette';
import { useAuth } from '../features/auth/AuthProvider';
import { fetchDashboardSummary, fetchPlatformStatus } from '../lib/api/endpoints';
import { cn, Badge, Button } from '../components/ui/primitives';
import { formatNumber, initials, titleCase } from '../lib/format';

function Clock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return (
    <span className="font-mono text-[11px] tabular-nums text-slate-400">
      {now.toLocaleTimeString('en-US', { hour12: false })} UTC
    </span>
  );
}

function BrandMark() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-veltrix-cyan/20 to-veltrix-blue/20 ring-1 ring-inset ring-cyan-400/30">
        <ShieldCheck className="h-[18px] w-[18px] text-cyan-300" />
        <span className="absolute inset-0 rounded-xl shadow-glow" />
      </div>
      <div className="leading-tight">
        <div className="text-sm font-black tracking-[0.22em] text-white">VELTRIX</div>
        <div className="text-[9px] font-medium uppercase tracking-[0.2em] text-slate-500">
          Security Operations
        </div>
      </div>
    </div>
  );
}

function NavBadge({ kind }: { kind: 'incidents' | 'scans' }) {
  const { isAuthenticated } = useAuth();
  const { data } = useQuery({
    queryKey: ['dashboard', 'summary', 24],
    queryFn: () => fetchDashboardSummary(24),
    enabled: isAuthenticated,
    select: (response) => response.data,
  });

  if (!data) return null;
  const counts =
    kind === 'incidents'
      ? (data.kpis.criticalIncidents || 0) + (data.kpis.openIncidents || 0)
      : data.kpis.activeScans || 0;
  if (!counts) return null;

  return (
    <span
      className={cn(
        'ml-auto rounded-md px-1.5 py-0.5 font-mono text-[10px] font-semibold',
        kind === 'incidents'
          ? 'bg-rose-500/15 text-rose-300'
          : 'bg-cyan-500/15 text-cyan-300'
      )}
    >
      {formatNumber(counts)}
    </span>
  );
}

function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4 vx-scroll" aria-label="Primary">
      {NAV_GROUPS.map((group) => (
        <div key={group.label}>
          <div className="px-2.5 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">
            {group.label}
          </div>
          <div className="space-y-0.5">
            {group.items.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === '/'}
                  onClick={onNavigate}
                  className={({ isActive }) =>
                    cn(
                      'group relative flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] font-medium transition',
                      isActive
                        ? 'bg-cyan-500/10 text-white shadow-[inset_0_0_0_1px_rgba(0,242,254,0.18)]'
                        : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-100'
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      {isActive ? (
                        <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-full bg-cyan-300 shadow-[0_0_8px_rgba(0,242,254,0.8)]" />
                      ) : null}
                      <Icon
                        className={cn(
                          'h-4 w-4 shrink-0 transition',
                          isActive ? 'text-cyan-300' : 'text-slate-500 group-hover:text-slate-300'
                        )}
                      />
                      <span className="truncate">{item.label}</span>
                      {item.badge ? <NavBadge kind={item.badge} /> : null}
                    </>
                  )}
                </NavLink>
              );
            })}
          </div>
        </div>
      ))}
    </nav>
  );
}

function UserCard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  if (!user) return null;

  return (
    <div className="border-t border-veltrix-border/70 p-3">
      <div className="flex items-center gap-2.5 rounded-lg border border-veltrix-border/70 bg-veltrix-surface/60 p-2.5">
        <div className="grid h-8 w-8 place-items-center rounded-lg bg-gradient-to-br from-cyan-400/25 to-blue-500/20 text-[11px] font-bold text-cyan-200 ring-1 ring-inset ring-cyan-400/25">
          {initials(user.username)}
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12px] font-semibold text-slate-100">{user.username}</div>
          <div className="truncate text-[10px] text-slate-500">{titleCase(user.role)}</div>
        </div>
        <button
          type="button"
          aria-label="Sign out"
          onClick={async () => {
            await logout();
            navigate('/login');
          }}
          className="rounded-md p-1.5 text-slate-500 transition hover:bg-white/5 hover:text-rose-300"
        >
          <LogOut className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="mt-2 flex items-center justify-between px-1 text-[10px] text-slate-600">
        <span className="truncate font-mono">{user.orgId}</span>
        <span className="flex items-center gap-1">
          <span className="h-1.5 w-1.5 animate-pulse-soft rounded-full bg-emerald-400" />
          session live
        </span>
      </div>
    </div>
  );
}

export function AppShell() {
  const location = useLocation();
  const { isAuthenticated } = useAuth();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const active = findNavItem(location.pathname);

  const platform = useQuery({
    queryKey: ['platform', 'status'],
    queryFn: fetchPlatformStatus,
    refetchInterval: 60_000,
    enabled: isAuthenticated,
    retry: 1,
  });

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const breadcrumb = useMemo(() => {
    const item = active;
    if (!item || item.path === '/') return ['Command', 'Overview'];
    const group = NAV_GROUPS.find((entry) => entry.items.some((nav) => nav.path === item.path));
    return [group?.label || 'Console', item.label];
  }, [active]);

  return (
    <div className="flex min-h-screen bg-veltrix-bg">
      <div className="pointer-events-none fixed inset-0 bg-vx-radial opacity-70" aria-hidden />
      <div className="pointer-events-none fixed inset-x-0 top-0 h-64 bg-vx-grid opacity-[0.35]" aria-hidden />

      {/* Desktop sidebar */}
      <aside className="sticky top-0 z-30 hidden h-screen w-[248px] shrink-0 flex-col border-r border-veltrix-border/80 bg-veltrix-chrome/85 backdrop-blur-xl lg:flex">
        <div className="flex h-16 items-center border-b border-veltrix-border/70 px-4">
          <Link to="/" className="transition hover:opacity-90">
            <BrandMark />
          </Link>
        </div>
        <div className="px-3 pt-3">
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            className="flex w-full items-center gap-2 rounded-lg border border-veltrix-border/80 bg-veltrix-surface/60 px-2.5 py-2 text-left text-[12px] text-slate-500 transition hover:border-slate-600 hover:text-slate-300"
          >
            <Search className="h-3.5 w-3.5" />
            <span className="flex-1">Search console…</span>
            <span className="flex items-center gap-0.5 rounded border border-slate-700 px-1 py-0.5 font-mono text-[9px] text-slate-500">
              <Command className="h-2.5 w-2.5" />K
            </span>
          </button>
        </div>
        <SidebarNav />
        <UserCard />
      </aside>

      {/* Mobile drawer */}
      {mobileOpen ? (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
            aria-hidden
          />
          <aside className="relative flex h-full w-[264px] flex-col border-r border-veltrix-border bg-veltrix-chrome">
            <div className="flex h-16 items-center justify-between border-b border-veltrix-border/70 px-4">
              <BrandMark />
              <button
                type="button"
                onClick={() => setMobileOpen(false)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-white/5"
                aria-label="Close navigation"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <SidebarNav onNavigate={() => setMobileOpen(false)} />
            <UserCard />
          </aside>
        </div>
      ) : null}

      <div className="relative flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-veltrix-border/80 bg-veltrix-bg/80 px-4 backdrop-blur-xl sm:px-6">
          <button
            type="button"
            onClick={() => setMobileOpen(true)}
            className="rounded-lg border border-veltrix-border p-2 text-slate-400 transition hover:text-white lg:hidden"
            aria-label="Open navigation"
          >
            <Menu className="h-4 w-4" />
          </button>

          <div className="flex min-w-0 items-center gap-2 text-[12px]">
            <span className="hidden text-slate-500 sm:inline">{breadcrumb[0]}</span>
            <ChevronRight className="hidden h-3 w-3 text-slate-700 sm:inline" />
            <span className="truncate font-semibold text-slate-200">{breadcrumb[1]}</span>
          </div>

          <div className="ml-auto flex items-center gap-2">
            <div className="hidden items-center gap-2 rounded-lg border border-veltrix-border/70 bg-veltrix-surface/50 px-2.5 py-1.5 md:flex">
              <span className="h-1.5 w-1.5 animate-pulse-soft rounded-full bg-emerald-400" />
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                {platform.data ? `${platform.data.data.storageMode} engine` : 'connecting'}
              </span>
            </div>
            <div className="hidden rounded-lg border border-veltrix-border/70 bg-veltrix-surface/50 px-2.5 py-1.5 sm:block">
              <Clock />
            </div>
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className="rounded-lg border border-veltrix-border p-2 text-slate-400 transition hover:text-white"
              aria-label="Search console"
            >
              <Search className="h-4 w-4" />
            </button>
            <Link
              to="/incidents"
              className="relative rounded-lg border border-veltrix-border p-2 text-slate-400 transition hover:text-white"
              aria-label="Open incidents"
            >
              <Bell className="h-4 w-4" />
            </Link>
          </div>
        </header>

        <main className="min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <div className="mx-auto w-full max-w-[1500px] animate-fade-up">
            <Outlet />
          </div>
        </main>

        <footer className="border-t border-veltrix-border/60 px-4 py-4 sm:px-6 lg:px-8">
          <div className="mx-auto flex w-full max-w-[1500px] flex-col gap-2 text-[10px] text-slate-600 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-3 w-3" />
              <span>
                VELTRIX {platform.data?.data.platform.version || '1.0.0'} ·{' '}
                {platform.data ? titleCase(platform.data.data.environment) : 'development'}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <Badge tone="info">
                <Sparkles className="h-2.5 w-2.5" />
                Authorized telemetry only
              </Badge>
              <span className="font-mono">
                uptime{' '}
                {platform.data
                  ? `${Math.floor(platform.data.data.uptimeSeconds / 60)}m`
                  : '—'}
              </span>
            </div>
          </div>
        </footer>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}

export function ShellErrorFallback() {
  const navigate = useNavigate();
  return (
    <div className="grid min-h-screen place-items-center p-6">
      <div className="vx-card max-w-md p-6 text-center">
        <div className="text-sm font-semibold text-white">Console session expired</div>
        <p className="mt-2 text-xs text-slate-400">
          Your session could not be restored. Sign in again to continue.
        </p>
        <Button variant="primary" className="mt-4" onClick={() => navigate('/login')}>
          Return to sign in
        </Button>
      </div>
    </div>
  );
}
