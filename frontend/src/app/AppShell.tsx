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
import { ThemeToggle } from '../theme/ThemeToggle';
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
    <span className="font-mono text-[11px] tabular-nums text-veltrix-textMeta">
      {now.toLocaleTimeString('en-US', { hour12: false })} UTC
    </span>
  );
}

function BrandMark() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="grid h-8 w-8 place-items-center rounded-control border border-veltrix-border bg-veltrix-elevated">
        <ShieldCheck className="h-[17px] w-[17px] text-veltrix-cyan" />
      </div>
      <div className="leading-tight">
        <div className="text-[12px] font-semibold tracking-[0.2em] text-white">VELTRIX</div>
        <div className="text-[9px] font-medium uppercase tracking-[0.18em] text-veltrix-textMeta">
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
        'ml-auto rounded-control px-1.5 py-0.5 font-mono text-[10px] font-medium tabular-nums',
        kind === 'incidents'
          ? 'bg-rose-500/15 text-rose-300'
          : 'bg-white/[0.06] text-veltrix-textMeta'
      )}
    >
      {formatNumber(counts)}
    </span>
  );
}

function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="vx-scroll flex-1 space-y-5 overflow-y-auto px-2.5 py-4" aria-label="Primary">
      {NAV_GROUPS.map((group) => (
        <div key={group.label}>
          <div className="px-2.5 pb-1.5 text-[10px] font-medium uppercase tracking-[0.16em] text-veltrix-textMeta">
            {group.label}
          </div>
          <div className="space-y-px">
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
                      'group relative flex items-center gap-2.5 rounded-control px-2.5 py-2 text-[13px] transition-colors',
                      isActive
                        ? 'bg-veltrix-elevated font-medium text-white'
                        : 'font-normal text-slate-400 hover:bg-white/[0.035] hover:text-slate-200'
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      {isActive ? (
                        <span
                          className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-veltrix-cyan"
                          aria-hidden
                        />
                      ) : null}
                      <Icon
                        className={cn(
                          'h-4 w-4 shrink-0 transition-colors',
                          isActive
                            ? 'text-veltrix-cyan'
                            : 'text-slate-500 group-hover:text-slate-300'
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
    <div className="border-t border-veltrix-border p-3">
      <div className="flex items-center gap-2.5 rounded-control border border-veltrix-border bg-veltrix-chrome px-2.5 py-2">
        <div className="grid h-7 w-7 place-items-center rounded-control border border-veltrix-border bg-veltrix-elevated font-mono text-[10px] font-medium text-slate-300">
          {initials(user.username)}
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12px] font-medium text-slate-100">{user.username}</div>
          <div className="truncate text-[10px] text-veltrix-textMeta">{titleCase(user.role)}</div>
        </div>
        <button
          type="button"
          aria-label="Sign out"
          onClick={async () => {
            await logout();
            navigate('/login');
          }}
          className="rounded-control p-1.5 text-slate-500 transition-colors hover:bg-white/[0.05] hover:text-rose-300"
        >
          <LogOut className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="mt-2 flex items-center justify-between px-1 font-mono text-[10px] text-slate-600">
        <span className="truncate">{user.orgId}</span>
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden />
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
      {/* Desktop sidebar */}
      <aside className="sticky top-0 z-30 hidden h-screen w-[240px] shrink-0 flex-col border-r border-veltrix-border bg-veltrix-surface lg:flex">
        <div className="flex h-16 items-center border-b border-veltrix-border px-4">
          <Link to="/" className="transition-colors hover:opacity-85">
            <BrandMark />
          </Link>
        </div>
        <div className="px-2.5 pt-3">
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            className="flex w-full items-center gap-2 rounded-control border border-veltrix-border bg-veltrix-chrome px-2.5 py-2 text-left text-[12px] text-veltrix-textMeta transition-colors hover:border-veltrix-borderStrong hover:text-slate-300"
          >
            <Search className="h-3.5 w-3.5" />
            <span className="flex-1">Search console…</span>
            <span className="flex items-center gap-0.5 rounded-[2px] border border-veltrix-border bg-veltrix-elevated px-1 py-0.5 font-mono text-[9px] text-slate-500">
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
            className="absolute inset-0 bg-black/75"
            onClick={() => setMobileOpen(false)}
            aria-hidden
          />
          <aside className="relative flex h-full w-[264px] flex-col border-r border-veltrix-border bg-veltrix-surface">
            <div className="flex h-16 items-center justify-between border-b border-veltrix-border px-4">
              <BrandMark />
              <button
                type="button"
                onClick={() => setMobileOpen(false)}
                className="rounded-control p-1.5 text-slate-400 transition-colors hover:bg-white/[0.05]"
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
        <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-veltrix-border bg-veltrix-bg px-4 sm:px-6">
          <button
            type="button"
            onClick={() => setMobileOpen(true)}
            className="rounded-control border border-veltrix-border p-2 text-slate-400 transition-colors hover:text-white lg:hidden"
            aria-label="Open navigation"
          >
            <Menu className="h-4 w-4" />
          </button>

          <div className="flex min-w-0 items-center gap-2 text-[12px]">
            <span className="hidden text-veltrix-textMeta sm:inline">{breadcrumb[0]}</span>
            <ChevronRight className="hidden h-3 w-3 text-slate-700 sm:inline" />
            <span className="truncate font-medium text-slate-100">{breadcrumb[1]}</span>
          </div>

          <div className="ml-auto flex items-center gap-2">
            <div className="hidden items-center gap-2 rounded-control border border-veltrix-border bg-veltrix-surface px-2.5 py-1.5 md:flex">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden />
              <span className="text-[10px] font-medium uppercase tracking-[0.1em] text-veltrix-textMeta">
                {platform.data ? `${platform.data.data.storageMode} engine` : 'connecting'}
              </span>
            </div>
            <div className="hidden rounded-control border border-veltrix-border bg-veltrix-surface px-2.5 py-1.5 sm:block">
              <Clock />
            </div>
            <ThemeToggle className="hidden sm:flex" />
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className="rounded-control border border-veltrix-border p-2 text-slate-400 transition-colors hover:border-veltrix-borderStrong hover:text-white"
              aria-label="Search console"
            >
              <Search className="h-4 w-4" />
            </button>
            <Link
              to="/incidents"
              className="relative rounded-control border border-veltrix-border p-2 text-slate-400 transition-colors hover:border-veltrix-borderStrong hover:text-white"
              aria-label="Open incidents"
            >
              <Bell className="h-4 w-4" />
            </Link>
          </div>
        </header>

        <main className="min-w-0 flex-1 px-[clamp(20px,4vw,48px)] py-7">
          <div className="vx-content animate-fade-up">
            <Outlet />
          </div>
        </main>

        <footer className="border-t border-veltrix-border px-[clamp(20px,4vw,48px)] py-4">
          <div className="vx-content flex flex-col gap-2 font-mono text-[10px] text-slate-600 sm:flex-row sm:items-center sm:justify-between">
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
              <span>
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
        <div className="text-sm font-medium text-white">Console session expired</div>
        <p className="mt-2 text-xs text-veltrix-textMuted">
          Your session could not be restored. Sign in again to continue.
        </p>
        <Button variant="primary" className="mt-4" onClick={() => navigate('/login')}>
          Return to sign in
        </Button>
      </div>
    </div>
  );
}
