import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowRight, Command, DatabaseZap, LogOut, Search } from 'lucide-react';
import { NAV_ITEMS } from './nav';
import { Modal } from '../components/ui/primitives';
import { useAuth } from '../features/auth/AuthProvider';
import { seedDemoData } from '../lib/api/endpoints';

interface PaletteEntry {
  id: string;
  label: string;
  hint: string;
  keywords: string;
  icon: typeof Search;
  run: () => void | Promise<void>;
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const [status, setStatus] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { can, logout } = useAuth();

  useEffect(() => {
    if (open) {
      setQuery('');
      setActive(0);
      setStatus(null);
      window.setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  const entries = useMemo<PaletteEntry[]>(() => {
    const navEntries: PaletteEntry[] = NAV_ITEMS.map((item) => ({
      id: item.path,
      label: item.label,
      hint: item.description,
      keywords: `${item.label} ${item.description} ${item.path}`,
      icon: item.icon,
      run: () => {
        navigate(item.path);
        onClose();
      },
    }));

    const actions: PaletteEntry[] = [];
    if (can(['ORG_ADMIN', 'SUPER_ADMIN'])) {
      actions.push({
        id: 'seed-demo',
        label: 'Load demo dataset',
        hint: 'Seed verified assets, attacks, incidents and audit records',
        keywords: 'demo seed dataset attack simulation',
        icon: DatabaseZap,
        run: async () => {
          setStatus('Seeding demo dataset…');
          try {
            const result = await seedDemoData();
            await queryClient.invalidateQueries();
            setStatus(
              result.data.alreadySeeded
                ? 'Demo dataset already present.'
                : `Seeded ${result.data.sites} assets, ${result.data.incidents} incidents.`
            );
          } catch (err) {
            setStatus(err instanceof Error ? err.message : 'Demo seed failed.');
          }
        },
      });
    }
    actions.push({
      id: 'logout',
      label: 'Sign out',
      hint: 'End the current console session',
      keywords: 'logout sign out session',
      icon: LogOut,
      run: async () => {
        await logout();
        navigate('/login');
        onClose();
      },
    });

    return [...navEntries, ...actions];
  }, [can, navigate, onClose, queryClient, logout]);

  const results = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return entries;
    return entries.filter((entry) => entry.keywords.toLowerCase().includes(normalized));
  }, [entries, query]);

  useEffect(() => {
    setActive(0);
  }, [query]);

  const handleKey = (event: React.KeyboardEvent) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActive((current) => Math.min(results.length - 1, current + 1));
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActive((current) => Math.max(0, current - 1));
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const entry = results[active];
      if (entry) void entry.run();
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Command palette"
      description="Jump to a module or run a console action"
      size="lg"
    >
      <div className="space-y-4" onKeyDown={handleKey}>
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search modules, incidents, actions…"
            className="vx-input pl-9"
          />
          <span className="pointer-events-none absolute right-3 top-1/2 hidden -translate-y-1/2 items-center gap-1 text-[10px] text-slate-500 sm:flex">
            <Command className="h-3 w-3" /> K
          </span>
        </div>

        <div className="max-h-[360px] space-y-1 overflow-y-auto vx-scroll">
          {results.length === 0 ? (
            <div className="px-3 py-10 text-center text-xs text-slate-500">
              No matching command or module.
            </div>
          ) : (
            results.map((entry, index) => {
              const Icon = entry.icon;
              return (
                <button
                  key={entry.id}
                  type="button"
                  onMouseEnter={() => setActive(index)}
                  onClick={() => void entry.run()}
                  className={`flex w-full items-center gap-3 rounded-control px-3 py-2.5 text-left transition-colors ${
                    active === index
                      ? 'bg-veltrix-elevated text-white shadow-[inset_2px_0_0_0_var(--dp-color-signal)]'
                      : 'text-slate-300 hover:bg-white/[0.035]'
                  }`}
                >
                  <span className="rounded-control border border-veltrix-border bg-veltrix-surface p-1.5 text-slate-400">
                    <Icon className="h-3.5 w-3.5" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-semibold">{entry.label}</span>
                    <span className="block truncate text-[10px] text-slate-500">{entry.hint}</span>
                  </span>
                  <ArrowRight className="h-3.5 w-3.5 text-slate-600" />
                </button>
              );
            })
          )}
        </div>

        {status ? (
          <div className="rounded-control border border-veltrix-border bg-veltrix-elevated px-3 py-2 text-[11px] text-slate-300">
            {status}
          </div>
        ) : null}

        <div className="flex items-center justify-between border-t border-veltrix-border pt-3 text-[10px] text-slate-500">
          <span>↑ ↓ navigate · Enter select · Esc close</span>
          <span>{results.length} results</span>
        </div>
      </div>
    </Modal>
  );
}
