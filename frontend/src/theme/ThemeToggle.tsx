import { Monitor, Moon, Sun } from 'lucide-react';
import { cn } from '../components/ui/primitives';
import { useTheme, type ThemePreference } from './ThemeProvider';

const OPTIONS: Array<{
  id: ThemePreference;
  label: string;
  icon: typeof Sun;
}> = [
  { id: 'light', label: 'Light theme', icon: Sun },
  { id: 'dark', label: 'Dark theme', icon: Moon },
  { id: 'system', label: 'Match system theme', icon: Monitor },
];

/**
 * Compact three-way theme switch. Radio semantics so arrow keys work the way a
 * segmented control is expected to behave.
 */
export function ThemeToggle({ className }: { className?: string }) {
  const { preference, setPreference } = useTheme();

  return (
    <div
      role="radiogroup"
      aria-label="Theme"
      className={cn(
        'flex items-center gap-0.5 rounded-control border border-veltrix-border bg-veltrix-surface p-0.5',
        className
      )}
    >
      {OPTIONS.map((option) => {
        const Icon = option.icon;
        const selected = preference === option.id;
        return (
          <button
            key={option.id}
            type="button"
            role="radio"
            aria-checked={selected}
            aria-label={option.label}
            title={option.label}
            onClick={() => setPreference(option.id)}
            className={cn(
              'grid h-6 w-6 place-items-center rounded-[3px] transition-colors',
              selected
                ? 'bg-veltrix-subtle text-veltrix-cyan'
                : 'text-slate-500 hover:text-slate-200'
            )}
          >
            <Icon className="h-3 w-3" aria-hidden />
          </button>
        );
      })}
    </div>
  );
}
