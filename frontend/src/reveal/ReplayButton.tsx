import { RotateCcw } from 'lucide-react';
import { cn } from '../components/ui/primitives';
import { useReveal } from './RevealProvider';

/**
 * Replays the visual reveal only. It never re-requests data or triggers any
 * security operation — the underlying queries are untouched.
 */
export function ReplayButton() {
  const { replay, active, reducedMotion } = useReveal();
  const disabled = active || reducedMotion;

  return (
    <div className="pointer-events-none sticky bottom-4 z-10 flex justify-end">
      <button
        type="button"
        onClick={replay}
        disabled={disabled}
        title={
          reducedMotion
            ? 'Replay is unavailable while reduced motion is enabled'
            : 'Replay the blueprint reveal'
        }
        className={cn(
          'pointer-events-auto inline-flex items-center gap-1.5 rounded-control border border-veltrix-border bg-veltrix-elevated/95 px-2.5 py-1.5 text-[11px] font-medium text-slate-300 shadow-card transition-colors',
          'hover:border-veltrix-borderStrong hover:text-slate-100',
          'disabled:cursor-not-allowed disabled:opacity-55 disabled:hover:border-veltrix-border'
        )}
      >
        <RotateCcw className={cn('h-3 w-3', active && 'opacity-60')} aria-hidden />
        {active ? 'Drafting…' : 'Replay reveal'}
      </button>
    </div>
  );
}
