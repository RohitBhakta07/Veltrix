import { useEffect, useRef, useState } from 'react';

interface CountUpOptions {
  /** Only meaningful metrics animate; identifiers and timestamps never do. */
  enabled: boolean;
  delay?: number;
  duration?: number;
  /** Changes on replay so the count restarts cleanly. */
  resetKey?: number;
}

/**
 * Counts from zero to the real backend value once a region resolves.
 * Without `enabled` it returns the target immediately, so non-reveal pages and
 * reduced-motion sessions show real numbers from the first frame.
 */
export function useCountUp(
  target: number | null | undefined,
  { enabled, delay = 0, duration = 620, resetKey = 0 }: CountUpOptions
): number {
  const resolvedTarget = typeof target === 'number' && Number.isFinite(target) ? target : null;
  const [value, setValue] = useState<number>(resolvedTarget ?? 0);
  const firstRun = useRef(true);

  useEffect(() => {
    if (resolvedTarget === null) return;
    if (!enabled) {
      setValue(resolvedTarget);
      return;
    }

    let frame = 0;
    let timer = 0;
    let cancelled = false;

    const start = () => {
      if (cancelled) return;
      const startedAt = performance.now();
      const step = (now: number) => {
        if (cancelled) return;
        const progress = Math.min(1, (now - startedAt) / Math.max(1, duration));
        const eased = 1 - Math.pow(1 - progress, 3);
        setValue(resolvedTarget * eased);
        if (progress < 1) frame = requestAnimationFrame(step);
      };
      frame = requestAnimationFrame(step);
    };

    // Replays restart from zero; the first mount honours the reveal delay.
    if (firstRun.current) {
      timer = window.setTimeout(start, Math.max(0, delay));
      firstRun.current = false;
    } else {
      setValue(0);
      timer = window.setTimeout(start, Math.max(0, delay));
    }

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      cancelAnimationFrame(frame);
    };
  }, [resolvedTarget, enabled, delay, duration, resetKey]);

  return resolvedTarget === null ? 0 : value;
}
