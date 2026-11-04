import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { REVEAL_PLAYED_KEY, revealTotalDuration } from './timing';

interface RevealContextValue {
  /** True while the blueprint is being drafted; real content is inert. */
  active: boolean;
  /** Increments on replay so counters restart. */
  run: number;
  sectionCount: number;
  registerSection: (index: number) => void;
  replay: () => void;
  reducedMotion: boolean;
}

const noop = () => undefined;

const RevealContext = createContext<RevealContextValue>({
  active: false,
  run: 0,
  sectionCount: 0,
  registerSection: noop,
  replay: noop,
  reducedMotion: true,
});

interface SectionRevealValue {
  active: boolean;
  resolveDelay: number;
  run: number;
}

/**
 * Safe default of `active: false` means any component using this outside the
 * dashboard (or in a reduced-motion session) simply shows real values.
 */
const SectionRevealContext = createContext<SectionRevealValue>({
  active: false,
  resolveDelay: 0,
  run: 0,
});

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function revealAlreadyPlayed(): boolean {
  try {
    return window.sessionStorage.getItem(REVEAL_PLAYED_KEY) === '1';
  } catch {
    return false;
  }
}

/**
 * Owns the blueprint reveal lifecycle. Sections draw themselves through CSS
 * animations; this provider only decides when the sequence starts, how long it
 * runs, and how to replay it — so no animation frame loop drives React renders.
 */
export function RevealProvider({ children }: { children: ReactNode }) {
  const [reducedMotion, setReducedMotion] = useState<boolean>(() => prefersReducedMotion());
  const [sectionCount, setSectionCount] = useState(0);
  const [run, setRun] = useState(0);
  const [active, setActive] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    if (prefersReducedMotion()) return false;
    return !revealAlreadyPlayed();
  });

  // Follow the OS setting live, and never trap a user in animation.
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = (event: MediaQueryListEvent) => {
      setReducedMotion(event.matches);
      if (event.matches) setActive(false);
    };
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);

  const registerSection = useCallback((index: number) => {
    setSectionCount((current) => (current > index ? current : index + 1));
  }, []);

  // End the sequence (and remember it for this session) once every region resolved.
  useEffect(() => {
    if (!active) return;
    const total = revealTotalDuration(sectionCount);
    const timer = window.setTimeout(() => {
      setActive(false);
      try {
        window.sessionStorage.setItem(REVEAL_PLAYED_KEY, '1');
      } catch {
        /* Non-fatal: the reveal simply replays on the next visit. */
      }
    }, total);
    return () => window.clearTimeout(timer);
  }, [active, sectionCount]);

  const replay = useCallback(() => {
    if (prefersReducedMotion()) return;
    // Two frames apart so the CSS animations restart from their keyframes.
    setActive(false);
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        setRun((current) => current + 1);
        setActive(true);
      });
    });
  }, []);

  const value = useMemo<RevealContextValue>(
    () => ({ active, run, sectionCount, registerSection, replay, reducedMotion }),
    [active, run, sectionCount, registerSection, replay, reducedMotion]
  );

  return <RevealContext.Provider value={value}>{children}</RevealContext.Provider>;
}

export function useReveal(): RevealContextValue {
  return useContext(RevealContext);
}

export function useSectionReveal(): SectionRevealValue {
  return useContext(SectionRevealContext);
}

export { SectionRevealContext };
