import { useEffect, useMemo, type CSSProperties, type ReactNode } from 'react';
import { cn } from '../components/ui/primitives';
import { BlueprintSketch } from './BlueprintSketch';
import { SectionRevealContext, useReveal } from './RevealProvider';
import { REVEAL_TIMING, revealDrawDelay, revealResolveDelay } from './timing';

/**
 * Marks one region of the dashboard as part of the blueprint reveal.
 *
 * While the sequence runs, the region shows its pencil draft and the real
 * content fades in on cue. Outside the sequence — or for reduced motion — the
 * content is simply present: no wrapper animation, no hidden information.
 */
export function RevealSection({
  index,
  children,
  className,
  sketch = true,
}: {
  index: number;
  children: ReactNode;
  className?: string;
  /** Disable the draft for regions where a sketch would be noise. */
  sketch?: boolean;
}) {
  const { active, run, registerSection } = useReveal();

  useEffect(() => {
    registerSection(index);
  }, [index, registerSection]);

  const drawDelay = revealDrawDelay(index);
  const resolveDelay = revealResolveDelay(index);

  const style = {
    '--vx-draw': `${REVEAL_TIMING.draw}ms`,
    '--vx-draw-delay': `${drawDelay}ms`,
    '--vx-resolve-delay': `${resolveDelay}ms`,
  } as CSSProperties;

  const sectionValue = useMemo(
    () => ({ active, resolveDelay, run }),
    [active, resolveDelay, run]
  );

  return (
    <SectionRevealContext.Provider value={sectionValue}>
      <div className={cn('relative', className)} data-reveal={active ? 'on' : undefined} style={style}>
        {active && sketch ? (
          <BlueprintSketch index={index} drawDelay={drawDelay} resolveDelay={resolveDelay} />
        ) : null}
        <div className="vx-reveal-body">{children}</div>
      </div>
    </SectionRevealContext.Provider>
  );
}
