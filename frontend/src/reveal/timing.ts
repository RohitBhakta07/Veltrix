/**
 * Blueprint reveal timing.
 *
 * Values follow the reference rhythm. `stagger` is the one deliberate
 * deviation: the reference spends 1500ms of *animation budget* per section
 * (tempo 1.3, amortised over the draft), which would hold an analyst for more
 * than ten seconds on a seven-section dashboard. Everything else is applied
 * verbatim.
 */
export const REVEAL_TIMING = {
  headerLead: 500,
  sectionStagger: 1500,
  tempo: 1.3,
  sketchMorph: 2000,
  morphMove: 700,
  morphSweep: 650,
  resolve: 460,
  interaction: 140,

  /** Section-to-section delay actually used (~250ms). */
  stagger: Math.round(1500 / 1.3 / 4.6),

  /** How long one section's pencil strokes take to draw. */
  draw: 620,

  /** Values count up as their region resolves. */
  countUp: 620,
} as const;

export function revealDrawDelay(index: number): number {
  return REVEAL_TIMING.headerLead + index * REVEAL_TIMING.stagger;
}

/** When a section's sketch starts resolving into real UI. */
export function revealResolveDelay(index: number): number {
  return revealDrawDelay(index) + REVEAL_TIMING.draw + 140;
}

/** Total reveal length for a dashboard of `sections` regions. */
export function revealTotalDuration(sections: number): number {
  const last = Math.max(0, sections - 1);
  return revealResolveDelay(last) + REVEAL_TIMING.resolve + 120;
}

export const REVEAL_PLAYED_KEY = 'veltrix.reveal.played';
