import { useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import { REVEAL_TIMING } from './timing';

interface Stroke {
  d: string;
  /** Relative duration factor — strokes finish at slightly different times. */
  k: number;
  /** Extra delay so the draft builds outward instead of appearing at once. */
  delay: number;
  className: string;
}

/** Deterministic PRNG so a region always drafts the same way. */
function mulberry32(seed: number): () => number {
  let state = seed;
  return () => {
    state |= 0;
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function buildStrokes(width: number, height: number, index: number): Stroke[] {
  const random = mulberry32(index * 7919 + 17);
  const wobble = (amount = 1.8) => (random() * 2 - 1) * amount;
  const k = () => 0.72 + random() * 0.42;

  const inset = 1.5;
  const radius = 6;
  const left = inset + wobble(0.8);
  const top = inset + wobble(0.8);
  const right = width - inset + wobble(0.8);
  const bottom = height - inset + wobble(0.8);

  const strokes: Stroke[] = [];

  // Outline in four passes so the frame reads as drafted, not vector-perfect.
  const outline = [
    `M ${left + radius} ${top}`,
    `L ${right - radius} ${top + wobble(0.7)}`,
    `M ${right} ${top + radius}`,
    `L ${right} ${bottom - radius}`,
    `M ${right - radius} ${bottom}`,
    `L ${left + radius} ${bottom + wobble(0.7)}`,
    `M ${left} ${bottom - radius}`,
    `L ${left} ${top + radius}`,
  ];
  outline.forEach((d, i) => {
    strokes.push({ d, k: k(), delay: i * 45, className: 'vx-sketch-stroke' });
  });

  // Corner crops — the registration marks of a drafting sheet.
  const crop = 7;
  const gap = 4;
  const corners: Array<[number, number, number, number]> = [
    [left - gap, top - gap, 1, 1],
    [right + gap, top - gap, -1, 1],
    [left - gap, bottom + gap, 1, -1],
    [right + gap, bottom + gap, -1, -1],
  ];
  corners.forEach(([x, y, dx, dy], i) => {
    strokes.push({
      d: `M ${x} ${y + crop * dy} L ${x} ${y} L ${x + crop * dx} ${y}`,
      k: k(),
      delay: 90 + i * 30,
      className: 'vx-sketch-stroke is-faint',
    });
  });

  // Measurement ticks along the top edge.
  for (let x = left + 22; x < right - 12; x += 38) {
    strokes.push({
      d: `M ${x} ${top - 3} L ${x} ${top + 3}`,
      k: 0.55,
      delay: 120 + (x / Math.max(1, width)) * 160,
      className: 'vx-sketch-stroke is-tick',
    });
  }

  // Interior construction: a heading rule and a few content guides.
  if (width > 90 && height > 60) {
    const pad = 16;
    strokes.push({
      d: `M ${pad + 4} ${top + 22} L ${pad + 4 + Math.min(132, width * 0.36)} ${top + 22 + wobble(0.6)}`,
      k: k(),
      delay: 220,
      className: 'vx-sketch-stroke',
    });
    for (let i = 0; i < 3; i += 1) {
      const y = top + 48 + i * 13;
      if (y > bottom - 12) break;
      const length = (width - pad * 2) * (0.86 - i * 0.16);
      strokes.push({
        d: `M ${pad + 4} ${y} L ${pad + 4 + Math.max(24, length)} ${y + wobble(0.5)}`,
        k: k(),
        delay: 280 + i * 60,
        className: 'vx-sketch-stroke is-faint',
      });
    }
  }

  // Corner hatching, top-right — restrained pencil texture.
  for (let i = 0; i < 3; i += 1) {
    const x = right - 26 - i * 7;
    const y = top + 14 + i * 6;
    strokes.push({
      d: `M ${x} ${y} L ${x + 9} ${y + 9}`,
      k: 0.5,
      delay: 180 + i * 40,
      className: 'vx-sketch-stroke is-tick',
    });
  }

  return strokes;
}

/**
 * The pencil layer. Sized from the section's real box (ResizeObserver), so a
 * resized viewport redraws a draft that fits instead of cropping a fixed canvas.
 */
export function BlueprintSketch({
  index,
  drawDelay,
  resolveDelay,
}: {
  index: number;
  drawDelay: number;
  resolveDelay: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });

  useLayoutEffect(() => {
    const node = ref.current;
    if (!node) return;

    const measure = () => {
      const rect = node.getBoundingClientRect();
      const width = Math.round(rect.width);
      const height = Math.round(rect.height);
      setSize((current) =>
        current.width === width && current.height === height ? current : { width, height }
      );
    };

    measure();

    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', measure);
      return () => window.removeEventListener('resize', measure);
    }
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  const strokes = useMemo(
    () => buildStrokes(size.width, size.height, index),
    [size.width, size.height, index]
  );

  const layerStyle: CSSProperties = {
    ['--vx-draw' as string]: `${REVEAL_TIMING.draw}ms`,
    ['--vx-resolve-delay' as string]: `${resolveDelay}ms`,
  };

  return (
    <div ref={ref} className="vx-sketch-layer" style={layerStyle} aria-hidden="true">
      {size.width > 10 && size.height > 10 ? (
        <svg
          width={size.width}
          height={size.height}
          viewBox={`0 0 ${size.width} ${size.height}`}
          fill="none"
          role="presentation"
          focusable="false"
        >
          {strokes.map((stroke, i) => (
            <path
              key={i}
              d={stroke.d}
              pathLength={1}
              className={stroke.className}
              style={
                {
                  ['--k' as string]: stroke.k,
                  ['--vx-draw-delay' as string]: `${drawDelay + stroke.delay}ms`,
                } as CSSProperties
              }
            />
          ))}
        </svg>
      ) : null}
    </div>
  );
}
