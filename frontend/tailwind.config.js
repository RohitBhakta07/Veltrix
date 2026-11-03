/**
 * Design tokens — Hybrid SOC Console.
 *
 * Every colour is expressed as `rgb(var(--dp-*) / <alpha-value>)` so the value
 * lives in CSS (and therefore can be themed) while Tailwind keeps working with
 * opacity modifiers such as `bg-veltrix-card/60`.
 *
 * The `slate` scale is remapped onto ink/line/surface roles: existing markup
 * written against Tailwind greys automatically becomes theme-aware. The same
 * applies to the severity families (rose = critical, orange = high,
 * amber = medium, sky = low, emerald = live), which map onto three semantic
 * channels each (ink / soft fill / line).
 */
const c = (variable) => `rgb(var(${variable}) / <alpha-value>)`;

const severity = (name) => ({
  // 50–600: readable ink. These are the shades used for text, icons, dots and
  // tinted fills, so they must stay legible on both grounds.
  50: c(`--dp-sev-${name}`),
  100: c(`--dp-sev-${name}`),
  200: c(`--dp-sev-${name}`),
  300: c(`--dp-sev-${name}`),
  400: c(`--dp-sev-${name}`),
  500: c(`--dp-sev-${name}`),
  600: c(`--dp-sev-${name}`),
  // 700–800: muted line, for borders drawn on a tinted surface.
  700: c(`--dp-sev-${name}-line`),
  800: c(`--dp-sev-${name}-line`),
  // 900–950: the soft fill that sits behind the ink.
  900: c(`--dp-sev-${name}-soft`),
  950: c(`--dp-sev-${name}-soft`),
});

const accent = (ink, soft, line) => ({
  // Same rule as severity: light shades are ink, mid shades carry borders,
  // only the darkest shades are fills.
  50: c(ink),
  100: c(ink),
  200: c(ink),
  300: c(ink),
  400: c(ink),
  500: c(ink),
  600: c(ink),
  700: c(line),
  800: c(line),
  900: c(soft),
  950: c(soft),
});

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        veltrix: {
          bg: c('--dp-ground'),
          chrome: c('--dp-sunken'),
          surface: c('--dp-panel'),
          card: c('--dp-panel'),
          elevated: c('--dp-panel-elevated'),
          subtle: c('--dp-panel-subtle'),
          border: c('--dp-line'),
          borderStrong: c('--dp-line-strong'),
          cyan: c('--dp-signal'),
          cyanMuted: c('--dp-signal'),
          blue: c('--dp-registration'),
          magenta: c('--dp-interference'),
          textMuted: c('--dp-ink-body'),
          textMeta: c('--dp-ink-muted'),
          textBright: c('--dp-ink'),
          critical: c('--dp-sev-critical'),
          high: c('--dp-sev-high'),
          medium: c('--dp-sev-medium'),
          low: c('--dp-sev-low'),
          success: c('--dp-live'),
          inverse: c('--dp-inverse-ink'),
          sketch: c('--dp-sketch'),
        },

        // `white` is remapped to theme ink so legacy `text-white` headings stay
        // readable in the light theme, and `bg-white/5` becomes a subtle wash.
        white: c('--dp-ink'),

        // Ink / line / surface roles, so legacy grey utilities theme correctly.
        slate: {
          50: c('--dp-ink'),
          100: c('--dp-ink'),
          200: c('--dp-ink'),
          300: c('--dp-ink-body'),
          400: c('--dp-ink-muted'),
          500: c('--dp-ink-muted'),
          600: c('--dp-ink-muted'),
          700: c('--dp-line'),
          800: c('--dp-line'),
          900: c('--dp-panel-subtle'),
          950: c('--dp-sunken'),
        },

        cyan: accent('--dp-signal', '--dp-signal-soft', '--dp-signal-soft'),
        emerald: accent('--dp-live', '--dp-live-soft', '--dp-live-line'),
        blue: accent('--dp-registration', '--dp-registration-soft', '--dp-registration-line'),
        indigo: accent('--dp-registration', '--dp-registration-soft', '--dp-registration-line'),
        purple: accent('--dp-registration', '--dp-registration-soft', '--dp-registration-line'),

        // Severity — never repurposed for decorative accents.
        rose: severity('critical'),
        red: severity('critical'),
        orange: severity('high'),
        amber: severity('medium'),
        sky: severity('low'),
      },

      fontFamily: {
        sans: ['Geist', 'Helvetica Neue', 'Arial', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['IBM Plex Mono', 'SFMono-Regular', 'Menlo', 'ui-monospace', 'monospace'],
      },

      // Tight geometry: existing rounded-* utilities inherit this scale.
      borderRadius: {
        none: '0',
        sm: '2px',
        DEFAULT: '3px',
        md: '4px',
        lg: '5px',
        xl: '6px',
        '2xl': '8px',
        '3xl': '10px',
        panel: '6px',
        control: '4px',
      },

      boxShadow: {
        card: 'var(--dp-shadow-panel)',
        md: 'var(--dp-shadow-md)',
        lg: 'var(--dp-shadow-lg)',
        xl: 'var(--dp-shadow-lg)',
        '2xl': 'var(--dp-shadow-lg)',
        // Neutralized: the system has no accent glow.
        glow: '0 0 0 0 rgba(0, 0, 0, 0)',
        'glow-danger': '0 0 0 0 rgba(0, 0, 0, 0)',
      },

      backgroundImage: {
        'vx-grid':
          'linear-gradient(rgb(var(--dp-line) / 0.55) 1px, transparent 1px), linear-gradient(90deg, rgb(var(--dp-line) / 0.55) 1px, transparent 1px)',
        'vx-radial':
          'radial-gradient(ellipse at 50% -10%, rgb(var(--dp-ink) / 0.05), transparent 62%)',
      },
      backgroundSize: {
        'vx-grid': '48px 48px',
      },

      transitionDuration: {
        DEFAULT: '140ms',
      },

      keyframes: {
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(6px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-500px 0' },
          '100%': { backgroundPosition: '500px 0' },
        },
      },
      animation: {
        'fade-up': 'fadeUp 160ms ease-out both',
        shimmer: 'shimmer 2s linear infinite',
      },
    },
  },
  plugins: [],
};
