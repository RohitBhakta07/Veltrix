/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        veltrix: {
          bg: '#0A0F1D',
          chrome: '#070B14',
          surface: '#0D1527',
          card: '#111C35',
          elevated: '#16213C',
          border: '#1E2B45',
          cyan: '#00F2FE',
          cyanMuted: '#00C2CB',
          blue: '#2563EB',
          textMuted: '#94A3B8',
          textBright: '#F8FAFC',
          critical: '#FF4D6D',
          high: '#FF8A3D',
          medium: '#FFC857',
          low: '#38BDF8',
          success: '#2DD4A7',
        },
      },
      fontFamily: {
        sans: [
          'Inter',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'sans-serif',
        ],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: '0 20px 40px rgba(0,0,0,0.35)',
        glow: '0 0 30px rgba(0,242,254,0.18)',
        'glow-danger': '0 0 30px rgba(255,77,109,0.18)',
      },
      backgroundImage: {
        'vx-grid':
          'linear-gradient(rgba(30,43,69,0.35) 1px, transparent 1px), linear-gradient(90deg, rgba(30,43,69,0.35) 1px, transparent 1px)',
        'vx-radial':
          'radial-gradient(ellipse at 20% 0%, rgba(0,242,254,0.09), transparent 55%), radial-gradient(ellipse at 90% 10%, rgba(37,99,235,0.12), transparent 50%)',
      },
      backgroundSize: {
        'vx-grid': '44px 44px',
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '-500px 0' },
          '100%': { backgroundPosition: '500px 0' },
        },
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        pulseSoft: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.45' },
        },
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(400%)' },
        },
        ticker: {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-50%)' },
        },
      },
      animation: {
        shimmer: 'shimmer 1.8s linear infinite',
        'fade-up': 'fadeUp 240ms cubic-bezier(.2,.8,.2,1) both',
        'pulse-soft': 'pulseSoft 2.4s ease-in-out infinite',
        scan: 'scan 4s linear infinite',
        ticker: 'ticker 40s linear infinite',
      },
    },
  },
  plugins: [],
};
