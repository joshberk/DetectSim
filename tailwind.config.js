/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'cyber-dark': '#0f172a',
        'cyber-darker': '#0c0c0c',
        'cyber-green': '#10b981',
        'cyber-green-dark': '#059669',
        'cyber-blue': '#3b82f6',
        'cyber-red': '#ef4444',
        'cyber-yellow': '#eab308',
        'cyber-purple': '#8b5cf6',
      },
      fontFamily: {
        mono: ['Fira Code', 'Cascadia Code', 'Consolas', 'monospace'],
      },
      animation: {
        // Existing
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'slide-in':   'slide-in 0.3s ease-out',
        'fade-in':    'fade-in 0.3s ease-out',
        // New
        'glitch':        'glitch 3s infinite',
        'scanline':      'scanline 8s linear infinite',
        'count-up':      'fade-in 0.6s ease-out',
        'shimmer':       'shimmer 1.6s infinite',
        'flash-tp':      'flash-tp 0.6s ease-out',
        'flash-fp':      'flash-fp 0.6s ease-out',
        'rank-reveal':   'rank-reveal 0.5s cubic-bezier(0.34,1.56,0.64,1)',
        'particle-float':'particle-float 3s ease-in-out infinite',
        'fill-bar':      'fill-bar 0.8s cubic-bezier(0.4,0,0.2,1) forwards',
        'ceremony-in':   'ceremony-in 0.4s cubic-bezier(0.34,1.56,0.64,1)',
        'spin-slow':     'spin 3s linear infinite',
        'ping-once':     'ping 0.6s ease-out 1',
      },
      keyframes: {
        // Existing
        'pulse-glow': {
          '0%, 100%': { boxShadow: '0 0 20px rgba(16,185,129,0.3)' },
          '50%':       { boxShadow: '0 0 40px rgba(16,185,129,0.6)' },
        },
        'slide-in': {
          '0%':   { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)',    opacity: '1' },
        },
        'fade-in': {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        // Glitch effect for hero title
        'glitch': {
          '0%, 90%, 100%': { transform: 'translate(0)', clipPath: 'none', opacity: '1' },
          '91%':  { transform: 'translate(-2px, 1px)',  clipPath: 'inset(20% 0 60% 0)', opacity: '0.9' },
          '92%':  { transform: 'translate(2px, -1px)',  clipPath: 'inset(60% 0 20% 0)', opacity: '0.9' },
          '93%':  { transform: 'translate(0)', clipPath: 'none', opacity: '1' },
          '94%':  { transform: 'translate(1px, 2px)',   clipPath: 'inset(40% 0 40% 0)', opacity: '0.85' },
          '95%':  { transform: 'translate(0)', clipPath: 'none', opacity: '1' },
        },
        // Moving scanline across screen
        'scanline': {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        // Skeleton shimmer
        'shimmer': {
          '0%':   { backgroundPosition: '-400px 0' },
          '100%': { backgroundPosition:  '400px 0' },
        },
        // Log line flash green on TP match
        'flash-tp': {
          '0%':   { backgroundColor: 'rgba(16,185,129,0.5)', transform: 'scaleX(1.01)' },
          '100%': { backgroundColor: 'rgba(16,185,129,0.1)', transform: 'scaleX(1)' },
        },
        // Log line flash red on FP match
        'flash-fp': {
          '0%':   { backgroundColor: 'rgba(239,68,68,0.5)', transform: 'scaleX(1.01)' },
          '100%': { backgroundColor: 'rgba(239,68,68,0.1)', transform: 'scaleX(1)' },
        },
        // Rank badge reveal bounce
        'rank-reveal': {
          '0%':   { transform: 'scale(0) rotate(-10deg)', opacity: '0' },
          '100%': { transform: 'scale(1) rotate(0deg)',   opacity: '1' },
        },
        // Floating particles
        'particle-float': {
          '0%, 100%': { transform: 'translateY(0px)   opacity: 1' },
          '50%':      { transform: 'translateY(-20px)', opacity: '0.3' },
        },
        // Progress bar fill from zero
        'fill-bar': {
          '0%':   { width: '0%' },
        },
        // Ceremony modal entrance
        'ceremony-in': {
          '0%':   { transform: 'scale(0.5)', opacity: '0' },
          '100%': { transform: 'scale(1)',   opacity: '1' },
        },
      },
      boxShadow: {
        'glow-green':  '0 0 20px rgba(16,185,129,0.4)',
        'glow-blue':   '0 0 20px rgba(59,130,246,0.4)',
        'glow-purple': '0 0 20px rgba(139,92,246,0.4)',
        'glow-red':    '0 0 20px rgba(239,68,68,0.4)',
        'glow-yellow': '0 0 20px rgba(234,179,8,0.4)',
      },
    },
  },
  plugins: [],
};
