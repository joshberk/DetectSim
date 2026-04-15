/**
 * Landing View
 * Hero page with CRT scanline overlay, glitch title, and count-up stats.
 */

import React, { useEffect, useRef, useState } from 'react';
import { Shield, ChevronRight, Terminal } from 'lucide-react';
import { useGame } from '../../context/GameContext';
import { Button } from '../ui';

// ─── Count-up hook ────────────────────────────────────────────────────────────
const useCountUp = (target, duration = 1400, startDelay = 0) => {
  const [count, setCount] = useState(0);
  const rafRef = useRef(null);

  useEffect(() => {
    let startTime = null;

    const tick = (timestamp) => {
      if (!startTime) startTime = timestamp;
      const elapsed = timestamp - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.round(eased * target));
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    };

    const timer = setTimeout(() => {
      rafRef.current = requestAnimationFrame(tick);
    }, startDelay);

    return () => {
      clearTimeout(timer);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [target, duration, startDelay]);

  return count;
};

// ─── Stat pill ────────────────────────────────────────────────────────────────
const StatPill = ({ value, label, color, delay }) => {
  const displayed = useCountUp(value, 1200, delay);
  return (
    <div className="text-center group">
      <div
        className={`text-4xl font-black font-mono tabular-nums ${color} drop-shadow-lg`}
        aria-label={`${value} ${label}`}
      >
        {displayed}
      </div>
      <div className="text-gray-500 uppercase tracking-widest text-xs mt-1 font-bold">
        {label}
      </div>
    </div>
  );
};

// ─── Landing ──────────────────────────────────────────────────────────────────
export const Landing = () => {
  const { state, actions } = useGame();
  const [mounted, setMounted] = useState(false);

  // Trigger mount-animations a tick after render
  useEffect(() => {
    const t = requestAnimationFrame(() => setMounted(true));
    return () => cancelAnimationFrame(t);
  }, []);

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-[#0f172a] text-center p-6 relative overflow-hidden select-none">

      {/* ── CRT scanline overlay ── */}
      <div className="scanline-overlay" aria-hidden="true" />

      {/* ── Background atmosphere ── */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden" aria-hidden="true">
        {/* Ambient glow blob */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] bg-emerald-500/8 rounded-full blur-3xl" />
        <div className="absolute top-1/4 right-1/4 w-[300px] h-[300px] bg-blue-600/5 rounded-full blur-3xl" />

        {/* Corner watermark text */}
        <div className="absolute top-8 left-8 text-emerald-900/40 font-mono text-8xl font-black leading-none select-none">
          DATA
        </div>
        <div className="absolute bottom-8 right-8 text-blue-900/40 font-mono text-8xl font-black leading-none select-none">
          LOGS
        </div>

        {/* Floating terminal lines */}
        {[
          { top: '15%', left: '3%',  text: '$ sigma compile rule.yml', delay: '0s',   dur: '6s'  },
          { top: '35%', left: '2%',  text: '> detection: match',       delay: '1.5s', dur: '7s'  },
          { top: '65%', left: '3%',  text: '$ siem --query TP:42',     delay: '0.8s', dur: '5.5s'},
          { top: '85%', left: '2%',  text: '> alert.fire()',           delay: '2s',   dur: '6.5s'},
          { top: '20%', right: '3%', text: '$ hunt -t T1059.001',      delay: '0.3s', dur: '7s'  },
          { top: '50%', right: '2%', text: '> fp_rate: 0.00%',         delay: '1.2s', dur: '5s'  },
          { top: '75%', right: '3%', text: '$ rank --promote',         delay: '1.8s', dur: '6s'  },
        ].map((item, i) => (
          <div
            key={i}
            className="absolute text-emerald-600/20 font-mono text-xs opacity-0"
            style={{
              top: item.top,
              left: item.left,
              right: item.right,
              animationName: 'fade-in',
              animationDuration: '0.8s',
              animationDelay: item.delay,
              animationFillMode: 'forwards',
            }}
          >
            {item.text}
          </div>
        ))}
      </div>

      {/* ── Main content ── */}
      <div
        className={`z-10 max-w-4xl w-full transition-all duration-700 ${
          mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
        }`}
      >
        {/* Logo */}
        <div className="mb-8 flex justify-center">
          <div className="h-24 w-24 bg-gray-800/80 rounded-2xl flex items-center justify-center border-2 border-emerald-500 shadow-[0_0_40px_rgba(16,185,129,0.4)] animate-pulse-glow">
            <Shield size={56} className="text-emerald-400" />
          </div>
        </div>

        {/* Glitch title */}
        <h1
          className="glitch-title text-7xl font-black text-white mb-6 tracking-tight drop-shadow-2xl"
          data-text="DETECTSIM"
        >
          DETECT<span className="text-emerald-400">SIM</span>
        </h1>

        {/* Tagline */}
        <p className="text-xl text-gray-400 mb-3 max-w-2xl mx-auto font-light tracking-wide">
          Detection Engineering{' '}
          <span className="text-emerald-500 font-semibold">RPG</span>
        </p>

        {/* Description */}
        <p className="text-base text-gray-500 mb-12 max-w-xl mx-auto leading-relaxed">
          Step into the shoes of a SOC Analyst. Analyze real-world logs, write{' '}
          <span className="text-white font-mono bg-gray-800 border border-gray-700 px-2 py-0.5 rounded text-sm">
            Sigma
          </span>{' '}
          rules, and hunt down adversaries before they breach the network.
        </p>

        {/* CTA */}
        <Button
          size="xl"
          onClick={() => actions.setView('dashboard')}
          icon={ChevronRight}
          iconPosition="right"
          className="group shadow-glow-green"
        >
          <span className="font-mono text-base tracking-widest">
            INITIALIZE_SEQUENCE
          </span>
        </Button>

        {/* Count-up stats */}
        <div className="mt-14 flex justify-center gap-12 text-sm relative">
          {/* Divider lines */}
          <div className="absolute inset-y-0 left-1/3 w-px bg-gray-700/50" aria-hidden="true" />
          <div className="absolute inset-y-0 left-2/3 w-px bg-gray-700/50" aria-hidden="true" />

          <StatPill value={50} label="Scenarios"   color="text-emerald-400" delay={300}  />
          <StatPill value={3}  label="Difficulties" color="text-blue-400"   delay={500}  />
          <StatPill value={6}  label="Ranks"        color="text-purple-400" delay={700}  />
        </div>

        {/* System status bar */}
        <div className="mt-12 inline-flex items-center gap-3 px-4 py-2 bg-gray-900/50 border border-gray-700/50 rounded-full text-xs font-mono text-gray-500">
          <Terminal size={12} className="text-emerald-500" />
          <span>
            SYSTEM: <span className="text-emerald-400">ONLINE</span>
          </span>
          <span className="text-gray-700">|</span>
          <span>v1.0.0</span>
          {state.user && (
            <>
              <span className="text-gray-700">|</span>
              <span className="text-gray-600">
                UID:{state.user.uid?.slice(0, 8) ?? 'local'}
              </span>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default Landing;
