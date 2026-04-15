/**
 * RankUpCeremony Component
 * Full-screen animated overlay that fires when the player earns a new rank.
 * Renders a badge reveal with particle-float effect and closes after 4 s
 * or on click.
 */

import React, { useEffect, useRef } from 'react';
import { X, ChevronUp } from 'lucide-react';

// Map Tailwind color names to hex (used in rank definitions)
const COLOR_MAP = {
  gray:    '#6b7280',
  blue:    '#3b82f6',
  purple:  '#8b5cf6',
  emerald: '#10b981',
  yellow:  '#eab308',
  red:     '#ef4444',
  green:   '#22c55e',
};

// ─── Particle ────────────────────────────────────────────────────────────────
const Particle = ({ style }) => (
  <div
    className="absolute w-2 h-2 rounded-full pointer-events-none animate-particle-float"
    style={style}
    aria-hidden="true"
  />
);

// Build deterministic (but varied) particles from the rank badge char-code
const buildParticles = (badge = '⭐') => {
  const seed = badge.codePointAt(0) ?? 42;
  return Array.from({ length: 20 }, (_, i) => {
    const angle = (i / 20) * 360;
    const dist  = 40 + ((seed * (i + 1)) % 60);
    const x     = 50 + Math.cos((angle * Math.PI) / 180) * dist;
    const y     = 50 + Math.sin((angle * Math.PI) / 180) * dist;
    const colors = [
      '#10b981', '#3b82f6', '#8b5cf6', '#eab308', '#f59e0b', '#ef4444',
    ];
    const color = colors[(seed + i) % colors.length];
    return {
      left:           `${x}%`,
      top:            `${y}%`,
      backgroundColor: color,
      animationDelay: `${(i * 0.15) % 2}s`,
      animationDuration: `${2 + ((i * 0.3) % 2)}s`,
      opacity: 0.7 + ((i % 4) * 0.075),
      transform: `scale(${0.5 + (i % 3) * 0.3})`,
    };
  });
};

// ─── Main component ───────────────────────────────────────────────────────────
export const RankUpCeremony = ({ rank, onClose }) => {
  const closeTimerRef = useRef(null);
  const rankColor = COLOR_MAP[rank?.color] ?? '#eab308';
  const particles = buildParticles(rank?.badge);

  // Auto-close after 4 s
  useEffect(() => {
    closeTimerRef.current = setTimeout(onClose, 4000);
    return () => clearTimeout(closeTimerRef.current);
  }, [onClose]);

  // Keyboard: Escape to close
  useEffect(() => {
    const handler = (e) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  if (!rank) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Rank up ceremony"
      className="fixed inset-0 z-50 flex items-center justify-center"
      onClick={onClose}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/85 backdrop-blur-sm" aria-hidden="true" />

      {/* Panel */}
      <div
        className="relative z-10 text-center px-10 py-12 animate-ceremony-in"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close button */}
        <button
          onClick={onClose}
          aria-label="Close rank-up ceremony"
          className="absolute top-2 right-2 p-1.5 rounded-full text-gray-500 hover:text-white hover:bg-white/10 transition-colors"
        >
          <X size={18} />
        </button>

        {/* Particles */}
        <div className="absolute inset-0 pointer-events-none" aria-hidden="true">
          {particles.map((style, i) => (
            <Particle key={i} style={style} />
          ))}
        </div>

        {/* Rank-up label */}
        <div className="flex items-center justify-center gap-2 mb-4">
          <ChevronUp size={18} className="text-yellow-400 animate-bounce" />
          <span className="text-yellow-400 font-bold text-sm uppercase tracking-[0.3em] font-mono">
            Rank Up
          </span>
          <ChevronUp size={18} className="text-yellow-400 animate-bounce" />
        </div>

        {/* Badge */}
        <div className="relative inline-flex items-center justify-center mb-6">
          {/* Outer glow ring */}
          <div
            className="absolute inset-0 rounded-full opacity-40 blur-xl animate-pulse"
            style={{ backgroundColor: rankColor }}
            aria-hidden="true"
          />
          {/* Badge circle */}
          <div
            className="relative w-28 h-28 rounded-full flex items-center justify-center border-4 shadow-2xl animate-rank-reveal"
            style={{
              borderColor: rankColor,
              backgroundColor: `${rankColor}22`,
              boxShadow: `0 0 40px ${rankColor}66`,
            }}
          >
            <span className="text-5xl" role="img" aria-label={rank.name}>
              {rank.badge}
            </span>
          </div>
        </div>

        {/* New rank name */}
        <h2
          className="text-4xl font-black tracking-tight mb-2"
          style={{ color: rankColor }}
        >
          {rank.name}
        </h2>

        {/* Subtitle */}
        {rank.description && (
          <p className="text-gray-400 text-sm max-w-xs mx-auto leading-relaxed mb-6">
            {rank.description}
          </p>
        )}

        {/* Dismiss hint */}
        <p className="text-gray-600 text-xs font-mono animate-pulse">
          Click anywhere or press Esc to continue
        </p>
      </div>
    </div>
  );
};

export default RankUpCeremony;
