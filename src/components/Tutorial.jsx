/**
 * Tutorial Overlay Component
 * Multi-step onboarding modal. Persists "seen" status to localStorage.
 * All content is static (no user input rendered) — no XSS surface.
 */

import React, { useEffect, useState, useCallback } from 'react';
import {
  X,
  ChevronRight,
  ChevronLeft,
  Shield,
  Layout,
  Terminal,
  Code,
  DollarSign,
  Award,
} from 'lucide-react';
import { Button } from './ui';

const STORAGE_KEY = 'detectsim_tutorial_seen';

const STEPS = [
  {
    icon: Shield,
    iconColor: 'text-emerald-400',
    title: 'Welcome to DetectSim',
    subtitle: 'Detection Engineering RPG',
    content: (
      <div className="space-y-3 text-gray-300 text-sm leading-relaxed">
        <p>
          You're a SOC Analyst. Your job: write <strong className="text-white">Sigma detection rules</strong> to
          identify malicious activity inside real-world log data.
        </p>
        <p>
          Sigma is a vendor-neutral rule language used by security teams worldwide. Rules
          describe <em className="text-emerald-300">patterns</em> in log fields — and DetectSim teaches
          you to write them by doing.
        </p>
        <div className="bg-gray-900/80 border border-gray-700 rounded-lg p-3 font-mono text-xs text-emerald-300">
          <div className="text-gray-500 mb-1"># Example Sigma rule</div>
          <div>detection:</div>
          <div className="ml-4">selection:</div>
          <div className="ml-8">Image|endswith: 'powershell.exe'</div>
          <div className="ml-4">condition: selection</div>
        </div>
      </div>
    ),
  },
  {
    icon: Layout,
    iconColor: 'text-blue-400',
    title: 'The Dashboard',
    subtitle: 'Your career map',
    content: (
      <div className="space-y-3 text-gray-300 text-sm leading-relaxed">
        <p>
          The Dashboard is your home base. It shows your <strong className="text-white">career map</strong> —
          50 scenarios across 3 difficulty levels.
        </p>
        <ul className="space-y-2">
          <li className="flex items-start gap-2">
            <span className="text-blue-400 mt-0.5">▸</span>
            <span><strong className="text-white">Level 1 (Junior)</strong> — straightforward patterns, single indicators. Start here.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-purple-400 mt-0.5">▸</span>
            <span><strong className="text-white">Level 2 (Intermediate)</strong> — unlocked after completing 10 L1 scenarios. More nuance required.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-red-400 mt-0.5">▸</span>
            <span><strong className="text-white">Level 3 (Advanced)</strong> — complex multi-stage attacks, low noise tolerance.</span>
          </li>
        </ul>
        <p className="text-gray-400 text-xs">
          Click any unlocked scenario card to open the Workspace.
        </p>
      </div>
    ),
  },
  {
    icon: Terminal,
    iconColor: 'text-yellow-400',
    title: 'Reading the Logs',
    subtitle: 'Know your data first',
    content: (
      <div className="space-y-3 text-gray-300 text-sm leading-relaxed">
        <p>
          Every scenario gives you a <strong className="text-white">log stream</strong> — a mix of
          benign and malicious events. Read the briefing, then study the logs carefully.
        </p>
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-emerald-950/30 border border-emerald-800/40 rounded-lg p-3 text-xs">
            <div className="text-emerald-400 font-bold mb-1">✅ True Positive (TP)</div>
            <div className="text-gray-400">Your rule correctly flags a malicious event.</div>
          </div>
          <div className="bg-red-950/30 border border-red-800/40 rounded-lg p-3 text-xs">
            <div className="text-red-400 font-bold mb-1">❌ False Positive (FP)</div>
            <div className="text-gray-400">Your rule flags a benign event by mistake.</div>
          </div>
        </div>
        <p className="text-xs text-gray-400">
          Toggle between <span className="font-mono text-white">Raw</span> and{' '}
          <span className="font-mono text-white">Parsed</span> view to understand each log field.
        </p>
      </div>
    ),
  },
  {
    icon: Code,
    iconColor: 'text-purple-400',
    title: 'Writing Your Rule',
    subtitle: 'YAML + Sigma syntax',
    content: (
      <div className="space-y-3 text-gray-300 text-sm leading-relaxed">
        <p>
          Write your Sigma rule in the editor on the right. Use{' '}
          <strong className="text-white">field modifiers</strong> to match specific patterns:
        </p>
        <div className="bg-gray-900/80 border border-gray-700 rounded-lg p-3 font-mono text-xs space-y-1">
          <div><span className="text-blue-300">field|contains</span><span className="text-gray-400">: 'value'</span></div>
          <div><span className="text-blue-300">field|endswith</span><span className="text-gray-400">: '.exe'</span></div>
          <div><span className="text-blue-300">field|startswith</span><span className="text-gray-400">: 'C:\\Windows'</span></div>
          <div><span className="text-blue-300">field|re</span><span className="text-gray-400">: 'pattern.*'</span></div>
        </div>
        <p className="text-xs text-gray-400">
          Combine fields with <span className="text-yellow-300 font-mono">AND</span> (same block) or{' '}
          <span className="text-yellow-300 font-mono">OR</span> (separate blocks + condition).
          Click <strong className="text-white">Hints</strong> if you get stuck.
        </p>
      </div>
    ),
  },
  {
    icon: DollarSign,
    iconColor: 'text-yellow-400',
    title: 'The Economy',
    subtitle: 'Budget & scoring',
    content: (
      <div className="space-y-3 text-gray-300 text-sm leading-relaxed">
        <p>
          Every action affects your <strong className="text-white">Budget</strong>. Budget is both
          your score and your currency for buying hints.
        </p>
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs bg-gray-900/60 rounded p-2">
            <span className="text-gray-400">Perfect detection</span>
            <span className="text-emerald-400 font-bold font-mono">+$150</span>
          </div>
          <div className="flex items-center justify-between text-xs bg-gray-900/60 rounded p-2">
            <span className="text-gray-400">First-try bonus</span>
            <span className="text-emerald-400 font-bold font-mono">+$25</span>
          </div>
          <div className="flex items-center justify-between text-xs bg-gray-900/60 rounded p-2">
            <span className="text-gray-400">False positive (each)</span>
            <span className="text-red-400 font-bold font-mono">-$25</span>
          </div>
          <div className="flex items-center justify-between text-xs bg-gray-900/60 rounded p-2">
            <span className="text-gray-400">Missed attack (each)</span>
            <span className="text-red-400 font-bold font-mono">-$50</span>
          </div>
        </div>
        <p className="text-xs text-gray-400">
          Spend wisely — hints cost $50–$200 each.
        </p>
      </div>
    ),
  },
  {
    icon: Award,
    iconColor: 'text-yellow-400',
    title: 'Ranks & Achievements',
    subtitle: 'Your career progression',
    content: (
      <div className="space-y-3 text-gray-300 text-sm leading-relaxed">
        <p>
          Progress through <strong className="text-white">6 career ranks</strong> — from Junior Analyst
          to Principal Engineer — by solving cases and maintaining high accuracy.
        </p>
        <p>
          Unlock <strong className="text-white">achievements</strong> for milestones like completing
          your first scenario, maintaining 90%+ accuracy, or finishing levels without hints.
        </p>
        <div className="bg-purple-950/30 border border-purple-800/40 rounded-lg p-3 text-xs">
          <div className="text-purple-300 font-bold mb-1">🏆 Pro tip</div>
          <div className="text-gray-400">
            Aim for <em>zero false positives</em>. Noisy rules cost budget and hurt your
            accuracy score, making rank progression harder.
          </div>
        </div>
        <p className="text-emerald-400 font-bold text-sm">
          You're ready. Good luck, Analyst. 🎯
        </p>
      </div>
    ),
  },
];

// ─── Component ────────────────────────────────────────────────────────────────

export const Tutorial = ({ onClose }) => {
  const [step, setStep] = useState(0);
  const [closing, setClosing] = useState(false);

  const total = STEPS.length;
  const current = STEPS[step];
  const Icon = current.icon;

  const markSeen = useCallback(() => {
    try {
      localStorage.setItem(STORAGE_KEY, '1');
    } catch {
      // localStorage unavailable — not a blocker
    }
  }, []);

  const handleClose = useCallback(() => {
    markSeen();
    setClosing(true);
    setTimeout(onClose, 250);
  }, [markSeen, onClose]);

  const handleNext = useCallback(() => {
    if (step < total - 1) {
      setStep((s) => s + 1);
    } else {
      handleClose();
    }
  }, [step, total, handleClose]);

  const handlePrev = useCallback(() => {
    setStep((s) => Math.max(0, s - 1));
  }, []);

  // Allow Escape key to dismiss
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') handleClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [handleClose]);

  return (
    <div
      className={`fixed inset-0 z-50 flex items-center justify-center p-4 transition-opacity duration-250 ${
        closing ? 'opacity-0' : 'opacity-100'
      }`}
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={handleClose}
        aria-hidden="true"
      />

      {/* Modal */}
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="tutorial-title"
        className={`relative bg-gray-800 border border-gray-700 rounded-2xl shadow-2xl w-full max-w-lg transition-all duration-250 ${
          closing ? 'scale-95 opacity-0' : 'scale-100 opacity-100'
        }`}
      >
        {/* Top gradient */}
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-500 to-blue-500 rounded-t-2xl" />

        {/* Close button */}
        <button
          onClick={handleClose}
          className="absolute top-4 right-4 p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-white transition-colors"
          aria-label="Close tutorial"
        >
          <X size={18} />
        </button>

        <div className="p-8">
          {/* Step icon & title */}
          <div className="flex items-center gap-4 mb-6">
            <div className="w-12 h-12 rounded-xl bg-gray-700/80 border border-gray-600 flex items-center justify-center flex-shrink-0">
              <Icon size={24} className={current.iconColor} />
            </div>
            <div>
              <h2 id="tutorial-title" className="text-xl font-bold text-white">
                {current.title}
              </h2>
              <p className="text-sm text-gray-400">{current.subtitle}</p>
            </div>
          </div>

          {/* Content */}
          <div className="min-h-[180px]">{current.content}</div>

          {/* Progress dots */}
          <div className="flex items-center justify-center gap-2 my-6">
            {STEPS.map((_, i) => (
              <button
                key={i}
                onClick={() => setStep(i)}
                aria-label={`Go to step ${i + 1}`}
                className={`rounded-full transition-all duration-200 ${
                  i === step
                    ? 'w-6 h-2.5 bg-emerald-500'
                    : i < step
                    ? 'w-2.5 h-2.5 bg-emerald-700'
                    : 'w-2.5 h-2.5 bg-gray-600 hover:bg-gray-500'
                }`}
              />
            ))}
          </div>

          {/* Navigation */}
          <div className="flex items-center justify-between gap-3">
            <Button
              variant="ghost"
              size="sm"
              onClick={handlePrev}
              disabled={step === 0}
              icon={ChevronLeft}
              iconPosition="left"
            >
              Back
            </Button>

            <span className="text-xs text-gray-500 font-mono">
              {step + 1} / {total}
            </span>

            <Button
              variant="primary"
              size="sm"
              onClick={handleNext}
              icon={ChevronRight}
              iconPosition="right"
            >
              {step === total - 1 ? "Let's Go!" : 'Next'}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

/**
 * Returns true if the user has NOT yet seen the tutorial.
 */
export const shouldShowTutorial = () => {
  try {
    return !localStorage.getItem(STORAGE_KEY);
  } catch {
    return false;
  }
};

export default Tutorial;
