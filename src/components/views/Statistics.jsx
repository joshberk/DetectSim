/**
 * Statistics Dashboard View
 * Displays detection performance metrics and career progress.
 * All data sourced from trusted game state — no user-supplied HTML rendered.
 */

import React, { useMemo } from 'react';
import {
  ArrowLeft,
  Target,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Award,
  BarChart2,
  Zap,
  Shield,
  ChevronRight,
} from 'lucide-react';
import { useGame } from '../../context/GameContext';
import { Card, Badge, ProgressBar } from '../ui';
import { RANKS, getNextRankRequirements } from '../../utils/scoring';
import { ACHIEVEMENTS_BY_ID } from '../../data/achievements';

// ─── Mini Components ─────────────────────────────────────────────────────────

const StatBox = ({ label, value, sub, icon: Icon, color = 'text-white' }) => (
  <div className="bg-gray-900/60 rounded-lg border border-gray-700 p-4 flex flex-col gap-1">
    <div className="flex items-center gap-2 text-xs text-gray-400 uppercase tracking-wide">
      {Icon && <Icon size={12} className={color} />}
      {label}
    </div>
    <div className={`text-2xl font-mono font-bold ${color}`}>{value}</div>
    {sub && <div className="text-xs text-gray-500">{sub}</div>}
  </div>
);

const DonutSegment = ({ pct, color, offset }) => {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  return (
    <circle
      r={r}
      cx="44"
      cy="44"
      fill="none"
      stroke={color}
      strokeWidth="12"
      strokeDasharray={`${dash} ${circ - dash}`}
      strokeDashoffset={-offset}
      strokeLinecap="butt"
      style={{ transition: 'stroke-dasharray 0.6s ease' }}
    />
  );
};

const AccuracyRing = ({ accuracy }) => {
  const color =
    accuracy >= 90 ? '#10b981' : accuracy >= 70 ? '#f59e0b' : '#ef4444';
  const r = 36;
  const circ = 2 * Math.PI * r;
  const dash = (accuracy / 100) * circ;
  return (
    <div className="relative w-24 h-24 mx-auto">
      <svg viewBox="0 0 88 88" className="w-full h-full -rotate-90">
        <circle r={r} cx="44" cy="44" fill="none" stroke="#1f2937" strokeWidth="12" />
        <circle
          r={r}
          cx="44"
          cy="44"
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.6s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-bold font-mono" style={{ color }}>
          {accuracy}%
        </span>
      </div>
    </div>
  );
};

// ─── Main Component ──────────────────────────────────────────────────────────

export const Statistics = () => {
  const { state, actions } = useGame();
  const { statistics, completedScenarios, budget, rank, accuracy, unlockedAchievements } = state;

  const stats = useMemo(() => {
    const tp = statistics.truePositives || 0;
    const fp = statistics.falsePositives || 0;
    const missed = statistics.missedAttacks || 0;
    const total = tp + fp + missed;
    const attempts = statistics.totalAttempts || 0;
    const perfect = statistics.perfectDetections || 0;
    const firstTryPerfect = statistics.firstTryPerfect || 0;

    const tpPct = total > 0 ? Math.round((tp / total) * 100) : 0;
    const fpPct = total > 0 ? Math.round((fp / total) * 100) : 0;
    const missedPct = total > 0 ? Math.round((missed / total) * 100) : 100 - tpPct - fpPct;

    const level1 = completedScenarios.filter((id) => id.startsWith('L1-')).length;
    const level2 = completedScenarios.filter((id) => id.startsWith('L2-')).length;
    const level3 = completedScenarios.filter((id) => id.startsWith('L3-')).length;

    return {
      tp, fp, missed, total, attempts, perfect, firstTryPerfect,
      tpPct, fpPct, missedPct,
      level1, level2, level3,
      perfectRate: attempts > 0 ? Math.round((perfect / attempts) * 100) : 0,
    };
  }, [statistics, completedScenarios]);

  const nextRank = useMemo(
    () =>
      getNextRankRequirements({
        completedCases: completedScenarios.length,
        accuracy,
        budget,
      }),
    [completedScenarios.length, accuracy, budget]
  );

  const currentRankIndex = RANKS.findIndex((r) => r.id === rank?.id);

  // Recent achievements (last 6)
  const recentAchievements = useMemo(
    () =>
      unlockedAchievements
        .slice()
        .reverse()
        .slice(0, 6)
        .map((id) => ACHIEVEMENTS_BY_ID[id])
        .filter(Boolean),
    [unlockedAchievements]
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-300 p-4 sm:p-8">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8 border-b border-gray-700 pb-6">
          <button
            onClick={() => actions.setView('dashboard')}
            className="p-2 rounded hover:bg-gray-700 text-gray-400 hover:text-white transition-colors"
            aria-label="Back to Dashboard"
          >
            <ArrowLeft size={20} />
          </button>
          <div>
            <h1 className="text-3xl font-black text-white flex items-center gap-3">
              <BarChart2 size={28} className="text-blue-400" />
              Performance Stats
            </h1>
            <p className="text-gray-500 text-sm mt-1">
              Your detection engineering track record
            </p>
          </div>
        </div>

        {/* Top KPIs */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
          <StatBox
            label="Cases Solved"
            value={completedScenarios.length}
            sub={`of 50 total`}
            icon={CheckCircle}
            color="text-emerald-400"
          />
          <StatBox
            label="Detection Rate"
            value={`${accuracy}%`}
            sub="overall accuracy"
            icon={Target}
            color={accuracy >= 90 ? 'text-emerald-400' : accuracy >= 70 ? 'text-yellow-400' : 'text-red-400'}
          />
          <StatBox
            label="Perfect Runs"
            value={stats.perfect}
            sub={`${stats.perfectRate}% of attempts`}
            icon={Zap}
            color="text-yellow-400"
          />
          <StatBox
            label="Budget"
            value={`$${budget}`}
            sub={`rank: ${rank?.name || 'Junior'}`}
            icon={Shield}
            color="text-purple-400"
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          {/* Detection Breakdown */}
          <Card header="Detection Breakdown" headerIcon={Target} headerColor="blue">
            <div className="flex items-center gap-6">
              <AccuracyRing accuracy={accuracy} />
              <div className="flex-1 space-y-3">
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-emerald-400">True Positives</span>
                    <span className="font-mono">{stats.tp} ({stats.tpPct}%)</span>
                  </div>
                  <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-emerald-500 rounded-full transition-all duration-700"
                      style={{ width: `${stats.tpPct}%` }}
                    />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-red-400">False Positives</span>
                    <span className="font-mono">{stats.fp} ({stats.fpPct}%)</span>
                  </div>
                  <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-red-500 rounded-full transition-all duration-700"
                      style={{ width: `${stats.fpPct}%` }}
                    />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-yellow-400">Missed Attacks</span>
                    <span className="font-mono">{stats.missed} ({stats.missedPct}%)</span>
                  </div>
                  <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-yellow-500 rounded-full transition-all duration-700"
                      style={{ width: `${stats.missedPct}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-gray-700 grid grid-cols-2 gap-3 text-sm">
              <div className="text-center">
                <div className="text-gray-400 text-xs uppercase tracking-wide mb-1">Total Attempts</div>
                <div className="font-mono font-bold text-white text-lg">{stats.attempts}</div>
              </div>
              <div className="text-center">
                <div className="text-gray-400 text-xs uppercase tracking-wide mb-1">First-Try Perfect</div>
                <div className="font-mono font-bold text-emerald-400 text-lg">{stats.firstTryPerfect}</div>
              </div>
            </div>
          </Card>

          {/* Level Progress */}
          <Card header="Level Progress" headerIcon={TrendingUp} headerColor="emerald">
            <div className="space-y-5">
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <div className="flex items-center gap-2">
                    <Badge variant="info" size="sm">L1</Badge>
                    <span className="text-gray-300">Junior</span>
                  </div>
                  <span className="font-mono text-gray-400">{stats.level1}/17</span>
                </div>
                <ProgressBar value={stats.level1} max={17} variant="info" size="sm" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <div className="flex items-center gap-2">
                    <Badge variant="purple" size="sm">L2</Badge>
                    <span className="text-gray-300">Intermediate</span>
                  </div>
                  <span className="font-mono text-gray-400">{stats.level2}/17</span>
                </div>
                <ProgressBar value={stats.level2} max={17} variant="purple" size="sm" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <div className="flex items-center gap-2">
                    <Badge variant="danger" size="sm">L3</Badge>
                    <span className="text-gray-300">Advanced</span>
                  </div>
                  <span className="font-mono text-gray-400">{stats.level3}/16</span>
                </div>
                <ProgressBar value={stats.level3} max={16} variant="danger" size="sm" />
              </div>
              <div className="pt-3 border-t border-gray-700">
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400 font-bold uppercase tracking-wide text-xs">Overall</span>
                  <span className="font-mono text-gray-400">{completedScenarios.length}/50</span>
                </div>
                <ProgressBar value={completedScenarios.length} max={50} size="md" />
              </div>
            </div>
          </Card>

          {/* Rank Progression */}
          <Card header="Rank Journey" headerIcon={Award} headerColor="yellow">
            <div className="space-y-2 mb-4">
              {RANKS.map((r, i) => {
                const isCurrentRank = r.id === rank?.id;
                const isPast = i < currentRankIndex;
                const isFuture = i > currentRankIndex;

                return (
                  <div
                    key={r.id}
                    className={`flex items-center gap-3 p-2 rounded-lg border transition-all ${
                      isCurrentRank
                        ? 'border-yellow-500/50 bg-yellow-950/30'
                        : isPast
                        ? 'border-emerald-900/50 bg-emerald-950/10 opacity-60'
                        : 'border-gray-800 opacity-40'
                    }`}
                  >
                    <div
                      className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold font-mono flex-shrink-0 ${
                        isPast
                          ? 'bg-emerald-800 text-emerald-300'
                          : isCurrentRank
                          ? 'bg-yellow-700 text-yellow-200 ring-2 ring-yellow-400'
                          : 'bg-gray-800 text-gray-500'
                      }`}
                    >
                      {isPast ? '✓' : r.badge}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className={`text-sm font-bold ${isCurrentRank ? 'text-yellow-300' : isFuture ? 'text-gray-500' : 'text-gray-400'}`}>
                        {r.name}
                      </div>
                      {isCurrentRank && (
                        <div className="text-xs text-yellow-600">← Current Rank</div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {nextRank && (
              <div className="pt-4 border-t border-gray-700">
                <div className="text-xs text-gray-400 uppercase tracking-wide mb-3">
                  To reach {nextRank.rank.name}:
                </div>
                <div className="space-y-1.5 text-xs">
                  {nextRank.requirements.casesNeeded > 0 && (
                    <div className="flex items-center gap-2 text-gray-400">
                      <ChevronRight size={12} className="text-blue-400" />
                      {nextRank.requirements.casesNeeded} more cases
                    </div>
                  )}
                  {nextRank.requirements.accuracyNeeded > 0 && (
                    <div className="flex items-center gap-2 text-gray-400">
                      <ChevronRight size={12} className="text-yellow-400" />
                      +{nextRank.requirements.accuracyNeeded.toFixed(1)}% accuracy
                    </div>
                  )}
                  {nextRank.requirements.budgetNeeded > 0 && (
                    <div className="flex items-center gap-2 text-gray-400">
                      <ChevronRight size={12} className="text-emerald-400" />
                      ${nextRank.requirements.budgetNeeded} more budget
                    </div>
                  )}
                </div>
              </div>
            )}
            {!nextRank && (
              <div className="pt-4 border-t border-gray-700 text-center text-sm text-yellow-400 font-bold">
                🏆 Maximum Rank Achieved
              </div>
            )}
          </Card>
        </div>

        {/* Recent Achievements */}
        {recentAchievements.length > 0 && (
          <Card header="Recent Achievements" headerIcon={Award} headerColor="purple">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {recentAchievements.map((achievement) => (
                <div
                  key={achievement.id}
                  className="flex items-center gap-3 p-3 bg-purple-950/20 border border-purple-800/30 rounded-lg"
                >
                  <span className="text-2xl flex-shrink-0" role="img" aria-label={achievement.title}>
                    {achievement.icon}
                  </span>
                  <div className="min-w-0">
                    <div className="text-sm font-bold text-white truncate">
                      {achievement.title}
                    </div>
                    <div className="text-xs text-gray-400 leading-tight">
                      {achievement.description}
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-4 text-center">
              <button
                onClick={() => actions.setView('achievements')}
                className="text-sm text-purple-400 hover:text-purple-300 transition-colors flex items-center gap-1 mx-auto"
              >
                View all achievements <ChevronRight size={14} />
              </button>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
};

export default Statistics;
