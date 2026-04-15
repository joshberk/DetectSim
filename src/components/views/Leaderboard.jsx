/**
 * Full Leaderboard View
 * Displays ranked global leaderboard with detailed stats per entry.
 * Security: all entry data rendered as plain text, capped at safe lengths.
 */

import React, { useMemo, useState } from 'react';
import { ArrowLeft, Trophy, Shield, Target, TrendingUp, Star } from 'lucide-react';
import { useGame } from '../../context/GameContext';
import { Card, Badge } from '../ui';

// Max lengths for user-supplied display data
const MAX_NAME_LEN = 30;
const MAX_RANK_LEN = 30;

/**
 * Sanitise a leaderboard entry for safe display (plain text only).
 */
const sanitiseEntry = (entry, index) => ({
  position: index + 1,
  user: String(entry.user || `Operative ${index + 1}`).slice(0, MAX_NAME_LEN),
  score: typeof entry.score === 'number' && isFinite(entry.score)
    ? Math.max(0, Math.floor(entry.score))
    : 0,
  rank: String(entry.rank || 'Junior Analyst').slice(0, MAX_RANK_LEN),
  completedCases: typeof entry.completedCases === 'number'
    ? Math.max(0, Math.floor(entry.completedCases))
    : 0,
  accuracy: typeof entry.accuracy === 'number' && isFinite(entry.accuracy)
    ? Math.min(100, Math.max(0, Math.round(entry.accuracy * 10) / 10))
    : 0,
  isCurrentUser: !!entry.isCurrentUser,
});

const MEDAL = ['🥇', '🥈', '🥉'];

const RankBadge = ({ position }) => {
  if (position <= 3) {
    return (
      <span className="text-xl" role="img" aria-label={`Position ${position}`}>
        {MEDAL[position - 1]}
      </span>
    );
  }
  return (
    <span className="w-8 h-8 flex items-center justify-center font-mono font-bold text-gray-500 text-sm">
      #{position}
    </span>
  );
};

const SORT_OPTIONS = [
  { id: 'score', label: 'Score' },
  { id: 'cases', label: 'Cases' },
  { id: 'accuracy', label: 'Accuracy' },
];

export const Leaderboard = () => {
  const { state, actions } = useGame();
  const [sortBy, setSortBy] = useState('score');

  const entries = useMemo(() => {
    // Sanitise all entries
    const safe = (state.leaderboard || []).map(sanitiseEntry);

    // Mark current user
    if (state.user?.uid) {
      const currentHandle = `Operative ${state.user.uid.slice(0, 6)}`;
      safe.forEach((e) => {
        if (e.user === currentHandle) e.isCurrentUser = true;
      });
    }

    // Sort
    const sorted = [...safe].sort((a, b) => {
      if (sortBy === 'cases') return b.completedCases - a.completedCases;
      if (sortBy === 'accuracy') return b.accuracy - a.accuracy;
      return b.score - a.score;
    });

    // Re-assign positions after sort
    return sorted.map((e, i) => ({ ...e, position: i + 1 }));
  }, [state.leaderboard, state.user, sortBy]);

  const currentUserEntry = entries.find((e) => e.isCurrentUser);

  const localEntry = useMemo(() => ({
    score: state.leaderboardScore || 0,
    completedCases: state.completedScenarios.length,
    accuracy: state.accuracy || 0,
    rank: state.rank?.name || 'Junior Analyst',
  }), [state]);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-300 p-4 sm:p-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8 border-b border-gray-700 pb-6">
          <button
            onClick={() => actions.setView('dashboard')}
            className="p-2 rounded hover:bg-gray-700 text-gray-400 hover:text-white transition-colors"
            aria-label="Back to Dashboard"
          >
            <ArrowLeft size={20} />
          </button>
          <div className="flex-1">
            <h1 className="text-3xl font-black text-white flex items-center gap-3">
              <Trophy size={28} className="text-yellow-400" />
              Global Leaderboard
            </h1>
            <p className="text-gray-500 text-sm mt-1">
              Top threat hunters across all operatives
            </p>
          </div>
          {/* Sort controls */}
          <div className="flex gap-2">
            {SORT_OPTIONS.map((opt) => (
              <button
                key={opt.id}
                onClick={() => setSortBy(opt.id)}
                className={`px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wide transition-colors ${
                  sortBy === opt.id
                    ? 'bg-yellow-500 text-black'
                    : 'bg-gray-700 text-gray-400 hover:text-white'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* Your Stats Panel */}
        <Card className="mb-6">
          <div className="flex flex-col sm:flex-row sm:items-center gap-4">
            <div className="flex items-center gap-3 flex-1">
              <div className="w-12 h-12 bg-gray-700 rounded-full flex items-center justify-center border-2 border-emerald-500/50 flex-shrink-0">
                <Shield size={24} className="text-emerald-400" />
              </div>
              <div>
                <div className="font-bold text-white text-sm">
                  {state.user?.uid
                    ? `Operative ${state.user.uid.slice(0, 6)}`
                    : 'You (Local)'}
                </div>
                <div className="text-xs text-emerald-400 font-mono">
                  {localEntry.rank}
                </div>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Score</div>
                <div className="text-xl font-mono font-bold text-white">
                  {localEntry.score.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Cases</div>
                <div className="text-xl font-mono font-bold text-blue-400">
                  {localEntry.completedCases}
                </div>
              </div>
              <div>
                <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Accuracy</div>
                <div className={`text-xl font-mono font-bold ${localEntry.accuracy >= 90 ? 'text-emerald-400' : localEntry.accuracy >= 70 ? 'text-yellow-400' : 'text-red-400'}`}>
                  {localEntry.accuracy}%
                </div>
              </div>
            </div>
            {currentUserEntry && (
              <div className="sm:ml-4 flex items-center gap-2 bg-yellow-950/30 border border-yellow-700/30 px-3 py-2 rounded-lg">
                <Star size={14} className="text-yellow-400" />
                <span className="text-sm font-bold text-yellow-300">
                  Rank #{currentUserEntry.position}
                </span>
              </div>
            )}
          </div>
        </Card>

        {/* Leaderboard Table */}
        <Card noPadding>
          {/* Column Headers */}
          <div className="grid grid-cols-[44px_1fr_100px_80px_80px] gap-2 px-4 py-3 border-b border-gray-700 text-xs text-gray-500 uppercase tracking-wider font-bold">
            <div className="text-center">#</div>
            <div>Operative</div>
            <div className="text-right">Score</div>
            <div className="text-right hidden sm:block">Cases</div>
            <div className="text-right hidden sm:block">Accuracy</div>
          </div>

          {entries.length === 0 ? (
            <div className="py-16 text-center text-gray-500 italic">
              <Trophy size={40} className="mx-auto mb-4 opacity-20" />
              <p>No leaderboard data yet.</p>
              <p className="text-sm mt-1">Complete scenarios to appear here.</p>
            </div>
          ) : (
            <div>
              {entries.map((entry) => (
                <div
                  key={entry.position}
                  className={`grid grid-cols-[44px_1fr_100px_80px_80px] gap-2 px-4 py-3 border-b border-gray-800 last:border-0 items-center transition-colors ${
                    entry.isCurrentUser
                      ? 'bg-emerald-950/20 border-l-2 border-l-emerald-500'
                      : 'hover:bg-gray-800/40'
                  }`}
                >
                  <div className="flex items-center justify-center">
                    <RankBadge position={entry.position} />
                  </div>

                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`font-bold text-sm truncate ${entry.isCurrentUser ? 'text-emerald-300' : 'text-gray-200'}`}>
                        {entry.user}
                      </span>
                      {entry.isCurrentUser && (
                        <Badge variant="success" size="sm">You</Badge>
                      )}
                    </div>
                    <div className="text-xs text-gray-500 font-mono truncate">
                      {entry.rank}
                    </div>
                  </div>

                  <div className="text-right">
                    <span className={`font-mono font-bold text-sm ${
                      entry.position === 1 ? 'text-yellow-400' :
                      entry.position === 2 ? 'text-gray-300' :
                      entry.position === 3 ? 'text-orange-400' : 'text-gray-400'
                    }`}>
                      {entry.score.toLocaleString()}
                    </span>
                  </div>

                  <div className="text-right hidden sm:block">
                    <span className="font-mono text-sm text-blue-400">
                      {entry.completedCases}
                    </span>
                  </div>

                  <div className="text-right hidden sm:block">
                    <span className={`font-mono text-sm ${
                      entry.accuracy >= 90 ? 'text-emerald-400' :
                      entry.accuracy >= 70 ? 'text-yellow-400' : 'text-red-400'
                    }`}>
                      {entry.accuracy}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Scoring formula */}
        <div className="mt-6 p-4 bg-gray-800/40 rounded-lg border border-gray-700 text-xs text-gray-500">
          <div className="font-bold uppercase tracking-wide text-gray-400 mb-2 flex items-center gap-2">
            <TrendingUp size={12} />
            Score Formula
          </div>
          <code className="font-mono text-gray-300">
            Score = (Budget × 10) + (Cases × 500) + (Accuracy × 10)
          </code>
        </div>
      </div>
    </div>
  );
};

export default Leaderboard;
