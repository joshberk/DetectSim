/**
 * Achievements Gallery View
 * Shows all achievements, locked/unlocked state, and progress hints.
 * No user-supplied content rendered — all text is from static definitions.
 */

import React, { useMemo, useState } from 'react';
import { ArrowLeft, Award, Lock } from 'lucide-react';
import { useGame } from '../../context/GameContext';
import { Card } from '../ui';
import { ACHIEVEMENTS } from '../../data/achievements';

const CATEGORIES = [
  { id: 'all', label: 'All' },
  { id: 'progression', label: 'Progression' },
  { id: 'levels', label: 'Levels' },
  { id: 'skill', label: 'Skill' },
  { id: 'economy', label: 'Economy' },
  { id: 'rank', label: 'Rank' },
  { id: 'special', label: 'Special' },
];

const AchievementCard = ({ achievement, isUnlocked }) => (
  <div
    className={`flex items-start gap-4 p-4 rounded-xl border transition-all ${
      isUnlocked
        ? 'bg-gray-800/80 border-purple-700/40 shadow-lg'
        : 'bg-gray-900/40 border-gray-800 opacity-60'
    }`}
  >
    <div
      className={`w-12 h-12 rounded-xl flex items-center justify-center text-2xl flex-shrink-0 ${
        isUnlocked ? 'bg-purple-900/50 border border-purple-700/50' : 'bg-gray-800 border border-gray-700'
      }`}
    >
      {isUnlocked ? (
        <span role="img" aria-label={achievement.title}>
          {achievement.icon}
        </span>
      ) : (
        <Lock size={20} className="text-gray-600" />
      )}
    </div>
    <div className="flex-1 min-w-0">
      <div className="flex items-center gap-2 mb-1">
        <span
          className={`font-bold text-sm ${isUnlocked ? 'text-white' : 'text-gray-500'}`}
        >
          {achievement.secret && !isUnlocked ? '???' : achievement.title}
        </span>
        {isUnlocked && (
          <span className="text-[10px] bg-purple-900/60 border border-purple-700/50 text-purple-300 px-1.5 py-0.5 rounded font-bold uppercase tracking-wider">
            Unlocked
          </span>
        )}
      </div>
      <p className={`text-xs leading-snug ${isUnlocked ? 'text-gray-400' : 'text-gray-600'}`}>
        {achievement.secret && !isUnlocked
          ? 'Keep playing to discover this hidden achievement.'
          : achievement.description}
      </p>
    </div>
  </div>
);

export const Achievements = () => {
  const { state, actions } = useGame();
  const [category, setCategory] = useState('all');

  const { unlockedCount, filteredAchievements } = useMemo(() => {
    const unlocked = new Set(state.unlockedAchievements);

    const sorted = [...ACHIEVEMENTS].sort((a, b) => {
      const aU = unlocked.has(a.id) ? 0 : 1;
      const bU = unlocked.has(b.id) ? 0 : 1;
      return aU - bU;
    });

    const filtered =
      category === 'all'
        ? sorted
        : sorted.filter((a) => a.category === category);

    return {
      unlockedCount: unlocked.size,
      filteredAchievements: filtered,
    };
  }, [state.unlockedAchievements, category]);

  const totalCount = ACHIEVEMENTS.length;
  const pct = totalCount > 0 ? Math.round((unlockedCount / totalCount) * 100) : 0;

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
              <Award size={28} className="text-purple-400" />
              Achievements
            </h1>
            <p className="text-gray-500 text-sm mt-1">
              {unlockedCount} / {totalCount} unlocked — {pct}% complete
            </p>
          </div>
        </div>

        {/* Overall progress bar */}
        <div className="mb-6">
          <div className="h-2.5 bg-gray-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-purple-500 to-pink-500 rounded-full transition-all duration-700"
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>

        {/* Category filter */}
        <div className="flex gap-2 flex-wrap mb-6">
          {CATEGORIES.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setCategory(cat.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wide transition-colors ${
                category === cat.id
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-700 text-gray-400 hover:text-white hover:bg-gray-600'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Achievement Grid */}
        <Card noPadding>
          <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
            {filteredAchievements.map((achievement) => (
              <AchievementCard
                key={achievement.id}
                achievement={achievement}
                isUnlocked={state.unlockedAchievements.includes(achievement.id)}
              />
            ))}
            {filteredAchievements.length === 0 && (
              <div className="col-span-2 py-12 text-center text-gray-500 italic">
                No achievements in this category yet.
              </div>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
};

export default Achievements;
