/**
 * App Component
 * Main application routing and layout
 */

import React, { useState, useEffect, useRef } from 'react';
import { useGame } from './context/GameContext';
import { Landing, Dashboard, Workspace, Statistics, Leaderboard, Achievements } from './components/views';
import { Tutorial, shouldShowTutorial } from './components/Tutorial';
import { RankUpCeremony } from './components/RankUpCeremony';
import { useToast } from './context/ToastContext';
import { ACHIEVEMENTS_BY_ID } from './data/achievements';

// Loading screen component
const LoadingScreen = () => (
  <div className="h-screen bg-[#0f172a] flex items-center justify-center">
    <div className="text-center">
      <div className="relative w-16 h-16 mx-auto mb-6">
        <div className="absolute inset-0 border-4 border-emerald-500/20 rounded-full" />
        <div className="absolute inset-0 border-4 border-transparent border-t-emerald-500 rounded-full animate-spin" />
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-3 h-3 bg-emerald-500 rounded-full animate-pulse" />
        </div>
      </div>
      <h2 className="text-emerald-400 font-bold text-lg tracking-wider uppercase">
        Initializing
      </h2>
      <p className="text-gray-500 text-sm mt-2 font-mono">
        Loading detection systems...
      </p>
    </div>
  </div>
);

// View router
const ViewRouter = ({ currentView }) => {
  switch (currentView) {
    case 'landing':      return <Landing />;
    case 'dashboard':    return <Dashboard />;
    case 'workspace':    return <Workspace />;
    case 'statistics':   return <Statistics />;
    case 'leaderboard':  return <Leaderboard />;
    case 'achievements': return <Achievements />;
    default:             return <Landing />;
  }
};

const App = () => {
  const { state } = useGame();
  const { toast } = useToast();
  const [showTutorial, setShowTutorial] = useState(false);
  const [ceremonyRank, setCeremonyRank] = useState(null);
  const prevRankRef = useRef(state.rank);

  // Show tutorial on first dashboard visit
  useEffect(() => {
    if (state.currentView === 'dashboard' && shouldShowTutorial()) {
      // Small delay so dashboard renders first
      const t = setTimeout(() => setShowTutorial(true), 600);
      return () => clearTimeout(t);
    }
  }, [state.currentView]);

  // Detect rank-up and show ceremony
  useEffect(() => {
    const prev = prevRankRef.current;
    const curr = state.rank;
    // Both must be set, must be different IDs, and not the initial load
    if (prev && curr && prev.id !== curr.id) {
      setCeremonyRank(curr);
    }
    prevRankRef.current = curr;
  }, [state.rank]);

  // Toast newly unlocked achievements
  const prevAchievementsRef = useRef(state.unlockedAchievements);
  useEffect(() => {
    const prev = new Set(prevAchievementsRef.current);
    const current = state.unlockedAchievements;
    current.forEach((id) => {
      if (!prev.has(id)) {
        const achievement = ACHIEVEMENTS_BY_ID[id];
        if (achievement) {
          toast.achievement(`${achievement.icon}  ${achievement.title}`, {
            title: 'Achievement Unlocked',
          });
        }
      }
    });
    prevAchievementsRef.current = current;
  }, [state.unlockedAchievements, toast]);

  if (state.isLoading) {
    return <LoadingScreen />;
  }

  return (
    <div className="min-h-screen bg-[#0f172a]">
      <ViewRouter currentView={state.currentView} />
      {showTutorial && (
        <Tutorial onClose={() => setShowTutorial(false)} />
      )}
      {ceremonyRank && (
        <RankUpCeremony
          rank={ceremonyRank}
          onClose={() => setCeremonyRank(null)}
        />
      )}
    </div>
  );
};

export default App;
