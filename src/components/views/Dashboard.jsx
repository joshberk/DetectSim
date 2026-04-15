/**
 * Dashboard View
 * Main navigation hub with career progression
 */

import React, { useState } from 'react';
import {
  Shield,
  DollarSign,
  User,
  Target,
  Activity,
  Trophy,
  Lock,
  CheckCircle,
  ChevronRight,
  Layout,
  BarChart2,
  Award,
  HelpCircle,
} from 'lucide-react';
import { useGame } from '../../context/GameContext';
import { useScenario } from '../../hooks';
import { Card, Badge, ProgressBar } from '../ui';
import { LEVELS } from '../../data/constants';
import { Tutorial, shouldShowTutorial } from '../Tutorial';

export const Dashboard = () => {
  const { state, actions } = useGame();
  const { progress, getLevelScenarios, checkLevelUnlocked, selectScenario } = useScenario();
  const [showTutorial, setShowTutorial] = useState(false);

  const levelConfigs = [
    { level: 1, ...LEVELS.JUNIOR,        scenarios: getLevelScenarios(1) },
    { level: 2, ...LEVELS.INTERMEDIATE,  scenarios: getLevelScenarios(2) },
    { level: 3, ...LEVELS.ADVANCED,      scenarios: getLevelScenarios(3) },
  ];

  return (
    <div className="min-h-screen bg-[#0f172a] p-4 sm:p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-end mb-10 border-b border-gray-700 pb-6 gap-4">
          <div>
            <div
              onClick={() => actions.setView('landing')}
              className="cursor-pointer group"
              title="Return to Landing"
            >
              <h1 className="text-3xl sm:text-4xl font-bold text-emerald-400 mb-2 flex items-center gap-3 transition-opacity group-hover:opacity-90">
                <Shield size={36} className="text-emerald-500" />
                DetectSim{' '}
                <span className="text-gray-500 text-xl sm:text-2xl font-mono">RPG</span>
              </h1>
            </div>
            <p className="text-gray-400 mt-2">
              Current Rank:{' '}
              <span className="text-white font-mono bg-gray-800 px-2 py-1 rounded border border-gray-700">
                {state.rank?.name || 'Junior Analyst'}
              </span>
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            {/* Quick-nav buttons */}
            <button
              onClick={() => actions.setView('statistics')}
              title="View Statistics"
              className="flex items-center gap-2 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-blue-400 hover:border-blue-500/50 transition-all text-sm"
            >
              <BarChart2 size={16} />
              <span className="hidden sm:inline">Stats</span>
            </button>

            <button
              onClick={() => actions.setView('leaderboard')}
              title="Leaderboard"
              className="flex items-center gap-2 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-yellow-400 hover:border-yellow-500/50 transition-all text-sm"
            >
              <Trophy size={16} />
              <span className="hidden sm:inline">Leaderboard</span>
            </button>

            <button
              onClick={() => actions.setView('achievements')}
              title="Achievements"
              className="flex items-center gap-2 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-purple-400 hover:border-purple-500/50 transition-all text-sm"
            >
              <Award size={16} />
              <span className="hidden sm:inline">
                Achievements
                {state.unlockedAchievements.length > 0 && (
                  <span className="ml-1.5 bg-purple-600 text-white text-xs px-1.5 py-0.5 rounded-full font-bold">
                    {state.unlockedAchievements.length}
                  </span>
                )}
              </span>
            </button>

            <button
              onClick={() => setShowTutorial(true)}
              title="Help / Tutorial"
              className="flex items-center gap-2 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-emerald-400 hover:border-emerald-500/50 transition-all text-sm"
            >
              <HelpCircle size={16} />
              <span className="hidden sm:inline">Help</span>
            </button>

            {/* Budget Display */}
            <div className="bg-gray-800 px-4 py-2 rounded-lg border border-gray-700 flex items-center gap-2 shadow-lg">
              <DollarSign size={20} className="text-yellow-400" />
              <div className="flex flex-col">
                <span className="text-[10px] text-gray-500 uppercase font-bold leading-none">Budget</span>
                <span className="font-mono text-xl font-bold text-white leading-tight">
                  {state.budget}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 sm:gap-8">
          {/* Career Map — Left Column */}
          <div className="lg:col-span-2">
            <Card header="Career Map" headerIcon={Layout} headerColor="emerald">
              <div className="space-y-6">
                {levelConfigs.map((levelConfig) => {
                  const isUnlocked = checkLevelUnlocked(levelConfig.level);
                  const levelProgress = progress[`level${levelConfig.level}`];

                  return (
                    <div key={levelConfig.level} className="space-y-3">
                      {/* Level Header */}
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge
                            variant={
                              levelConfig.level === 1
                                ? 'info'
                                : levelConfig.level === 2
                                ? 'purple'
                                : 'danger'
                            }
                          >
                            Level {levelConfig.level}
                          </Badge>
                          <span className="font-bold text-white">
                            {levelConfig.name}
                          </span>
                          {!isUnlocked && (
                            <Lock size={14} className="text-gray-500" />
                          )}
                        </div>
                        <span className="text-sm text-gray-400">
                          {levelProgress?.completed || 0}/{levelProgress?.total || 0}
                        </span>
                      </div>

                      {/* Level Progress */}
                      <ProgressBar
                        value={levelProgress?.completed || 0}
                        max={levelProgress?.total || 1}
                        variant={
                          levelConfig.level === 1
                            ? 'info'
                            : levelConfig.level === 2
                            ? 'purple'
                            : 'danger'
                        }
                        size="sm"
                      />

                      {/* Scenarios Grid */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {levelConfig.scenarios.map((scenario) => (
                          <button
                            key={scenario.id}
                            disabled={!isUnlocked}
                            onClick={() => selectScenario(scenario.id)}
                            className={`
                              w-full text-left p-3 rounded-lg border transition-all flex justify-between items-center group
                              ${
                                !isUnlocked
                                  ? 'bg-gray-900 border-gray-800 text-gray-600 cursor-not-allowed opacity-60'
                                  : 'bg-gray-700/50 border-gray-600 hover:border-emerald-500 hover:bg-gray-700 text-gray-200 cursor-pointer'
                              }
                              ${
                                scenario.isCompleted
                                  ? 'border-emerald-500/50 bg-emerald-900/10'
                                  : ''
                              }
                            `}
                          >
                            <div className="min-w-0 flex-1">
                              <div className="text-[10px] font-mono uppercase tracking-widest mb-0.5 text-gray-500 flex items-center gap-2">
                                {scenario.id}
                                {scenario.isCompleted && (
                                  <span className="text-emerald-500">DONE</span>
                                )}
                              </div>
                              <div className="font-medium text-sm truncate">
                                {scenario.title}
                              </div>
                            </div>
                            <div className="flex items-center gap-2 ml-2">
                              {scenario.isCompleted ? (
                                <CheckCircle className="text-emerald-500" size={18} />
                              ) : isUnlocked ? (
                                <ChevronRight
                                  className="text-gray-400 group-hover:translate-x-1 transition-transform"
                                  size={18}
                                />
                              ) : (
                                <Lock size={14} className="text-gray-600" />
                              )}
                            </div>
                          </button>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>
          </div>

          {/* Right Column — Profile, Stats & Leaderboard */}
          <div className="space-y-6">
            {/* Profile Card */}
            <Card>
              <div className="flex items-center gap-4 mb-6">
                <div className="h-14 w-14 bg-gray-700 rounded-full flex items-center justify-center border-2 border-gray-600 flex-shrink-0">
                  <User size={28} className="text-gray-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white">Operative</h2>
                  <div className="text-sm text-emerald-400 font-mono flex items-center gap-1">
                    <Shield size={12} />
                    {state.rank?.name || 'Junior Analyst'}
                  </div>
                </div>
              </div>

              {/* Overall Progress */}
              <ProgressBar
                value={progress.overall?.completed || 0}
                max={progress.overall?.total || 50}
                label="Clearance Progress"
                showLabel
                className="mb-5"
              />

              {/* Stats Grid */}
              <div className="grid grid-cols-2 gap-3 mb-4">
                <div className="bg-gray-900/50 p-3 rounded border border-gray-700">
                  <div className="flex items-center gap-1 text-gray-400 text-xs mb-1">
                    <Target size={12} className="text-blue-400" />
                    Cases Solved
                  </div>
                  <div className="text-2xl font-mono font-bold text-white">
                    {progress.overall?.completed || 0}
                    <span className="text-gray-600 text-sm">
                      /{progress.overall?.total || 50}
                    </span>
                  </div>
                </div>
                <div className="bg-gray-900/50 p-3 rounded border border-gray-700">
                  <div className="flex items-center gap-1 text-gray-400 text-xs mb-1">
                    <Activity size={12} className="text-emerald-400" />
                    Accuracy
                  </div>
                  <div className="text-2xl font-mono font-bold text-emerald-400">
                    {state.accuracy || 100}%
                  </div>
                </div>
              </div>

              {/* Achievements mini-bar */}
              {state.unlockedAchievements.length > 0 && (
                <button
                  onClick={() => actions.setView('achievements')}
                  className="w-full flex items-center justify-between p-2 bg-purple-950/30 border border-purple-800/30 rounded-lg hover:border-purple-600/50 transition-colors group"
                >
                  <div className="flex items-center gap-2 text-xs text-purple-300">
                    <Award size={14} className="text-purple-400" />
                    <span>{state.unlockedAchievements.length} Achievement{state.unlockedAchievements.length !== 1 ? 's' : ''} Unlocked</span>
                  </div>
                  <ChevronRight size={14} className="text-purple-500 group-hover:translate-x-0.5 transition-transform" />
                </button>
              )}
            </Card>

            {/* Leaderboard Preview Card */}
            <Card
              header="Top Hunters"
              headerIcon={Trophy}
              headerColor="yellow"
              footer={
                <button
                  onClick={() => actions.setView('leaderboard')}
                  className="w-full text-xs text-yellow-400 hover:text-yellow-300 transition-colors flex items-center justify-center gap-1"
                >
                  View full leaderboard <ChevronRight size={12} />
                </button>
              }
            >
              {state.leaderboard.length === 0 ? (
                <div className="text-center text-gray-500 py-4 italic text-sm">
                  Complete scenarios to appear on the leaderboard
                </div>
              ) : (
                <div className="space-y-2">
                  {state.leaderboard.slice(0, 5).map((entry, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-2 rounded text-sm bg-gray-900/30 border border-gray-800"
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`font-mono font-bold w-6 text-center ${
                            index < 3 ? 'text-yellow-400' : 'text-gray-500'
                          }`}
                        >
                          #{index + 1}
                        </div>
                        <div className="font-bold text-gray-300 truncate max-w-[120px]">
                          {String(entry.user || `Operative ${index + 1}`).slice(0, 20)}
                        </div>
                      </div>
                      <div className="font-mono text-white font-bold text-xs">
                        {typeof entry.score === 'number'
                          ? Math.max(0, Math.floor(entry.score)).toLocaleString()
                          : '0'}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>
        </div>
      </div>

      {/* Tutorial modal (re-openable via Help button) */}
      {showTutorial && (
        <Tutorial onClose={() => setShowTutorial(false)} />
      )}
    </div>
  );
};

export default Dashboard;
