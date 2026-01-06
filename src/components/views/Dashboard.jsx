/**
 * Dashboard View
 * Main navigation hub with career progression
 */

import React from 'react';
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
} from 'lucide-react';
import { useGame } from '../../context/GameContext';
import { useScenario } from '../../hooks';
import { Card, Badge, ProgressBar, Button } from '../ui';
import { LEVELS } from '../../data/constants';

export const Dashboard = () => {
  const { state, actions } = useGame();
  const { progress, getLevelScenarios, checkLevelUnlocked, selectScenario } = useScenario();

  const levelConfigs = [
    { level: 1, ...LEVELS.JUNIOR, scenarios: getLevelScenarios(1) },
    { level: 2, ...LEVELS.INTERMEDIATE, scenarios: getLevelScenarios(2) },
    { level: 3, ...LEVELS.ADVANCED, scenarios: getLevelScenarios(3) },
  ];

  return (
    <div className="min-h-screen bg-[#0f172a] p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-end mb-12 border-b border-gray-700 pb-8">
          <div>
            <div
              onClick={() => actions.setView('landing')}
              className="cursor-pointer group"
              title="Return to Landing"
            >
              <h1 className="text-4xl font-bold text-emerald-400 mb-2 flex items-center gap-3 transition-opacity group-hover:opacity-90">
                <Shield size={40} className="text-emerald-500" />
                DetectSim{' '}
                <span className="text-gray-500 text-2xl font-mono">RPG</span>
              </h1>
            </div>
            <p className="text-gray-400 mt-2">
              Current Rank:{' '}
              <span className="text-white font-mono bg-gray-800 px-2 py-1 rounded border border-gray-700">
                {state.rank?.name || 'Junior Analyst'}
              </span>
            </p>
          </div>

          {/* Budget Display */}
          <div className="bg-gray-800 px-6 py-3 rounded-lg border border-gray-700 flex items-center gap-3 shadow-lg">
            <DollarSign size={24} className="text-yellow-400" />
            <div className="flex flex-col">
              <span className="text-xs text-gray-500 uppercase font-bold">Budget</span>
              <span className="font-mono text-2xl font-bold text-white">
                {state.budget}
              </span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Career Map - Left Column */}
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
                        {levelConfig.scenarios.slice(0, 6).map((scenario) => (
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
                                <CheckCircle
                                  className="text-emerald-500"
                                  size={18}
                                />
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

                      {/* Show more */}
                      {levelConfig.scenarios.length > 6 && (
                        <div className="text-center">
                          <span className="text-xs text-gray-500">
                            +{levelConfig.scenarios.length - 6} more scenarios
                          </span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </Card>
          </div>

          {/* Right Column - Profile & Stats */}
          <div className="space-y-6">
            {/* Profile Card */}
            <Card>
              <div className="flex items-center gap-4 mb-6">
                <div className="h-16 w-16 bg-gray-700 rounded-full flex items-center justify-center border-2 border-gray-600">
                  <User size={32} className="text-gray-400" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">Operative</h2>
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
                className="mb-6"
              />

              {/* Stats Grid */}
              <div className="grid grid-cols-2 gap-3">
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
            </Card>

            {/* Leaderboard Card */}
            <Card header="Top Hunters" headerIcon={Trophy} headerColor="yellow">
              {state.leaderboard.length === 0 ? (
                <div className="text-center text-gray-500 py-4 italic">
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
                        <div className="font-bold text-gray-300">
                          {entry.user || `Operative ${index + 1}`}
                        </div>
                      </div>
                      <div className="font-mono text-white font-bold">
                        {entry.score?.toLocaleString() || 0}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
