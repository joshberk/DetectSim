/**
 * Landing View
 * Entry point with hero section
 */

import React from 'react';
import { Shield, ChevronRight } from 'lucide-react';
import { useGame } from '../../context/GameContext';
import { Button } from '../ui';

export const Landing = () => {
  const { state, actions } = useGame();

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-[#0f172a] text-center p-6 relative overflow-hidden">
      {/* Background elements */}
      <div className="absolute top-0 left-0 w-full h-full overflow-hidden pointer-events-none opacity-20">
        <div className="absolute top-10 left-10 text-emerald-900 font-mono text-9xl font-bold select-none opacity-20">
          DATA
        </div>
        <div className="absolute bottom-10 right-10 text-blue-900 font-mono text-9xl font-bold select-none opacity-20">
          LOGS
        </div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-emerald-500/10 rounded-full blur-3xl" />
      </div>

      {/* Content */}
      <div className="z-10 max-w-4xl w-full">
        {/* Logo */}
        <div className="mb-8 flex justify-center">
          <div className="h-24 w-24 bg-gray-800 rounded-2xl flex items-center justify-center border-2 border-emerald-500 shadow-[0_0_30px_rgba(16,185,129,0.3)] animate-pulse">
            <Shield size={64} className="text-emerald-400" />
          </div>
        </div>

        {/* Title */}
        <h1 className="text-6xl font-black text-white mb-6 tracking-tight drop-shadow-xl">
          DETECT<span className="text-emerald-500">SIM</span>
        </h1>

        {/* Subtitle */}
        <p className="text-xl text-gray-400 mb-4 max-w-2xl mx-auto">
          Detection Engineering RPG
        </p>

        {/* Description */}
        <p className="text-lg text-gray-500 mb-12 max-w-2xl mx-auto leading-relaxed">
          Step into the shoes of a SOC Analyst. Analyze real-world logs, write{' '}
          <span className="text-white font-mono bg-gray-800 px-2 py-1 rounded">
            Sigma
          </span>{' '}
          rules, and hunt down adversaries before they breach the network.
        </p>

        {/* CTA Button */}
        <Button
          size="xl"
          onClick={() => actions.setView('dashboard')}
          icon={ChevronRight}
          iconPosition="right"
          className="group"
        >
          <span className="mr-2 text-lg font-mono">INITIALIZE_SEQUENCE</span>
        </Button>

        {/* Stats preview */}
        <div className="mt-12 flex justify-center gap-8 text-sm">
          <div className="text-center">
            <div className="text-3xl font-bold text-emerald-400 font-mono">50</div>
            <div className="text-gray-500 uppercase tracking-wider">Scenarios</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-blue-400 font-mono">3</div>
            <div className="text-gray-500 uppercase tracking-wider">Difficulty Levels</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-purple-400 font-mono">6</div>
            <div className="text-gray-500 uppercase tracking-wider">Ranks</div>
          </div>
        </div>

        {/* System status */}
        <div className="mt-12 text-xs text-gray-500 font-mono flex flex-col gap-1 items-center">
          <div>
            System Status: <span className="text-emerald-500">ONLINE</span> | v1.0.0
          </div>
          {state.user && (
            <div className="text-gray-600">
              User ID: {state.user.uid?.slice(0, 8) || 'local'}...
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Landing;
