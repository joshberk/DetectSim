/**
 * App Component
 * Main application routing and layout
 */

import React from 'react';
import { useGame } from './context/GameContext';
import { Landing, Dashboard, Workspace } from './components/views';

// Loading screen component
const LoadingScreen = () => (
  <div className="h-screen bg-[#0f172a] flex items-center justify-center">
    <div className="text-center">
      <div className="relative w-16 h-16 mx-auto mb-6">
        {/* Animated ring */}
        <div className="absolute inset-0 border-4 border-emerald-500/20 rounded-full" />
        <div className="absolute inset-0 border-4 border-transparent border-t-emerald-500 rounded-full animate-spin" />
        {/* Center dot */}
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
    case 'landing':
      return <Landing />;
    case 'dashboard':
      return <Dashboard />;
    case 'workspace':
      return <Workspace />;
    default:
      return <Landing />;
  }
};

const App = () => {
  const { state } = useGame();

  // Show loading screen while initializing
  if (state.isLoading) {
    return <LoadingScreen />;
  }

  return (
    <div className="min-h-screen bg-[#0f172a]">
      <ViewRouter currentView={state.currentView} />
    </div>
  );
};

export default App;
