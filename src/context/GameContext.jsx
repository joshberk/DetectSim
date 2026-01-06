/**
 * Game Context
 * Provides global game state management
 */

import React, { createContext, useContext, useReducer, useEffect, useCallback } from 'react';
import { loadGameState, saveGameState, getDefaultGameState } from '../services/storage';
import { calculateAccuracy, determineRank, calculateLeaderboardScore } from '../utils/scoring';
import { subscribeToAuthState, signInAnon, isFirebaseConfigured } from '../services/firebase';

// Initial state
const initialState = {
  // User state
  user: null,
  isAuthenticated: false,
  isLoading: true,

  // Game state
  budget: 150,
  completedScenarios: [],
  scenarioAttempts: {},
  statistics: {
    totalAttempts: 0,
    truePositives: 0,
    falsePositives: 0,
    missedAttacks: 0,
    perfectDetections: 0,
  },
  purchasedHints: [],

  // Computed values
  rank: null,
  accuracy: 100,
  leaderboardScore: 0,

  // UI state
  currentView: 'landing',
  activeScenarioId: null,

  // Leaderboard
  leaderboard: [],
};

// Action types
const ActionTypes = {
  SET_USER: 'SET_USER',
  SET_LOADING: 'SET_LOADING',
  LOAD_GAME_STATE: 'LOAD_GAME_STATE',
  UPDATE_BUDGET: 'UPDATE_BUDGET',
  COMPLETE_SCENARIO: 'COMPLETE_SCENARIO',
  RECORD_ATTEMPT: 'RECORD_ATTEMPT',
  PURCHASE_HINT: 'PURCHASE_HINT',
  UPDATE_STATISTICS: 'UPDATE_STATISTICS',
  SET_VIEW: 'SET_VIEW',
  SET_ACTIVE_SCENARIO: 'SET_ACTIVE_SCENARIO',
  SET_LEADERBOARD: 'SET_LEADERBOARD',
  RESET_GAME: 'RESET_GAME',
};

// Reducer
const gameReducer = (state, action) => {
  switch (action.type) {
    case ActionTypes.SET_USER:
      return {
        ...state,
        user: action.payload,
        isAuthenticated: !!action.payload,
      };

    case ActionTypes.SET_LOADING:
      return {
        ...state,
        isLoading: action.payload,
      };

    case ActionTypes.LOAD_GAME_STATE: {
      const gameState = action.payload;
      const stats = {
        completedCases: gameState.completedScenarios?.length || 0,
        accuracy: calculateAccuracy(gameState.statistics || {}),
        budget: gameState.budget || 150,
      };

      return {
        ...state,
        budget: gameState.budget || 150,
        completedScenarios: gameState.completedScenarios || [],
        scenarioAttempts: gameState.scenarioAttempts || {},
        statistics: gameState.statistics || initialState.statistics,
        purchasedHints: gameState.purchasedHints || [],
        rank: determineRank(stats),
        accuracy: stats.accuracy,
        leaderboardScore: calculateLeaderboardScore(stats),
      };
    }

    case ActionTypes.UPDATE_BUDGET:
      return {
        ...state,
        budget: Math.max(0, action.payload),
      };

    case ActionTypes.COMPLETE_SCENARIO: {
      const { scenarioId, reward, stats } = action.payload;

      if (state.completedScenarios.includes(scenarioId)) {
        return state;
      }

      const newCompleted = [...state.completedScenarios, scenarioId];
      const newBudget = state.budget + reward;
      const newStatistics = {
        ...state.statistics,
        perfectDetections: state.statistics.perfectDetections + 1,
        truePositives: state.statistics.truePositives + (stats?.truePositives || 0),
      };

      const updatedStats = {
        completedCases: newCompleted.length,
        accuracy: calculateAccuracy(newStatistics),
        budget: newBudget,
      };

      return {
        ...state,
        budget: newBudget,
        completedScenarios: newCompleted,
        statistics: newStatistics,
        rank: determineRank(updatedStats),
        accuracy: updatedStats.accuracy,
        leaderboardScore: calculateLeaderboardScore(updatedStats),
      };
    }

    case ActionTypes.RECORD_ATTEMPT: {
      const { scenarioId, attempt } = action.payload;
      const attempts = state.scenarioAttempts[scenarioId] || [];

      const newStatistics = {
        ...state.statistics,
        totalAttempts: state.statistics.totalAttempts + 1,
        truePositives: state.statistics.truePositives + (attempt.truePositives || 0),
        falsePositives: state.statistics.falsePositives + (attempt.falsePositives || 0),
        missedAttacks: state.statistics.missedAttacks + (attempt.missedAttacks || 0),
      };

      return {
        ...state,
        scenarioAttempts: {
          ...state.scenarioAttempts,
          [scenarioId]: [...attempts, { ...attempt, timestamp: Date.now() }],
        },
        statistics: newStatistics,
        accuracy: calculateAccuracy(newStatistics),
      };
    }

    case ActionTypes.PURCHASE_HINT: {
      const { scenarioId, hintIndex, cost } = action.payload;
      const hintKey = `${scenarioId}_${hintIndex}`;

      if (state.purchasedHints.includes(hintKey) || state.budget < cost) {
        return state;
      }

      return {
        ...state,
        budget: state.budget - cost,
        purchasedHints: [...state.purchasedHints, hintKey],
      };
    }

    case ActionTypes.UPDATE_STATISTICS:
      return {
        ...state,
        statistics: {
          ...state.statistics,
          ...action.payload,
        },
      };

    case ActionTypes.SET_VIEW:
      return {
        ...state,
        currentView: action.payload,
      };

    case ActionTypes.SET_ACTIVE_SCENARIO:
      return {
        ...state,
        activeScenarioId: action.payload,
      };

    case ActionTypes.SET_LEADERBOARD:
      return {
        ...state,
        leaderboard: action.payload,
      };

    case ActionTypes.RESET_GAME:
      return {
        ...initialState,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
        isLoading: false,
      };

    default:
      return state;
  }
};

// Create context
const GameContext = createContext(null);

// Provider component
export const GameProvider = ({ children }) => {
  const [state, dispatch] = useReducer(gameReducer, initialState);

  // Initialize authentication
  useEffect(() => {
    const initAuth = async () => {
      if (isFirebaseConfigured()) {
        const unsubscribe = subscribeToAuthState((user) => {
          dispatch({ type: ActionTypes.SET_USER, payload: user });

          if (user) {
            const gameState = loadGameState(user.uid);
            dispatch({ type: ActionTypes.LOAD_GAME_STATE, payload: gameState });
          }

          dispatch({ type: ActionTypes.SET_LOADING, payload: false });
        });

        // Try anonymous sign in
        await signInAnon();

        return unsubscribe;
      } else {
        // Use local storage only
        const gameState = loadGameState('local');
        dispatch({ type: ActionTypes.LOAD_GAME_STATE, payload: gameState });
        dispatch({ type: ActionTypes.SET_LOADING, payload: false });
      }
    };

    initAuth();
  }, []);

  // Save state changes to storage
  useEffect(() => {
    if (!state.isLoading) {
      const userId = state.user?.uid || 'local';
      saveGameState(
        {
          budget: state.budget,
          completedScenarios: state.completedScenarios,
          scenarioAttempts: state.scenarioAttempts,
          statistics: state.statistics,
          purchasedHints: state.purchasedHints,
        },
        userId
      );
    }
  }, [
    state.budget,
    state.completedScenarios,
    state.scenarioAttempts,
    state.statistics,
    state.purchasedHints,
    state.isLoading,
    state.user,
  ]);

  // Actions
  const actions = {
    setView: useCallback((view) => {
      dispatch({ type: ActionTypes.SET_VIEW, payload: view });
    }, []),

    setActiveScenario: useCallback((scenarioId) => {
      dispatch({ type: ActionTypes.SET_ACTIVE_SCENARIO, payload: scenarioId });
    }, []),

    completeScenario: useCallback((scenarioId, reward, stats = {}) => {
      dispatch({
        type: ActionTypes.COMPLETE_SCENARIO,
        payload: { scenarioId, reward, stats },
      });
    }, []),

    recordAttempt: useCallback((scenarioId, attempt) => {
      dispatch({
        type: ActionTypes.RECORD_ATTEMPT,
        payload: { scenarioId, attempt },
      });
    }, []),

    purchaseHint: useCallback((scenarioId, hintIndex, cost) => {
      if (state.budget >= cost) {
        dispatch({
          type: ActionTypes.PURCHASE_HINT,
          payload: { scenarioId, hintIndex, cost },
        });
        return true;
      }
      return false;
    }, [state.budget]),

    updateBudget: useCallback((amount) => {
      dispatch({ type: ActionTypes.UPDATE_BUDGET, payload: amount });
    }, []),

    applyPenalty: useCallback((amount) => {
      dispatch({ type: ActionTypes.UPDATE_BUDGET, payload: state.budget - amount });
    }, [state.budget]),

    resetGame: useCallback(() => {
      dispatch({ type: ActionTypes.RESET_GAME });
    }, []),

    isScenarioCompleted: useCallback(
      (scenarioId) => state.completedScenarios.includes(scenarioId),
      [state.completedScenarios]
    ),

    isHintPurchased: useCallback(
      (scenarioId, hintIndex) =>
        state.purchasedHints.includes(`${scenarioId}_${hintIndex}`),
      [state.purchasedHints]
    ),

    getAttemptCount: useCallback(
      (scenarioId) => state.scenarioAttempts[scenarioId]?.length || 0,
      [state.scenarioAttempts]
    ),
  };

  return (
    <GameContext.Provider value={{ state, actions, dispatch }}>
      {children}
    </GameContext.Provider>
  );
};

// Custom hook
export const useGame = () => {
  const context = useContext(GameContext);
  if (!context) {
    throw new Error('useGame must be used within a GameProvider');
  }
  return context;
};

export default GameContext;
