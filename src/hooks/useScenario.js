/**
 * useScenario Hook
 * Manages scenario selection and state
 */

import { useState, useEffect, useCallback, useMemo } from 'react';
import { useGame } from '../context/GameContext';
import {
  getScenarioById,
  getScenariosByLevel,
  getProgressStats,
  isLevelUnlocked,
} from '../data/scenarios';

export const useScenario = () => {
  const { state, actions } = useGame();
  const [currentScenario, setCurrentScenario] = useState(null);
  const [userCode, setUserCode] = useState('');

  // Load scenario when activeScenarioId changes
  useEffect(() => {
    if (state.activeScenarioId) {
      const scenario = getScenarioById(state.activeScenarioId);
      if (scenario) {
        setCurrentScenario(scenario);
        setUserCode(scenario.starterCode || '');
      }
    } else {
      setCurrentScenario(null);
      setUserCode('');
    }
  }, [state.activeScenarioId]);

  // Get progress statistics
  const progress = useMemo(
    () => getProgressStats(state.completedScenarios),
    [state.completedScenarios]
  );

  // Get scenarios by level with completion status
  const getLevelScenarios = useCallback(
    (level) => {
      const scenarios = getScenariosByLevel(level);
      return scenarios.map((scenario) => ({
        ...scenario,
        isCompleted: state.completedScenarios.includes(scenario.id),
        attemptCount: state.scenarioAttempts[scenario.id]?.length || 0,
      }));
    },
    [state.completedScenarios, state.scenarioAttempts]
  );

  // Check if level is unlocked
  const checkLevelUnlocked = useCallback(
    (level) => isLevelUnlocked(level, state.completedScenarios),
    [state.completedScenarios]
  );

  // Select a scenario
  const selectScenario = useCallback(
    (scenarioId) => {
      const scenario = getScenarioById(scenarioId);
      if (scenario) {
        // Check if level is unlocked
        if (!isLevelUnlocked(scenario.level, state.completedScenarios)) {
          return false;
        }
        actions.setActiveScenario(scenarioId);
        actions.setView('workspace');
        return true;
      }
      return false;
    },
    [actions, state.completedScenarios]
  );

  // Navigate back to dashboard
  const exitScenario = useCallback(() => {
    actions.setActiveScenario(null);
    actions.setView('dashboard');
  }, [actions]);

  // Get hint content (if purchased)
  const getHintContent = useCallback(
    (hintIndex) => {
      if (!currentScenario || !currentScenario.hints) {
        return null;
      }

      const hint = currentScenario.hints[hintIndex];
      if (!hint) {
        return null;
      }

      const isPurchased = actions.isHintPurchased(currentScenario.id, hintIndex);

      return {
        ...hint,
        isPurchased,
        content: isPurchased ? hint.content : null,
      };
    },
    [currentScenario, actions]
  );

  // Purchase a hint
  const purchaseHint = useCallback(
    (hintIndex) => {
      if (!currentScenario || !currentScenario.hints) {
        return false;
      }

      const hint = currentScenario.hints[hintIndex];
      if (!hint) {
        return false;
      }

      return actions.purchaseHint(currentScenario.id, hintIndex, hint.cost);
    },
    [currentScenario, actions]
  );

  // Apply hint to code editor
  const applyHintToCode = useCallback(
    (hintIndex) => {
      const hint = getHintContent(hintIndex);
      if (hint?.isPurchased && hint?.isSolution) {
        // Format the solution for the code editor
        const formattedCode = hint.content.replace(/\\n/g, '\n');
        setUserCode(formattedCode);
        return true;
      }
      return false;
    },
    [getHintContent]
  );

  return {
    currentScenario,
    userCode,
    setUserCode,
    progress,
    getLevelScenarios,
    checkLevelUnlocked,
    selectScenario,
    exitScenario,
    getHintContent,
    purchaseHint,
    applyHintToCode,
    isCompleted: currentScenario
      ? state.completedScenarios.includes(currentScenario.id)
      : false,
  };
};

export default useScenario;
