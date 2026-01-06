/**
 * useDetection Hook
 * Manages detection rule execution and results
 */

import { useState, useCallback } from 'react';
import { runDetection } from '../engine';
import { useGame } from '../context/GameContext';
import { SCORING } from '../utils/scoring';

export const useDetection = (scenario) => {
  const { state, actions } = useGame();
  const [results, setResults] = useState(null);
  const [feedback, setFeedback] = useState(null);
  const [isRunning, setIsRunning] = useState(false);

  const executeDetection = useCallback(
    (ruleText) => {
      if (!scenario || !scenario.logs) {
        setFeedback({
          type: 'error',
          message: 'No Scenario Loaded',
          details: 'Please select a scenario first.',
        });
        return null;
      }

      setIsRunning(true);
      setFeedback(null);

      try {
        // Run detection
        const result = runDetection(ruleText, scenario.logs, scenario.logSource);

        if (!result.success) {
          setFeedback({
            type: 'error',
            message: `${result.phase === 'parsing' ? 'Syntax' : 'Logic'} Error`,
            details: result.error,
          });

          // Apply syntax error penalty
          if (result.phase === 'parsing') {
            actions.applyPenalty(Math.abs(SCORING.SYNTAX_ERROR));
          }

          setIsRunning(false);
          return null;
        }

        // Update results
        setResults(result.results);

        // Record attempt
        const attemptCount = actions.getAttemptCount(scenario.id);
        const isFirstTry = attemptCount === 0;

        actions.recordAttempt(scenario.id, {
          truePositives: result.summary.truePositives,
          falsePositives: result.summary.falsePositives,
          missedAttacks: result.summary.missedAttacks,
          isPerfect: result.isPerfect,
        });

        // Generate feedback and handle scoring
        if (result.isPerfect) {
          // Perfect detection!
          if (!actions.isScenarioCompleted(scenario.id)) {
            const baseReward = SCORING.PERFECT_DETECTION;
            const firstTryBonus = isFirstTry ? SCORING.FIRST_TRY_BONUS : 0;
            const totalReward = baseReward + firstTryBonus;

            actions.completeScenario(scenario.id, totalReward, result.summary);

            setFeedback({
              type: 'success',
              message: 'Threat Neutralized!',
              details: `Perfect detection! ${result.summary.truePositives} threat(s) caught with 0 false positives. +$${totalReward} Budget${isFirstTry ? ' (includes first try bonus!)' : ''}`,
            });
          } else {
            setFeedback({
              type: 'success',
              message: 'Perfect Detection (Already Completed)',
              details: `${result.summary.truePositives} threat(s) caught with 0 false positives. No additional reward.`,
            });
          }
        } else if (result.summary.falsePositives > 0 && result.summary.missedAttacks > 0) {
          // Both FPs and misses
          const penalty =
            result.summary.falsePositives * Math.abs(SCORING.FALSE_POSITIVE) +
            result.summary.missedAttacks * Math.abs(SCORING.MISSED_ATTACK);

          actions.applyPenalty(penalty);

          setFeedback({
            type: 'error',
            message: 'Detection Needs Work',
            details: `Found ${result.summary.truePositives}/${result.summary.totalMalicious} threats, but had ${result.summary.falsePositives} false positive(s) and missed ${result.summary.missedAttacks} attack(s). -$${penalty}`,
          });
        } else if (result.summary.falsePositives > 0) {
          // Only FPs
          const penalty = result.summary.falsePositives * Math.abs(SCORING.FALSE_POSITIVE);
          actions.applyPenalty(penalty);

          setFeedback({
            type: 'warning',
            message: 'Detection Too Noisy',
            details: `Caught all threats but flagged ${result.summary.falsePositives} benign event(s). Refine your logic to reduce false positives. -$${penalty}`,
          });
        } else {
          // Only misses
          const penalty = result.summary.missedAttacks * Math.abs(SCORING.MISSED_ATTACK);
          actions.applyPenalty(penalty);

          setFeedback({
            type: 'error',
            message: 'Attack Missed',
            details: `Failed to catch ${result.summary.missedAttacks} malicious event(s). Review the log data and broaden your detection criteria. -$${penalty}`,
          });
        }

        setIsRunning(false);
        return result;
      } catch (error) {
        setFeedback({
          type: 'error',
          message: 'Execution Error',
          details: error.message,
        });
        setIsRunning(false);
        return null;
      }
    },
    [scenario, actions]
  );

  const clearResults = useCallback(() => {
    setResults(null);
    setFeedback(null);
  }, []);

  return {
    results,
    feedback,
    isRunning,
    executeDetection,
    clearResults,
    attemptCount: scenario ? actions.getAttemptCount(scenario.id) : 0,
    isCompleted: scenario ? actions.isScenarioCompleted(scenario.id) : false,
  };
};

export default useDetection;
