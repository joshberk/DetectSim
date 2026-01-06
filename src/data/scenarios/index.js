/**
 * Scenarios Index
 * Combines all scenario levels and provides utility functions
 */

import { LEVEL_1_SCENARIOS } from './level1-junior';
import { LEVEL_2_SCENARIOS } from './level2-intermediate';
import { LEVEL_3_SCENARIOS } from './level3-advanced';

// Export individual levels
export { LEVEL_1_SCENARIOS } from './level1-junior';
export { LEVEL_2_SCENARIOS } from './level2-intermediate';
export { LEVEL_3_SCENARIOS } from './level3-advanced';

// Combined scenarios array
export const ALL_SCENARIOS = [
  ...LEVEL_1_SCENARIOS,
  ...LEVEL_2_SCENARIOS,
  ...LEVEL_3_SCENARIOS,
];

// Scenario counts
export const SCENARIO_COUNTS = {
  level1: LEVEL_1_SCENARIOS.length,
  level2: LEVEL_2_SCENARIOS.length,
  level3: LEVEL_3_SCENARIOS.length,
  total: ALL_SCENARIOS.length,
};

/**
 * Get scenario by ID
 * @param {string} id - Scenario ID (e.g., 'L1-001')
 * @returns {Object|null} Scenario object or null
 */
export const getScenarioById = (id) => {
  return ALL_SCENARIOS.find((s) => s.id === id) || null;
};

/**
 * Get scenarios by level
 * @param {number} level - Level number (1, 2, or 3)
 * @returns {Array} Array of scenarios
 */
export const getScenariosByLevel = (level) => {
  switch (level) {
    case 1:
      return LEVEL_1_SCENARIOS;
    case 2:
      return LEVEL_2_SCENARIOS;
    case 3:
      return LEVEL_3_SCENARIOS;
    default:
      return [];
  }
};

/**
 * Get scenarios by difficulty
 * @param {number} difficulty - Difficulty rating (1-5)
 * @returns {Array} Array of scenarios
 */
export const getScenariosByDifficulty = (difficulty) => {
  return ALL_SCENARIOS.filter((s) => s.difficulty === difficulty);
};

/**
 * Get scenarios by MITRE tactic
 * @param {string} tactic - MITRE tactic name
 * @returns {Array} Array of scenarios
 */
export const getScenariosByTactic = (tactic) => {
  return ALL_SCENARIOS.filter(
    (s) => s.mitre?.tactic?.toLowerCase() === tactic.toLowerCase()
  );
};

/**
 * Get scenarios by log source
 * @param {string} logSource - Log source type
 * @returns {Array} Array of scenarios
 */
export const getScenariosByLogSource = (logSource) => {
  return ALL_SCENARIOS.filter((s) => s.logSource === logSource);
};

/**
 * Get next scenario based on completion
 * @param {Array} completedIds - Array of completed scenario IDs
 * @returns {Object|null} Next recommended scenario
 */
export const getNextScenario = (completedIds = []) => {
  // First, try to find an incomplete scenario in the current level
  for (const scenario of ALL_SCENARIOS) {
    if (!completedIds.includes(scenario.id)) {
      return scenario;
    }
  }
  return null;
};

/**
 * Get progress statistics
 * @param {Array} completedIds - Array of completed scenario IDs
 * @returns {Object} Progress statistics
 */
export const getProgressStats = (completedIds = []) => {
  const completedL1 = LEVEL_1_SCENARIOS.filter((s) =>
    completedIds.includes(s.id)
  ).length;
  const completedL2 = LEVEL_2_SCENARIOS.filter((s) =>
    completedIds.includes(s.id)
  ).length;
  const completedL3 = LEVEL_3_SCENARIOS.filter((s) =>
    completedIds.includes(s.id)
  ).length;

  return {
    level1: {
      completed: completedL1,
      total: LEVEL_1_SCENARIOS.length,
      percentage: Math.round((completedL1 / LEVEL_1_SCENARIOS.length) * 100),
    },
    level2: {
      completed: completedL2,
      total: LEVEL_2_SCENARIOS.length,
      percentage: Math.round((completedL2 / LEVEL_2_SCENARIOS.length) * 100),
    },
    level3: {
      completed: completedL3,
      total: LEVEL_3_SCENARIOS.length,
      percentage: Math.round((completedL3 / LEVEL_3_SCENARIOS.length) * 100),
    },
    overall: {
      completed: completedIds.length,
      total: ALL_SCENARIOS.length,
      percentage: Math.round((completedIds.length / ALL_SCENARIOS.length) * 100),
    },
  };
};

/**
 * Check if a level is unlocked
 * @param {number} level - Level to check
 * @param {Array} completedIds - Array of completed scenario IDs
 * @returns {boolean} Whether level is unlocked
 */
export const isLevelUnlocked = (level, completedIds = []) => {
  if (level === 1) return true;

  // Level 2 requires at least 10 Level 1 completions
  if (level === 2) {
    const l1Completed = LEVEL_1_SCENARIOS.filter((s) =>
      completedIds.includes(s.id)
    ).length;
    return l1Completed >= 10;
  }

  // Level 3 requires at least 10 Level 2 completions
  if (level === 3) {
    const l2Completed = LEVEL_2_SCENARIOS.filter((s) =>
      completedIds.includes(s.id)
    ).length;
    return l2Completed >= 10;
  }

  return false;
};

/**
 * Get unique MITRE tactics from all scenarios
 * @returns {Array} Array of unique tactics
 */
export const getUniqueTactics = () => {
  const tactics = new Set();
  ALL_SCENARIOS.forEach((s) => {
    if (s.mitre?.tactic) {
      tactics.add(s.mitre.tactic);
    }
  });
  return Array.from(tactics).sort();
};

/**
 * Get unique log sources from all scenarios
 * @returns {Array} Array of unique log sources
 */
export const getUniqueLogSources = () => {
  const sources = new Set();
  ALL_SCENARIOS.forEach((s) => {
    if (s.logSource) {
      sources.add(s.logSource);
    }
  });
  return Array.from(sources).sort();
};

export default {
  ALL_SCENARIOS,
  LEVEL_1_SCENARIOS,
  LEVEL_2_SCENARIOS,
  LEVEL_3_SCENARIOS,
  SCENARIO_COUNTS,
  getScenarioById,
  getScenariosByLevel,
  getScenariosByDifficulty,
  getScenariosByTactic,
  getScenariosByLogSource,
  getNextScenario,
  getProgressStats,
  isLevelUnlocked,
  getUniqueTactics,
  getUniqueLogSources,
};
