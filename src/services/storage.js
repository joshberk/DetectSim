/**
 * Local Storage Service
 * Fallback storage when Firebase is not configured
 * Handles game state persistence locally
 */

const STORAGE_PREFIX = 'detectsim_';

/**
 * Get item from localStorage with prefix
 * @param {string} key - Storage key
 * @returns {any} Parsed value or null
 */
export const getItem = (key) => {
  try {
    const item = localStorage.getItem(`${STORAGE_PREFIX}${key}`);
    return item ? JSON.parse(item) : null;
  } catch (error) {
    console.error('Storage getItem error:', error);
    return null;
  }
};

/**
 * Set item in localStorage with prefix
 * @param {string} key - Storage key
 * @param {any} value - Value to store
 * @returns {boolean} Success status
 */
export const setItem = (key, value) => {
  try {
    localStorage.setItem(`${STORAGE_PREFIX}${key}`, JSON.stringify(value));
    return true;
  } catch (error) {
    console.error('Storage setItem error:', error);
    return false;
  }
};

/**
 * Remove item from localStorage
 * @param {string} key - Storage key
 * @returns {boolean} Success status
 */
export const removeItem = (key) => {
  try {
    localStorage.removeItem(`${STORAGE_PREFIX}${key}`);
    return true;
  } catch (error) {
    console.error('Storage removeItem error:', error);
    return false;
  }
};

/**
 * Clear all DetectSim data from localStorage
 * @returns {boolean} Success status
 */
export const clearAll = () => {
  try {
    const keys = Object.keys(localStorage).filter((key) =>
      key.startsWith(STORAGE_PREFIX)
    );
    keys.forEach((key) => localStorage.removeItem(key));
    return true;
  } catch (error) {
    console.error('Storage clearAll error:', error);
    return false;
  }
};

/**
 * Get default game state
 * @returns {Object} Default state
 */
export const getDefaultGameState = () => ({
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
  createdAt: Date.now(),
  updatedAt: Date.now(),
});

/**
 * Load game state
 * @param {string} userId - User ID (optional)
 * @returns {Object} Game state
 */
export const loadGameState = (userId = 'local') => {
  const state = getItem(`gamestate_${userId}`);
  return state || getDefaultGameState();
};

/**
 * Save game state
 * @param {Object} state - Game state
 * @param {string} userId - User ID (optional)
 * @returns {boolean} Success status
 */
export const saveGameState = (state, userId = 'local') => {
  return setItem(`gamestate_${userId}`, {
    ...state,
    updatedAt: Date.now(),
  });
};

/**
 * Record scenario attempt
 * @param {string} scenarioId - Scenario ID
 * @param {Object} attempt - Attempt data
 * @param {string} userId - User ID (optional)
 * @returns {Object} Updated state
 */
export const recordAttempt = (scenarioId, attempt, userId = 'local') => {
  const state = loadGameState(userId);

  if (!state.scenarioAttempts[scenarioId]) {
    state.scenarioAttempts[scenarioId] = [];
  }

  state.scenarioAttempts[scenarioId].push({
    ...attempt,
    timestamp: Date.now(),
  });

  state.statistics.totalAttempts++;

  saveGameState(state, userId);
  return state;
};

/**
 * Get attempt count for a scenario
 * @param {string} scenarioId - Scenario ID
 * @param {string} userId - User ID (optional)
 * @returns {number} Attempt count
 */
export const getAttemptCount = (scenarioId, userId = 'local') => {
  const state = loadGameState(userId);
  return state.scenarioAttempts[scenarioId]?.length || 0;
};

/**
 * Check if scenario is completed
 * @param {string} scenarioId - Scenario ID
 * @param {string} userId - User ID (optional)
 * @returns {boolean} Completion status
 */
export const isScenarioCompleted = (scenarioId, userId = 'local') => {
  const state = loadGameState(userId);
  return state.completedScenarios.includes(scenarioId);
};

/**
 * Mark scenario as completed
 * @param {string} scenarioId - Scenario ID
 * @param {number} reward - Reward amount
 * @param {string} userId - User ID (optional)
 * @returns {Object} Updated state
 */
export const completeScenario = (scenarioId, reward, userId = 'local') => {
  const state = loadGameState(userId);

  if (!state.completedScenarios.includes(scenarioId)) {
    state.completedScenarios.push(scenarioId);
    state.budget += reward;
    state.statistics.perfectDetections++;
  }

  saveGameState(state, userId);
  return state;
};

/**
 * Record a hint purchase
 * @param {string} scenarioId - Scenario ID
 * @param {number} hintIndex - Hint index
 * @param {number} cost - Hint cost
 * @param {string} userId - User ID (optional)
 * @returns {Object} Updated state or null if insufficient funds
 */
export const purchaseHint = (scenarioId, hintIndex, cost, userId = 'local') => {
  const state = loadGameState(userId);

  if (state.budget < cost) {
    return null;
  }

  const hintKey = `${scenarioId}_${hintIndex}`;

  if (!state.purchasedHints.includes(hintKey)) {
    state.purchasedHints.push(hintKey);
    state.budget -= cost;
  }

  saveGameState(state, userId);
  return state;
};

/**
 * Check if hint is purchased
 * @param {string} scenarioId - Scenario ID
 * @param {number} hintIndex - Hint index
 * @param {string} userId - User ID (optional)
 * @returns {boolean} Purchase status
 */
export const isHintPurchased = (scenarioId, hintIndex, userId = 'local') => {
  const state = loadGameState(userId);
  const hintKey = `${scenarioId}_${hintIndex}`;
  return state.purchasedHints.includes(hintKey);
};

/**
 * Apply penalty to budget
 * @param {number} amount - Penalty amount (positive number)
 * @param {string} userId - User ID (optional)
 * @returns {Object} Updated state
 */
export const applyPenalty = (amount, userId = 'local') => {
  const state = loadGameState(userId);
  state.budget = Math.max(0, state.budget - Math.abs(amount));
  saveGameState(state, userId);
  return state;
};

/**
 * Update statistics
 * @param {Object} stats - Statistics to add
 * @param {string} userId - User ID (optional)
 * @returns {Object} Updated state
 */
export const updateStatistics = (stats, userId = 'local') => {
  const state = loadGameState(userId);

  if (stats.truePositives) {
    state.statistics.truePositives += stats.truePositives;
  }
  if (stats.falsePositives) {
    state.statistics.falsePositives += stats.falsePositives;
  }
  if (stats.missedAttacks) {
    state.statistics.missedAttacks += stats.missedAttacks;
  }

  saveGameState(state, userId);
  return state;
};

export default {
  getItem,
  setItem,
  removeItem,
  clearAll,
  getDefaultGameState,
  loadGameState,
  saveGameState,
  recordAttempt,
  getAttemptCount,
  isScenarioCompleted,
  completeScenario,
  purchaseHint,
  isHintPurchased,
  applyPenalty,
  updateStatistics,
};
