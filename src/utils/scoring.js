/**
 * Scoring and Economy System
 * Handles all point calculations, rank progression, and economy mechanics
 */

// Scoring constants
export const SCORING = {
  PERFECT_DETECTION: 150,
  OPTIMAL_BONUS: 50,
  FIRST_TRY_BONUS: 25,
  TRUE_POSITIVE: 10,
  FALSE_POSITIVE: -25,
  MISSED_ATTACK: -50,
  SYNTAX_ERROR: -10,

  // Hint costs
  HINT_BASIC: 50,
  HINT_ADVANCED: 100,
  HINT_SOLUTION: 200,
  LOG_HIGHLIGHTER: 75,

  // Attempt limits
  MAX_FREE_ATTEMPTS: 3,
};

// Rank definitions
export const RANKS = [
  {
    id: 'junior_analyst',
    name: 'Junior Analyst',
    minCases: 0,
    minAccuracy: 0,
    minBudget: 0,
    badge: 'JA',
    color: 'gray',
  },
  {
    id: 'analyst',
    name: 'Analyst',
    minCases: 5,
    minAccuracy: 70,
    minBudget: 500,
    badge: 'AN',
    color: 'blue',
  },
  {
    id: 'senior_analyst',
    name: 'Senior Analyst',
    minCases: 15,
    minAccuracy: 80,
    minBudget: 1500,
    badge: 'SA',
    color: 'purple',
  },
  {
    id: 'detection_engineer',
    name: 'Detection Engineer',
    minCases: 30,
    minAccuracy: 85,
    minBudget: 3000,
    badge: 'DE',
    color: 'emerald',
  },
  {
    id: 'senior_engineer',
    name: 'Senior Engineer',
    minCases: 50,
    minAccuracy: 90,
    minBudget: 5000,
    badge: 'SE',
    color: 'yellow',
  },
  {
    id: 'principal_engineer',
    name: 'Principal Engineer',
    minCases: 75,
    minAccuracy: 95,
    minBudget: 7500,
    badge: 'PE',
    color: 'red',
  },
];

/**
 * Calculate accuracy percentage
 * @param {Object} stats - Statistics object
 * @returns {number} Accuracy percentage (0-100)
 */
export const calculateAccuracy = (stats) => {
  const { truePositives = 0, falsePositives = 0, missedAttacks = 0 } = stats;
  const total = truePositives + falsePositives + missedAttacks;

  if (total === 0) return 100;

  return Math.round((truePositives / total) * 100 * 10) / 10;
};

/**
 * Calculate score for a detection attempt
 * @param {Object} result - Detection result
 * @param {boolean} isFirstTry - Whether this is the first attempt
 * @param {boolean} isOptimal - Whether the solution is optimal
 * @returns {Object} Score breakdown
 */
export const calculateDetectionScore = (result, isFirstTry = false, isOptimal = false) => {
  const { truePositives, falsePositives, missedAttacks, totalMalicious } = result;

  let score = 0;
  const breakdown = [];

  // Check for perfect detection (all malicious caught, no FPs)
  const isPerfect = truePositives === totalMalicious && falsePositives === 0 && missedAttacks === 0;

  if (isPerfect) {
    score += SCORING.PERFECT_DETECTION;
    breakdown.push({ label: 'Perfect Detection', points: SCORING.PERFECT_DETECTION });

    if (isOptimal) {
      score += SCORING.OPTIMAL_BONUS;
      breakdown.push({ label: 'Optimal Solution Bonus', points: SCORING.OPTIMAL_BONUS });
    }

    if (isFirstTry) {
      score += SCORING.FIRST_TRY_BONUS;
      breakdown.push({ label: 'First Try Bonus', points: SCORING.FIRST_TRY_BONUS });
    }
  } else {
    // Partial credit for TPs
    if (truePositives > 0) {
      const tpPoints = truePositives * SCORING.TRUE_POSITIVE;
      score += tpPoints;
      breakdown.push({ label: `True Positives (${truePositives})`, points: tpPoints });
    }

    // Penalties
    if (falsePositives > 0) {
      const fpPenalty = falsePositives * SCORING.FALSE_POSITIVE;
      score += fpPenalty;
      breakdown.push({ label: `False Positives (${falsePositives})`, points: fpPenalty });
    }

    if (missedAttacks > 0) {
      const missPenalty = missedAttacks * SCORING.MISSED_ATTACK;
      score += missPenalty;
      breakdown.push({ label: `Missed Attacks (${missedAttacks})`, points: missPenalty });
    }
  }

  return {
    score: Math.max(score, 0), // Minimum 0
    breakdown,
    isPerfect,
    accuracy: calculateAccuracy({ truePositives, falsePositives, missedAttacks }),
  };
};

/**
 * Determine rank based on stats
 * @param {Object} stats - Player statistics
 * @returns {Object} Current rank object
 */
export const determineRank = (stats) => {
  const { completedCases = 0, accuracy = 0, budget = 0 } = stats;

  // Find highest qualifying rank (iterate in reverse)
  for (let i = RANKS.length - 1; i >= 0; i--) {
    const rank = RANKS[i];
    if (
      completedCases >= rank.minCases &&
      accuracy >= rank.minAccuracy &&
      budget >= rank.minBudget
    ) {
      return rank;
    }
  }

  return RANKS[0]; // Default to Junior Analyst
};

/**
 * Calculate next rank requirements
 * @param {Object} currentStats - Current player statistics
 * @returns {Object|null} Next rank requirements or null if max rank
 */
export const getNextRankRequirements = (currentStats) => {
  const currentRank = determineRank(currentStats);
  const currentIndex = RANKS.findIndex(r => r.id === currentRank.id);

  if (currentIndex >= RANKS.length - 1) {
    return null; // Already at max rank
  }

  const nextRank = RANKS[currentIndex + 1];

  return {
    rank: nextRank,
    requirements: {
      casesNeeded: Math.max(0, nextRank.minCases - currentStats.completedCases),
      accuracyNeeded: Math.max(0, nextRank.minAccuracy - currentStats.accuracy),
      budgetNeeded: Math.max(0, nextRank.minBudget - currentStats.budget),
    },
  };
};

/**
 * Calculate leaderboard score
 * @param {Object} stats - Player statistics
 * @returns {number} Total leaderboard score
 */
export const calculateLeaderboardScore = (stats) => {
  const { budget = 0, completedCases = 0, accuracy = 0 } = stats;

  // Formula: budget * 10 + cases * 500 + accuracy bonus
  const baseScore = (budget * 10) + (completedCases * 500);
  const accuracyBonus = Math.floor(accuracy) * 10;

  return baseScore + accuracyBonus;
};

/**
 * Check if player can afford a purchase
 * @param {number} currentBudget - Current budget
 * @param {number} cost - Cost of item
 * @returns {boolean} Whether player can afford it
 */
export const canAfford = (currentBudget, cost) => {
  return currentBudget >= cost;
};

/**
 * Process a purchase
 * @param {number} currentBudget - Current budget
 * @param {number} cost - Cost of item
 * @returns {Object} Result with new budget or error
 */
export const processPurchase = (currentBudget, cost) => {
  if (!canAfford(currentBudget, cost)) {
    return {
      success: false,
      error: `Insufficient funds. Need $${cost}, have $${currentBudget}`,
      newBudget: currentBudget,
    };
  }

  return {
    success: true,
    newBudget: currentBudget - cost,
    spent: cost,
  };
};

export default {
  SCORING,
  RANKS,
  calculateAccuracy,
  calculateDetectionScore,
  determineRank,
  getNextRankRequirements,
  calculateLeaderboardScore,
  canAfford,
  processPurchase,
};
