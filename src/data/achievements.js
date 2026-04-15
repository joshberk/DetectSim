/**
 * Achievement Definitions
 * All achievement IDs are static constants — only pre-defined IDs can ever be unlocked,
 * preventing injection of arbitrary achievement keys via state manipulation.
 */

export const ACHIEVEMENT_IDS = Object.freeze({
  // Progression
  FIRST_BLOOD: 'first_blood',
  FIVE_CASES: 'five_cases',
  TEN_CASES: 'ten_cases',
  TWENTY_FIVE_CASES: 'twenty_five_cases',
  ALL_CASES: 'all_cases',

  // Level milestones
  LEVEL_1_COMPLETE: 'level_1_complete',
  LEVEL_2_COMPLETE: 'level_2_complete',
  LEVEL_3_COMPLETE: 'level_3_complete',
  LEVEL_2_UNLOCK: 'level_2_unlock',
  LEVEL_3_UNLOCK: 'level_3_unlock',

  // Detection quality
  CLEAN_SHEET: 'clean_sheet',         // Perfect detection on first try
  PRECISION: 'precision',             // 90%+ accuracy after 20 attempts
  ZERO_FP: 'zero_fp',                // 10 perfect detections (no FP)
  NO_HINTS_5: 'no_hints_5',          // 5 scenarios without buying hints
  NO_HINTS_LEVEL1: 'no_hints_level1', // All Level 1 without hints

  // Economy
  WELL_FUNDED: 'well_funded',         // $1,000 budget
  LOADED: 'loaded',                   // $5,000 budget
  THRIFTY: 'thrifty',                // Never spent on hints (10+ scenarios)

  // Rank
  PROMOTED: 'promoted',               // Reach Analyst
  VETERAN: 'veteran',                 // Reach Senior Analyst
  ELITE: 'elite',                     // Reach Detection Engineer
  LEGEND: 'legend',                   // Reach Principal Engineer

  // Special
  DEEP_END: 'deep_end',              // Complete first Level 3 scenario
  SPEED_RUN: 'speed_run',            // Perfect detection on first attempt, 3 times
});

// Whitelist set for validation — only these IDs can be stored in state
export const VALID_ACHIEVEMENT_IDS = new Set(Object.values(ACHIEVEMENT_IDS));

export const ACHIEVEMENTS = [
  // ── Progression ────────────────────────────────────────────────────────────
  {
    id: ACHIEVEMENT_IDS.FIRST_BLOOD,
    title: 'First Blood',
    description: 'Complete your first scenario.',
    icon: '🎯',
    category: 'progression',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.FIVE_CASES,
    title: 'Gaining Ground',
    description: 'Complete 5 scenarios.',
    icon: '📁',
    category: 'progression',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.TEN_CASES,
    title: 'Double Digits',
    description: 'Complete 10 scenarios.',
    icon: '🔟',
    category: 'progression',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.TWENTY_FIVE_CASES,
    title: 'Halfway There',
    description: 'Complete 25 scenarios.',
    icon: '⚡',
    category: 'progression',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.ALL_CASES,
    title: 'Master Analyst',
    description: 'Complete all 50 scenarios.',
    icon: '🏆',
    category: 'progression',
    secret: false,
  },

  // ── Level Milestones ────────────────────────────────────────────────────────
  {
    id: ACHIEVEMENT_IDS.LEVEL_2_UNLOCK,
    title: 'Rising Through the Ranks',
    description: 'Unlock Level 2: Intermediate.',
    icon: '🔓',
    category: 'levels',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.LEVEL_3_UNLOCK,
    title: 'Into the Deep End',
    description: 'Unlock Level 3: Advanced.',
    icon: '🔥',
    category: 'levels',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.LEVEL_1_COMPLETE,
    title: 'Rookie No More',
    description: 'Complete all Level 1 scenarios.',
    icon: '🥇',
    category: 'levels',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.LEVEL_2_COMPLETE,
    title: 'Mid-Career Mastery',
    description: 'Complete all Level 2 scenarios.',
    icon: '🥈',
    category: 'levels',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.LEVEL_3_COMPLETE,
    title: 'Advanced Threat Hunter',
    description: 'Complete all Level 3 scenarios.',
    icon: '🥉',
    category: 'levels',
    secret: false,
  },

  // ── Detection Quality ───────────────────────────────────────────────────────
  {
    id: ACHIEVEMENT_IDS.CLEAN_SHEET,
    title: 'Clean Sheet',
    description: 'Achieve a perfect detection on your very first attempt.',
    icon: '✨',
    category: 'skill',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.PRECISION,
    title: 'Surgical Precision',
    description: 'Maintain 90%+ accuracy across 20 or more detection attempts.',
    icon: '🎯',
    category: 'skill',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.ZERO_FP,
    title: 'Zero Tolerance',
    description: 'Achieve 10 perfect detections with zero false positives.',
    icon: '🔬',
    category: 'skill',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.NO_HINTS_5,
    title: 'Unaided',
    description: 'Complete 5 scenarios without purchasing any hints.',
    icon: '🧠',
    category: 'skill',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.NO_HINTS_LEVEL1,
    title: 'Eagle Eye',
    description: 'Complete all Level 1 scenarios without purchasing hints.',
    icon: '👁️',
    category: 'skill',
    secret: true,
  },
  {
    id: ACHIEVEMENT_IDS.SPEED_RUN,
    title: 'Speed Runner',
    description: 'Achieve perfect first-try detections 3 times.',
    icon: '⚡',
    category: 'skill',
    secret: false,
  },

  // ── Economy ─────────────────────────────────────────────────────────────────
  {
    id: ACHIEVEMENT_IDS.WELL_FUNDED,
    title: 'Well Funded',
    description: 'Accumulate $1,000 in your budget.',
    icon: '💰',
    category: 'economy',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.LOADED,
    title: 'Loaded',
    description: 'Accumulate $5,000 in your budget.',
    icon: '💎',
    category: 'economy',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.THRIFTY,
    title: 'Thrifty',
    description: 'Complete 10 scenarios without ever purchasing a hint.',
    icon: '🪙',
    category: 'economy',
    secret: true,
  },

  // ── Rank ────────────────────────────────────────────────────────────────────
  {
    id: ACHIEVEMENT_IDS.PROMOTED,
    title: 'Promoted',
    description: 'Reach the rank of Analyst.',
    icon: '📈',
    category: 'rank',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.VETERAN,
    title: 'Veteran',
    description: 'Reach the rank of Senior Analyst.',
    icon: '🎖️',
    category: 'rank',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.ELITE,
    title: 'Elite',
    description: 'Reach the rank of Detection Engineer.',
    icon: '⭐',
    category: 'rank',
    secret: false,
  },
  {
    id: ACHIEVEMENT_IDS.LEGEND,
    title: 'Legend',
    description: 'Reach the rank of Principal Engineer.',
    icon: '👑',
    category: 'rank',
    secret: true,
  },

  // ── Special ─────────────────────────────────────────────────────────────────
  {
    id: ACHIEVEMENT_IDS.DEEP_END,
    title: 'Into the Deep End',
    description: 'Complete your first Level 3: Advanced scenario.',
    icon: '🌊',
    category: 'special',
    secret: false,
  },
];

// Build lookup map for O(1) access
export const ACHIEVEMENTS_BY_ID = Object.freeze(
  ACHIEVEMENTS.reduce((acc, a) => ({ ...acc, [a.id]: a }), {})
);

/**
 * Determine which achievements should be unlocked given current game state.
 * Returns only IDs not already in unlockedAchievements.
 *
 * @param {Object} state - Full game state
 * @param {string[]} alreadyUnlocked - Currently unlocked achievement IDs
 * @returns {string[]} Array of newly earned achievement IDs
 */
export const evaluateAchievements = (state, alreadyUnlocked = []) => {
  const unlocked = new Set(alreadyUnlocked);
  const newlyEarned = [];

  const earn = (id) => {
    if (!unlocked.has(id) && VALID_ACHIEVEMENT_IDS.has(id)) {
      newlyEarned.push(id);
      unlocked.add(id);
    }
  };

  const {
    completedScenarios = [],
    statistics = {},
    budget = 0,
    purchasedHints = [],
    rank,
  } = state;

  const completed = completedScenarios.length;
  const perfectDetections = statistics.perfectDetections || 0;
  const totalAttempts = statistics.totalAttempts || 0;
  const accuracy = state.accuracy || 0;

  // Helper: scenarios from a level
  const level1 = completedScenarios.filter((id) => id.startsWith('L1-'));
  const level2 = completedScenarios.filter((id) => id.startsWith('L2-'));
  const level3 = completedScenarios.filter((id) => id.startsWith('L3-'));

  // Helper: scenarios completed without using any hints
  const hintsUsedForScenario = (scenarioId) =>
    purchasedHints.some((h) => h.startsWith(`${scenarioId}_`));

  const scenariosWithoutHints = completedScenarios.filter(
    (id) => !hintsUsedForScenario(id)
  );

  // ── Progression ────────────────────────────────────────────────────────────
  if (completed >= 1) earn(ACHIEVEMENT_IDS.FIRST_BLOOD);
  if (completed >= 5) earn(ACHIEVEMENT_IDS.FIVE_CASES);
  if (completed >= 10) earn(ACHIEVEMENT_IDS.TEN_CASES);
  if (completed >= 25) earn(ACHIEVEMENT_IDS.TWENTY_FIVE_CASES);
  if (completed >= 50) earn(ACHIEVEMENT_IDS.ALL_CASES);

  // ── Level milestones ────────────────────────────────────────────────────────
  if (level1.length >= 10) earn(ACHIEVEMENT_IDS.LEVEL_2_UNLOCK);
  if (level2.length >= 10) earn(ACHIEVEMENT_IDS.LEVEL_3_UNLOCK);
  if (level1.length >= 17) earn(ACHIEVEMENT_IDS.LEVEL_1_COMPLETE);
  if (level2.length >= 17) earn(ACHIEVEMENT_IDS.LEVEL_2_COMPLETE);
  if (level3.length >= 16) earn(ACHIEVEMENT_IDS.LEVEL_3_COMPLETE);

  // ── Detection quality ───────────────────────────────────────────────────────
  if (perfectDetections >= 10) earn(ACHIEVEMENT_IDS.ZERO_FP);
  if (totalAttempts >= 20 && accuracy >= 90) earn(ACHIEVEMENT_IDS.PRECISION);
  if (scenariosWithoutHints.length >= 5) earn(ACHIEVEMENT_IDS.NO_HINTS_5);
  if (level3.length >= 1) earn(ACHIEVEMENT_IDS.DEEP_END);

  // Eagle Eye: all L1 done without hints
  const level1WithoutHints = level1.filter((id) => !hintsUsedForScenario(id));
  if (level1.length >= 17 && level1WithoutHints.length >= 17) {
    earn(ACHIEVEMENT_IDS.NO_HINTS_LEVEL1);
  }

  // Thrifty: 10+ completed, none with hints
  if (completed >= 10 && purchasedHints.length === 0) {
    earn(ACHIEVEMENT_IDS.THRIFTY);
  }

  // ── Economy ─────────────────────────────────────────────────────────────────
  if (budget >= 1000) earn(ACHIEVEMENT_IDS.WELL_FUNDED);
  if (budget >= 5000) earn(ACHIEVEMENT_IDS.LOADED);

  // ── Rank ────────────────────────────────────────────────────────────────────
  const RANK_ACHIEVEMENTS = {
    analyst: ACHIEVEMENT_IDS.PROMOTED,
    senior_analyst: ACHIEVEMENT_IDS.VETERAN,
    detection_engineer: ACHIEVEMENT_IDS.ELITE,
    principal_engineer: ACHIEVEMENT_IDS.LEGEND,
  };

  if (rank?.id && RANK_ACHIEVEMENTS[rank.id]) {
    earn(RANK_ACHIEVEMENTS[rank.id]);
    // Also earn all lower rank achievements
    const rankOrder = ['analyst', 'senior_analyst', 'detection_engineer', 'principal_engineer'];
    const rankIndex = rankOrder.indexOf(rank.id);
    for (let i = 0; i < rankIndex; i++) {
      earn(RANK_ACHIEVEMENTS[rankOrder[i]]);
    }
  }

  return newlyEarned;
};

export default ACHIEVEMENTS;
