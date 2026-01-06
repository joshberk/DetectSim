/**
 * Input Validation Utilities
 * OWASP A03:2021 - Injection Prevention
 */

/**
 * Validate scenario ID format
 * @param {string} id - Scenario ID
 * @returns {boolean} Whether ID is valid
 */
export const isValidScenarioId = (id) => {
  if (!id || typeof id !== 'string') return false;
  // Format: L{level}-{number} e.g., L1-001, L2-015, L3-025
  return /^L[1-3]-\d{3}$/.test(id);
};

/**
 * Validate user ID format (Firebase UID)
 * @param {string} uid - User ID
 * @returns {boolean} Whether UID is valid
 */
export const isValidUserId = (uid) => {
  if (!uid || typeof uid !== 'string') return false;
  // Firebase UIDs are typically 28 characters alphanumeric
  return /^[a-zA-Z0-9]{20,128}$/.test(uid);
};

/**
 * Validate YAML structure (basic check)
 * @param {string} yaml - YAML string
 * @returns {Object} Validation result
 */
export const validateYAMLStructure = (yaml) => {
  if (!yaml || typeof yaml !== 'string') {
    return { valid: false, error: 'Empty or invalid input' };
  }

  // Check for required keys
  if (!yaml.includes('detection:')) {
    return { valid: false, error: "Missing 'detection:' block" };
  }

  if (!yaml.includes('condition:')) {
    return { valid: false, error: "Missing 'condition:' key" };
  }

  // Check for potential injection attempts
  const dangerousPatterns = [
    /!!python/i,
    /!!ruby/i,
    /!!js/i,
    /!!perl/i,
    /!!bash/i,
    /<%/,
    /%>/,
    /<script/i,
    /javascript:/i,
    /eval\s*\(/i,
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(yaml)) {
      return { valid: false, error: 'Potentially dangerous content detected' };
    }
  }

  // Check for reasonable length
  if (yaml.length > 50000) {
    return { valid: false, error: 'Rule exceeds maximum length (50KB)' };
  }

  return { valid: true };
};

/**
 * Validate regex pattern safety
 * @param {string} pattern - Regex pattern
 * @returns {Object} Validation result
 */
export const validateRegexPattern = (pattern) => {
  if (!pattern || typeof pattern !== 'string') {
    return { valid: false, error: 'Empty or invalid pattern' };
  }

  // Check length
  if (pattern.length > 500) {
    return { valid: false, error: 'Pattern exceeds maximum length (500 chars)' };
  }

  // Check for ReDoS-prone patterns
  const redosPatterns = [
    /\(\.\*\)\+/,           // (.*)+
    /\(\.\+\)\+/,           // (.+)+
    /\([^)]*\+\)\+/,        // (x+)+
    /\([^)]*\*\)\+/,        // (x*)+
    /\([^)]*\+\)\*/,        // (x+)*
    /\([^)]*\{[^}]+\}\)\+/, // (x{n,m})+
  ];

  for (const redos of redosPatterns) {
    if (redos.test(pattern)) {
      return { valid: false, error: 'Pattern may cause catastrophic backtracking (ReDoS)' };
    }
  }

  // Try to compile the regex
  try {
    new RegExp(pattern);
  } catch (e) {
    return { valid: false, error: `Invalid regex: ${e.message}` };
  }

  return { valid: true };
};

/**
 * Validate detection result structure
 * @param {Object} result - Detection result object
 * @returns {boolean} Whether result structure is valid
 */
export const isValidDetectionResult = (result) => {
  if (!result || typeof result !== 'object') return false;

  const requiredFields = ['truePositives', 'falsePositives', 'missedAttacks', 'totalMalicious'];

  for (const field of requiredFields) {
    if (typeof result[field] !== 'number' || result[field] < 0) {
      return false;
    }
  }

  // Sanity check: TP + missed should equal total malicious
  if (result.truePositives + result.missedAttacks !== result.totalMalicious) {
    return false;
  }

  return true;
};

/**
 * Sanitize and validate score submission
 * @param {Object} submission - Score submission
 * @returns {Object} Validation result
 */
export const validateScoreSubmission = (submission) => {
  const errors = [];

  if (!submission.scenarioId || !isValidScenarioId(submission.scenarioId)) {
    errors.push('Invalid scenario ID');
  }

  if (!submission.userId || !isValidUserId(submission.userId)) {
    errors.push('Invalid user ID');
  }

  if (typeof submission.score !== 'number' || submission.score < 0 || submission.score > 10000) {
    errors.push('Invalid score value');
  }

  if (typeof submission.timestamp !== 'number') {
    errors.push('Invalid timestamp');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
};

/**
 * Rate limiting check (client-side, for UX only)
 * Server-side validation is still required
 * @param {string} action - Action type
 * @param {Object} tracker - Rate limit tracker
 * @param {Object} limits - Rate limits
 * @returns {Object} Rate limit check result
 */
export const checkRateLimit = (action, tracker, limits = {}) => {
  const now = Date.now();
  const defaultLimits = {
    maxAttempts: 10,
    windowMs: 60000, // 1 minute
    ...limits,
  };

  if (!tracker[action]) {
    tracker[action] = { attempts: [], blocked: false };
  }

  const actionTracker = tracker[action];

  // Clean old attempts outside window
  actionTracker.attempts = actionTracker.attempts.filter(
    (time) => now - time < defaultLimits.windowMs
  );

  // Check if blocked
  if (actionTracker.attempts.length >= defaultLimits.maxAttempts) {
    const oldestAttempt = actionTracker.attempts[0];
    const timeUntilReset = defaultLimits.windowMs - (now - oldestAttempt);

    return {
      allowed: false,
      remaining: 0,
      resetIn: Math.ceil(timeUntilReset / 1000),
    };
  }

  // Record attempt
  actionTracker.attempts.push(now);

  return {
    allowed: true,
    remaining: defaultLimits.maxAttempts - actionTracker.attempts.length,
    resetIn: null,
  };
};

export default {
  isValidScenarioId,
  isValidUserId,
  validateYAMLStructure,
  validateRegexPattern,
  isValidDetectionResult,
  validateScoreSubmission,
  checkRateLimit,
};
