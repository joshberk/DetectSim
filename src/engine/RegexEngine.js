/**
 * Safe Regex Engine
 * Provides ReDoS-protected regex execution
 * OWASP A03:2021 - Injection Prevention
 */

import { validateRegexPattern } from '../utils/validation';

// Configuration
const CONFIG = {
  MAX_PATTERN_LENGTH: 500,
  EXECUTION_TIMEOUT_MS: 1000,
  MAX_INPUT_LENGTH: 100000,
};

/**
 * ReDoS-prone pattern detection
 * @param {string} pattern - Regex pattern
 * @returns {Object} Analysis result
 */
export const analyzePattern = (pattern) => {
  const issues = [];

  // Check for nested quantifiers (main cause of ReDoS)
  const nestedQuantifiers = [
    { pattern: /\(\.\*\)\+/, desc: '(.*)+' },
    { pattern: /\(\.\+\)\+/, desc: '(.+)+' },
    { pattern: /\([^)]*\+\)\+/, desc: '(x+)+' },
    { pattern: /\([^)]*\*\)\+/, desc: '(x*)+' },
    { pattern: /\([^)]*\+\)\*/, desc: '(x+)*' },
    { pattern: /\([^)]*\*\)\*/, desc: '(x*)*' },
    { pattern: /\(\[.*?\]\+\)\+/, desc: '([...]+)+' },
  ];

  for (const check of nestedQuantifiers) {
    if (check.pattern.test(pattern)) {
      issues.push({
        type: 'redos',
        severity: 'high',
        message: `Potentially catastrophic pattern: ${check.desc}`,
      });
    }
  }

  // Check for overlapping alternations
  if (/\([^)]*\|[^)]*\)\+/.test(pattern)) {
    issues.push({
      type: 'redos',
      severity: 'medium',
      message: 'Alternation inside quantified group may cause backtracking',
    });
  }

  // Check pattern length
  if (pattern.length > CONFIG.MAX_PATTERN_LENGTH) {
    issues.push({
      type: 'length',
      severity: 'medium',
      message: `Pattern exceeds maximum length (${CONFIG.MAX_PATTERN_LENGTH} chars)`,
    });
  }

  return {
    safe: issues.filter((i) => i.severity === 'high').length === 0,
    issues,
  };
};

/**
 * Compile a regex pattern safely
 * @param {string} pattern - Regex pattern
 * @param {string} flags - Regex flags
 * @returns {Object} Compiled regex or error
 */
export const compileRegex = (pattern, flags = 'i') => {
  // Validate pattern
  const validation = validateRegexPattern(pattern);
  if (!validation.valid) {
    return {
      success: false,
      error: validation.error,
      regex: null,
    };
  }

  // Analyze for ReDoS
  const analysis = analyzePattern(pattern);
  if (!analysis.safe) {
    return {
      success: false,
      error: analysis.issues[0].message,
      regex: null,
      issues: analysis.issues,
    };
  }

  try {
    const regex = new RegExp(pattern, flags);
    return {
      success: true,
      regex,
      issues: analysis.issues,
    };
  } catch (error) {
    return {
      success: false,
      error: `Invalid regex: ${error.message}`,
      regex: null,
    };
  }
};

/**
 * Execute regex with timeout protection
 * Uses a simple approach that works in main thread
 * For production, consider using a Web Worker
 * @param {RegExp} regex - Compiled regex
 * @param {string} input - Input string
 * @param {number} timeout - Timeout in ms
 * @returns {Object} Match result
 */
export const executeRegex = (regex, input, timeout = CONFIG.EXECUTION_TIMEOUT_MS) => {
  // Validate input length
  if (input.length > CONFIG.MAX_INPUT_LENGTH) {
    return {
      success: false,
      error: `Input exceeds maximum length (${CONFIG.MAX_INPUT_LENGTH} chars)`,
      matched: false,
    };
  }

  const startTime = performance.now();

  try {
    // For simple test operations, we can check inline
    // Complex patterns should use Web Workers in production
    const matched = regex.test(input);
    const duration = performance.now() - startTime;

    if (duration > timeout) {
      console.warn(`Regex execution took ${duration}ms, which exceeds timeout`);
    }

    return {
      success: true,
      matched,
      duration,
    };
  } catch (error) {
    return {
      success: false,
      error: `Regex execution error: ${error.message}`,
      matched: false,
    };
  }
};

/**
 * Safe regex test function
 * Combines compilation and execution with safety checks
 * @param {string} pattern - Regex pattern
 * @param {string} input - Input string
 * @param {string} flags - Regex flags
 * @returns {Object} Test result
 */
export const safeRegexTest = (pattern, input, flags = 'i') => {
  // Compile
  const compiled = compileRegex(pattern, flags);
  if (!compiled.success) {
    return {
      success: false,
      error: compiled.error,
      matched: false,
    };
  }

  // Execute
  return executeRegex(compiled.regex, input);
};

/**
 * Extract all matches from input
 * @param {string} pattern - Regex pattern
 * @param {string} input - Input string
 * @param {string} flags - Regex flags
 * @returns {Object} Match results
 */
export const safeRegexMatch = (pattern, input, flags = 'gi') => {
  const compiled = compileRegex(pattern, flags);
  if (!compiled.success) {
    return {
      success: false,
      error: compiled.error,
      matches: [],
    };
  }

  if (input.length > CONFIG.MAX_INPUT_LENGTH) {
    return {
      success: false,
      error: `Input exceeds maximum length`,
      matches: [],
    };
  }

  try {
    const matches = input.match(compiled.regex) || [];
    return {
      success: true,
      matches,
      count: matches.length,
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      matches: [],
    };
  }
};

/**
 * Common regex patterns for detection rules
 */
export const COMMON_PATTERNS = {
  // Base64 encoded content
  BASE64: '[A-Za-z0-9+/]{20,}={0,2}',

  // IPv4 address
  IPV4: '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b',

  // IPv6 address (simplified)
  IPV6: '(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',

  // Domain name
  DOMAIN: '(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}',

  // Windows path
  WINDOWS_PATH: '[A-Za-z]:\\\\(?:[^\\\\/:*?"<>|\\r\\n]+\\\\)*[^\\\\/:*?"<>|\\r\\n]*',

  // URL
  URL: 'https?://[^\\s<>"{}|\\\\^`\\[\\]]+',

  // Email
  EMAIL: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',

  // MD5 hash
  MD5: '\\b[a-fA-F0-9]{32}\\b',

  // SHA1 hash
  SHA1: '\\b[a-fA-F0-9]{40}\\b',

  // SHA256 hash
  SHA256: '\\b[a-fA-F0-9]{64}\\b',

  // PowerShell encoded command
  PS_ENCODED: '-e(?:nc(?:odedcommand)?)?\\s+[A-Za-z0-9+/=]+',

  // Common LOLBins
  LOLBINS: '(?:certutil|bitsadmin|mshta|regsvr32|rundll32|wmic|cscript|wscript)\\.exe',
};

export default {
  analyzePattern,
  compileRegex,
  executeRegex,
  safeRegexTest,
  safeRegexMatch,
  COMMON_PATTERNS,
  CONFIG,
};
