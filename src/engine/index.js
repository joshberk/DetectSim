/**
 * Detection Engine Exports
 */

export { SigmaParser, MODIFIERS, TOKEN_TYPES } from './SigmaParser';
export {
  analyzePattern,
  compileRegex,
  executeRegex,
  safeRegexTest,
  safeRegexMatch,
  COMMON_PATTERNS,
} from './RegexEngine';
export { DetectionEngine, createDetectionEngine } from './DetectionEngine';

// Convenience function to run full detection pipeline
import { SigmaParser } from './SigmaParser';
import { DetectionEngine } from './DetectionEngine';

/**
 * Run a complete detection pipeline
 * @param {string} ruleText - Sigma rule text
 * @param {Array} logs - Log array
 * @param {string} logSource - Log source type
 * @returns {Object} Detection results
 */
export const runDetection = (ruleText, logs, logSource = 'process_creation') => {
  const parser = new SigmaParser();
  const engine = new DetectionEngine();

  // Parse the rule
  const parseResult = parser.parse(ruleText);

  if (!parseResult.success) {
    return {
      success: false,
      phase: 'parsing',
      error: parseResult.error,
      results: null,
    };
  }

  // Evaluate against logs
  const evalResult = engine.evaluate(parseResult.ast, logs, logSource);

  if (!evalResult.success) {
    return {
      success: false,
      phase: 'evaluation',
      error: evalResult.error,
      results: null,
    };
  }

  return {
    success: true,
    ast: parseResult.ast,
    results: evalResult.results,
    summary: evalResult.summary,
    feedback: engine.generateFeedback(),
    isPerfect: engine.isPerfectDetection(),
    warnings: parseResult.warnings,
  };
};

export default {
  SigmaParser,
  DetectionEngine,
  runDetection,
};
