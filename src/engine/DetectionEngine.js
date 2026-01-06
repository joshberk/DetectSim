/**
 * Detection Engine
 * Evaluates parsed Sigma rules against log data
 * Core game logic for matching and scoring
 */

import { MODIFIERS } from './SigmaParser';
import { safeRegexTest } from './RegexEngine';
import { getFieldMappings } from '../utils/logGenerator';

/**
 * Detection Engine class
 * Executes parsed Sigma AST against log entries
 */
export class DetectionEngine {
  constructor() {
    this.lastResult = null;
  }

  /**
   * Evaluate a parsed rule against a set of logs
   * @param {Object} ast - Parsed Sigma AST
   * @param {Array} logs - Array of log objects
   * @param {string} logSource - Log source type for field mapping
   * @returns {Object} Detection results
   */
  evaluate(ast, logs, logSource = 'process_creation') {
    if (!ast || !ast.condition) {
      return {
        success: false,
        error: 'Invalid AST: missing condition',
        results: [],
      };
    }

    const fieldMappings = getFieldMappings(logSource);
    const results = [];

    let truePositives = 0;
    let falsePositives = 0;
    let missedAttacks = 0;
    const totalMalicious = logs.filter((log) => log.malicious).length;

    for (const log of logs) {
      const detected = this.evaluateCondition(ast.condition, ast, log, fieldMappings);

      if (detected) {
        if (log.malicious) {
          truePositives++;
        } else {
          falsePositives++;
        }
      } else {
        if (log.malicious) {
          missedAttacks++;
        }
      }

      results.push({
        ...log,
        detected,
        classification: this.classifyResult(detected, log.malicious),
      });
    }

    this.lastResult = {
      success: true,
      results,
      summary: {
        truePositives,
        falsePositives,
        missedAttacks,
        totalMalicious,
        totalLogs: logs.length,
        precision: truePositives + falsePositives > 0
          ? (truePositives / (truePositives + falsePositives) * 100).toFixed(1)
          : 0,
        recall: totalMalicious > 0
          ? (truePositives / totalMalicious * 100).toFixed(1)
          : 100,
      },
    };

    return this.lastResult;
  }

  /**
   * Classify a detection result
   * @param {boolean} detected - Whether log was detected
   * @param {boolean} malicious - Whether log is malicious
   * @returns {string} Classification
   */
  classifyResult(detected, malicious) {
    if (detected && malicious) return 'true_positive';
    if (detected && !malicious) return 'false_positive';
    if (!detected && malicious) return 'false_negative';
    return 'true_negative';
  }

  /**
   * Evaluate a condition against a log entry
   * @param {Object} condition - Condition AST node
   * @param {Object} ast - Full AST for selection lookups
   * @param {Object} log - Log entry
   * @param {Object} fieldMappings - Field name mappings
   * @returns {boolean} Whether condition matches
   */
  evaluateCondition(condition, ast, log, fieldMappings) {
    switch (condition.type) {
      case 'reference':
        return this.evaluateSelection(condition.name, ast, log, fieldMappings);

      case 'and':
        return condition.operands.every((op) =>
          this.evaluateCondition(op, ast, log, fieldMappings)
        );

      case 'or':
        return condition.operands.some((op) =>
          this.evaluateCondition(op, ast, log, fieldMappings)
        );

      case 'not':
        return !this.evaluateCondition(condition.operand, ast, log, fieldMappings);

      case 'all_of':
        return this.evaluateAllOf(condition.pattern, ast, log, fieldMappings);

      case 'one_of':
        return this.evaluateOneOf(condition.pattern, ast, log, fieldMappings);

      default:
        console.warn(`Unknown condition type: ${condition.type}`);
        return false;
    }
  }

  /**
   * Evaluate a selection block against a log
   * @param {string} selectionName - Selection name
   * @param {Object} ast - Full AST
   * @param {Object} log - Log entry
   * @param {Object} fieldMappings - Field mappings
   * @returns {boolean} Whether selection matches
   */
  evaluateSelection(selectionName, ast, log, fieldMappings) {
    // Check in selections first, then filters
    let filters = ast.selections[selectionName] || ast.filters[selectionName];

    if (!filters || filters.length === 0) {
      // If selection not found, treat as false
      return false;
    }

    // All filters in a selection must match (AND logic)
    return filters.every((filter) =>
      this.evaluateFilter(filter, log, fieldMappings)
    );
  }

  /**
   * Evaluate a single filter against a log
   * @param {Object} filter - Filter object
   * @param {Object} log - Log entry
   * @param {Object} fieldMappings - Field mappings
   * @returns {boolean} Whether filter matches
   */
  evaluateFilter(filter, log, fieldMappings) {
    const { field, modifier, matchAll, values } = filter;

    // Get the actual log field name from mappings
    const logFieldName = fieldMappings[field] || field.toLowerCase();
    const logValue = this.getLogValue(log, logFieldName);

    if (logValue === null || logValue === undefined) {
      return false;
    }

    const stringValue = String(logValue);

    // Get the modifier function
    const modifierFn = MODIFIERS[modifier] || MODIFIERS.exact;

    if (matchAll) {
      // ALL values must match
      return values.every((target) => modifierFn(stringValue, target));
    } else {
      // ANY value must match (OR logic within filter)
      return values.some((target) => {
        if (modifier === 're') {
          // Use safe regex for regex modifiers
          const result = safeRegexTest(target, stringValue);
          return result.success && result.matched;
        }
        return modifierFn(stringValue, target);
      });
    }
  }

  /**
   * Get value from log object, supporting nested paths
   * @param {Object} log - Log entry
   * @param {string} fieldName - Field name (can be nested with dots)
   * @returns {any} Field value
   */
  getLogValue(log, fieldName) {
    // Direct field access
    if (log.hasOwnProperty(fieldName)) {
      return log[fieldName];
    }

    // Try case-insensitive match
    const lowerFieldName = fieldName.toLowerCase();
    for (const key of Object.keys(log)) {
      if (key.toLowerCase() === lowerFieldName) {
        return log[key];
      }
    }

    // Try nested path (e.g., "event.data.field")
    if (fieldName.includes('.')) {
      const parts = fieldName.split('.');
      let value = log;
      for (const part of parts) {
        if (value && typeof value === 'object') {
          value = value[part];
        } else {
          return null;
        }
      }
      return value;
    }

    return null;
  }

  /**
   * Evaluate "all of selection*" pattern
   * @param {string} pattern - Selection pattern (e.g., "selection*")
   * @param {Object} ast - Full AST
   * @param {Object} log - Log entry
   * @param {Object} fieldMappings - Field mappings
   * @returns {boolean} Whether all matching selections match
   */
  evaluateAllOf(pattern, ast, log, fieldMappings) {
    const matchingSelections = this.findMatchingSelections(pattern, ast);

    if (matchingSelections.length === 0) {
      return false;
    }

    return matchingSelections.every((name) =>
      this.evaluateSelection(name, ast, log, fieldMappings)
    );
  }

  /**
   * Evaluate "1 of selection*" pattern
   * @param {string} pattern - Selection pattern
   * @param {Object} ast - Full AST
   * @param {Object} log - Log entry
   * @param {Object} fieldMappings - Field mappings
   * @returns {boolean} Whether any matching selection matches
   */
  evaluateOneOf(pattern, ast, log, fieldMappings) {
    const matchingSelections = this.findMatchingSelections(pattern, ast);

    if (matchingSelections.length === 0) {
      return false;
    }

    return matchingSelections.some((name) =>
      this.evaluateSelection(name, ast, log, fieldMappings)
    );
  }

  /**
   * Find selections matching a pattern
   * @param {string} pattern - Pattern (e.g., "selection*")
   * @param {Object} ast - Full AST
   * @returns {Array} Matching selection names
   */
  findMatchingSelections(pattern, ast) {
    const allSelections = [
      ...Object.keys(ast.selections || {}),
      ...Object.keys(ast.filters || {}),
    ];

    if (pattern.endsWith('*')) {
      const prefix = pattern.slice(0, -1);
      return allSelections.filter((name) => name.startsWith(prefix));
    }

    return allSelections.filter((name) => name === pattern);
  }

  /**
   * Get the last evaluation result
   * @returns {Object|null} Last result
   */
  getLastResult() {
    return this.lastResult;
  }

  /**
   * Check if the last evaluation was a perfect detection
   * @returns {boolean} Whether detection was perfect
   */
  isPerfectDetection() {
    if (!this.lastResult || !this.lastResult.summary) {
      return false;
    }

    const { falsePositives, missedAttacks } = this.lastResult.summary;
    return falsePositives === 0 && missedAttacks === 0;
  }

  /**
   * Generate feedback message based on results
   * @returns {Object} Feedback object
   */
  generateFeedback() {
    if (!this.lastResult || !this.lastResult.summary) {
      return {
        type: 'error',
        message: 'No detection results',
        details: 'Run a detection first',
      };
    }

    const { truePositives, falsePositives, missedAttacks, totalMalicious } = this.lastResult.summary;

    if (falsePositives > 0 && missedAttacks > 0) {
      return {
        type: 'error',
        message: 'Detection Needs Work',
        details: `Found ${truePositives}/${totalMalicious} threats but had ${falsePositives} false positive(s) and missed ${missedAttacks} attack(s).`,
      };
    }

    if (falsePositives > 0) {
      return {
        type: 'warning',
        message: 'Detection Too Noisy',
        details: `Caught all threats but flagged ${falsePositives} benign event(s). Refine your logic to reduce false positives.`,
      };
    }

    if (missedAttacks > 0) {
      return {
        type: 'error',
        message: 'Attack Missed',
        details: `Failed to catch ${missedAttacks} malicious event(s). Review the log data and broaden your detection criteria.`,
      };
    }

    return {
      type: 'success',
      message: 'Threat Neutralized',
      details: `Perfect detection! ${truePositives} threat(s) caught with 0 false positives.`,
    };
  }
}

/**
 * Create and return a detection engine instance
 * @returns {DetectionEngine} Engine instance
 */
export const createDetectionEngine = () => {
  return new DetectionEngine();
};

export default DetectionEngine;
