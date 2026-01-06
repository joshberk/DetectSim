/**
 * Sigma Rule Parser
 * Parses Sigma-style YAML detection rules into an AST
 * Supports: selection blocks, modifiers, lists, AND/OR/NOT conditions
 */

import { validateYAMLStructure, validateRegexPattern } from '../utils/validation';

/**
 * Token types for the parser
 */
export const TOKEN_TYPES = {
  SELECTION: 'selection',
  FILTER: 'filter',
  CONDITION: 'condition',
  FIELD: 'field',
  VALUE: 'value',
  MODIFIER: 'modifier',
  LIST: 'list',
  OPERATOR: 'operator',
};

/**
 * Supported field modifiers
 */
export const MODIFIERS = {
  contains: (value, target) => value.toLowerCase().includes(target.toLowerCase()),
  endswith: (value, target) => value.toLowerCase().endsWith(target.toLowerCase()),
  startswith: (value, target) => value.toLowerCase().startsWith(target.toLowerCase()),
  exact: (value, target) => value.toLowerCase() === target.toLowerCase(),
  re: (value, pattern) => {
    try {
      const regex = new RegExp(pattern, 'i');
      return regex.test(value);
    } catch {
      return false;
    }
  },
  cidr: (value, cidr) => {
    // Basic CIDR matching for IP addresses
    try {
      const [subnet, bits] = cidr.split('/');
      const mask = ~(2 ** (32 - parseInt(bits)) - 1);
      const ipToNum = (ip) => ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct), 0);
      return (ipToNum(value) & mask) === (ipToNum(subnet) & mask);
    } catch {
      return false;
    }
  },
  base64: (value, target) => {
    try {
      const decoded = atob(value);
      return decoded.toLowerCase().includes(target.toLowerCase());
    } catch {
      return false;
    }
  },
  gt: (value, target) => parseFloat(value) > parseFloat(target),
  gte: (value, target) => parseFloat(value) >= parseFloat(target),
  lt: (value, target) => parseFloat(value) < parseFloat(target),
  lte: (value, target) => parseFloat(value) <= parseFloat(target),
};

/**
 * Parse a Sigma rule string into an Abstract Syntax Tree
 */
export class SigmaParser {
  constructor() {
    this.errors = [];
    this.warnings = [];
  }

  /**
   * Parse a Sigma rule YAML string
   * @param {string} ruleText - The Sigma rule text
   * @returns {Object} Parsed AST or error object
   */
  parse(ruleText) {
    this.errors = [];
    this.warnings = [];

    // Validate basic structure
    const structureValidation = validateYAMLStructure(ruleText);
    if (!structureValidation.valid) {
      return {
        success: false,
        error: structureValidation.error,
        ast: null,
      };
    }

    try {
      const ast = this.parseToAST(ruleText);
      return {
        success: true,
        ast,
        errors: this.errors,
        warnings: this.warnings,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        ast: null,
      };
    }
  }

  /**
   * Parse rule text into AST
   * @param {string} ruleText - Rule text
   * @returns {Object} AST
   */
  parseToAST(ruleText) {
    const lines = ruleText.split('\n');
    const ast = {
      selections: {},
      filters: {},
      condition: null,
      metadata: {},
    };

    let currentBlock = null;
    let currentBlockName = null;
    let currentField = null;
    let indentLevel = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      // Calculate indent level
      const lineIndent = line.search(/\S/);

      // Check for top-level blocks
      if (lineIndent === 0 || (trimmed.endsWith(':') && !trimmed.includes('|'))) {
        if (trimmed === 'detection:') {
          currentBlock = 'detection';
          continue;
        }
        if (trimmed.startsWith('title:')) {
          ast.metadata.title = trimmed.substring(6).trim();
          continue;
        }
        if (trimmed.startsWith('status:')) {
          ast.metadata.status = trimmed.substring(7).trim();
          continue;
        }
        if (trimmed.startsWith('description:')) {
          ast.metadata.description = trimmed.substring(12).trim();
          continue;
        }
        if (trimmed.startsWith('level:')) {
          ast.metadata.level = trimmed.substring(6).trim();
          continue;
        }
      }

      // Inside detection block
      if (currentBlock === 'detection') {
        // Check for selection/filter definitions
        if (trimmed.endsWith(':') && !trimmed.includes('|')) {
          const blockName = trimmed.slice(0, -1).trim();

          if (blockName === 'condition') {
            // Handle condition on same line
            const conditionLine = lines[i + 1]?.trim();
            if (conditionLine && !conditionLine.endsWith(':')) {
              ast.condition = this.parseCondition(conditionLine);
            }
            currentBlockName = null;
            currentField = null;
            continue;
          }

          if (blockName.startsWith('selection') || blockName.startsWith('filter')) {
            const isFilter = blockName.startsWith('filter');
            const targetObj = isFilter ? ast.filters : ast.selections;

            if (!targetObj[blockName]) {
              targetObj[blockName] = [];
            }
            currentBlockName = blockName;
            currentField = null;
            continue;
          }
        }

        // Check for condition value
        if (trimmed.startsWith('condition:')) {
          const conditionValue = trimmed.substring(10).trim();
          if (conditionValue) {
            ast.condition = this.parseCondition(conditionValue);
          }
          currentBlockName = null;
          continue;
        }

        // Parse field:value pairs inside selections/filters
        if (currentBlockName) {
          const targetObj = currentBlockName.startsWith('filter')
            ? ast.filters
            : ast.selections;

          // Handle list items (- value)
          if (trimmed.startsWith('-')) {
            if (currentField) {
              const value = trimmed.substring(1).trim().replace(/^['"]|['"]$/g, '');
              const existingFilter = targetObj[currentBlockName].find(
                (f) => f.field === currentField.field && f.modifier === currentField.modifier
              );
              if (existingFilter) {
                if (!Array.isArray(existingFilter.values)) {
                  existingFilter.values = [existingFilter.values];
                }
                existingFilter.values.push(value);
              }
            }
            continue;
          }

          // Handle field: value or field|modifier: value
          if (trimmed.includes(':')) {
            const colonIndex = trimmed.indexOf(':');
            const fieldPart = trimmed.substring(0, colonIndex).trim();
            let valuePart = trimmed.substring(colonIndex + 1).trim();

            // Parse field and modifier
            let field = fieldPart;
            let modifier = 'exact';
            let matchAll = false;

            if (fieldPart.includes('|')) {
              const parts = fieldPart.split('|');
              field = parts[0];

              for (let j = 1; j < parts.length; j++) {
                const mod = parts[j].toLowerCase();
                if (mod === 'all') {
                  matchAll = true;
                } else if (MODIFIERS[mod]) {
                  modifier = mod;
                }
              }
            }

            // Validate regex patterns
            if (modifier === 're' && valuePart) {
              const regexValidation = validateRegexPattern(valuePart.replace(/^['"]|['"]$/g, ''));
              if (!regexValidation.valid) {
                this.warnings.push(`Line ${i + 1}: ${regexValidation.error}`);
              }
            }

            // Handle inline arrays [val1, val2]
            if (valuePart.startsWith('[') && valuePart.endsWith(']')) {
              const arrayContent = valuePart.slice(1, -1);
              const values = arrayContent.split(',').map((v) =>
                v.trim().replace(/^['"]|['"]$/g, '')
              );
              targetObj[currentBlockName].push({
                field,
                modifier,
                matchAll,
                values,
              });
              currentField = null;
              continue;
            }

            // Handle empty value (list follows)
            if (!valuePart) {
              currentField = { field, modifier, matchAll };
              targetObj[currentBlockName].push({
                field,
                modifier,
                matchAll,
                values: [],
              });
              continue;
            }

            // Single value
            valuePart = valuePart.replace(/^['"]|['"]$/g, '');
            targetObj[currentBlockName].push({
              field,
              modifier,
              matchAll,
              values: [valuePart],
            });
            currentField = null;
          }
        }
      }
    }

    // Default condition if not specified
    if (!ast.condition && Object.keys(ast.selections).length > 0) {
      const selectionNames = Object.keys(ast.selections);
      if (selectionNames.length === 1) {
        ast.condition = { type: 'reference', name: selectionNames[0] };
      } else {
        ast.condition = {
          type: 'and',
          operands: selectionNames.map((name) => ({ type: 'reference', name })),
        };
      }
    }

    return ast;
  }

  /**
   * Parse condition string into condition AST
   * @param {string} conditionStr - Condition string
   * @returns {Object} Condition AST
   */
  parseCondition(conditionStr) {
    const str = conditionStr.trim();

    // Handle NOT
    if (str.toLowerCase().startsWith('not ')) {
      return {
        type: 'not',
        operand: this.parseCondition(str.substring(4)),
      };
    }

    // Handle parentheses
    if (str.startsWith('(') && str.endsWith(')')) {
      return this.parseCondition(str.slice(1, -1));
    }

    // Handle OR (lowest precedence)
    const orIndex = this.findOperator(str, ' or ');
    if (orIndex !== -1) {
      return {
        type: 'or',
        operands: [
          this.parseCondition(str.substring(0, orIndex)),
          this.parseCondition(str.substring(orIndex + 4)),
        ],
      };
    }

    // Handle AND
    const andIndex = this.findOperator(str, ' and ');
    if (andIndex !== -1) {
      return {
        type: 'and',
        operands: [
          this.parseCondition(str.substring(0, andIndex)),
          this.parseCondition(str.substring(andIndex + 5)),
        ],
      };
    }

    // Handle 1/all of pattern
    const ofMatch = str.match(/^(1|all)\s+of\s+(\w+\*?)$/i);
    if (ofMatch) {
      return {
        type: ofMatch[1].toLowerCase() === 'all' ? 'all_of' : 'one_of',
        pattern: ofMatch[2],
      };
    }

    // Simple reference
    return {
      type: 'reference',
      name: str.trim(),
    };
  }

  /**
   * Find operator position accounting for parentheses
   * @param {string} str - String to search
   * @param {string} op - Operator to find
   * @returns {number} Index or -1
   */
  findOperator(str, op) {
    let depth = 0;
    const lowerStr = str.toLowerCase();
    const lowerOp = op.toLowerCase();

    for (let i = 0; i < str.length; i++) {
      if (str[i] === '(') depth++;
      if (str[i] === ')') depth--;

      if (depth === 0 && lowerStr.substring(i, i + op.length) === lowerOp) {
        return i;
      }
    }
    return -1;
  }

  /**
   * Get parsing errors
   * @returns {Array} Error messages
   */
  getErrors() {
    return this.errors;
  }

  /**
   * Get parsing warnings
   * @returns {Array} Warning messages
   */
  getWarnings() {
    return this.warnings;
  }
}

export default SigmaParser;
