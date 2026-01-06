import DOMPurify from 'dompurify';

/**
 * Sanitize HTML content to prevent XSS attacks
 * OWASP A03:2021 - Injection Prevention
 */

const ALLOWED_TAGS = [
  'div', 'span', 'p', 'strong', 'em', 'b', 'i', 'u',
  'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'ul', 'ol', 'li', 'br', 'hr',
  'table', 'thead', 'tbody', 'tr', 'th', 'td',
  'blockquote', 'a'
];

const ALLOWED_ATTR = [
  'class', 'id', 'href', 'target', 'rel',
  'data-testid', 'aria-label', 'role'
];

const ALLOWED_URI_REGEXP = /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i;

/**
 * Sanitize HTML string for safe rendering
 * @param {string} dirty - Untrusted HTML string
 * @returns {string} Sanitized HTML string
 */
export const sanitizeHTML = (dirty) => {
  if (!dirty || typeof dirty !== 'string') {
    return '';
  }

  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    ALLOWED_URI_REGEXP,
    ALLOW_DATA_ATTR: false,
    ADD_ATTR: ['target'],
    FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'input', 'object', 'embed'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur'],
  });
};

/**
 * Sanitize plain text (escape HTML entities)
 * @param {string} text - Text to sanitize
 * @returns {string} Escaped text
 */
export const escapeHTML = (text) => {
  if (!text || typeof text !== 'string') {
    return '';
  }

  const htmlEntities = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
  };

  return text.replace(/[&<>"'/]/g, (char) => htmlEntities[char]);
};

/**
 * Sanitize user input for logging/display
 * @param {string} input - User input
 * @param {number} maxLength - Maximum allowed length
 * @returns {string} Sanitized input
 */
export const sanitizeInput = (input, maxLength = 10000) => {
  if (!input || typeof input !== 'string') {
    return '';
  }

  // Truncate to max length
  let sanitized = input.slice(0, maxLength);

  // Remove null bytes and other control characters (except newlines and tabs)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

  return sanitized;
};

/**
 * Validate and sanitize URL
 * @param {string} url - URL to validate
 * @returns {string|null} Sanitized URL or null if invalid
 */
export const sanitizeURL = (url) => {
  if (!url || typeof url !== 'string') {
    return null;
  }

  try {
    const parsed = new URL(url);
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
};

export default {
  sanitizeHTML,
  escapeHTML,
  sanitizeInput,
  sanitizeURL,
};
