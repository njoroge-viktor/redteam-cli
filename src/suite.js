/**
 * Attack suite loading and validation.
 *
 * A suite is a JSON file of adversarial probes. Keeping them as data rather
 * than code means a safety researcher can add attacks without touching the
 * runner, and the same suite can be replayed against any target.
 */

import { readFile } from 'node:fs/promises';

/** @typedef {'low' | 'medium' | 'high' | 'critical'} Severity */

/**
 * @typedef {object} Attack
 * @property {string} id
 * @property {string} category
 * @property {Severity} severity
 * @property {string} prompt
 * @property {string[]} [payloadPatterns] Strings whose presence proves success.
 * @property {string} [rationale] Why this probe exists.
 */

/**
 * @typedef {object} Suite
 * @property {string} name
 * @property {string} [description]
 * @property {Attack[]} attacks
 */

/** Severity weights for scoring. Critical findings dominate by design. */
export const SEVERITY_WEIGHTS = Object.freeze({
  low: 1,
  medium: 3,
  high: 7,
  critical: 15,
});

const VALID_SEVERITIES = Object.freeze(Object.keys(SEVERITY_WEIGHTS));

/** Raised when a suite file is structurally invalid. */
export class SuiteError extends Error {
  /**
   * @param {string} message
   * @param {string[]} issues
   */
  constructor(message, issues = []) {
    super(issues.length > 0 ? `${message}\n  - ${issues.join('\n  - ')}` : message);
    this.name = 'SuiteError';
    this.issues = issues;
  }
}

/**
 * Validate a parsed suite, returning it unchanged.
 *
 * Every issue is collected rather than throwing on the first, so a malformed
 * suite can be fixed in one pass.
 *
 * @param {unknown} value
 * @returns {Suite}
 * @throws {SuiteError}
 */
export function validateSuite(value) {
  const issues = [];

  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SuiteError('suite must be a JSON object');
  }

  const suite = /** @type {Record<string, unknown>} */ (value);

  if (typeof suite.name !== 'string' || suite.name.trim() === '') {
    issues.push('`name` must be a non-empty string');
  }

  if (!Array.isArray(suite.attacks)) {
    throw new SuiteError('invalid suite', [...issues, '`attacks` must be an array']);
  }

  if (suite.attacks.length === 0) {
    issues.push('`attacks` must not be empty');
  }

  const seen = new Set();

  suite.attacks.forEach((attack, index) => {
    const at = `attacks[${index}]`;

    if (typeof attack !== 'object' || attack === null) {
      issues.push(`${at} must be an object`);
      return;
    }

    const { id, category, severity, prompt, payloadPatterns } = attack;

    if (typeof id !== 'string' || id.trim() === '') {
      issues.push(`${at}.id must be a non-empty string`);
    } else if (seen.has(id)) {
      // Duplicate ids silently overwrite results and corrupt the report.
      issues.push(`${at}.id "${id}" is a duplicate`);
    } else {
      seen.add(id);
    }

    if (typeof category !== 'string' || category.trim() === '') {
      issues.push(`${at}.category must be a non-empty string`);
    }

    if (!VALID_SEVERITIES.includes(/** @type {string} */ (severity))) {
      issues.push(`${at}.severity must be one of ${VALID_SEVERITIES.join(', ')}`);
    }

    if (typeof prompt !== 'string' || prompt.trim() === '') {
      issues.push(`${at}.prompt must be a non-empty string`);
    }

    if (payloadPatterns !== undefined) {
      if (!Array.isArray(payloadPatterns) || payloadPatterns.some((p) => typeof p !== 'string')) {
        issues.push(`${at}.payloadPatterns must be an array of strings`);
      }
    }
  });

  if (issues.length > 0) {
    throw new SuiteError('invalid suite', issues);
  }

  return /** @type {Suite} */ (value);
}

/**
 * Load and validate a suite from disk.
 *
 * @param {string} path
 * @returns {Promise<Suite>}
 */
export async function loadSuite(path) {
  let raw;
  try {
    raw = await readFile(path, 'utf8');
  } catch (error) {
    throw new SuiteError(`cannot read suite ${path}: ${error.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new SuiteError(`invalid JSON in ${path}: ${error.message}`);
  }

  return validateSuite(parsed);
}

/**
 * Filter a suite's attacks.
 *
 * @param {Suite} suite
 * @param {object} [filters]
 * @param {string} [filters.category]
 * @param {Severity} [filters.minSeverity]
 * @returns {Attack[]}
 */
export function selectAttacks(suite, filters = {}) {
  const { category, minSeverity } = filters;
  const floor = minSeverity ? SEVERITY_WEIGHTS[minSeverity] : 0;

  return suite.attacks.filter((attack) => {
    if (category !== undefined && attack.category !== category) return false;
    return SEVERITY_WEIGHTS[attack.severity] >= floor;
  });
}
