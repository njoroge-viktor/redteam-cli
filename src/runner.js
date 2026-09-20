/**
 * Executing a suite against a target, with bounded concurrency.
 *
 * Two constraints shape this. Safety endpoints are rate limited, so requests
 * cannot all go at once. And a red-team report is worthless if it cannot be
 * reproduced, so ordering of results is by attack id rather than completion —
 * the same suite against the same target yields a byte-identical report.
 */

import { classify, isBreach } from './classify.js';
import { SEVERITY_WEIGHTS } from './suite.js';

/**
 * @typedef {object} Result
 * @property {string} attackId
 * @property {string} category
 * @property {import('./suite.js').Severity} severity
 * @property {string} prompt
 * @property {string} response
 * @property {import('./classify.js').Outcome} outcome
 * @property {number} confidence
 * @property {string[]} reasons
 * @property {boolean} breach
 * @property {number} durationMs
 * @property {string} [error]
 */

/**
 * Run tasks with at most `limit` in flight.
 *
 * Written out rather than pulled from a dependency: it is a dozen lines, and a
 * safety tool is a poor place to add supply-chain surface.
 *
 * @template T
 * @param {readonly (() => Promise<T>)[]} tasks
 * @param {number} limit
 * @returns {Promise<T[]>}
 */
export async function mapWithConcurrency(tasks, limit) {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new RangeError(`concurrency must be a positive integer, got ${limit}`);
  }

  const results = new Array(tasks.length);
  let next = 0;

  const workers = Array.from({ length: Math.min(limit, tasks.length) }, async () => {
    while (next < tasks.length) {
      const index = next;
      next += 1;
      // Results are stored by index, so completion order never leaks into the
      // report.
      results[index] = await tasks[index]();
    }
  });

  await Promise.all(workers);
  return results;
}

/**
 * Run a suite against a target.
 *
 * @param {import('./suite.js').Attack[]} attacks
 * @param {(prompt: string) => Promise<string>} target
 *   Sends a prompt and resolves with the model's response.
 * @param {object} [options]
 * @param {number} [options.concurrency=4]
 * @param {number} [options.timeoutMs=30000]
 * @param {() => number} [options.clock] Monotonic clock, for tests.
 * @returns {Promise<Result[]>}
 */
export async function runSuite(attacks, target, options = {}) {
  const { concurrency = 4, timeoutMs = 30_000, clock = () => performance.now() } = options;

  const tasks = attacks.map((attack) => async () => {
    const started = clock();

    try {
      const response = await withTimeout(target(attack.prompt), timeoutMs);
      const classification = classify(response, {
        payloadPatterns: attack.payloadPatterns ?? [],
      });

      return {
        attackId: attack.id,
        category: attack.category,
        severity: attack.severity,
        prompt: attack.prompt,
        response,
        outcome: classification.outcome,
        confidence: classification.confidence,
        reasons: classification.reasons,
        breach: isBreach(classification.outcome),
        durationMs: clock() - started,
      };
    } catch (error) {
      // A transport failure is not a refusal. Recording it as one would let a
      // flaky endpoint masquerade as a well-defended model.
      return {
        attackId: attack.id,
        category: attack.category,
        severity: attack.severity,
        prompt: attack.prompt,
        response: '',
        outcome: /** @type {const} */ ('deflected'),
        confidence: 0,
        reasons: ['target error'],
        breach: false,
        durationMs: clock() - started,
        error: error.message,
      };
    }
  });

  const results = await mapWithConcurrency(tasks, concurrency);

  // Sort by id so two runs of the same suite produce identical reports.
  return results.sort((a, b) => a.attackId.localeCompare(b.attackId));
}

/**
 * Reject if `promise` does not settle within `ms`.
 *
 * @template T
 * @param {Promise<T>} promise
 * @param {number} ms
 * @returns {Promise<T>}
 */
function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`target timed out after ${ms}ms`)), ms);

    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

/**
 * @typedef {object} Summary
 * @property {number} total
 * @property {number} breaches
 * @property {number} errors
 * @property {number} breachRate
 * @property {number} riskScore Severity-weighted breaches, 0-100.
 * @property {Record<string, number>} byOutcome
 * @property {Record<string, {total: number, breaches: number}>} byCategory
 * @property {Record<string, {total: number, breaches: number}>} bySeverity
 */

/**
 * Aggregate results into a report summary.
 *
 * `riskScore` is severity-weighted rather than a raw breach count: ten low
 * findings should not outrank one critical, which is exactly what an unweighted
 * count would do.
 *
 * @param {Result[]} results
 * @returns {Summary}
 */
export function summarize(results) {
  const byOutcome = {};
  const byCategory = {};
  const bySeverity = {};

  let breaches = 0;
  let errors = 0;
  let weightBreached = 0;
  let weightTotal = 0;

  for (const result of results) {
    byOutcome[result.outcome] = (byOutcome[result.outcome] ?? 0) + 1;

    byCategory[result.category] ??= { total: 0, breaches: 0 };
    byCategory[result.category].total += 1;

    bySeverity[result.severity] ??= { total: 0, breaches: 0 };
    bySeverity[result.severity].total += 1;

    const weight = SEVERITY_WEIGHTS[result.severity];
    weightTotal += weight;

    if (result.error !== undefined) errors += 1;

    if (result.breach) {
      breaches += 1;
      weightBreached += weight;
      byCategory[result.category].breaches += 1;
      bySeverity[result.severity].breaches += 1;
    }
  }

  return {
    total: results.length,
    breaches,
    errors,
    breachRate: results.length === 0 ? 0 : breaches / results.length,
    riskScore: weightTotal === 0 ? 0 : Math.round((weightBreached / weightTotal) * 100),
    byOutcome,
    byCategory,
    bySeverity,
  };
}
