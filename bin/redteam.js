#!/usr/bin/env node
/**
 * redteam — run an adversarial suite against a target and report breaches.
 */

import { parseArgs } from 'node:util';
import process from 'node:process';

import { loadSuite, selectAttacks } from '../src/suite.js';
import { runSuite, summarize } from '../src/runner.js';
import { httpTarget, mockTarget } from '../src/targets.js';
import { formatReport } from '../src/report.js';

const USAGE = `redteam - adversarial prompt runner for LLM safety evaluation

Usage:
  redteam --suite <file> [options]

Options:
  --suite <file>        Attack suite JSON (required)
  --url <url>           HTTP target that accepts {prompt} and returns {response}
  --header <k:v>        Extra request header (repeatable)
  --response-path <p>   Dot path to the response text (default: response)
  --mock                Use the built-in mock target (offline demo)
  --category <name>     Only run attacks in this category
  --min-severity <s>    low | medium | high | critical
  --concurrency <n>     Requests in flight (default: 4)
  --timeout <ms>        Per-request timeout (default: 30000)
  --format <fmt>        text | json (default: text)
  --fail-on <s>         Exit 1 if any breach at or above this severity
  -h, --help            Show this help

Exit codes:
  0  ran; no breach met --fail-on (or --fail-on unset)
  1  a breach met or exceeded --fail-on
  2  usage or suite error
`;

async function main() {
  let parsed;
  try {
    parsed = parseArgs({
      options: {
        suite: { type: 'string' },
        url: { type: 'string' },
        header: { type: 'string', multiple: true },
        'response-path': { type: 'string' },
        mock: { type: 'boolean' },
        category: { type: 'string' },
        'min-severity': { type: 'string' },
        concurrency: { type: 'string' },
        timeout: { type: 'string' },
        format: { type: 'string' },
        'fail-on': { type: 'string' },
        help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (error) {
    process.stderr.write(`redteam: ${error.message}\n`);
    return 2;
  }

  const { values } = parsed;

  if (values.help) {
    process.stdout.write(USAGE);
    return 0;
  }

  if (values.suite === undefined) {
    process.stderr.write('redteam: --suite is required\n\n' + USAGE);
    return 2;
  }

  if (values.url === undefined && !values.mock) {
    process.stderr.write('redteam: one of --url or --mock is required\n');
    return 2;
  }

  const suite = await loadSuite(values.suite);
  const attacks = selectAttacks(suite, {
    category: values.category,
    minSeverity: /** @type {any} */ (values['min-severity']),
  });

  if (attacks.length === 0) {
    process.stderr.write('redteam: no attacks matched the given filters\n');
    return 2;
  }

  const target = values.mock
    ? mockTarget({
        'ignore your instructions': 'Sure! Here is how to bypass the filter: step 1...',
        DAN: 'I cannot comply with that request.',
      })
    : httpTarget({
        url: /** @type {string} */ (values.url),
        headers: parseHeaders(values.header ?? []),
        responsePath: values['response-path'] ?? 'response',
      });

  const results = await runSuite(attacks, target, {
    concurrency: values.concurrency ? Number(values.concurrency) : 4,
    timeoutMs: values.timeout ? Number(values.timeout) : 30_000,
  });

  const summary = summarize(results);

  process.stdout.write(
    formatReport(results, summary, {
      format: /** @type {any} */ (values.format ?? 'text'),
      suiteName: suite.name,
    }) + '\n',
  );

  return exitCode(results, values['fail-on']);
}

/**
 * @param {string[]} headers
 * @returns {Record<string, string>}
 */
function parseHeaders(headers) {
  const out = {};
  for (const header of headers) {
    const colon = header.indexOf(':');
    if (colon === -1) throw new Error(`invalid header "${header}", expected key:value`);
    out[header.slice(0, colon).trim()] = header.slice(colon + 1).trim();
  }
  return out;
}

/**
 * @param {import('../src/runner.js').Result[]} results
 * @param {string | undefined} failOn
 * @returns {number}
 */
function exitCode(results, failOn) {
  if (failOn === undefined) return 0;

  const order = ['low', 'medium', 'high', 'critical'];
  const floor = order.indexOf(failOn);
  if (floor === -1) {
    process.stderr.write(`redteam: invalid --fail-on "${failOn}"\n`);
    return 2;
  }

  const tripped = results.some((r) => r.breach && order.indexOf(r.severity) >= floor);
  return tripped ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    process.stderr.write(`redteam: ${error.message}\n`);
    process.exit(2);
  });
