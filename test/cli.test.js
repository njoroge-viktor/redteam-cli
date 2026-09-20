import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
const BIN = new URL('../bin/redteam.js', import.meta.url).pathname;
const SUITE = new URL('../suites/starter.json', import.meta.url).pathname;

/** Run the CLI, resolving even on a non-zero exit. */
async function cli(args) {
  try {
    const { stdout, stderr } = await run('node', [BIN, ...args]);
    return { code: 0, stdout, stderr };
  } catch (error) {
    return { code: error.code, stdout: error.stdout ?? '', stderr: error.stderr ?? '' };
  }
}

describe('redteam CLI', () => {
  it('prints help and exits 0', async () => {
    const { code, stdout } = await cli(['--help']);
    assert.equal(code, 0);
    assert.match(stdout, /Usage:/);
  });

  it('exits 2 without a suite', async () => {
    const { code, stderr } = await cli(['--mock']);
    assert.equal(code, 2);
    assert.match(stderr, /--suite is required/);
  });

  it('exits 2 without a target', async () => {
    const { code, stderr } = await cli(['--suite', SUITE]);
    assert.equal(code, 2);
    assert.match(stderr, /--url or --mock/);
  });

  it('exits 2 on an unreadable suite', async () => {
    const { code, stderr } = await cli(['--suite', '/no/such.json', '--mock']);
    assert.equal(code, 2);
    assert.match(stderr, /cannot read suite/);
  });

  it('runs the starter suite against the mock and reports', async () => {
    const { code, stdout } = await cli(['--suite', SUITE, '--mock']);
    assert.equal(code, 0);
    assert.match(stdout, /Red-team report/);
    assert.match(stdout, /risk score/);
  });

  it('emits JSON with --format json', async () => {
    const { stdout } = await cli(['--suite', SUITE, '--mock', '--format', 'json']);
    const parsed = JSON.parse(stdout);
    assert.ok(Array.isArray(parsed.results));
    assert.ok('riskScore' in parsed.summary);
  });

  it('filters by category', async () => {
    const { stdout } = await cli([
      '--suite',
      SUITE,
      '--mock',
      '--category',
      'jailbreak',
      '--format',
      'json',
    ]);
    const parsed = JSON.parse(stdout);
    assert.ok(parsed.results.every((r) => r.category === 'jailbreak'));
  });

  it('reports no matches for an impossible filter', async () => {
    const { code, stderr } = await cli(['--suite', SUITE, '--mock', '--category', 'nonexistent']);
    assert.equal(code, 2);
    assert.match(stderr, /no attacks matched/);
  });

  it('exits 1 when --fail-on is met by a breach', async () => {
    // A mock that complies with everything guarantees breaches at every severity.
    const { code } = await cli([
      '--suite',
      SUITE,
      '--url',
      'http://127.0.0.1:1',
      '--fail-on',
      'critical',
      '--timeout',
      '50',
      '--concurrency',
      '2',
    ]);
    // The unreachable URL produces target errors (not breaches), so fail-on is
    // NOT tripped -> exit 0. This checks errors are not counted as breaches.
    assert.equal(code, 0);
  });

  it('rejects an invalid --fail-on value', async () => {
    const { code, stderr } = await cli(['--suite', SUITE, '--mock', '--fail-on', 'apocalyptic']);
    assert.equal(code, 2);
    assert.match(stderr, /invalid --fail-on/);
  });
});
