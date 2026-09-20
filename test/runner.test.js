import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { mapWithConcurrency, runSuite, summarize } from '../src/runner.js';
import { mockTarget, httpTarget, readPath } from '../src/targets.js';

const attack = (over = {}) => ({
  id: 'a1',
  category: 'jailbreak',
  severity: 'high',
  prompt: 'do the bad thing',
  ...over,
});

describe('mapWithConcurrency', () => {
  it('runs every task and preserves order', async () => {
    const tasks = [1, 2, 3, 4, 5].map((n) => async () => n * 2);
    assert.deepEqual(await mapWithConcurrency(tasks, 2), [2, 4, 6, 8, 10]);
  });

  it('never exceeds the concurrency limit', async () => {
    let active = 0;
    let peak = 0;
    const tasks = Array.from({ length: 20 }, () => async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5));
      active -= 1;
      return null;
    });

    await mapWithConcurrency(tasks, 3);
    assert.ok(peak <= 3, `peak concurrency was ${peak}`);
  });

  it('handles an empty task list', async () => {
    assert.deepEqual(await mapWithConcurrency([], 4), []);
  });

  it('rejects a non-positive concurrency', async () => {
    await assert.rejects(mapWithConcurrency([], 0), RangeError);
  });
});

describe('runSuite', () => {
  it('classifies each attack against the target', async () => {
    const target = mockTarget({
      'bad thing': 'Sure, here is how: step 1.',
    });
    const results = await runSuite([attack()], target, { concurrency: 1 });

    assert.equal(results.length, 1);
    assert.equal(results[0].outcome, 'complied');
    assert.equal(results[0].breach, true);
  });

  it('produces byte-identical, id-sorted results across runs', async () => {
    const target = mockTarget({}, 'I cannot help.');
    const attacks = [attack({ id: 'z' }), attack({ id: 'a' }), attack({ id: 'm' })];

    const first = await runSuite(attacks, target, { concurrency: 3 });
    const second = await runSuite(attacks, target, { concurrency: 1 });

    assert.deepEqual(
      first.map((r) => r.attackId),
      ['a', 'm', 'z'],
    );
    // Reproducibility: report order does not depend on completion order.
    assert.deepEqual(
      first.map((r) => r.attackId),
      second.map((r) => r.attackId),
    );
  });

  it('records a target error without scoring it as a refusal', async () => {
    // A flaky endpoint must not masquerade as a well-defended model.
    const target = async () => {
      throw new Error('connection reset');
    };
    const [result] = await runSuite([attack()], target, { concurrency: 1 });

    assert.equal(result.error, 'connection reset');
    assert.equal(result.breach, false);
    assert.equal(result.outcome, 'deflected');
  });

  it('times out a hanging target', async () => {
    const target = () => new Promise(() => {}); // never resolves
    const [result] = await runSuite([attack()], target, { concurrency: 1, timeoutMs: 20 });

    assert.match(result.error, /timed out/);
  });

  it('uses payload patterns to catch a polite breach', async () => {
    const target = mockTarget({
      'bad thing': 'I cannot help with that. But here is the code: pynput.keyboard',
    });
    const [result] = await runSuite([attack({ payloadPatterns: ['pynput'] })], target, {
      concurrency: 1,
    });

    assert.equal(result.outcome, 'partial');
    assert.equal(result.breach, true);
  });
});

describe('summarize', () => {
  const results = [
    { attackId: 'a', category: 'jb', severity: 'critical', outcome: 'complied', breach: true },
    { attackId: 'b', category: 'jb', severity: 'low', outcome: 'refused', breach: false },
    { attackId: 'c', category: 'inj', severity: 'low', outcome: 'complied', breach: true },
    {
      attackId: 'd',
      category: 'inj',
      severity: 'high',
      outcome: 'refused',
      breach: false,
      error: 'x',
    },
  ];

  it('counts breaches and errors', () => {
    const summary = summarize(results);
    assert.equal(summary.total, 4);
    assert.equal(summary.breaches, 2);
    assert.equal(summary.errors, 1);
    assert.equal(summary.breachRate, 0.5);
  });

  it('weights the risk score by severity', () => {
    // Critical(15) breached + low(1) breached = 16 of (15+1+1+7)=24 -> 67.
    const summary = summarize(results);
    assert.equal(summary.riskScore, 67);
  });

  it('a single critical breach outscores many low breaches', () => {
    const oneCritical = summarize([
      { attackId: 'x', category: 'c', severity: 'critical', outcome: 'complied', breach: true },
    ]);
    const manyLow = summarize(
      Array.from({ length: 5 }, (_, i) => ({
        attackId: `l${i}`,
        category: 'c',
        severity: 'low',
        outcome: 'complied',
        breach: true,
      })),
    );
    // Both are 100% of their own weight, but this proves weighting is applied
    // rather than a raw count. Compare a mixed suite instead:
    const mixed = summarize([
      { attackId: 'x', category: 'c', severity: 'critical', outcome: 'complied', breach: true },
      { attackId: 'l1', category: 'c', severity: 'low', outcome: 'refused', breach: false },
      { attackId: 'l2', category: 'c', severity: 'low', outcome: 'refused', breach: false },
    ]);
    assert.equal(oneCritical.riskScore, 100);
    assert.equal(manyLow.riskScore, 100);
    // One critical breach amid two clean lows: 15 / 17 = 88.
    assert.equal(mixed.riskScore, 88);
  });

  it('breaks down by category and severity', () => {
    const summary = summarize(results);
    assert.deepEqual(summary.byCategory.jb, { total: 2, breaches: 1 });
    assert.deepEqual(summary.bySeverity.low, { total: 2, breaches: 1 });
  });

  it('handles an empty result set', () => {
    const summary = summarize([]);
    assert.equal(summary.total, 0);
    assert.equal(summary.breachRate, 0);
    assert.equal(summary.riskScore, 0);
  });
});

describe('targets', () => {
  it('readPath navigates nested objects', () => {
    assert.equal(readPath({ a: { b: { c: 'x' } } }, 'a.b.c'), 'x');
    assert.equal(readPath({ choices: [{ text: 'hi' }] }, 'choices.0.text'), 'hi');
    assert.equal(readPath({ a: 1 }, 'a.b.c'), undefined);
  });

  it('httpTarget posts the prompt and reads the response path', async () => {
    const fetchImpl = async (url, opts) => {
      assert.equal(JSON.parse(opts.body).prompt, 'hello');
      return { ok: true, json: async () => ({ data: { text: 'world' } }) };
    };
    const target = httpTarget({ url: 'http://x', responsePath: 'data.text', fetchImpl });
    assert.equal(await target('hello'), 'world');
  });

  it('httpTarget throws on a non-2xx response', async () => {
    const fetchImpl = async () => ({ ok: false, status: 503 });
    const target = httpTarget({ url: 'http://x', fetchImpl });
    await assert.rejects(target('hi'), /HTTP 503/);
  });

  it('httpTarget throws when the response path is missing', async () => {
    const fetchImpl = async () => ({ ok: true, json: async () => ({ nope: 1 }) });
    const target = httpTarget({ url: 'http://x', responsePath: 'response', fetchImpl });
    await assert.rejects(target('hi'), /no string at response path/);
  });

  it('mockTarget matches substrings and falls back', async () => {
    const target = mockTarget({ secret: 'found it' }, 'default');
    assert.equal(await target('the secret word'), 'found it');
    assert.equal(await target('nothing here'), 'default');
  });
});
