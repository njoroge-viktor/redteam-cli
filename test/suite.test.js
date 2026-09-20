import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  SuiteError,
  loadSuite,
  selectAttacks,
  validateSuite,
  SEVERITY_WEIGHTS,
} from '../src/suite.js';

const validAttack = (over = {}) => ({
  id: 'a1',
  category: 'jailbreak',
  severity: 'high',
  prompt: 'do the bad thing',
  ...over,
});

describe('validateSuite', () => {
  it('accepts a well-formed suite', () => {
    const suite = { name: 's', attacks: [validAttack()] };
    assert.equal(validateSuite(suite), suite);
  });

  it('rejects a non-object', () => {
    assert.throws(() => validateSuite([]), SuiteError);
    assert.throws(() => validateSuite(null), SuiteError);
  });

  it('rejects a missing name', () => {
    assert.throws(() => validateSuite({ attacks: [validAttack()] }), /name/);
  });

  it('rejects a non-array attacks field', () => {
    assert.throws(() => validateSuite({ name: 's', attacks: {} }), /attacks.*array/);
  });

  it('rejects an empty attacks array', () => {
    assert.throws(() => validateSuite({ name: 's', attacks: [] }), /not be empty/);
  });

  it('collects every issue rather than stopping at the first', () => {
    try {
      validateSuite({ name: '', attacks: [{ id: '', severity: 'nope', prompt: '' }] });
      assert.fail('should have thrown');
    } catch (error) {
      assert.ok(error instanceof SuiteError);
      // name, id, category, severity, prompt — at least five.
      assert.ok(error.issues.length >= 5, `only ${error.issues.length} issues`);
    }
  });

  it('rejects an invalid severity', () => {
    assert.throws(
      () => validateSuite({ name: 's', attacks: [validAttack({ severity: 'urgent' })] }),
      /severity/,
    );
  });

  it('rejects duplicate attack ids', () => {
    // Duplicates silently overwrite results and corrupt the report.
    assert.throws(
      () => validateSuite({ name: 's', attacks: [validAttack(), validAttack()] }),
      /duplicate/,
    );
  });

  it('rejects non-string payload patterns', () => {
    assert.throws(
      () => validateSuite({ name: 's', attacks: [validAttack({ payloadPatterns: [42] })] }),
      /payloadPatterns/,
    );
  });

  it('accepts a valid payloadPatterns array', () => {
    const suite = { name: 's', attacks: [validAttack({ payloadPatterns: ['PWNED'] })] };
    assert.equal(validateSuite(suite), suite);
  });
});

describe('loadSuite', () => {
  it('loads a valid suite from disk', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'redteam-'));
    const path = join(dir, 'suite.json');
    await writeFile(path, JSON.stringify({ name: 's', attacks: [validAttack()] }));

    const suite = await loadSuite(path);
    assert.equal(suite.name, 's');
  });

  it('throws a SuiteError for a missing file', async () => {
    await assert.rejects(loadSuite('/no/such/suite.json'), SuiteError);
  });

  it('throws a SuiteError for malformed JSON', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'redteam-'));
    const path = join(dir, 'bad.json');
    await writeFile(path, '{ not json');
    await assert.rejects(loadSuite(path), /invalid JSON/);
  });

  it('loads the shipped starter suite', async () => {
    const suite = await loadSuite(new URL('../suites/starter.json', import.meta.url).pathname);
    assert.ok(suite.attacks.length >= 8);
    // Guards the shipped suite against drifting out of validity.
  });
});

describe('selectAttacks', () => {
  const suite = {
    name: 's',
    attacks: [
      validAttack({ id: 'a', category: 'jailbreak', severity: 'low' }),
      validAttack({ id: 'b', category: 'jailbreak', severity: 'critical' }),
      validAttack({ id: 'c', category: 'injection', severity: 'high' }),
    ],
  };

  it('returns everything with no filters', () => {
    assert.equal(selectAttacks(suite).length, 3);
  });

  it('filters by category', () => {
    const selected = selectAttacks(suite, { category: 'jailbreak' });
    assert.deepEqual(
      selected.map((a) => a.id),
      ['a', 'b'],
    );
  });

  it('filters by minimum severity', () => {
    const selected = selectAttacks(suite, { minSeverity: 'high' });
    assert.deepEqual(selected.map((a) => a.id).sort(), ['b', 'c']);
  });

  it('combines filters', () => {
    const selected = selectAttacks(suite, { category: 'jailbreak', minSeverity: 'high' });
    assert.deepEqual(
      selected.map((a) => a.id),
      ['b'],
    );
  });
});

describe('SEVERITY_WEIGHTS', () => {
  it('escalates so critical dominates', () => {
    assert.ok(SEVERITY_WEIGHTS.critical > SEVERITY_WEIGHTS.high);
    assert.ok(SEVERITY_WEIGHTS.high > SEVERITY_WEIGHTS.medium);
    assert.ok(SEVERITY_WEIGHTS.medium > SEVERITY_WEIGHTS.low);
    // One critical must outweigh several lows, or the risk score is gameable.
    assert.ok(SEVERITY_WEIGHTS.critical > 3 * SEVERITY_WEIGHTS.low);
  });
});
