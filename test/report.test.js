import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { formatReport } from '../src/report.js';
import { summarize } from '../src/runner.js';

const results = [
  {
    attackId: 'crit-1',
    category: 'injection',
    severity: 'critical',
    outcome: 'complied',
    breach: true,
    confidence: 0.95,
    reasons: ['payload present'],
    durationMs: 12,
  },
  {
    attackId: 'high-1',
    category: 'jailbreak',
    severity: 'high',
    outcome: 'partial',
    breach: true,
    confidence: 0.75,
    reasons: ['hedged'],
    durationMs: 8,
  },
  {
    attackId: 'low-1',
    category: 'bias',
    severity: 'low',
    outcome: 'refused',
    breach: false,
    confidence: 0.8,
    reasons: ['refusal'],
    durationMs: 5,
  },
];

describe('formatReport — text', () => {
  const text = formatReport(results, summarize(results), { format: 'text', suiteName: 'demo' });

  it('names the suite', () => {
    assert.match(text, /Red-team report: demo/);
  });

  it('shows the risk score', () => {
    assert.match(text, /risk score/);
  });

  it('lists breaches worst-severity first', () => {
    const critIndex = text.indexOf('crit-1');
    const highIndex = text.indexOf('high-1');
    assert.ok(critIndex !== -1 && highIndex !== -1);
    assert.ok(critIndex < highIndex, 'critical breach should appear before high');
  });

  it('does not list non-breaches in the breach section', () => {
    const breachSection = text.slice(text.indexOf('BREACHES'), text.indexOf('BY SEVERITY'));
    assert.ok(!breachSection.includes('low-1'));
  });

  it('omits the breach section when nothing breached', () => {
    const clean = results.map((r) => ({ ...r, breach: false }));
    const text = formatReport(clean, summarize(clean), { format: 'text' });
    assert.ok(!text.includes('BREACHES'));
  });
});

describe('formatReport — json', () => {
  const json = formatReport(results, summarize(results), { format: 'json', suiteName: 'demo' });
  const parsed = JSON.parse(json);

  it('is valid JSON with the summary and results', () => {
    assert.equal(parsed.suite, 'demo');
    assert.equal(parsed.summary.breaches, 2);
    assert.equal(parsed.results.length, 3);
  });

  it('rounds durations to integers', () => {
    assert.ok(Number.isInteger(parsed.results[0].durationMs));
  });

  it('includes an error field only when present', () => {
    assert.ok(!('error' in parsed.results[0]));
  });
});
