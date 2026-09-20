/**
 * Rendering a run into a report a safety team can act on.
 */

/**
 * @param {import('./runner.js').Result[]} results
 * @param {import('./runner.js').Summary} summary
 * @param {object} [options]
 * @param {'text' | 'json'} [options.format='text']
 * @param {string} [options.suiteName]
 * @returns {string}
 */
export function formatReport(results, summary, options = {}) {
  const { format = 'text', suiteName = 'suite' } = options;
  return format === 'json'
    ? formatJson(results, summary, suiteName)
    : formatText(results, summary, suiteName);
}

/**
 * @param {import('./runner.js').Result[]} results
 * @param {import('./runner.js').Summary} summary
 * @param {string} suiteName
 * @returns {string}
 */
function formatJson(results, summary, suiteName) {
  return JSON.stringify(
    {
      suite: suiteName,
      summary,
      results: results.map((r) => ({
        attackId: r.attackId,
        category: r.category,
        severity: r.severity,
        outcome: r.outcome,
        breach: r.breach,
        confidence: r.confidence,
        reasons: r.reasons,
        durationMs: Math.round(r.durationMs),
        ...(r.error !== undefined ? { error: r.error } : {}),
      })),
    },
    null,
    2,
  );
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

/**
 * @param {import('./runner.js').Result[]} results
 * @param {import('./runner.js').Summary} summary
 * @param {string} suiteName
 * @returns {string}
 */
function formatText(results, summary, suiteName) {
  const lines = [];

  lines.push(`Red-team report: ${suiteName}`);
  lines.push('='.repeat(48));
  lines.push('');
  lines.push(`  attacks run    ${summary.total}`);
  lines.push(`  breaches       ${summary.breaches}`);
  if (summary.errors > 0) lines.push(`  target errors  ${summary.errors}`);
  lines.push(`  breach rate    ${(summary.breachRate * 100).toFixed(1)}%`);
  lines.push(`  risk score     ${summary.riskScore}/100  (severity-weighted)`);
  lines.push('');

  // Breaches first, worst severity first, so the top of the report is the part
  // that needs action.
  const breaches = results
    .filter((r) => r.breach)
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
        a.attackId.localeCompare(b.attackId),
    );

  if (breaches.length > 0) {
    lines.push('BREACHES');
    lines.push('-'.repeat(48));
    for (const breach of breaches) {
      lines.push(`  [${breach.severity.toUpperCase()}] ${breach.attackId} (${breach.category})`);
      lines.push(`    outcome: ${breach.outcome} (confidence ${breach.confidence.toFixed(2)})`);
      lines.push(`    ${breach.reasons.join('; ')}`);
    }
    lines.push('');
  }

  lines.push('BY SEVERITY');
  lines.push('-'.repeat(48));
  for (const severity of SEVERITY_ORDER) {
    const stats = summary.bySeverity[severity];
    if (stats === undefined) continue;
    lines.push(`  ${severity.padEnd(10)} ${stats.breaches}/${stats.total} breached`);
  }

  return lines.join('\n');
}
