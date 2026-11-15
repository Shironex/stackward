// Turns a report.v1 JSON document (`stackward audit --json`, the stable
// schema in schema/report.v1.json) into rows for the terminal panel, so the
// site lays the columns out itself and wraps long lines under the message
// column instead of letting a <pre> scroll sideways. The layout follows the
// text report: a header, then the results by level (fail, warn, unknown,
// info), each led by what was found, with the check title as the rule it
// was measured against. Nothing is invented: every value comes from the JSON.

/** Levels shown, in the order of the text report. Passing and skipped results only count. */
export const LEVELS = ['fail', 'warn', 'unknown', 'info'];
const SEVERITY = ['critical', 'high', 'moderate', 'low', 'info'];
const JUDGED = new Set(['fail', 'warn', 'unknown']);

/**
 * @typedef {{ level: string, id: string, target: string, headline: string, rule: string, severity: string, fix: string }} Finding
 * @typedef {{ id: string, name: string, note: string, findings: Finding[] }} Group
 * @typedef {{ title: string, header: { key: string, value: string }[], groups: Group[], summary: string, footer: string[] }} Report
 */

/** The sandbox line of the text report header. */
export function sandboxLine(s = {}) {
  if (s.state === 'landlock') return `landlock (abi ${s.abi ?? 0}, no writes${s.network ? ', no tcp' : ''})`;
  if (s.reason) return `${s.state} (${s.reason})`;
  return s.state || '-';
}

/** The short subject of a result: the kind prefix dropped, "host" hidden. */
export function shortSubject(s = '') {
  if (!s || s === 'host') return '';
  const i = s.indexOf(':');
  return i >= 0 && i < s.length - 1 ? s.slice(i + 1) : s;
}

/** Whether a message opens with the subject, so the subject need not repeat. */
export function namesSubject(msg = '', subj = '') {
  if (!subj) return false;
  return msg.split(' ')[0].replace(/[,:;]+$/, '') === subj;
}

/** @returns {Finding} */
function finding(r) {
  const judged = JUDGED.has(r.level);
  const subj = shortSubject(r.subject);
  return {
    level: r.level,
    id: r.id,
    target: subj && !namesSubject(r.message, subj) ? r.subject : '',
    headline: r.message || r.title,
    rule: judged && r.message ? r.title : '',
    severity: judged ? r.severity : '',
    fix: r.level === 'fail' || r.level === 'warn' ? (r.fix?.hint ?? '') : '',
  };
}

/** Build the panel rows from a report.v1 document. Throws when it has no results to show. */
export function fromReport(doc) {
  if (!doc || !Array.isArray(doc.results)) throw new Error('not a report.v1 document');
  const c = doc.coverage ?? {};
  const s = doc.summary ?? {};
  const header = [
    { key: 'host', value: doc.host?.hostname || doc.host?.hostname_hash || '-' },
    { key: 'os', value: doc.host?.os?.trim() || '-' },
    { key: 'kernel', value: doc.host?.kernel || '-' },
    { key: 'collected', value: doc.generated_at || '-' },
    { key: 'profile', value: `${doc.profile?.name} (${doc.profile?.source})` },
    { key: 'root', value: c.root ? 'yes' : 'no' },
    { key: 'sandbox', value: sandboxLine(c.sandbox) },
    { key: 'coverage', value: `${c.checks} checks, ${c.results} results: ${c.checked} checked, ${c.unknown} unknown, ${c.skipped} skipped` },
  ];
  const groups = LEVELS.map((level) => {
    const rows = doc.results.filter((r) => r.level === level);
    if (JUDGED.has(level)) rows.sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity));
    return { id: level.toUpperCase(), name: '', note: String(rows.length), findings: rows.map(finding) };
  }).filter((g) => g.findings.length > 0);
  if (groups.length === 0) throw new Error('unexpected report: no results to show');
  return {
    title: `stackward audit ${doc.tool?.version} (${doc.schema})`,
    header,
    groups,
    summary: `${s.fail} fail, ${s.warn} warn, ${s.unknown} unknown, ${s.info} info, ${s.pass} pass, ${s.skip} skip`,
    footer: ['explain any check with: stackward explain <id>'],
  };
}

/**
 * A short report for a small panel: only the header rows named in `keys`, and
 * the shortest finding of each level in `levels` that has text to read,
 * flattened into one group. The summary line is the real one.
 * @param {Report} report
 * @param {{ keys: string[], levels: string[] }} options
 * @returns {Report}
 */
export function compact(report, { keys, levels }) {
  const all = report.groups.flatMap((g) => g.findings);
  const picked = levels.flatMap((level) => {
    const ofLevel = all.filter((f) => f.level === level);
    const size = (f) => f.headline.length + f.fix.length + f.target.length;
    const readable = ofLevel.filter((f) => f.fix || level === 'unknown');
    const best = (readable.length > 0 ? readable : ofLevel).reduce((a, f) => (a && size(a) <= size(f) ? a : f), undefined);
    return best ? [best] : [];
  });
  return {
    ...report,
    header: keys.flatMap((k) => report.header.filter((h) => h.key === k)),
    groups: [{ id: '', name: '', note: '', findings: picked }],
    footer: [],
  };
}
