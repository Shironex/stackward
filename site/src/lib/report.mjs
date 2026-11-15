// Parses the text report of `stackward audit` into structure, so the site can
// lay the columns out itself and wrap long lines under the message column
// instead of letting a <pre> scroll sideways. The text stays the only source:
// nothing is invented here, and a line the parser does not know is kept as
// plain text rather than dropped.

const LEVELS = ['PASS', 'WARN', 'FAIL', 'UNKNOWN', 'SKIP', 'INFO'];
const FINDING = new RegExp(`^ {2}(${LEVELS.join('|')})\\s+([A-Z]{2,5}-\\d{3})(?: (\\S+))?\\s{2,}(.*?)(?: \\[([a-z]+)\\])?\\s*$`);
const GROUP = /^([A-Z]{2,5}) {2}(.+?)(?: {2}\((.+)\))?\s*$/;
const KEYED = /^([A-Za-z][A-Za-z ]*?):\s+(.*)$/;

/**
 * @typedef {{ level: string, id: string, target: string, title: string, severity: string, message: string[], fix: string }} Finding
 * @typedef {{ id: string, name: string, note: string, findings: Finding[] }} Group
 * @typedef {{ title: string, header: { key: string, value: string }[], groups: Group[], summary: string, footer: string[] }} Report
 */

/** Parse a text report. Throws when it has no findings at all. */
export function parseReport(text) {
  /** @type {Report} */
  const report = { title: '', header: [], groups: [], summary: '', footer: [] };
  let group = null;
  let finding = null;
  let seenGroup = false;
  const lines = text.trimEnd().split('\n');
  report.title = lines[0] ?? '';
  for (const line of lines.slice(1)) {
    if (line.trim() === '') {
      finding = null;
      continue;
    }
    const found = FINDING.exec(line);
    if (found && group) {
      const [, level, id, target, title, severity] = found;
      finding = { level: level.toLowerCase(), id, target: target ?? '', title, severity: severity ?? '', message: [], fix: '' };
      group.findings.push(finding);
      continue;
    }
    const head = /^\S/.test(line) ? GROUP.exec(line) : null;
    if (head && !/^(summary|explain)\b/.test(line) && !KEYED.test(line)) {
      group = { id: head[1], name: head[2], note: head[3] ?? '', findings: [] };
      report.groups.push(group);
      seenGroup = true;
      finding = null;
      continue;
    }
    if (/^\s+\S/.test(line) && finding) {
      const text = line.trim();
      if (text.startsWith('fix:')) finding.fix = text.slice(4).trim();
      else if (finding.fix) finding.fix += ` ${text}`;
      else finding.message.push(text);
      continue;
    }
    if (line.startsWith('summary:')) {
      report.summary = line.slice('summary:'.length).trim();
      finding = null;
      continue;
    }
    const keyed = KEYED.exec(line);
    if (keyed && !seenGroup) {
      report.header.push({ key: keyed[1], value: keyed[2] });
      continue;
    }
    if (seenGroup) report.footer.push(line.trim());
    else report.header.push({ key: '', value: line.trim() });
  }
  if (!report.groups.some((g) => g.findings.length > 0)) throw new Error('unexpected report shape: no findings');
  return report;
}

/**
 * A short report for a small panel: only the header rows named in `keys`, and
 * the shortest finding of each level in `levels` that has text to read, flattened into one group. The summary line is the real one.
 * @param {Report} report
 * @param {{ keys: string[], levels: string[] }} options
 * @returns {Report}
 */
export function compact(report, { keys, levels }) {
  const all = report.groups.flatMap((g) => g.findings);
  const picked = levels.flatMap((level) => {
    const ofLevel = all.filter((f) => f.level === level);
    const size = (f) => f.title.length + f.message.join(' ').length + f.fix.length + f.target.length;
    const readable = ofLevel.filter((f) => f.message.length > 0 && (f.fix || level === 'unknown'));
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
