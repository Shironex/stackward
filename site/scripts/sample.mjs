// Regenerates src/samples/audit-showcase.txt, the report shown on the home
// page and the usage page, from the current code:
//
//   pnpm sample
//
// It builds the stackward binary, runs `audit` over the saved facts of the
// showcase-coolify-tunnel fixture and keeps an excerpt: the header, the groups
// worth reading and the real summary line. Everything kept is the binary's own
// output; only whole groups are left out, and the page caption says so.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SITE_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO_DIR = join(SITE_DIR, '..');
export const FIXTURE = 'test/fixtures/showcase-coolify-tunnel/facts.json';
export const OUT = join(SITE_DIR, 'src', 'samples', 'audit-showcase.txt');
/** Groups kept in the excerpt, in report order. */
export const KEEP_GROUPS = ['NET', 'DKR', 'SEC', 'PAAS'];

/**
 * Keep the header lines, the listed groups and the footer of a text report.
 * The build version is shortened to `dev` so the sample does not go stale.
 */
export function excerpt(report, keep = KEEP_GROUPS) {
  const lines = report.trimEnd().split('\n');
  const first = lines.findIndex((l) => /^[A-Z]{2,4}\s\s/.test(l));
  const summary = lines.findIndex((l) => l.startsWith('summary:'));
  if (first === -1 || summary === -1) throw new Error('unexpected report shape: no group or summary line');
  const header = lines.slice(0, first).map((l, i) => (i === 0 ? l.replace(/^stackward \S+/, 'stackward dev') : l));
  const body = [];
  let shown = false;
  for (const line of lines.slice(first, summary)) {
    const group = /^([A-Z]{2,4})\s\s/.exec(line);
    if (group) shown = keep.includes(group[1]);
    if (shown) body.push(line);
  }
  while (body.length > 0 && body.at(-1) === '') body.pop();
  return [...header, ...body, '', ...lines.slice(summary), ''].join('\n');
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: REPO_DIR, encoding: 'utf8', ...options });
  if (result.error) throw result.error;
  return result;
}

function main() {
  const dir = mkdtempSync(join(tmpdir(), 'stackward-sample-'));
  try {
    const binary = join(dir, process.platform === 'win32' ? 'stackward.exe' : 'stackward');
    const build = run('go', ['build', '-o', binary, './cmd/stackward'], { env: { ...process.env, CGO_ENABLED: '0' } });
    if (build.status !== 0) throw new Error(`go build failed:\n${build.stderr}`);
    // Exit code 1 only means the fixture has findings.
    const audit = run(binary, ['audit', '--facts', FIXTURE, '--no-sandbox']);
    if (audit.status !== 0 && audit.status !== 1) throw new Error(`audit failed (${audit.status}):\n${audit.stderr}`);
    writeFileSync(OUT, excerpt(audit.stdout));
    console.log(`sample: wrote ${OUT}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main();
