// Regenerates src/samples/audit-showcase.json, the report shown on the home
// page and the usage page, from the current code:
//
//   pnpm sample
//
// It builds the stackward binary, runs `audit --json` over the saved facts of
// the showcase-coolify-tunnel fixture and keeps an excerpt of the report.v1
// document: every field but the passing and skipped results and the evidence.
// Everything kept is the binary's own output, and the summary counts stay
// the real ones. The site reads the JSON (the stable schema), never the text
// report, so a change to the text layout cannot break it.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SITE_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO_DIR = join(SITE_DIR, '..');
export const FIXTURE = 'test/fixtures/showcase-coolify-tunnel/facts.json';
export const OUT = join(SITE_DIR, 'src', 'samples', 'audit-showcase.json');
/** Levels kept in the excerpt; passing and skipped results only count. */
export const KEEP_LEVELS = ['fail', 'warn', 'unknown', 'info'];

/**
 * Keep a report.v1 document without its passing and skipped results and
 * without evidence. The build version is shortened to `dev` so the sample
 * does not go stale.
 */
export function excerpt(doc, keep = KEEP_LEVELS) {
  if (!doc || doc.schema !== 'stackward.report.v1' || !Array.isArray(doc.results)) {
    throw new Error('unexpected report: not a stackward.report.v1 document');
  }
  const results = doc.results.filter((r) => keep.includes(r.level)).map(({ evidence, ...r }) => r);
  return { ...doc, tool: { ...doc.tool, version: 'dev' }, results };
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
    const audit = run(binary, ['audit', '--facts', FIXTURE, '--no-sandbox', '--json']);
    if (audit.status !== 0 && audit.status !== 1) throw new Error(`audit failed (${audit.status}):\n${audit.stderr}`);
    mkdirSync(dirname(OUT), { recursive: true });
    writeFileSync(OUT, `${JSON.stringify(excerpt(JSON.parse(audit.stdout)), null, 2)}\n`);
    console.log(`sample: wrote ${OUT}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main();
