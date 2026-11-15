// Cross platform runner for the Astro CLI: sets ASTRO_TELEMETRY_DISABLED in
// the environment (an inline `VAR=1 cmd` does not work in Windows shells),
// syncs generated pages first, and checks the emitted site after a build.
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const command = process.argv[2];
if (!['dev', 'build', 'preview'].includes(command)) {
  console.error('usage: node scripts/run.mjs dev|build|preview [astro args]');
  process.exit(2);
}

const env = { ...process.env, ASTRO_TELEMETRY_DISABLED: '1' };
function step(file, args) {
  const result = spawnSync(process.execPath, [file, ...args], { cwd: root, env, stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const astroBin = join(root, 'node_modules', 'astro', 'bin', 'astro.mjs');
if (command !== 'preview') step(join(here, 'sync.mjs'), []);
step(astroBin, [command, ...process.argv.slice(3)]);
if (command === 'build') step(join(here, 'check-build.mjs'), []);
