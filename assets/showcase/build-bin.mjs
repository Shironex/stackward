// Builds the stackward binary the captures run, into bin/ (ignored by git).
// Same flags as a release build, with a fixed version string so the header
// line does not change with every commit.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..', '..');
const out = path.join(here, 'bin', process.platform === 'win32' ? 'stackward.exe' : 'stackward');

const res = spawnSync(
  'go',
  [
    'build',
    '-trimpath',
    '-ldflags',
    '-s -w -buildid= -X github.com/Shironex/stackward/internal/version.Version=0.1.0-dev',
    '-o',
    out,
    './cmd/stackward',
  ],
  { cwd: repo, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } },
);
if (res.error) throw res.error;
process.exit(res.status ?? 1);
