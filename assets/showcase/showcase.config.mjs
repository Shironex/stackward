// The README terminal pictures. Every image is the real stackward binary
// (built by build-bin.mjs) running in a pseudo terminal over a saved facts
// file, so two runs on one OS give the same pixels and no real host is shown.
//
//   pnpm install && pnpm exec playwright install chromium
//   pnpm run all        # build the binary, capture, frame, record
//
// To add a picture, add one entry to `shots` (or `clips`): `keys` is what is
// typed at the prompt, `waitFor` is text the finished screen shows, and
// `restart: true` starts it from a fresh prompt.
import { defineConfig } from '@noctcore/showcase-kit';
import { fileURLToPath } from 'node:url';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));

// Brand palette (assets/brand/README.md). The report colors the result marks,
// section labels and counts: red fail, yellow warn, magenta unknown, cyan
// info, green pass.
const ink = '#102b2b';
const paper = '#f3f6f1';
const mint = '#72d6bc';
const muted = '#b7cac4';
const warn = '#f3c879';
const fail = '#ff9c90';
const info = '#9cc9e3';
const dim = '#6f9a90';
const ansi = [ink, fail, mint, warn, info, muted, info, paper];

// The saved facts every picture runs on: a Coolify host behind a tunnel,
// documentation addresses and example.com only.
const fixture = here('../../test/fixtures/showcase-coolify-tunnel/');

const typed = (command) => `${command}{Enter}`;

// The audit still shows the start of the report: it runs in a terminal tall
// enough for the whole report, and crop.mjs keeps the prompt, the header,
// the summary box and the first two fails.
export const auditRows = 130;
export const auditKeepRows = 42;

// Clip steps that type a command one key per frame, then press Enter.
const typeOut = (command) => [...command].map((c) => ({ keys: c })).concat({ sleep: 300 }, { keys: '{Enter}' });

export default defineConfig({
  name: 'stackward',
  target: {
    mode: 'tty',
    command: ['node', here('./shell.mjs')],
    cwd: fixture,
    // Nothing from the environment that renders the pictures reaches them.
    inheritEnv: false,
    cols: 140,
    rows: 38,
    quitKey: false,
  },
  ready: '$',
  deviceScaleFactor: 2,
  terminal: {
    // An ink background: stackward tui asks the terminal for it and picks its
    // dark palette (it also defaults to dark when nothing answers).
    theme: { background: ink, foreground: paper, cursor: mint, ansi: [...ansi, ...ansi.map((c, i) => (i === 0 ? dim : c))] },
    font: {
      size: 15,
      file: './node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2',
      boldFile: './node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-600-normal.woff2',
      italicFile: './node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-italic.woff2',
      boldItalicFile: './node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-600-italic.woff2',
    },
    lineHeight: 1.35,
    padding: 14,
  },
  shots: [
    {
      id: 'audit',
      title: 'stackward audit',
      alt: 'A terminal showing the start of a stackward audit report for a Coolify host: the header, a summary box with 4 fail, 5 warn, 3 unknown, 17 info, 143 pass and 9 skip, the four fails most severe first and the commands to dig in, then the first two fails with their rule and fix.',
      nav: async (tty) => {
        await tty.resize(140, auditRows);
        await tty.press(typed('stackward audit --facts facts.json'));
        await tty.waitForText('explain any check with');
      },
    },
    {
      id: 'explain',
      title: 'stackward explain',
      alt: 'A terminal showing stackward explain PAAS-003: why an open platform panel port matters, how to verify it by hand, the fix, and what the fix can break.',
      restart: true,
      // explain wraps at 80 columns: a smaller terminal keeps the picture tight.
      nav: async (tty) => {
        await tty.resize(84, 25);
        await tty.press(typed('stackward explain PAAS-003'));
        await tty.waitForText('More:');
      },
    },
    {
      id: 'tui',
      title: 'stackward tui',
      alt: 'stackward tui in a terminal: the findings list grouped by check group on the left with fail, warn and unknown results first, and PAAS-003, the Coolify panel port open to the world, selected with its explanation, fix and verify steps in the pane on the right.',
      restart: true,
      nav: async (tty) => {
        await tty.resize(110, 36);
        await tty.press(typed('stackward tui --facts facts.json'));
        await tty.waitForText('FINDINGS');
        // Select PAAS-003, the panel port open to the world.
        await tty.press('jjjjjjjjjjjjjjjj');
        await tty.waitForText('PAAS-003  Coolify');
        await tty.waitForText('WHY IT MATTERS');
      },
    },
  ],
  clips: [
    {
      id: 'audit-run',
      title: 'stackward audit',
      alt: 'An animation: stackward audit runs over a saved facts file and prints its report, from the summary box to the compact info list, then stackward explain PAAS-003 prints why the open panel port matters and how to fix it.',
      steps: [
        { sleep: 600 },
        ...typeOut('stackward audit --facts facts.json'),
        { waitFor: 'explain any check with' },
        { sleep: 3500 },
        ...typeOut('stackward explain PAAS-003'),
        { waitFor: 'More:' },
      ],
      tailMs: 5000,
      durationMs: 30000,
      formats: ['webp'],
    },
  ],
  frame: {
    style: 'terminal',
    theme: 'dark',
    title: '{title}',
    background: { type: 'transparent' },
    padding: 24,
    radius: 12,
  },
  outputs: {
    raw: 'showcase-out/raw/{id}.png',
    readme: '{id}.webp',
    clips: '{id}.{ext}',
  },
});
