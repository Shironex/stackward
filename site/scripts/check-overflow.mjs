// Browser check: no terminal panel, code block or page scrolls sideways from
// phone to wide desktop widths, in both themes. Needs a build (pnpm build) and
// a Chromium that playwright-core can launch:
//
//   pnpm check:overflow                # checks the pages in PAGES
//   SCREENSHOTS=/some/dir pnpm check:overflow   # also writes PNGs of the hero
//   CHROMIUM=/path/to/chrome-headless-shell pnpm check:overflow
//
// It serves dist/ itself and never captures the screen: headless pages only.
import { createServer } from 'node:http';
import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

import { BASE } from '../src/lib/site.mjs';

const DIST = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
export const WIDTHS = [390, 768, 1280, 1440, 1920];
export const PAGES = ['', 'usage/', 'install/', 'learn/ssh/', 'learn/docker-socket/', 'learn/firewall-and-docker/', 'checks/net-002/'];
const TYPES = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.json': 'application/json' };

function serve() {
  const server = createServer((req, res) => {
    let path = decodeURIComponent((req.url ?? '/').split('?')[0]);
    if (!path.startsWith(`${BASE}/`)) path = `${BASE}/`;
    let file = join(DIST, path.slice(BASE.length));
    if (existsSync(file) && statSync(file).isDirectory()) file = join(file, 'index.html');
    if (!existsSync(file)) {
      res.writeHead(404).end('not found');
      return;
    }
    res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' }).end(readFileSync(file));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

/** Runs in the page: every element that scrolls sideways, plus the page itself. */
function findOverflow() {
  const bad = [];
  for (const el of document.querySelectorAll('.terminal, .t-screen, pre, .expressive-code .frame, .t-body')) {
    if (el.scrollWidth > el.clientWidth + 0.5) bad.push(`${el.tagName.toLowerCase()}.${String(el.className).split(' ')[0]} ${el.scrollWidth}>${el.clientWidth}`);
  }
  const doc = document.documentElement;
  if (doc.scrollWidth > doc.clientWidth + 0.5) bad.push(`page ${doc.scrollWidth}>${doc.clientWidth}`);
  return bad;
}

async function main() {
  const server = await serve();
  const origin = `http://127.0.0.1:${server.address().port}${BASE}/`;
  const shots = process.env.SCREENSHOTS;
  if (shots) mkdirSync(shots, { recursive: true });
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
  const failures = [];
  let runs = 0;
  try {
    for (const scheme of ['dark', 'light']) {
      for (const width of WIDTHS) {
        const context = await browser.newContext({ viewport: { width, height: 900 }, colorScheme: scheme });
        const page = await context.newPage();
        for (const path of PAGES) {
          await page.goto(origin + path, { waitUntil: 'load' });
          await page.evaluate(() => document.fonts.ready);
          const bad = await page.evaluate(findOverflow);
          runs += 1;
          for (const b of bad) failures.push(`${scheme} ${width}px /${path}: ${b}`);
          if (shots && (path === '' || path === 'usage/')) {
            const name = `${path === '' ? 'home' : 'usage'}-${scheme}-${width}`;
            if (path === '') await page.screenshot({ path: join(shots, `${name}.png`) });
            await page.locator('.terminal').first().screenshot({ path: join(shots, `${name}-terminal.png`) });
          }
        }
        await context.close();
      }
    }
  } finally {
    await browser.close();
    server.close();
  }
  if (failures.length > 0) {
    console.error(`overflow: ${failures.length} problem(s)\n${failures.join('\n')}`);
    process.exit(1);
  }
  console.log(`overflow: ${runs} page views, no sideways scrolling`);
}

main();
