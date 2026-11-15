// Post-build check of dist/. A green `astro build` proves little: a wrong
// base builds fine and 404s every asset, and a dropped page builds fine too.
// This reads what was actually emitted.
//
// 1. Every internal href and src in every page (start tags only, so HTML
//    shown inside <code> is never mistaken for a link) sits under the base
//    and resolves to an emitted file, and every #fragment on a same site link
//    exists as an id on the target page.
// 2. One page per catalog entry, and one per Learn topic.
// 3. No em or en dash and no IPv4 address outside the documentation ranges
//    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), the tailnet range
//    100.64.0.0/10, private ranges and loopback appears in any page's text.
// 4. Fonts are self hosted: nothing loads Google Fonts.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadCatalog } from './sync.mjs';
import { TOPICS } from '../src/lib/learn.mjs';
import { BASE, SITE } from '../src/lib/site.mjs';

const DIST = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

/** Map a site path (`/stackward/x/`) to the emitted file, or null. */
export function emitted(pathname, dist = DIST) {
  if (!pathname.startsWith(`${BASE}/`)) return null;
  const rel = decodeURIComponent(pathname.slice(BASE.length + 1));
  const candidates = rel === '' || rel.endsWith('/') ? [join(dist, rel, 'index.html')] : [join(dist, rel), join(dist, rel, 'index.html')];
  return candidates.find((c) => existsSync(c)) ?? null;
}

/**
 * Attributes of every start tag in an HTML document. A linear scanner, not a
 * regex over the whole text: text nodes have `<` escaped as `&lt;`, so only
 * real tags are seen, and <script> and <style> bodies are skipped.
 */
export function startTags(html) {
  const tags = [];
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf('<', i);
    if (lt === -1) break;
    if (html.startsWith('<!--', lt)) {
      const end = html.indexOf('-->', lt + 4);
      i = end === -1 ? html.length : end + 3;
      continue;
    }
    const nameMatch = /^<([a-zA-Z][a-zA-Z0-9-]*)/.exec(html.slice(lt, lt + 40));
    if (!nameMatch) {
      i = lt + 1;
      continue;
    }
    const name = nameMatch[1].toLowerCase();
    let j = lt + nameMatch[0].length;
    const attrs = {};
    while (j < html.length && html[j] !== '>') {
      const rest = /^\s*([^\s=>/"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+)))?/.exec(html.slice(j, j + 4096));
      if (!rest || rest[0].length === 0) {
        j++;
        continue;
      }
      attrs[rest[1].toLowerCase()] = rest[2] ?? rest[3] ?? rest[4] ?? '';
      j += rest[0].length;
    }
    tags.push({ name, attrs });
    i = j + 1;
    if (name === 'script' || name === 'style') {
      const close = html.toLowerCase().indexOf(`</${name}`, i);
      i = close === -1 ? html.length : close;
    }
  }
  return tags;
}

/** Visible text of a page: tags, scripts, styles and comments removed. */
export function visibleText(html) {
  return html
    .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

/** True for addresses a public docs page may show. */
export function allowedIPv4(ip) {
  const p = ip.split('.').map(Number);
  if (p.some((n) => n > 255)) return true; // not an address (a version string)
  const [a, b, c] = p;
  return (
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 255 && b === 255)
  );
}

function main() {
  const failures = [];
  const files = walk(DIST);
  const pages = files.filter((f) => f.endsWith('.html'));
  const idsCache = new Map();
  const idsOf = (file) => {
    if (!idsCache.has(file)) {
      const ids = new Set(startTags(readFileSync(file, 'utf8')).map((t) => t.attrs.id).filter(Boolean));
      idsCache.set(file, ids);
    }
    return idsCache.get(file);
  };

  let links = 0;
  let fragments = 0;
  let external = 0;
  for (const page of pages) {
    const where = page.slice(DIST.length);
    const html = readFileSync(page, 'utf8');
    for (const tag of startTags(html)) {
      for (const attr of ['href', 'src']) {
        let target = tag.attrs[attr];
        if (!target || tag.name === 'base') continue;
        // The not-found page names a canonical /404/ route that GitHub Pages serves as 404.html.
        if (where === '/404.html' && tag.attrs.rel === 'canonical') continue;
        if (target.startsWith(SITE)) target = target.slice(SITE.length);
        if (/^(?:[a-z]+:|\/\/)/i.test(target)) {
          external++;
          continue;
        }
        if (target.startsWith('#')) {
          if (target.length > 1 && !idsOf(page).has(decodeURIComponent(target.slice(1)))) failures.push(`${where}: no element with id "${target}"`);
          continue;
        }
        if (!target.startsWith('/')) {
          failures.push(`${where}: relative ${attr} "${target}" (use a root relative path under ${BASE}/)`);
          continue;
        }
        const [path, hash] = target.split('#');
        const clean = path.split('?')[0];
        links++;
        if (!clean.startsWith(`${BASE}/`)) {
          failures.push(`${where}: "${target}" is outside the ${BASE}/ base`);
          continue;
        }
        const file = emitted(clean);
        if (!file) {
          failures.push(`${where}: "${target}" does not resolve to an emitted file`);
          continue;
        }
        if (hash && file.endsWith('.html')) {
          fragments++;
          if (!idsOf(file).has(decodeURIComponent(hash))) failures.push(`${where}: "${target}" points at a missing #${hash}`);
        }
      }
    }

    const text = visibleText(html);
    const dash = /[\u2013\u2014]/.exec(text);
    if (dash) failures.push(`${where}: contains an em or en dash near "${text.slice(Math.max(0, dash.index - 30), dash.index + 30).replace(/\s+/g, ' ')}"`);
    for (const m of text.matchAll(/(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])/g)) {
      if (!allowedIPv4(m[1])) failures.push(`${where}: address ${m[1]} is not in a documentation, private or tailnet range`);
    }
    if (/fonts\.(?:googleapis|gstatic)\.com/.test(html)) failures.push(`${where}: loads Google Fonts`);
  }

  const catalog = loadCatalog();
  for (const c of catalog.checks) {
    if (!emitted(`${BASE}/checks/${c.id.toLowerCase()}/`)) failures.push(`no page emitted for ${c.id}`);
  }
  for (const t of TOPICS) {
    if (!emitted(`${BASE}/learn/${t.slug}/`)) failures.push(`no page emitted for learn/${t.slug}`);
  }
  if (!existsSync(join(DIST, '404.html'))) failures.push('dist/404.html was not emitted');

  console.log(
    `check-build: ${pages.length} pages, ${links} internal links (${fragments} with fragments) resolved, ${external} external links skipped, ` +
      `${catalog.count} check pages, ${TOPICS.length} learn topics, text free of dashes and real addresses`,
  );
  if (failures.length > 0) {
    const unique = [...new Set(failures)];
    console.error(`check-build: ${unique.length} failure(s)\n  ${unique.slice(0, 60).join('\n  ')}`);
    process.exit(1);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
