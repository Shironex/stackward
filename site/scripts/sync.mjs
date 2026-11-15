// Writes the generated parts of the site from the repo, before Astro runs:
//
// 1. src/generated/catalog.json from internal/catalog/data/*.json, with group
//    names and order read from internal/catalog/catalog.go. Components read it.
// 2. One page per check under src/content/docs/checks/, so a check added by
//    any slice appears on the site with no edit here.
// 3. The project docs (docs/install.md, threat-model.md, safety.md,
//    architecture.md) copied in with their links rewritten, so the site
//    renders them instead of keeping a second copy of their text.
//
// Every output path is gitignored. Missing inputs never fail the sync: an
// empty catalog renders an empty reference, a missing doc renders a short
// "not written yet" page.
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, posix } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { BASE, REPO_BLOB, url } from '../src/lib/site.mjs';
import { topicsForCheck } from '../src/lib/learn.mjs';

const SITE_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO_DIR = join(SITE_DIR, '..');
const CONTENT = join(SITE_DIR, 'src', 'content', 'docs');

/** Synced project docs: source under docs/, page under src/content/docs/. */
export const DOC_PAGES = [
  { source: 'install.md', page: 'install.md', route: 'install', sidebar: 'Install and verify' },
  { source: 'threat-model.md', page: 'project/threat-model.md', route: 'project/threat-model', sidebar: 'Threat model' },
  { source: 'safety.md', page: 'project/safety.md', route: 'project/safety', sidebar: 'Safety design' },
  { source: 'architecture.md', page: 'contributing/architecture.md', route: 'contributing/architecture', sidebar: 'Architecture' },
];

export const SEVERITY_ORDER = ['critical', 'high', 'moderate', 'low', 'info'];

/** Group ids and names in report order, parsed from catalog.Groups. */
export function parseGroups(goSource) {
  const block = /var Groups = \[\]Group\{([\s\S]*?)\n\}/.exec(goSource);
  if (!block) return [];
  return [...block[1].matchAll(/\{"([A-Z]{2,4})",\s*"([^"]+)"\}/g)].map(([, id, name]) => ({ id, name }));
}

/** Load every catalog entry, grouped in report order. */
export function loadCatalog(repoDir = REPO_DIR) {
  const goFile = join(repoDir, 'internal', 'catalog', 'catalog.go');
  const groups = existsSync(goFile) ? parseGroups(readFileSync(goFile, 'utf8')) : [];
  const dataDir = join(repoDir, 'internal', 'catalog', 'data');
  const files = existsSync(dataDir) ? readdirSync(dataDir).filter((f) => f.endsWith('.json')).sort() : [];
  const checks = [];
  for (const file of files) {
    const data = JSON.parse(readFileSync(join(dataDir, file), 'utf8'));
    if (!groups.some((g) => g.id === data.group)) groups.push({ id: data.group, name: data.group });
    for (const entry of data.checks ?? []) {
      checks.push({
        id: entry.id,
        group: data.group,
        title: entry.title,
        severity: entry.severity,
        rationale: entry.rationale,
        verify: entry.verify ?? '',
        fix: entry.fix,
        breaks: entry.breaks ?? '',
        docs: entry.docs ?? '',
        needsRoot: entry.needs_root === true,
      });
    }
  }
  const rank = (id) => groups.findIndex((g) => g.id === id);
  checks.sort((a, b) => rank(a.group) - rank(b.group) || a.id.localeCompare(b.id));
  return {
    count: checks.length,
    groups: groups.map((g) => ({ ...g, checks: checks.filter((c) => c.group === g.id).map((c) => c.id) })),
    checks,
  };
}

export function checkRoute(id) {
  return `checks/${id.toLowerCase()}`;
}

/** Escape catalog prose for Markdown: it is plain text, never markup. */
export function escapeMarkdown(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/([\\`*_[\]{}|#])/g, '\\$1');
}

/**
 * Catalog prose as Markdown. Inline code spans pass through untouched so they
 * render literally (typographic punctuation never reaches them). Outside code,
 * the text is escaped, check ids become links (or code when not in the
 * catalog), and command flags such as --token are wrapped in code so the
 * Markdown renderer cannot turn their double hyphen into a dash.
 */
export function proseWithIds(text, known) {
  const plain = (chunk) =>
    escapeMarkdown(chunk)
      .replace(/\b([A-Z]{2,4}-\d{3})\b/g, (id) => (known.has(id) ? `[${id}](${url(checkRoute(id))})` : `\`${id}\``))
      .replace(/(?<![\w-])(--[a-z][\w-]*)/g, '`$1`');
  return String(text)
    .split(/(`[^`\n]+`)/)
    .map((part, i) => (i % 2 === 1 ? part : plain(part)))
    .join('');
}

function yamlString(value) {
  return JSON.stringify(String(value));
}

function escapeHtml(text) {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** The Markdown page for one check. */
export function checkPage(entry, groupName, known, order) {
  const topics = topicsForCheck(entry.id);
  const facts = [
    `<dl class="check-facts not-content" data-check="${entry.id}">`,
    `<div><dt>Check id</dt><dd><code class="check-id">${entry.id}</code></dd></div>`,
    `<div><dt>Group</dt><dd>${escapeHtml(groupName)}${groupName === entry.group ? '' : ` <span class="muted">(${entry.group})</span>`}</dd></div>`,
    `<div><dt>Severity when it fails</dt><dd><span class="sev sev-${entry.severity}">${entry.severity}</span></dd></div>`,
    `<div><dt>Root</dt><dd>${entry.needsRoot ? 'needed for a full result' : 'not needed'}</dd></div>`,
    `</dl>`,
  ].join('\n');
  const lines = [
    '---',
    `title: ${yamlString(`${entry.id}: ${entry.title}`)}`,
    `description: ${yamlString(entry.rationale.split(/(?<=\.)\s/)[0])}`,
    `sidebar:`,
    `  label: ${yamlString(entry.id)}`,
    `  order: ${order}`,
    `editUrl: ${yamlString(`${REPO_BLOB.replace('/blob/', '/edit/')}/internal/catalog/data/${entry.group.toLowerCase()}.json`)}`,
    '---',
    '',
    `<!-- Generated by site/scripts/sync.mjs from internal/catalog/data/${entry.group.toLowerCase()}.json. Do not edit. -->`,
    '',
    facts,
    '',
    '## Why it matters',
    '',
    proseWithIds(entry.rationale, known),
    '',
  ];
  if (entry.verify) {
    lines.push('## Verify by hand', '', 'These commands only read. Run them on the server itself.', '', '```sh', entry.verify.replace(/;\s+/g, '\n'), '```', '');
  }
  lines.push('## How to fix it', '', proseWithIds(entry.fix, known), '');
  if (entry.breaks) lines.push('## What a fix can break', '', proseWithIds(entry.breaks, known), '');
  if (topics.length > 0) {
    lines.push('## Learn more', '', ...topics.map((t) => `- [${escapeMarkdown(t.title)}](${url(`learn/${t.slug}`)}): ${escapeMarkdown(t.summary)}`), '');
  }
  if (entry.docs) lines.push(`Further reading: <${entry.docs}>`, '');
  lines.push(`Run \`stackward explain ${entry.id}\` to read this in your terminal.`, '');
  return lines.join('\n');
}

/**
 * Rewrite the links of a doc under docs/: other synced docs and check pages
 * become site routes under BASE, anything else in the repo becomes a GitHub
 * link. Fenced code is left alone.
 */
export function rewriteDocLinks(markdown, known) {
  const routes = new Map(DOC_PAGES.map((d) => [`docs/${d.source}`, d.route]));
  let inFence = false;
  return markdown
    .split('\n')
    .map((line) => {
      if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;
      if (inFence) return line;
      return line.replace(/\]\(([^)\s]+)\)/g, (whole, target) => {
        if (/^(?:[a-z]+:|#|\/)/i.test(target)) return whole;
        const [path, hash = ''] = target.split('#');
        const resolved = posix.normalize(posix.join('docs', path));
        const anchor = hash ? `#${hash}` : '';
        if (routes.has(resolved)) return `](${url(routes.get(resolved))}${anchor})`;
        const check = /^docs\/checks\/([A-Z]{2,4}-\d{3})\.md$/.exec(resolved);
        if (check) return `](${known.has(check[1]) ? url(checkRoute(check[1])) : url('checks')}${anchor})`;
        if (resolved === 'docs/checks/index.md' || resolved === 'docs/checks') return `](${url('checks')}${anchor})`;
        return `](${REPO_BLOB}/${resolved}${anchor})`;
      });
    })
    .join('\n');
}

/** A synced doc page: the H1 becomes the title, links are rewritten. */
export function docPage(doc, source, known) {
  const editUrl = `${REPO_BLOB.replace('/blob/', '/edit/')}/docs/${doc.source}`;
  if (source === null) {
    return [
      '---',
      `title: ${yamlString(doc.sidebar)}`,
      `editUrl: ${yamlString(editUrl)}`,
      '---',
      '',
      `This page is rendered from \`docs/${doc.source}\` in the repository, which has not been written yet.`,
      '',
    ].join('\n');
  }
  const h1 = /^#\s+(.+)$/m.exec(source);
  const title = h1 ? h1[1].trim() : doc.sidebar;
  const body = h1 ? source.replace(h1[0], '').replace(/^\s+/, '') : source;
  const firstPara = body.split(/\n\s*\n/).find((p) => p.trim() && !p.startsWith('<!--') && !p.startsWith('#') && !p.startsWith('|'));
  const description = firstPara ? firstPara.replace(/\s+/g, ' ').replace(/[`*[\]]/g, '').replace(/\(([^)]*)\)/g, '').trim().split(/(?<=\.)\s/)[0] : title;
  return [
    '---',
    `title: ${yamlString(title)}`,
    `description: ${yamlString(description)}`,
    `editUrl: ${yamlString(editUrl)}`,
    '---',
    '',
    `<!-- Generated by site/scripts/sync.mjs from docs/${doc.source}. Edit that file, not this one. -->`,
    '',
    rewriteDocLinks(body, known),
  ].join('\n');
}

function write(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
}

export function sync() {
  const catalog = loadCatalog();
  const known = new Set(catalog.checks.map((c) => c.id));
  const groupName = (id) => catalog.groups.find((g) => g.id === id)?.name ?? id;

  write(join(SITE_DIR, 'src', 'generated', 'catalog.json'), `${JSON.stringify(catalog, null, 2)}\n`);

  const checksDir = join(CONTENT, 'checks');
  rmSync(checksDir, { recursive: true, force: true });
  catalog.checks.forEach((entry, i) => {
    write(join(checksDir, `${entry.id.toLowerCase()}.md`), checkPage(entry, groupName(entry.group), known, i + 1));
  });

  for (const doc of DOC_PAGES) {
    const sourcePath = join(REPO_DIR, 'docs', doc.source);
    const source = existsSync(sourcePath) ? readFileSync(sourcePath, 'utf8') : null;
    write(join(CONTENT, doc.page), docPage(doc, source, known));
  }

  console.log(`sync: ${catalog.count} checks in ${catalog.groups.filter((g) => g.checks.length).length} groups, ${DOC_PAGES.length} docs pages (base ${BASE})`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) sync();
