import assert from 'node:assert/strict';
import { test } from 'node:test';

import { escapeMarkdown, parseGroups, proseWithIds, rewriteDocLinks } from './sync.mjs';
import { excerpt } from './sample.mjs';
import { allowedIPv4, startTags } from './check-build.mjs';

test('parseGroups reads catalog.Groups in order', () => {
  const go = 'var Groups = []Group{\n\t{"SYS", "System"},\n\t{"SSH", "SSH"},\n\t{"PAAS", "Coolify and Dokploy"},\n}\n';
  assert.deepEqual(parseGroups(go), [
    { id: 'SYS', name: 'System' },
    { id: 'SSH', name: 'SSH' },
    { id: 'PAAS', name: 'Coolify and Dokploy' },
  ]);
});

test('catalog prose is escaped, and ids link only when they exist', () => {
  assert.equal(escapeMarkdown('a <b> *c* [d]'), 'a &lt;b&gt; \\*c\\* \\[d\\]');
  const known = new Set(['SYS-002']);
  assert.equal(proseWithIds('see SYS-002 and UPD-004', known), 'see [SYS-002](/stackward/checks/sys-002/) and `UPD-004`');
});

test('flags and code spans in catalog prose survive typography', () => {
  const known = new Set(['CF-001']);
  const text = 'Run `grep -c -- --token` or pass --now; CF-001 and --i-own-this use a <host> a - b, not a dash.';
  const out = proseWithIds(text, known);
  assert.ok(out.includes('`grep -c -- --token`'), out);
  assert.ok(out.includes('pass `--now`;'), out);
  assert.ok(out.includes('`--i-own-this`'), out);
  assert.ok(out.includes('[CF-001](/stackward/checks/cf-001/)'), out);
  assert.ok(out.includes('&lt;host&gt;'), out);
  assert.ok(!/[\u2013\u2014]/.test(out));
});

test('doc links become site routes or GitHub links, fences untouched', () => {
  const known = new Set(['SYS-001']);
  const md = [
    'See [safety](safety.md#apply-rules), [checks](checks/index.md), [one](checks/SYS-001.md),',
    '[missing](checks/NET-001.md), [schema](../schema/report.v1.json) and [web](https://example.com/).',
    '```',
    '[keep](safety.md)',
    '```',
  ].join('\n');
  const out = rewriteDocLinks(md, known);
  assert.match(out, /\]\(\/stackward\/project\/safety\/#apply-rules\)/);
  assert.match(out, /\[checks\]\(\/stackward\/checks\/\)/);
  assert.match(out, /\[one\]\(\/stackward\/checks\/sys-001\/\)/);
  assert.match(out, /\[missing\]\(\/stackward\/checks\/\)/);
  assert.match(out, /\]\(https:\/\/github\.com\/Shironex\/stackward\/blob\/main\/schema\/report\.v1\.json\)/);
  assert.match(out, /\[web\]\(https:\/\/example\.com\/\)/);
  assert.match(out, /\n\[keep\]\(safety\.md\)\n/);
});

test('the link checker reads real tags, not text that looks like one', () => {
  const html = '<p>use &lt;img src="x.webp"&gt;</p><a href="/stackward/a/">a</a><script>const s = "<a href=\'/nope/\'>";</script><img src="/stackward/b.png">';
  const links = startTags(html).flatMap((t) => [t.attrs.href, t.attrs.src]).filter(Boolean);
  assert.deepEqual(links, ['/stackward/a/', '/stackward/b.png']);
});

test('only documentation, private and tailnet IPv4 ranges are allowed', () => {
  for (const ok of ['192.0.2.10', '198.51.100.20', '203.0.113.7', '100.64.0.10', '10.0.0.0', '172.16.0.0', '192.168.1.1', '127.0.0.1', '1.2.3.400']) assert.ok(allowedIPv4(ok), ok);
  for (const bad of ['8.8.8.8', '1.1.1.1', '198.51.99.1', '203.0.114.9']) assert.ok(!allowedIPv4(bad), bad);
});

test('the sample excerpt keeps the header, chosen groups and summary only', () => {
  const report = [
    'stackward v0.0.0-2026+dirty audit (stackward.report.v1)',
    'host:      sha256:abc',
    '',
    'SYS  System  (4 passing or skipped not shown)',
    '  WARN    SYS-003  Kernel [moderate]',
    '',
    'NET  Firewall and exposure',
    '  FAIL    NET-002  IPv6 [high]',
    '',
    'summary: 1 fail, 1 warn',
    'explain any check with: stackward explain <id>',
  ].join('\n');
  const out = excerpt(report, ['NET']);
  assert.ok(out.startsWith('stackward dev audit (stackward.report.v1)\n'));
  assert.ok(out.includes('NET-002') && !out.includes('SYS-003'));
  assert.ok(out.includes('summary: 1 fail, 1 warn'));
  assert.throws(() => excerpt('nothing here'));
});
