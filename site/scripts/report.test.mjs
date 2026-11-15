import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';

import { compact, parseReport } from '../src/lib/report.mjs';

const REPORT = [
  'stackward dev audit (stackward.report.v1)',
  'host:      sha256:abc',
  'profile:   tunnel (inferred)',
  'coverage:  10 checked, 2 unknown',
  '',
  'NET  Firewall and exposure  (3 passing or skipped not shown)',
  '  FAIL    NET-002  IPv6 is filtered [high]',
  '          UFW has IPV6=no while the host has a global address',
  '          so traffic is not filtered',
  '          fix: Set IPV6=yes, then ufw reload',
  '  WARN    NET-004 port:tcp/8000  Exposure [moderate]',
  '          published on wildcard',
  '  UNKNOWN NET-003  SSH private path [high]',
  '          Tailscale facts are missing',
  '',
  'DKR  Docker',
  '  WARN    DKR-034  Engine is supported [moderate]',
  '          Engine 27 is out of support',
  '          fix: Upgrade it.',
  '',
  'summary: 1 fail, 2 warn',
  'explain any check with: stackward explain <id>',
].join('\n');

test('a text report parses into header, groups, findings and summary', () => {
  const r = parseReport(REPORT);
  assert.equal(r.title, 'stackward dev audit (stackward.report.v1)');
  assert.deepEqual(r.header.map((h) => h.key), ['host', 'profile', 'coverage']);
  assert.deepEqual(r.groups.map((g) => [g.id, g.name, g.note]), [['NET', 'Firewall and exposure', '3 passing or skipped not shown'], ['DKR', 'Docker', '']]);
  const [fail, warn, unknown] = r.groups[0].findings;
  assert.deepEqual([fail.level, fail.id, fail.severity, fail.fix], ['fail', 'NET-002', 'high', 'Set IPV6=yes, then ufw reload']);
  assert.equal(fail.message.length, 2);
  assert.deepEqual([warn.id, warn.target, warn.title], ['NET-004', 'port:tcp/8000', 'Exposure']);
  assert.deepEqual([unknown.level, unknown.fix], ['unknown', '']);
  assert.equal(r.summary, '1 fail, 2 warn');
  assert.deepEqual(r.footer, ['explain any check with: stackward explain <id>']);
});

test('a changed header or coverage format still parses, and nothing is dropped', () => {
  const changed = REPORT.replace('coverage:  10 checked, 2 unknown', 'coverage:  10 checked (2 unknown, 0 skipped of 12 checks)\nextra:     a new header row');
  const r = parseReport(changed);
  assert.equal(r.header.find((h) => h.key === 'coverage').value, '10 checked (2 unknown, 0 skipped of 12 checks)');
  assert.equal(r.header.find((h) => h.key === 'extra').value, 'a new header row');
  assert.equal(r.groups.flatMap((g) => g.findings).length, 4);
});

test('a finding without a severity tag or a message still parses', () => {
  const r = parseReport('stackward dev audit\nhost: x\n\nSYS  System\n  PASS    SYS-001  Kernel is current\n\nsummary: 1 pass');
  assert.deepEqual(r.groups[0].findings[0], { level: 'pass', id: 'SYS-001', target: '', title: 'Kernel is current', severity: '', message: [], fix: '' });
});

test('a report with no findings is an error', () => {
  assert.throws(() => parseReport('nothing here'));
});

test('compact keeps the named header rows and one finding per level, the shortest first', () => {
  const r = compact(parseReport(REPORT), { keys: ['host', 'coverage'], levels: ['fail', 'warn', 'unknown', 'info'] });
  assert.deepEqual(r.header.map((h) => h.key), ['host', 'coverage']);
  assert.deepEqual(r.groups[0].findings.map((f) => f.id), ['NET-002', 'DKR-034', 'NET-003']);
  assert.equal(r.summary, '1 fail, 2 warn');
});

test('the committed sample parses and has a fail, a warn and an unknown to show', () => {
  const r = parseReport(readFileSync(new URL('../src/samples/audit-showcase.txt', import.meta.url), 'utf8'));
  const levels = new Set(r.groups.flatMap((g) => g.findings.map((f) => f.level)));
  for (const level of ['fail', 'warn', 'unknown']) assert.ok(levels.has(level), level);
  assert.ok(r.summary.length > 0);
});
