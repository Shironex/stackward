import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';

import { compact, fromReport, namesSubject, sandboxLine, shortSubject } from '../src/lib/report.mjs';

const result = (level, id, title, severity, subject, message, hint = '') => ({
  id, group: id.split('-')[0], title, level, severity, subject, message, fix: { hint },
});

const DOC = {
  schema: 'stackward.report.v1',
  tool: { name: 'stackward', version: 'dev' },
  generated_at: '2026-03-01T12:00:00Z',
  host: { hostname_hash: 'sha256:abc', os: 'Ubuntu 24.04.1 LTS', kernel: '6.8.0' },
  profile: { name: 'tunnel', source: 'inferred' },
  coverage: { checks: 4, results: 6, checked: 5, unknown: 1, skipped: 0, root: true, sandbox: { state: 'landlock', abi: 4, network: true }, collectors: [] },
  summary: { fail: 1, warn: 2, unknown: 1, info: 1, pass: 1, skip: 0 },
  results: [
    result('warn', 'NET-004', 'Exposure', 'moderate', 'port:tcp/8000', 'tcp/8000 is published on wildcard', 'Bind it to 127.0.0.1.'),
    result('fail', 'NET-002', 'IPv6 is filtered', 'high', 'host', 'UFW has IPV6=no', 'Set IPV6=yes, then ufw reload'),
    result('unknown', 'NET-003', 'SSH private path', 'high', 'host', 'Tailscale facts are missing'),
    result('warn', 'DKR-034', 'Engine is supported', 'critical', 'host', 'Engine 27 is out of support', 'Upgrade it.'),
    result('info', 'TS-005', 'Tailnet Lock state', 'info', 'host', 'Tailnet Lock is off'),
    result('pass', 'SYS-001', 'Tested release', 'low', 'host', 'ubuntu 24.04 is tested'),
  ],
};

test('a report.v1 document becomes header, levels, findings and summary', () => {
  const r = fromReport(DOC);
  assert.equal(r.title, 'stackward audit dev (stackward.report.v1)');
  assert.deepEqual(r.header.map((h) => h.key), ['host', 'os', 'kernel', 'collected', 'profile', 'root', 'sandbox', 'coverage']);
  assert.equal(r.header.find((h) => h.key === 'sandbox').value, 'landlock (abi 4, no writes, no tcp)');
  assert.equal(r.header.find((h) => h.key === 'coverage').value, '4 checks, 6 results: 5 checked, 1 unknown, 0 skipped');
  assert.deepEqual(r.groups.map((g) => [g.id, g.note]), [['FAIL', '1'], ['WARN', '2'], ['UNKNOWN', '1'], ['INFO', '1']]);
  const [fail] = r.groups[0].findings;
  assert.deepEqual(fail, { level: 'fail', id: 'NET-002', target: '', headline: 'UFW has IPV6=no', rule: 'IPv6 is filtered', severity: 'high', fix: 'Set IPV6=yes, then ufw reload' });
  // Most severe first within a level; a message that names its subject drops it.
  assert.deepEqual(r.groups[1].findings.map((f) => [f.id, f.target]), [['DKR-034', ''], ['NET-004', '']]);
  const [info] = r.groups[3].findings;
  assert.deepEqual([info.severity, info.rule, info.fix], ['', '', '']);
  assert.equal(r.summary, '1 fail, 2 warn, 1 unknown, 1 info, 1 pass, 0 skip');
});

test('helpers match the text report', () => {
  assert.equal(shortSubject('container:app/web'), 'app/web');
  assert.equal(shortSubject('host'), '');
  assert.ok(namesSubject('socket-proxy: mounts it', 'socket-proxy'));
  assert.ok(!namesSubject('socket-proxy-2 mounts it', 'socket-proxy'));
  assert.equal(sandboxLine({ state: 'disabled', reason: 'turned off with --no-sandbox' }), 'disabled (turned off with --no-sandbox)');
  assert.equal(sandboxLine({}), '-');
});

test('a document without results to show is an error', () => {
  assert.throws(() => fromReport({}));
  assert.throws(() => fromReport({ ...DOC, results: [DOC.results[5]] }));
});

test('compact keeps the named header rows and one finding per level, the shortest first', () => {
  const r = compact(fromReport(DOC), { keys: ['host', 'coverage'], levels: ['fail', 'warn', 'unknown'] });
  assert.deepEqual(r.header.map((h) => h.key), ['host', 'coverage']);
  assert.deepEqual(r.groups[0].findings.map((f) => f.id), ['NET-002', 'DKR-034', 'NET-003']);
  assert.equal(r.summary, '1 fail, 2 warn, 1 unknown, 1 info, 1 pass, 0 skip');
});

test('the committed sample loads and has a fail, a warn and an unknown to show', () => {
  const r = fromReport(JSON.parse(readFileSync(new URL('../src/samples/audit-showcase.json', import.meta.url), 'utf8')));
  const levels = new Set(r.groups.flatMap((g) => g.findings.map((f) => f.level)));
  for (const level of ['fail', 'warn', 'unknown']) assert.ok(levels.has(level), level);
  assert.ok(r.summary.length > 0);
});
