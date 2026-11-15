// WCAG contrast of the theme's text and background pairs, computed from the
// oklch() literals in src/styles/tokens.css for both themes. Body text needs
// 4.5:1 (AA); the dim coverage cells and focus ring are non text UI and need 3:1.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const css = readFileSync(new URL('../src/styles/tokens.css', import.meta.url), 'utf8');

function block(selectorStart) {
  const i = css.indexOf(selectorStart);
  assert.ok(i >= 0, `no block starting with ${selectorStart}`);
  return css.slice(css.indexOf('{', i) + 1, css.indexOf('\n}', i));
}

function tokens(text) {
  const out = {};
  for (const m of text.matchAll(/--(sw-[a-z0-9-]+):\s*oklch\(([\d.]+)%\s+([\d.]+)\s+([\d.]+)\)/g)) out[m[1]] = [Number(m[2]) / 100, Number(m[3]), Number(m[4])];
  return out;
}

const dark = tokens(block(':root,\n::backdrop {'));
const light = { ...dark, ...tokens(block(":root[data-theme='light'],\n")) };

/** oklch -> linear sRGB -> relative luminance. */
export function luminance([L, C, h]) {
  const a = C * Math.cos((h * Math.PI) / 180);
  const b = C * Math.sin((h * Math.PI) / 180);
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const clamp = (v) => Math.min(1, Math.max(0, v));
  const r = clamp(4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s);
  const g = clamp(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s);
  const bl = clamp(-0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s);
  return 0.2126 * r + 0.7152 * g + 0.0722 * bl;
}

export function contrast(x, y) {
  const [hi, lo] = [luminance(x), luminance(y)].sort((p, q) => q - p);
  return (hi + 0.05) / (lo + 0.05);
}

const TEXT = [
  ['ink', 'bg'], ['ink', 'bg-2'], ['ink', 'bg-3'],
  ['ink-2', 'bg'], ['ink-2', 'bg-2'], ['ink-2', 'bg-3'],
  ['ink-3', 'bg'], ['ink-3', 'bg-2'], ['ink-3', 'bg-3'],
  ['mint-ink', 'bg'], ['mint-ink', 'bg-2'], ['mint-ink', 'mint-wash'],
  ['on-mint', 'mint'],
  ['fail', 'bg'], ['fail', 'fail-wash'], ['warn', 'bg'], ['warn', 'warn-wash'],
  ['pass', 'bg'], ['pass', 'pass-wash'], ['unknown', 'bg'], ['unknown', 'unknown-wash'],
  ['ink-2', 'pass-wash'], ['ink-2', 'warn-wash'], ['ink-2', 'fail-wash'],
  ['term-ink', 'term-bg'], ['term-dim', 'term-bg'], ['term-fail', 'term-bg'], ['term-warn', 'term-bg'], ['term-pass', 'term-bg'], ['term-unknown', 'term-bg'],
];
const UI = [['dim', 'bg'], ['focus', 'bg'], ['focus', 'bg-2'], ['mint-ink', 'bg']];

for (const [name, theme] of [['dark', dark], ['light', light]]) {
  test(`${name} theme text pairs reach 4.5:1`, () => {
    for (const [fg, bg] of TEXT) {
      assert.ok(theme[`sw-${fg}`] && theme[`sw-${bg}`], `${name}: missing --sw-${fg} or --sw-${bg}`);
      const ratio = contrast(theme[`sw-${fg}`], theme[`sw-${bg}`]);
      assert.ok(ratio >= 4.5, `${name}: --sw-${fg} on --sw-${bg} is ${ratio.toFixed(2)}:1`);
    }
  });
  test(`${name} theme UI pairs reach 3:1`, () => {
    for (const [fg, bg] of UI) {
      const ratio = contrast(theme[`sw-${fg}`], theme[`sw-${bg}`]);
      assert.ok(ratio >= 3 - 0.05, `${name}: --sw-${fg} on --sw-${bg} is ${ratio.toFixed(2)}:1`);
    }
  });
}
