// One home for the deploy address. Project Pages for github.com/Shironex/stackward
// serve from https://shironex.github.io/stackward/, so every root relative link
// carries BASE. scripts/check-build.mjs fails the build on any link outside it.
export const SITE = 'https://shironex.github.io';
export const BASE = '/stackward';
export const REPO = 'https://github.com/Shironex/stackward';
export const REPO_BLOB = `${REPO}/blob/main`;

/** A site path under the base: url('learn/ssh') -> '/stackward/learn/ssh/'. */
export function url(path = '') {
  const clean = String(path).replace(/^\/+|\/+$/g, '');
  return clean === '' ? `${BASE}/` : `${BASE}/${clean}/`;
}
