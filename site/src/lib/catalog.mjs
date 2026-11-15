// The generated catalog (scripts/sync.mjs writes src/generated/catalog.json
// before Astro runs) and small helpers the components share.
import catalog from '../generated/catalog.json';

import { url } from './site.mjs';

export { catalog };

const byId = new Map(catalog.checks.map((c) => [c.id, c]));

/** The catalog entry for an id, or undefined when the check has not landed. */
export function lookup(id) {
  return byId.get(id);
}

export function checkUrl(id) {
  return url(`checks/${id.toLowerCase()}`);
}

export function groupName(id) {
  return catalog.groups.find((g) => g.id === id)?.name ?? id;
}

export function groupOf(id) {
  return id.split('-')[0];
}
