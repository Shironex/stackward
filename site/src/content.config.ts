import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

// src/content/docs/checks/, project/, install.md and contributing/architecture.md
// are written by scripts/sync.mjs and gitignored; everything else is authored.
export const collections = {
  docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
};
