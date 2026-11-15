import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

import { loadCatalog } from './scripts/sync.mjs';
import { TOPICS } from './src/lib/learn.mjs';
import { BASE, REPO, SITE } from './src/lib/site.mjs';

// The catalog is read from the repo here as well as in scripts/sync.mjs, so
// the rail's check count can never disagree with the pages that sync wrote.
const CHECK_COUNT = loadCatalog().count;

export default defineConfig({
  site: SITE,
  base: BASE,
  trailingSlash: 'always',
  // Smart punctuation would turn a command flag such as --token into an en
  // dash in prose, so it stays off.
  markdown: { smartypants: false },
  integrations: [
    starlight({
      title: 'stackward',
      description:
        'A read only security audit for self hosted Linux servers running Docker, a PaaS, tunnels and intrusion prevention, plus a runbook track that explains every finding.',
      favicon: '/favicon.svg',
      // The watch-log theme in load order: tokens and fonts, element and
      // Starlight chrome, the site's own components, then responsive rules.
      customCss: ['./src/styles/tokens.css', './src/styles/base.css', './src/styles/components.css', './src/styles/layout.css'],
      components: {
        SiteTitle: './src/components/SiteTitle.astro',
        PageTitle: './src/components/PageTitle.astro',
      },
      social: [{ icon: 'github', label: 'stackward on GitHub', href: REPO }],
      editLink: { baseUrl: `${REPO}/edit/main/site/` },
      lastUpdated: false,
      sidebar: [
        {
          label: 'Use stackward',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'Install and verify', link: '/install/' },
            { label: 'Usage and reports', link: '/usage/' },
          ],
        },
        {
          label: 'Learn',
          items: [
            { label: 'Start here', link: '/learn/' },
            ...TOPICS.map((topic, i) => ({ label: `${i + 1}. ${topic.short}`, link: `/learn/${topic.slug}/` })),
            { label: 'Glossary', link: '/learn/glossary/' },
          ],
        },
        {
          label: 'Check reference',
          items: [
            { label: 'All checks', link: '/checks/', badge: { text: String(CHECK_COUNT), variant: 'default' } },
            { label: 'Every check', collapsed: true, items: [{ autogenerate: { directory: 'checks' } }] },
          ],
        },
        {
          label: 'Project',
          items: [
            { label: 'Threat model', link: '/project/threat-model/' },
            { label: 'Safety design', link: '/project/safety/' },
            { label: 'Architecture', link: '/contributing/architecture/' },
            { label: 'Contributing', link: `${REPO}/blob/main/CONTRIBUTING.md`, attrs: { rel: 'external' } },
          ],
        },
      ],
    }),
  ],
});
