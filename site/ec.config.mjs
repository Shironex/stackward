import { defineEcConfig } from '@astrojs/starlight/expressive-code';

// Muted Vitesse themes suit the calm palette; the frame and font come from
// the site tokens so code blocks match the terminal panels on the overview.
export default defineEcConfig({
  // Commands are short; a terminal window frame around every one line
  // command is noise. Titled blocks still get a file tab.
  // Long commands wrap instead of scrolling, which reads better at 390 px.
  defaultProps: { frame: 'code', wrap: true, preserveIndent: true },
  themes: ['vitesse-dark', 'vitesse-light'],
  styleOverrides: {
    borderRadius: '4px',
    borderColor: 'var(--sw-line)',
    codeFontFamily: 'var(--sw-font-code)',
    codeFontSize: '0.875rem',
    uiFontFamily: 'var(--sw-font-ui)',
    frames: {
      shadowColor: 'transparent',
    },
  },
});
