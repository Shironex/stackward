# stackward identity

Open strata is a small stack with an honest boundary: three solid layers and
three separate, quieter cells. The gaps stay open. The short cells suggest the
parts that could not be inspected; they are never silently painted as a pass.
The symbol is a coverage metaphor, not a score or a claim that a host is secure.

The lowercase wordmark and calm ink and mint palette fit a CLI built for self
hosters and students. The tagline is **Audit your self-hosted stack.** The
supporting promise is **Read only by default. Unknown is never pass.** Future
hardening must remain an explicit, separate action.

## Files

| File | Use |
| --- | --- |
| `icon.svg` | Square mark with an ink tile, suitable on light and dark surfaces |
| `icon-mono.svg` | Transparent single ink mark using `currentColor`, black by default |
| `icon-{16,32,64,180,512}.png` | Favicon, touch icon and avatar exports |
| `logo.svg` | Default transparent lockup for a light background |
| `logo-light.svg` | Ink wordmark and deep teal symbol for a light background |
| `logo-dark.svg` | Paper wordmark and mint symbol for a dark background |
| `social-preview.svg` | Editable 1280 x 640 social preview source, outlined lettering |
| `social-preview.png` | GitHub social preview, exactly 1280 x 640, below 1 MB |
| `readme-header-light.svg` | 1280 x 360 banner for light mode |
| `readme-header-dark.svg` | 1280 x 360 banner for dark mode |
| `export.mjs` | Rebuilds and verifies every shipped PNG |

Variant suffixes describe the intended background. SVGs contain accessible
names and descriptions. All visible lettering is paths: no font installation,
network resource or embedded raster is needed to display them. The standalone
social SVG is editable in a vector editor; its core message also appears
in its accessibility description. The CLI excerpt is explicitly illustrative,
not a live audit or a byte-for-byte rendering of CLI output. No real host data,
addresses, check IDs or version claims are used.

## Palette and contrast

Ratios use WCAG relative luminance with opaque sRGB colors. All text pairings
below exceed the 4.5:1 AA threshold for normal text. The dim cells exceed 3:1
against their intended backgrounds, but are decorative and must not be used as
body text. Color never replaces a result label.

| Token | Hex | Pairing and ratio |
| --- | --- | --- |
| Ink | `#102B2B` | On paper: 13.74:1 |
| Paper | `#F3F6F1` | On ink: 13.74:1 |
| Mint | `#72D6BC` | On ink: 8.60:1 |
| Muted | `#B7CAC4` | On ink: 8.74:1 |
| Dim dark | `#497B70` | On ink: 3.10:1, decorative cells only |
| Deep teal | `#246B5B` | On paper: 5.79:1 |
| Quiet light | `#49675D` | On paper: 5.70:1 |
| Dim light | `#739184` | On paper: 3.15:1, decorative cells only |
| Warn dark | `#F3C879` | On ink: 9.52:1 |
| Fail dark | `#FF9C90` | On ink: 7.42:1 |
| Warn light | `#875400` | On paper: 5.84:1 |
| Fail light | `#AD3C30` | On paper: 5.56:1 |

Use these CSS custom properties as the source palette for the docs site. Mint,
muted, amber and coral are intended for ink surfaces. Their light mode aliases
use darker colors to preserve contrast. Unknown uses neutral text with an
explicit `unknown` label; it never shares pass green.

```css
:root {
  color-scheme: light dark;
  --sw-ink: #102b2b;
  --sw-paper: #f3f6f1;
  --sw-mint: #72d6bc;
  --sw-muted: #b7cac4;
  --sw-teal: #246b5b;
  --sw-quiet-light: #49675d;
  --sw-dim-dark: #497b70;
  --sw-dim-light: #739184;
  --sw-warn-dark: #f3c879;
  --sw-fail-dark: #ff9c90;
  --sw-warn-light: #875400;
  --sw-fail-light: #ad3c30;

  --sw-bg: var(--sw-paper);
  --sw-fg: var(--sw-ink);
  --sw-accent: var(--sw-teal);
  --sw-secondary: var(--sw-quiet-light);
  --sw-dim: var(--sw-dim-light);
  --sw-pass: var(--sw-teal);
  --sw-warn: var(--sw-warn-light);
  --sw-fail: var(--sw-fail-light);
  --sw-unknown: var(--sw-quiet-light);
}

@media (prefers-color-scheme: dark) {
  :root {
    --sw-bg: var(--sw-ink);
    --sw-fg: var(--sw-paper);
    --sw-accent: var(--sw-mint);
    --sw-secondary: var(--sw-muted);
    --sw-dim: var(--sw-dim-dark);
    --sw-pass: var(--sw-mint);
    --sw-warn: var(--sw-warn-dark);
    --sw-fail: var(--sw-fail-dark);
    --sw-unknown: var(--sw-muted);
  }
}
```

## Usage rules

- Keep the name lowercase: `stackward`.
- Preserve the three rows, staggered long cells, short cells and open gaps.
- Leave at least 8 SVG units of clear space around the mark's 48-unit width.
  The square icon includes that space. Keep one short cell of clear space
  around the lockup when placing it beside other content.
- Use the supplied square icon down to 16 px. Its rows, cells and gaps align
  to a 4-unit grid, giving crisp geometry at both 16 and 32 px. The geometry
  survives without a separate favicon design. Prefer at least 24 px for the
  transparent mark and at least 160 px wide for the full lockup.
- Keep the tile ink on both themes. Use the transparent lockup variant that
  matches the surface. For other backgrounds, use a contrasting monochrome
  mark or place the supplied tile on the surface.
- `currentColor` inherits in inline SVG. For an external mono SVG in an `img`,
  black is the default; use a CSS mask or explicitly set its SVG color if
  another ink is required.
- Keep the dim cells visibly separate. Never turn every cell mint to imply a
  perfect audit, close the gaps, add a checkmark, stretch, rotate or add effects.
- Never communicate a result with color alone. Keep pass, warn, fail and
  unknown as visible words; unknown is never a pass.
- The social preview keeps essential content within x=112..1168 and
  y=108..534 on a 1280 x 640 canvas. Preserve those margins when editing.
  Severe alternate aspect-ratio crops can still remove secondary content.

## README picture snippet

Paste this into the repository root README when ready. That README is not
changed by this asset set. The fallback is light mode.

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/readme-header-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/brand/readme-header-light.svg">
  <img src="assets/brand/readme-header-light.svg" width="1280" height="360" alt="stackward. Audit your self-hosted stack. Read only by default. Unknown is never pass.">
</picture>
```

## Typography and licenses

The wordmark and prose are **IBM Plex Sans Medium**, weight 500, normal width.
The social preview command and findings use **IBM Plex Mono Regular**, weight
400. Both are licensed under the SIL Open Font License 1.1. The complete font
licenses and copyright notices are included in
[`licenses/IBM-Plex-Sans-OFL.txt`](licenses/IBM-Plex-Sans-OFL.txt) and
[`licenses/IBM-Plex-Mono-OFL.txt`](licenses/IBM-Plex-Mono-OFL.txt).

The fonts came from the IBM Plex families in the Google Fonts repository:
[Sans](https://github.com/google/fonts/tree/main/ofl/ibmplexsans) and
[Mono](https://github.com/google/fonts/tree/main/ofl/ibmplexmono). Lettering is
outlined in the delivered SVGs. No font binaries are distributed here. The
original mark, layouts and export script are covered by this repository's
Apache-2.0 license; font licensing remains OFL-1.1.

## Export and verify

Requires Node.js 22 or later and npm. Run from the repository root:

```sh
npm --prefix assets/brand ci
npm --prefix assets/brand run export
npm --prefix assets/brand run check
```

The lockfile pins `@resvg/resvg-js` 2.6.2. It renders the icon SVG at 16, 32,
64, 180 and 512 px, and the social SVG at its native 1280 x 640 size. System
fonts are disabled. PNGs are generated directly from the SVGs with no screen
capture, post-processing or lossy compression. The command prints dimensions
and byte sizes and rejects an oversized preview. `check` renders again and
compares every output byte without writing files, catching stale exports.
All SVGs are also parsed by the renderer before the PNG checks.

GitHub requires manually uploading `social-preview.png` in the repository's
Settings, under Social preview. GitHub provides no API to upload this image;
opening or merging the asset PR does not activate it.
