// Keeps the top of the audit capture. A terminal shows the last screen of a
// long report, but the README picture should show its start: the header and
// the summary box. So the audit shot runs in a terminal tall enough for the
// whole report (see `auditRows` in showcase.config.mjs), and this script
// cuts the raw capture down to its first `auditKeepRows` rows, keeping the
// terminal padding, before `showcase frame` frames it. It only reads and
// writes showcase-out/raw/audit.png, in a headless browser.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

import config, { auditKeepRows, auditRows } from './showcase.config.mjs';

const file = fileURLToPath(new URL('./showcase-out/raw/audit.png', import.meta.url));
const scale = config.deviceScaleFactor;
const pad = config.terminal.padding * scale;

const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  const png = await page.evaluate(
    async ({ data, rows, keep, pad }) => {
      const img = new Image();
      img.src = `data:image/png;base64,${data}`;
      await img.decode();
      const rowHeight = (img.height - 2 * pad) / rows;
      const height = Math.round(2 * pad + keep * rowHeight);
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      // The bottom padding is the background colour of the top left pixel.
      ctx.drawImage(img, 0, 0, img.width, height - pad, 0, 0, img.width, height - pad);
      ctx.drawImage(img, 0, 0, img.width, pad, 0, height - pad, img.width, pad);
      return canvas.toDataURL('image/png').split(',')[1];
    },
    { data: readFileSync(file).toString('base64'), rows: auditRows, keep: auditKeepRows, pad },
  );
  writeFileSync(file, Buffer.from(png, 'base64'));
  console.log(`  ok    cropped audit.png to the first ${auditKeepRows} of ${auditRows} rows`);
} finally {
  await browser.close();
}
