// All lettering is outlined. Exports never depend on locally installed fonts.
import { Resvg } from '@resvg/resvg-js';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const directory = dirname(fileURLToPath(import.meta.url));
const check = process.argv.includes('--check');
// Parse every source, including variants that have no shipped PNG export.
for (const source of readdirSync(directory).filter(name => name.endsWith('.svg'))) {
  new Resvg(readFileSync(join(directory, source)), {
    font: { loadSystemFonts: false },
  });
}
const outputs = [
  ...[16, 32, 64, 180, 512].map(size => ({
    source: 'icon.svg', output: `icon-${size}.png`, width: size, height: size,
  })),
  { source: 'social-preview.svg', output: 'social-preview.png', width: 1280, height: 640 },
];

for (const { source, output, width, height } of outputs) {
  const sourceBytes = readFileSync(join(directory, source));
  const png = new Resvg(sourceBytes, {
    fitTo: { mode: 'width', value: width },
    font: { loadSystemFonts: false },
  }).render().asPng();
  const pngWidth = png.readUInt32BE(16);
  const pngHeight = png.readUInt32BE(20);
  if (pngWidth !== width || pngHeight !== height) {
    throw new Error(`${output}: expected ${width}x${height}, got ${pngWidth}x${pngHeight}`);
  }
  if (output === 'social-preview.png' && png.length >= 1_000_000) {
    throw new Error('Social preview must be smaller than 1 MB');
  }
  if (check) {
    if (!readFileSync(join(directory, output)).equals(png)) {
      throw new Error(`${output}: stale export; run npm run export`);
    }
  } else {
    writeFileSync(join(directory, output), png);
  }
  console.log(`${output}: ${pngWidth}x${pngHeight}, ${png.length} bytes${check ? ' (verified)' : ''}`);
}
