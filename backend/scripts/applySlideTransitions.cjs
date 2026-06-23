const fs = require('fs');
const path = require('path');
const JSZip = require('jszip');

const OUT = path.join(
  __dirname,
  '..',
  '..',
  '..',
  'archive',
  'presentation',
  'final',
  'MNIDS_Final_Presentation.pptx',
);
const NEEDLE = '</p:clrMapOvr></p:sld>';
const REPLACEMENT = '</p:clrMapOvr><p:transition spd="med"><p:fade/></p:transition></p:sld>';

async function main() {
  if (!fs.existsSync(OUT)) {
    console.error('Missing:', OUT);
    process.exit(1);
  }
  const buf = fs.readFileSync(OUT);
  const zip = await JSZip.loadAsync(buf);
  const names = Object.keys(zip.files).filter(
    (f) => /^ppt\/slides\/slide\d+\.xml$/.test(f) && !zip.files[f].dir,
  );
  let n = 0;
  for (const name of names) {
    let xml = await zip.file(name).async('string');
    if (xml.includes('<p:transition')) continue;
    if (!xml.includes(NEEDLE)) continue;
    xml = xml.replace(NEEDLE, REPLACEMENT);
    zip.file(name, xml);
    n += 1;
  }
  const outBuf = await zip.generateAsync({
    type: 'nodebuffer',
    compression: 'DEFLATE',
    compressionOptions: { level: 6 },
  });
  fs.writeFileSync(OUT, outBuf);
  console.log('Slide transitions (fade):', n, 'of', names.length, 'slides');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
