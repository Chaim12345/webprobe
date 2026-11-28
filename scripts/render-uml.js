// render-uml.js — render every Mermaid block under docs/uml/*.md to an SVG in
// docs/uml/img/, so the diagrams display wherever Markdown images do, also
// when a diagram is too large for a site's own Mermaid renderer.
//
// Usage: node scripts/render-uml.js   (needs the `playwright` package and network
// access to cdnjs for mermaid.min.js)
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const dir = path.join(__dirname, '..', 'docs', 'uml');
const out = path.join(dir, 'img');
const MERMAID = 'https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.9.1/mermaid.min.js';

(async () => {
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setContent('<html><body style="background:#fff"><div id="o"></div></body></html>');
  await page.addScriptTag({ url: MERMAID });
  await page.evaluate(() =>
    mermaid.initialize({ startOnLoad: false, maxTextSize: 500000, maxEdges: 5000, theme: 'neutral', securityLevel: 'strict' }));
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.md') && f !== 'README.md').sort()) {
    const text = fs.readFileSync(path.join(dir, file), 'utf8');
    const blocks = [...text.matchAll(/```mermaid\n([\s\S]*?)\n```/g)].map((m) => m[1]);
    for (let i = 0; i < blocks.length; i++) {
      const name = path.basename(file, '.md') + (blocks.length > 1 ? `-${i + 1}` : '') + '.svg';
      const svg = await page.evaluate(async ([id, src]) => (await mermaid.render(id, src)).svg, [`d${i}`, blocks[i]]);
      fs.writeFileSync(path.join(out, name), svg + '\n');
      console.log(`wrote docs/uml/img/${name}`);
    }
  }
  await browser.close();
})().catch((e) => { console.error(String(e)); process.exit(1); });
