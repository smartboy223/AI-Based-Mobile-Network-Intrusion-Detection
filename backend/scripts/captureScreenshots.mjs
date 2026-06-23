/**
 * Capture MNIDS UI screenshots with Playwright (Chromium).
 * Requires dev server: npm run dev (port 3000 by default).
 *
 * Output names match `generateFinalPresentation.cjs` embed paths:
 *   01-live-dashboard.png, 02-analytics.png, 03-ml-lab.png, 04-ai-assistant.png
 *
 * Usage:
 *   npm run dev   # in another terminal
 *   npm run capture:screenshots
 *
 * Or: BASE_URL=http://127.0.0.1:5173 npm run capture:screenshots
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const OUT_DIR = path.join(REPO_ROOT, 'archive', 'presentation', 'final', 'screenshots');
const PORT_CANDIDATES = (process.env.PORTS || '3000,3001,5173')
  .split(',')
  .map((p) => p.trim())
  .filter(Boolean);

async function resolveBaseUrl() {
  if (process.env.BASE_URL) return process.env.BASE_URL;
  const maxMs = 120000;
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    for (const port of PORT_CANDIDATES) {
      const url = `http://127.0.0.1:${port}`;
      try {
        const r = await fetch(url, { redirect: 'manual' });
        if (r.ok || r.status === 302 || r.status === 301) return url;
      } catch {
        /* try next */
      }
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(
    `No dev server on ports ${PORT_CANDIDATES.join(', ')}. Run: npm run dev`,
  );
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const BASE_URL = await resolveBaseUrl();
  console.log('Using', BASE_URL);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 1,
  });
  const page = await context.newPage();

  async function shot(name, fullPage = false) {
    const p = path.join(OUT_DIR, name);
    await page.screenshot({ path: p, fullPage });
    console.log('Wrote', p);
  }

  const delay = (ms) => new Promise((r) => setTimeout(r, ms));

  await page.goto(`${BASE_URL}/?fresh=1`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.getByRole('button', { name: 'Dashboard' }).first().waitFor({ state: 'visible', timeout: 30000 });
  await delay(2500);

  await page.getByRole('button', { name: 'Dashboard' }).first().click();
  await delay(1000);
  await shot('01-live-dashboard.png', true);

  await page.getByRole('button', { name: 'Analytics' }).first().click();
  await delay(1200);
  await shot('02-analytics.png', true);

  await page.getByRole('button', { name: 'ML lab' }).first().click();
  await delay(1200);
  await shot('03-ml-lab.png', true);

  await page.getByRole('button', { name: 'AI Assistant' }).first().click();
  await delay(1500);
  await shot('04-ai-assistant.png', true);

  await browser.close();
  console.log('Done. Files in:', OUT_DIR);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
