/**
 * Production UI + PCAP API + ML proxy (same behavior as Vite dev for /api/pcap and /api/ml).
 * Default: MNIDS_PORT=3000  →  node mnids/backend/server.js
 */
import fs from 'fs';
import path from 'path';
import { Readable } from 'stream';
import { fileURLToPath } from 'url';
import express from 'express';
import dotenv from 'dotenv';
import { createPcapMiddleware } from './pcapRoutes.mjs';
import { createVirusTotalRouter } from './virusTotalRoutes.mjs';
import deepseekRouter from './deepseekRoutes.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Load environment variables from backend/.env if it exists
 * Falls back to root .env if backend/.env doesn't exist
 */
const backendEnvPath = path.join(__dirname, '.env');
const rootEnvPath = path.join(__dirname, '..', '.env');

if (fs.existsSync(backendEnvPath)) {
  const result = dotenv.config({ path: backendEnvPath });
  if (result.error) {
    console.warn('⚠️ Error loading backend/.env:', result.error.message);
  } else {
    console.log('✓ Loaded config from backend/.env');
  }
} else if (fs.existsSync(rootEnvPath)) {
  const result = dotenv.config({ path: rootEnvPath });
  if (result.error) {
    console.warn('⚠️ Error loading root .env:', result.error.message);
  } else {
    console.log('✓ Loaded config from root .env');
  }
} else {
  console.warn('⚠️ No .env file found. Using environment variables only.');
}

// Verify critical API keys are configured
if (!process.env.DEEPSEEK_API_KEY) {
  console.warn('⚠️ DEEPSEEK_API_KEY not configured. Chat will not work.');
} else {
  console.log('✓ DEEPSEEK_API_KEY configured (last 8 chars: ' + process.env.DEEPSEEK_API_KEY.slice(-8) + ')');
}

/**
 * Resolve the MNIDS "lab root" (folder that contains `frontend/dist`), whether
 * the server file lives at `mnids/backend/` or a stray `backend/` at repo root.
 */
function resolveLabRoot() {
  let dir = path.resolve(__dirname);
  for (let i = 0; i < 8; i += 1) {
    const nested = path.join(dir, 'mnids', 'frontend', 'dist', 'index.html');
    const flat = path.join(dir, 'frontend', 'dist', 'index.html');
    if (fs.existsSync(nested)) return path.join(dir, 'mnids');
    if (fs.existsSync(flat)) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.resolve(__dirname, '..');
}

const ROOT = resolveLabRoot();

// Default web port: 5003 to align with the host machine's existing service map.
// Override via MNIDS_PORT in backend/.env if it conflicts with something on
// the new PC.
const PORT = Number(process.env.MNIDS_PORT || 5003);
const dist = path.join(ROOT, 'frontend', 'dist');
const PCAP_DIR = path.join(ROOT, 'dataset', 'pcap');
const TRAINED_PCAP_DIR = path.join(ROOT, 'dataset', 'trained');
const ML_BASE = (process.env.ML_SERVER_URL || 'http://127.0.0.1:8787').replace(/\/$/, '');

/**
 * SERVER_BOOT_ID — random per launcher start.
 *
 * The frontend reads this from /api/health and pairs it with the persisted
 * traffic table in localStorage. On a browser refresh the boot ID matches
 * and the dashboard auto-restores its previous results. On a server restart
 * (a fresh START.bat run) a new boot ID is minted and the frontend drops
 * the saved data. That gives exactly the lifetime users expect: results
 * survive Ctrl+F5 but die when the user closes the launcher window.
 */
const SERVER_BOOT_ID =
  (globalThis.crypto && globalThis.crypto.randomUUID
    ? globalThis.crypto.randomUUID()
    : `boot-${Date.now()}-${Math.random().toString(36).slice(2)}`);
const SERVER_STARTED_AT = new Date().toISOString();

const app = express();
app.use(express.json({ limit: '4mb' }));

app.use(createPcapMiddleware(PCAP_DIR));

app.use('/lab-artifacts', express.static(path.join(ROOT, 'cnn_model')));

app.get('/api/ml-meta', (_req, res) => {
  try {
    const p = path.join(ROOT, 'cnn_model', 'meta.json');
    const cnnDir = path.join(ROOT, 'cnn_model');
    if (!fs.existsSync(p)) {
      res.status(404).json({ ok: false, error: 'cnn_model/meta.json missing — run npm run ml:build --prefix mnids' });
      return;
    }
    const data = JSON.parse(fs.readFileSync(p, 'utf8'));
    const savedFiles = fs
      .readdirSync(cnnDir, { withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => e.name);
    res.setHeader('Content-Type', 'application/json');
    res.json({
      ok: true,
      ...data,
      saved_artifact_files: savedFiles,
      saved_artifact_count: savedFiles.length,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e instanceof Error ? e.message : 'read failed' });
  }
});

const VT_MIN_MS = Math.max(1000, Number(process.env.VIRUSTOTAL_MIN_INTERVAL_MS) || 15_000);
app.use(
  '/api/vt',
  createVirusTotalRouter({
    apiKey: process.env.VIRUSTOTAL_API_KEY,
    minIntervalMs: VT_MIN_MS,
  }),
);

app.use('/api/deepseek', deepseekRouter);

app.use('/api/ml', async (req, res) => {
  // `req.url` (inside an app.use mount) is the path + query AFTER the mount prefix,
  // e.g. `/retrain-stream?baseline=true`. We must forward the query string verbatim
  // so endpoints that depend on flags (?baseline=true, ?dataset=name) actually receive
  // them — using `req.path` here would silently strip the query and break the ML Lab
  // "Restore safe model" / dataset-row training buttons.
  const qIdx = req.url.indexOf('?');
  const pathOnly = qIdx >= 0 ? req.url.slice(0, qIdx) : req.url;
  const query = qIdx >= 0 ? req.url.slice(qIdx) : '';
  const suffix = (pathOnly === '/' || pathOnly === '' ? '/health' : pathOnly) + query;
  const target = `${ML_BASE}${suffix}`;
  try {
    const init = {
      method: req.method,
      headers: {'Content-Type': req.headers['content-type'] || 'application/json'},
    };
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const ctype = String(req.headers['content-type'] || '');
      if (ctype.includes('multipart/form-data')) {
        const chunks = [];
        for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        init.body = Buffer.concat(chunks);
      } else if (req.body !== undefined) {
        init.body = JSON.stringify(req.body);
      }
    }
    const r = await fetch(target, init);
    res.status(r.status);
    const ct = r.headers.get('content-type');
    if (ct) res.setHeader('Content-Type', ct);
    // Stream SSE (and similar) so ML Lab training logs arrive incrementally in production.
    if (r.body && ct && ct.includes('text/event-stream')) {
      const nocache = r.headers.get('cache-control');
      if (nocache) res.setHeader('Cache-Control', nocache);
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      Readable.fromWeb(r.body).on('error', () => res.destroy()).pipe(res);
      return;
    }
    const buf = Buffer.from(await r.arrayBuffer());
    res.end(buf);
  } catch (e) {
    res.status(502).json({
      ok: false,
      error: e instanceof Error ? e.message : 'ML proxy failed',
      results: [],
    });
  }
});

// List trained PCAP files (for quick-select dropdown)
app.get('/api/pcap/trained-list', (_req, res) => {
  try {
    if (!fs.existsSync(TRAINED_PCAP_DIR)) {
      return res.json({ ok: true, files: [] });
    }
    const files = fs
      .readdirSync(TRAINED_PCAP_DIR, { withFileTypes: true })
      .filter((d) => d.isFile() && /\.(pcap|cap|pcapng)$/i.test(d.name))
      .map((d) => d.name)
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
    res.json({ ok: true, files });
  } catch (e) {
    res.status(500).json({
      ok: false,
      error: e instanceof Error ? e.message : 'list failed',
      files: [],
    });
  }
});

// Serve trained PCAP files
app.get('/api/pcap/trained-file/:name', (req, res) => {
  try {
    const raw = decodeURIComponent(req.params.name);
    const base = path.basename(raw);
    if (!/\.(pcap|cap|pcapng)$/i.test(base)) {
      return res.status(400).send('Invalid file name');
    }
    const abs = path.resolve(TRAINED_PCAP_DIR, base);
    if (!abs.startsWith(TRAINED_PCAP_DIR) || !fs.existsSync(abs)) {
      return res.status(404).send('Not found');
    }
    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
    res.setHeader('Content-Disposition', `attachment; filename="${base}"`);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    fs.createReadStream(abs).pipe(res);
  } catch (e) {
    res.status(500).send(e instanceof Error ? e.message : 'serve failed');
  }
});

// ============================================================================
// CRITICAL: Serve React frontend from dist folder
// ============================================================================
app.use(express.static(dist));

// Catch-all route: serve index.html for any route not matched by API endpoints
app.get('*', (_req, res) => {
  const indexPath = path.join(dist, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({
      ok: false,
      error: `index.html not found at ${indexPath}. React build may have failed.`,
    });
  }
});

// Health check endpoint — also exposes the SERVER_BOOT_ID so the frontend
// can decide whether its localStorage snapshot still belongs to the running
// server (auto-restore) or to a previous launcher run (drop and start fresh).
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    deepseek: !!process.env.DEEPSEEK_API_KEY,
    virustotal: !!process.env.VIRUSTOTAL_API_KEY,
    ml_server: ML_BASE,
    timestamp: new Date().toISOString(),
    serverBootId: SERVER_BOOT_ID,
    serverStartedAt: SERVER_STARTED_AT,
  });
});

// ============================================================================
// Start server
// ============================================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('╔════════════════════════════════════════════╗');
  console.log('║   MNIDS Backend Started Successfully       ║');
  console.log('╚════════════════════════════════════════════╝');
  console.log('');
  console.log(`🌐 Dashboard: http://127.0.0.1:${PORT}/`);
  console.log(`📊 ML Lab:    http://127.0.0.1:${PORT}/mllab`);
  console.log(`💬 Assistant: http://127.0.0.1:${PORT}/assistant`);
  console.log('');
  console.log('API Endpoints:');
  console.log(`  ✓ PCAP:      /api/pcap/list`);
  console.log(`  ✓ DeepSeek:  /api/deepseek/chat (${process.env.DEEPSEEK_API_KEY ? '✓ Configured' : '✗ Missing'})`);
  console.log(`  ✓ VirusTotal: /api/vt (${process.env.VIRUSTOTAL_API_KEY ? '✓ Configured' : '✗ Optional'})`);
  console.log(`  ✓ ML Proxy:  /api/ml → ${ML_BASE}`);
  console.log(`  ✓ Health:    /api/health`);
  console.log('');
  console.log(`📁 Frontend: ${fs.existsSync(dist) ? '✓ Built' : '✗ Missing'}`);
  console.log('');
});
