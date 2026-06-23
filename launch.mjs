#!/usr/bin/env node
/**
 * MNIDS unified launcher.
 *
 * Spawns the FastAPI ML service (:8787) and the Express web server (:3000)
 * in a single terminal with color-prefixed log streams. Waits for the ML
 * service to answer /health before opening the dashboard in the browser,
 * so the ML Lab page never gets a cold-start 502.
 *
 * Usage: node launch.mjs
 *   or:   START.bat   (Windows wrapper)
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = __dirname;

const ML_PORT = Number(process.env.ML_SERVER_PORT || 8787);
const WEB_PORT = Number(process.env.MNIDS_PORT || 5003);
const ML_HEALTH_TIMEOUT_MS = 30_000;
const ML_HEALTH_POLL_MS = 750;

// --- pretty printing -------------------------------------------------------
const C = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

function banner() {
  console.log('');
  console.log(C.cyan + '╔════════════════════════════════════════════════╗' + C.reset);
  console.log(C.cyan + '║   AI-Based Mobile Network Intrusion Detection  ║' + C.reset);
  console.log(C.cyan + '║   unified launcher                             ║' + C.reset);
  console.log(C.cyan + '╚════════════════════════════════════════════════╝' + C.reset);
  console.log('');
  console.log(`${C.gray}ML service (FastAPI):  http://127.0.0.1:${ML_PORT}${C.reset}`);
  console.log(`${C.gray}Web server (Express):  http://127.0.0.1:${WEB_PORT}${C.reset}`);
  console.log('');
}

function prefixedStream(stream, color, tag) {
  let buf = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, i).replace(/\r$/, '');
      buf = buf.slice(i + 1);
      if (line.length === 0) {
        process.stdout.write('\n');
      } else {
        process.stdout.write(`${color}[${tag}]${C.reset} ${line}\n`);
      }
    }
  });
  stream.on('end', () => {
    if (buf.trim().length) process.stdout.write(`${color}[${tag}]${C.reset} ${buf}\n`);
  });
}

// --- preflight -------------------------------------------------------------
function findOrFail(cmd, hint) {
  // We don't run `which`; just trust PATH. Surface a clearer error if spawn fails.
  return cmd;
}

/**
 * Pick the Python interpreter we should use for the FastAPI ML server.
 *
 * Preference order:
 *   1. Explicit override via process.env.PYTHON (set by START.bat when the
 *      project's .venv exists — keeps installs isolated from system Python).
 *   2. Auto-detect a sibling `.venv` (POSIX `.venv/bin/python` or Windows
 *      `.venv\Scripts\python.exe`) so `node launch.mjs` standalone also
 *      uses the project's virtual environment when one is present.
 *   3. Fall back to the system `python` on PATH.
 */
function resolvePython() {
  if (process.env.PYTHON && fs.existsSync(process.env.PYTHON)) {
    return process.env.PYTHON;
  }
  const venvWin = path.join(ROOT, '.venv', 'Scripts', 'python.exe');
  const venvPosix = path.join(ROOT, '.venv', 'bin', 'python');
  if (fs.existsSync(venvWin)) return venvWin;
  if (fs.existsSync(venvPosix)) return venvPosix;
  return 'python';
}
const PY = resolvePython();
const NODE = process.execPath;

// Verify the built frontend exists AND is up to date. If sources in
// frontend/src/ are newer than dist/index.html, rebuild — otherwise the
// browser keeps running the stale bundle and source-code fixes silently
// don't apply. (This is exactly what caused the "Add DEEPSEEK_API_KEY"
// banner on /assistant: the runtime probe shipped in source weeks ago,
// but dist/ was still the pre-fix bundle.)
const distIndex = path.join(ROOT, 'frontend', 'dist', 'index.html');
const SRC_DIR = path.join(ROOT, 'frontend', 'src');

function newestMTimeInDir(dir) {
  let newest = 0;
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        const sub = newestMTimeInDir(full);
        if (sub > newest) newest = sub;
      } else if (entry.isFile()) {
        const m = fs.statSync(full).mtimeMs;
        if (m > newest) newest = m;
      }
    }
  } catch {
    /* unreadable dir — skip */
  }
  return newest;
}

function ensureBuild() {
  return new Promise((resolve, reject) => {
    const distExists = fs.existsSync(distIndex);
    let reason = null;
    if (!distExists) {
      reason = 'frontend/dist/index.html missing';
    } else {
      const distMTime = fs.statSync(distIndex).mtimeMs;
      const srcMTime = newestMTimeInDir(SRC_DIR);
      if (srcMTime > distMTime) {
        reason = 'frontend/src is newer than dist (stale bundle)';
      }
    }
    if (!reason) {
      resolve(false);
      return;
    }
    console.log(`${C.yellow}[build]${C.reset} ${reason} — running ${C.bold}npm run build${C.reset}…`);
    // On Windows `npm` is a `.cmd` shim. Recent Node (≥20) refuses to spawn
    // .cmd / .bat with shell:false (security CVE patch) and returns
    // ENOENT / EINVAL. Setting shell:true makes Windows run it through cmd.exe.
    const isWin = process.platform === 'win32';
    const npm = isWin ? 'npm.cmd' : 'npm';
    const proc = spawn(npm, ['run', 'build'], {
      cwd: ROOT,
      stdio: 'inherit',
      shell: isWin,
    });
    proc.on('exit', (code) => {
      if (code === 0 && fs.existsSync(distIndex)) resolve(true);
      else reject(new Error(`npm run build failed (exit ${code}).`));
    });
    proc.on('error', reject);
  });
}

// --- launchers -------------------------------------------------------------
// Detect a native-side crash (Windows access violation, SIGSEGV, etc.) so we
// can give the user actionable next steps instead of leaving them staring at
// "Models present — start API". The classic culprit is TensorFlow failing on
// import on a machine missing AVX2 / VC++ runtime.
const NATIVE_CRASH_CODES = new Set([
  3221225477, // 0xC0000005 — Windows access violation (TF native crash)
  3221225781, // 0xC0000135 — DLL not found
  139,        // POSIX SIGSEGV
]);

function startMl() {
  // Show which Python is being used so a venv mix-up is obvious in the log.
  const pyTag = PY.includes('.venv') ? `${C.green}[.venv]${C.reset}` : `${C.yellow}[system]${C.reset}`;
  console.log(`${C.magenta}[ML]${C.reset} starting FastAPI on :${ML_PORT} ${pyTag} ${C.gray}${PY}${C.reset}`);
  const proc = spawn(PY, ['backend/inference_server.py'], {
    cwd: ROOT,
    env: { ...process.env, PYTHONUNBUFFERED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
  });
  prefixedStream(proc.stdout, C.magenta, 'ML');
  prefixedStream(proc.stderr, C.magenta, 'ML');
  proc.on('exit', (code) => {
    console.log(`${C.magenta}[ML]${C.reset} ${C.red}exited with code ${code}${C.reset}`);
    if (code != null && NATIVE_CRASH_CODES.has(code)) {
      console.log('');
      console.log(`${C.yellow}═══ ML service crashed natively (likely TensorFlow) ═══${C.reset}`);
      console.log(`${C.gray}Exit code ${code} is a Windows access violation / DLL miss.${C.reset}`);
      console.log(`${C.gray}Quick fix — disable TensorFlow (RF + IF will still work):${C.reset}`);
      console.log(`${C.cyan}  1. Add this line to backend/.env:${C.reset}`);
      console.log(`${C.bold}     MNIDS_DISABLE_TF=1${C.reset}`);
      console.log(`${C.cyan}  2. Re-run START.bat${C.reset}`);
      console.log('');
      console.log(`${C.gray}Full fix — repair TensorFlow:${C.reset}`);
      console.log(`${C.gray}  • Install VC++ Redist 2015-2022 (x64) from Microsoft${C.reset}`);
      console.log(`${C.gray}  • pip install --upgrade --force-reinstall tensorflow-cpu==2.15.0${C.reset}`);
      console.log(`${C.gray}  • Ensure your CPU supports AVX2 (TF 2.11+ requires it)${C.reset}`);
      console.log('');
    }
  });
  return proc;
}

function startWeb() {
  console.log(`${C.blue}[WEB]${C.reset} starting Express on :${WEB_PORT}…`);
  const proc = spawn(NODE, ['backend/server.js'], {
    cwd: ROOT,
    env: { ...process.env, NODE_ENV: process.env.NODE_ENV || 'production' },
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
  });
  prefixedStream(proc.stdout, C.blue, 'WEB');
  prefixedStream(proc.stderr, C.blue, 'WEB');
  proc.on('exit', (code) => {
    console.log(`${C.blue}[WEB]${C.reset} ${C.red}exited with code ${code}${C.reset}`);
  });
  return proc;
}

function pingMl() {
  return new Promise((resolve) => {
    const req = http.get(
      { host: '127.0.0.1', port: ML_PORT, path: '/health', timeout: 1500 },
      (res) => {
        // 2xx OR 4xx (no route) both prove the socket is open.
        resolve(res.statusCode >= 200 && res.statusCode < 500);
        res.resume();
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitForMlHealth() {
  const started = Date.now();
  process.stdout.write(`${C.magenta}[ML]${C.reset} waiting for /health…`);
  while (Date.now() - started < ML_HEALTH_TIMEOUT_MS) {
    if (await pingMl()) {
      process.stdout.write(` ${C.green}up${C.reset}\n`);
      return true;
    }
    process.stdout.write('.');
    await new Promise((r) => setTimeout(r, ML_HEALTH_POLL_MS));
  }
  process.stdout.write(` ${C.yellow}timeout${C.reset}\n`);
  return false;
}

function openBrowser(url) {
  const cmd =
    process.platform === 'win32'
      ? ['cmd', ['/c', 'start', '""', url]]
      : process.platform === 'darwin'
        ? ['open', [url]]
        : ['xdg-open', [url]];
  try {
    spawn(cmd[0], cmd[1], { detached: true, stdio: 'ignore' }).unref();
  } catch {
    /* ignore — user can open manually */
  }
}

// --- main ------------------------------------------------------------------
let mlProc = null;
let webProc = null;

function shutdown(reason) {
  console.log(`\n${C.gray}shutting down (${reason})${C.reset}`);
  try { mlProc && mlProc.kill(); } catch { /* ignore */ }
  try { webProc && webProc.kill(); } catch { /* ignore */ }
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

async function main() {
  banner();
  try {
    await ensureBuild();
  } catch (e) {
    console.error(`${C.red}Build failed:${C.reset}`, e.message);
    process.exit(1);
  }
  mlProc = startMl();
  webProc = startWeb();

  const ok = await waitForMlHealth();
  const url = `http://127.0.0.1:${WEB_PORT}/`;
  if (ok) {
    console.log(`${C.green}All services ready.${C.reset} Opening ${C.bold}${url}${C.reset}`);
  } else {
    console.log(
      `${C.yellow}ML service did not respond within ${ML_HEALTH_TIMEOUT_MS / 1000}s.${C.reset} ` +
        `Opening ${url} anyway — use the Retry button on /mllab once ML is up.`,
    );
  }
  openBrowser(url);
  console.log(`\n${C.gray}Press Ctrl+C to stop both services.${C.reset}\n`);
}

main().catch((e) => {
  console.error(`${C.red}Launcher failed:${C.reset}`, e);
  shutdown('error');
});
