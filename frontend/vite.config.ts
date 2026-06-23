import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {fileURLToPath} from 'node:url';
import {defineConfig, loadEnv} from 'vite';
import {pcapApiPlugin} from './vite-plugins/pcapApiPlugin';
import {mlMetaApiPlugin} from './vite-plugins/mlMetaApiPlugin';
import {virusTotalApiPlugin} from './vite-plugins/virusTotalApiPlugin';
import {labArtifactsPlugin} from './vite-plugins/labArtifactsPlugin';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const REPO_ROOT = path.join(__dirname, '..', '..');
const CNN_MODEL_DIR = path.join(ROOT, 'cnn_model');
const PCAP_DIR = path.join(ROOT, 'dataset', 'pcap');
const ML_META_PATH = path.join(ROOT, 'cnn_model', 'meta.json');

export default defineConfig(({mode}) => {
  const env = {
    ...loadEnv(mode, ROOT, ''),
    ...loadEnv(mode, REPO_ROOT, ''),
    ...loadEnv(mode, path.join(REPO_ROOT, 'config'), ''),
    // backend/.env is the canonical secrets file (holds VIRUSTOTAL_API_KEY,
    // DEEPSEEK_API_KEY). Without this line `npm run dev` shows "VT no key"
    // even when the key is present, because loadEnv never looked in backend/.
    ...loadEnv(mode, path.join(ROOT, 'backend'), ''),
  };
  const mlServer = env.ML_SERVER_URL || 'http://127.0.0.1:8787';
  // In dev, route the DeepSeek proxy at our own Express backend so the key
  // stays server-side. (Default backend port is 3000; override with MNIDS_PORT.)
  const backendServer =
    env.MNIDS_BACKEND_URL ||
    (env.MNIDS_PORT ? `http://127.0.0.1:${env.MNIDS_PORT}` : 'http://127.0.0.1:5003');
  return {
    root: __dirname,
    plugins: [
      react(),
      tailwindcss(),
      pcapApiPlugin(PCAP_DIR),
      mlMetaApiPlugin(ML_META_PATH),
      virusTotalApiPlugin({
        apiKey: env.VIRUSTOTAL_API_KEY,
        minIntervalMs: Math.max(
          1000,
          Number(env.VIRUSTOTAL_MIN_INTERVAL_MS) || 15_000,
        ),
      }),
      labArtifactsPlugin(CNN_MODEL_DIR),
    ],
    define: {
      // DEEPSEEK_API_KEY is intentionally NOT injected — the key stays on the
      // backend; the frontend talks to /api/deepseek/* via the Express proxy.
      // Only the (non-secret) model name is exposed for optional overrides.
      'process.env.DEEPSEEK_MODEL': JSON.stringify(env.DEEPSEEK_MODEL ?? 'deepseek-chat'),
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, 'src'),
      },
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
      proxy: {
        '/api/ml': {
          target: mlServer,
          changeOrigin: true,
          rewrite: (p) => {
            const x = p.replace(/^\/api\/ml/, '');
            return x.length ? x : '/';
          },
        },
        // In dev, hit the Express backend (which holds the API key) rather than
        // api.deepseek.com directly. Production uses the same /api/deepseek path
        // served by Express, so the frontend code is identical in both modes.
        '/api/deepseek': {
          target: backendServer,
          changeOrigin: true,
          // No rewrite — keep `/api/deepseek/*` path so Express router matches.
        },
      },
    },
    preview: {
      proxy: {
        '/api/ml': {
          target: mlServer,
          changeOrigin: true,
          rewrite: (p) => {
            const x = p.replace(/^\/api\/ml/, '');
            return x.length ? x : '/';
          },
        },
      },
    },
  };
});
