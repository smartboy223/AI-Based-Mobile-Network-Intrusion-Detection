import fs from 'node:fs';
import type { Plugin, PreviewServer, ViteDevServer } from 'vite';

function attachMlMeta(server: ViteDevServer | PreviewServer, metaPath: string) {
  server.middlewares.use((req, res, next) => {
    const url = req.url?.split('?')[0] ?? '';
    if (req.method !== 'GET' || url !== '/api/ml-meta') {
      next();
      return;
    }
    try {
      if (!fs.existsSync(metaPath)) {
        res.statusCode = 404;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ ok: false, error: 'cnn_model/meta.json missing — run npm run ml:build --prefix mnids' }));
        return;
      }
      const raw = fs.readFileSync(metaPath, 'utf8');
      const data = JSON.parse(raw) as Record<string, unknown>;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, ...data }));
    } catch (e) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          ok: false,
          error: e instanceof Error ? e.message : 'read failed',
        }),
      );
    }
  });
}

/** Serves trained-model metadata from disk (dev + preview) without the Python server. */
export function mlMetaApiPlugin(metaPath: string): Plugin {
  return {
    name: 'mnids-ml-meta-api',
    configureServer(server) {
      attachMlMeta(server, metaPath);
    },
    configurePreviewServer(server) {
      attachMlMeta(server, metaPath);
    },
  };
}
