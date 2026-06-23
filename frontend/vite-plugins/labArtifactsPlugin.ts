import fs from 'fs';
import path from 'path';
import type { Plugin } from 'vite';

/** Serve trained lab artifacts (Plotly HTML, PNG plots) from repo `cnn_model/` during `npm run dev`. */
export function labArtifactsPlugin(cnnModelDir: string): Plugin {
  return {
    name: 'mnids-lab-artifacts',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url ?? '';
        if (!url.startsWith('/lab-artifacts/')) {
          next();
          return;
        }
        const name = path.basename(url.split('?')[0]);
        if (!name || name.includes('..')) {
          res.statusCode = 400;
          res.end();
          return;
        }
        const fp = path.join(cnnModelDir, name);
        if (!fs.existsSync(fp) || !fs.statSync(fp).isFile()) {
          res.statusCode = 404;
          res.end('Not found — run npm run ml:build --prefix mnids');
          return;
        }
        const ext = path.extname(name).toLowerCase();
        const ct =
          ext === '.html' ? 'text/html; charset=utf-8' : ext === '.png' ? 'image/png' : 'application/octet-stream';
        res.setHeader('Content-Type', ct);
        res.end(fs.readFileSync(fp));
      });
    },
  };
}
