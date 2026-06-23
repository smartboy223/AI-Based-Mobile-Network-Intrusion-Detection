import type { Plugin, PreviewServer, ViteDevServer } from 'vite';
import { createPcapMiddleware } from '../../backend/pcapRoutes.mjs';

function attachPcapMiddleware(
  server: ViteDevServer | PreviewServer,
  pcapDir: string,
) {
  const mw = createPcapMiddleware(pcapDir);
  server.middlewares.use(mw);
}

/**
 * Serves `GET /api/pcap/list` and `GET /api/pcap/file/<name>` from a local folder (dev + preview).
 */
export function pcapApiPlugin(pcapDir: string): Plugin {
  return {
    name: 'mnids-pcap-api',
    configureServer(server) {
      attachPcapMiddleware(server, pcapDir);
    },
    configurePreviewServer(server) {
      attachPcapMiddleware(server, pcapDir);
    },
  };
}
