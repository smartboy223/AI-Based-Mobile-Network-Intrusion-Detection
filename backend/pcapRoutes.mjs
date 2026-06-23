/**
 * Shared Connect/Express middleware: /api/pcap/list, /api/pcap/file/:name, /api/pcap/reveal-folder
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';

const ALLOWED = /^[a-zA-Z0-9._-]+\.(pcap|cap|pcapng)$/i;

export function createPcapMiddleware(pcapDir) {
  const resolvedDir = path.resolve(pcapDir);
  return (req, res, next) => {
    const url = req.url?.split('?')[0] ?? '';

    if (req.method === 'GET' && url === '/api/pcap/list') {
      try {
        if (!fs.existsSync(resolvedDir)) {
          fs.mkdirSync(resolvedDir, { recursive: true });
        }
        const names = fs
          .readdirSync(resolvedDir, { withFileTypes: true })
          .filter((d) => d.isFile() && ALLOWED.test(d.name))
          .map((d) => d.name)
          .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ ok: true, files: names }));
      } catch (e) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            ok: false,
            error: e instanceof Error ? e.message : 'list failed',
            files: [],
          }),
        );
      }
      return;
    }

    if (req.method === 'GET' && url.startsWith('/api/pcap/file/')) {
      const raw = decodeURIComponent(url.slice('/api/pcap/file/'.length));
      const base = path.basename(raw);
      if (!ALLOWED.test(base)) {
        res.statusCode = 400;
        res.end('Invalid file name');
        return;
      }
      const abs = path.resolve(resolvedDir, base);
      if (!abs.startsWith(resolvedDir) || !fs.existsSync(abs)) {
        res.statusCode = 404;
        res.end('Not found');
        return;
      }
      res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
      res.setHeader('Content-Disposition', `attachment; filename="${base}"`);
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      fs.createReadStream(abs).pipe(res);
      return;
    }

    if (req.method === 'POST' && url === '/api/pcap/reveal-folder') {
      try {
        if (!fs.existsSync(resolvedDir)) {
          fs.mkdirSync(resolvedDir, { recursive: true });
        }
        if (process.platform === 'win32') {
          spawn('explorer.exe', [resolvedDir], {
            detached: true,
            stdio: 'ignore',
            windowsHide: true,
          }).unref();
        } else if (process.platform === 'darwin') {
          spawn('open', [resolvedDir], { detached: true, stdio: 'ignore' }).unref();
        } else {
          spawn('xdg-open', [resolvedDir], { detached: true, stdio: 'ignore' }).unref();
        }
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ ok: true, path: resolvedDir }));
      } catch (e) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            ok: false,
            error: e instanceof Error ? e.message : 'reveal failed',
          }),
        );
      }
      return;
    }

    next();
  };
}
