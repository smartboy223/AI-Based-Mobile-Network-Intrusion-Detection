import type { Plugin, PreviewServer, ViteDevServer } from 'vite';
import {
  isPrivateOrNonRoutableIpv4,
  vtSkippedPrivateIpResult,
} from '../src/lib/virusTotal';

const VT_API = 'https://www.virustotal.com/api/v3';

export type VirusTotalPluginOptions = {
  apiKey: string | undefined;
  /** Minimum delay between each VirusTotal API request (free tier ~4/min → default 15s). */
  minIntervalMs: number;
};

let vtRequestChain: Promise<void> = Promise.resolve();
let lastVtApiRequestEnd = 0;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Serialize VT API calls and enforce spacing so free-tier quotas (e.g. 4 req/min) are not bursted.
 * Skipped/private IPs do not use this path.
 */
async function fetchVtIpThrottled(
  apiKey: string,
  ip: string,
  minIntervalMs: number,
): Promise<Awaited<ReturnType<typeof fetchVtIp>>> {
  const run = vtRequestChain.then(async () => {
    const elapsed = Date.now() - lastVtApiRequestEnd;
    const wait = Math.max(0, minIntervalMs - elapsed);
    if (wait > 0) await sleep(wait);
    try {
      return await fetchVtIp(apiKey, ip);
    } finally {
      lastVtApiRequestEnd = Date.now();
    }
  });
  vtRequestChain = run.then(() => {}).catch(() => {});
  return run;
}

function guiDomainUrl(domain: string) {
  return `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`;
}

function isValidVtDomainHost(host: string): boolean {
  const s = host.trim().toLowerCase();
  if (s.length < 3 || s.length > 253) return false;
  if (isIpv4(s)) return false;
  if (s.includes('..') || s.startsWith('.') || s.endsWith('.')) return false;
  return /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(s);
}

async function fetchVtDomain(
  apiKey: string,
  domain: string,
): Promise<{
  domain: string;
  ok: boolean;
  guiUrl: string;
  stats?: VtStatsPayload;
  totalEngines?: number;
  error?: string;
}> {
  const d = domain.trim().toLowerCase();
  const guiUrl = guiDomainUrl(d);
  try {
    const r = await fetch(`${VT_API}/domains/${encodeURIComponent(d)}`, {
      headers: { 'x-apikey': apiKey },
    });
    if (r.status === 404) {
      return {
        domain: d,
        ok: true,
        guiUrl,
        stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
        totalEngines: 0,
      };
    }
    if (r.status === 429) {
      return { domain: d, ok: false, guiUrl, error: 'VirusTotal rate limit (try again in a minute).' };
    }
    if (!r.ok) {
      return { domain: d, ok: false, guiUrl, error: `VirusTotal HTTP ${r.status}` };
    }
    const j = (await r.json()) as {
      data?: { attributes?: { last_analysis_stats?: Record<string, number> } };
    };
    const s = j?.data?.attributes?.last_analysis_stats ?? {};
    const malicious = Number(s.malicious ?? 0);
    const suspicious = Number(s.suspicious ?? 0);
    const harmless = Number(s.harmless ?? 0);
    const undetected = Number(s.undetected ?? 0);
    const timeout = Number(s.timeout ?? 0) + Number((s as { 'confirmed-timeout'?: number })['confirmed-timeout'] ?? 0);
    const stats: VtStatsPayload = { malicious, suspicious, harmless, undetected, timeout };
    const totalEngines = malicious + suspicious + harmless + undetected + timeout;
    return { domain: d, ok: true, guiUrl, stats, totalEngines };
  } catch (e) {
    return {
      domain: d,
      ok: false,
      guiUrl,
      error: e instanceof Error ? e.message : 'VirusTotal request failed',
    };
  }
}

async function fetchVtDomainThrottled(
  apiKey: string,
  domain: string,
  minIntervalMs: number,
): Promise<Awaited<ReturnType<typeof fetchVtDomain>>> {
  const run = vtRequestChain.then(async () => {
    const elapsed = Date.now() - lastVtApiRequestEnd;
    const wait = Math.max(0, minIntervalMs - elapsed);
    if (wait > 0) await sleep(wait);
    try {
      return await fetchVtDomain(apiKey, domain);
    } finally {
      lastVtApiRequestEnd = Date.now();
    }
  });
  vtRequestChain = run.then(() => {}).catch(() => {});
  return run;
}

export type VtStatsPayload = {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
};

function guiIpUrl(ip: string) {
  return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`;
}

function isIpv4(s: string): boolean {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return false;
  return s.split('.').every((p) => {
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

async function fetchVtIp(
  apiKey: string,
  ip: string,
): Promise<{
  ip: string;
  ok: boolean;
  guiUrl: string;
  stats?: VtStatsPayload;
  totalEngines?: number;
  error?: string;
}> {
  const guiUrl = guiIpUrl(ip);
  try {
    const r = await fetch(`${VT_API}/ip_addresses/${encodeURIComponent(ip)}`, {
      headers: { 'x-apikey': apiKey },
    });
    if (r.status === 404) {
      return {
        ip,
        ok: true,
        guiUrl,
        stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
        totalEngines: 0,
      };
    }
    if (r.status === 429) {
      return { ip, ok: false, guiUrl, error: 'VirusTotal rate limit (try again in a minute).' };
    }
    if (!r.ok) {
      return { ip, ok: false, guiUrl, error: `VirusTotal HTTP ${r.status}` };
    }
    const j = (await r.json()) as {
      data?: { attributes?: { last_analysis_stats?: Record<string, number> } };
    };
    const s = j?.data?.attributes?.last_analysis_stats ?? {};
    const malicious = Number(s.malicious ?? 0);
    const suspicious = Number(s.suspicious ?? 0);
    const harmless = Number(s.harmless ?? 0);
    const undetected = Number(s.undetected ?? 0);
    const timeout = Number(s.timeout ?? 0) + Number((s as { 'confirmed-timeout'?: number })['confirmed-timeout'] ?? 0);
    const stats: VtStatsPayload = { malicious, suspicious, harmless, undetected, timeout };
    const totalEngines = malicious + suspicious + harmless + undetected + timeout;
    return { ip, ok: true, guiUrl, stats, totalEngines };
  } catch (e) {
    return {
      ip,
      ok: false,
      guiUrl,
      error: e instanceof Error ? e.message : 'VirusTotal request failed',
    };
  }
}

function attachVtMiddleware(
  server: ViteDevServer | PreviewServer,
  apiKey: string | undefined,
  minIntervalMs: number,
) {
  const rawKey = apiKey?.trim();
  // Treat the .env.example placeholder (and empty string) as "no key" so dev
  // reports VT as unconfigured instead of enabling lookups that all 401.
  const key = rawKey && rawKey !== 'YOUR_API_KEY_HERE' ? rawKey : undefined;

  server.middlewares.use((req, res, next) => {
    const rawUrl = req.url ?? '';
    const pathOnly = rawUrl.split('?')[0] ?? '';

    if (req.method === 'GET' && pathOnly === '/api/vt/status') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, configured: Boolean(key) }));
      return;
    }

    if (req.method === 'GET' && pathOnly === '/api/vt/health') {
      void (async () => {
        let virustotalPortalReachable = false;
        try {
          const ac = new AbortController();
          const timer = setTimeout(() => ac.abort(), 6000);
          const r = await fetch('https://www.virustotal.com/', {
            method: 'HEAD',
            signal: ac.signal,
          });
          clearTimeout(timer);
          virustotalPortalReachable =
            r.ok || r.status === 403 || r.status === 405 || r.status === 302 || r.status === 301;
        } catch {
          virustotalPortalReachable = false;
        }
        if (res.writableEnded) return;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            ok: true,
            configured: Boolean(key),
            virustotalPortalReachable,
          }),
        );
      })();
      return;
    }

    if (req.method === 'GET' && pathOnly === '/api/vt/lookup-ip') {
      const u = new URL(rawUrl, 'http://local');
      const ip = (u.searchParams.get('ip') ?? '').trim();

      if (!isIpv4(ip)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ ok: false, error: 'ip must be a valid IPv4 address.' }));
        return;
      }

      if (!key) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            ok: true,
            configured: false,
            result: { ip, guiUrl: guiIpUrl(ip) },
          }),
        );
        return;
      }

      void (async () => {
        try {
          if (isPrivateOrNonRoutableIpv4(ip)) {
            if (res.writableEnded) return;
            res.setHeader('Content-Type', 'application/json');
            res.end(
              JSON.stringify({
                ok: true,
                configured: true,
                result: vtSkippedPrivateIpResult(ip),
              }),
            );
            return;
          }
          const result = await fetchVtIpThrottled(key, ip, minIntervalMs);
          if (res.writableEnded) return;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ ok: true, configured: true, result }));
        } catch (e) {
          if (res.writableEnded) return;
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              ok: false,
              error: e instanceof Error ? e.message : 'lookup-ip failed',
            }),
          );
        }
      })();
      return;
    }

    if (req.method === 'GET' && pathOnly === '/api/vt/lookup') {
      const u = new URL(rawUrl, 'http://local');
      const src = (u.searchParams.get('src') ?? '').trim();
      const dst = (u.searchParams.get('dst') ?? '').trim();

      if (!isIpv4(src) || !isIpv4(dst)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ ok: false, error: 'src and dst must be IPv4 addresses.' }));
        return;
      }

      if (!key) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            ok: true,
            configured: false,
            src: { ip: src, guiUrl: guiIpUrl(src) },
            dst: { ip: dst, guiUrl: guiIpUrl(dst) },
          }),
        );
        return;
      }

      void (async () => {
        try {
          const a = isPrivateOrNonRoutableIpv4(src)
            ? vtSkippedPrivateIpResult(src)
            : await fetchVtIpThrottled(key, src, minIntervalMs);
          const b = isPrivateOrNonRoutableIpv4(dst)
            ? vtSkippedPrivateIpResult(dst)
            : await fetchVtIpThrottled(key, dst, minIntervalMs);
          if (res.writableEnded) return;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ ok: true, configured: true, src: a, dst: b }));
        } catch (e) {
          if (res.writableEnded) return;
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              ok: false,
              error: e instanceof Error ? e.message : 'lookup failed',
            }),
          );
        }
      })();
      return;
    }

    if (req.method === 'GET' && pathOnly === '/api/vt/lookup-domain') {
      const u = new URL(rawUrl, 'http://local');
      const host = (u.searchParams.get('host') ?? '').trim();

      if (!isValidVtDomainHost(host)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ ok: false, error: 'host must be a public-looking domain (not IPv4, not empty).' }));
        return;
      }

      if (!key) {
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            ok: true,
            configured: false,
            result: { domain: host.toLowerCase(), guiUrl: guiDomainUrl(host) },
          }),
        );
        return;
      }

      void (async () => {
        try {
          const result = await fetchVtDomainThrottled(key, host, minIntervalMs);
          if (res.writableEnded) return;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ ok: true, configured: true, result }));
        } catch (e) {
          if (res.writableEnded) return;
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              ok: false,
              error: e instanceof Error ? e.message : 'lookup-domain failed',
            }),
          );
        }
      })();
      return;
    }

    next();
  });
}

/** Dev/preview middleware: /api/vt/status, /api/vt/health, /api/vt/lookup-ip?ip=, /api/vt/lookup-domain?host=, /api/vt/lookup?src=&dst= */
export function virusTotalApiPlugin(opts: VirusTotalPluginOptions): Plugin {
  const minMs = Number.isFinite(opts.minIntervalMs) ? opts.minIntervalMs : 15_000;
  return {
    name: 'mnids-virustotal-api',
    configureServer(server) {
      attachVtMiddleware(server, opts.apiKey, minMs);
    },
    configurePreviewServer(server) {
      attachVtMiddleware(server, opts.apiKey, minMs);
    },
  };
}
