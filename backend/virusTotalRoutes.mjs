/**
 * Production parity with Vite dev: /api/vt/* — same behavior as frontend/vite-plugins/virusTotalApiPlugin.ts
 */
import express from 'express';

const VT_API = 'https://www.virustotal.com/api/v3';

function guiIpUrl(ip) {
  return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`;
}
function guiDomainUrl(domain) {
  return `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain.trim().toLowerCase())}`;
}
function isIpv4(s) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return false;
  return s.split('.').every((p) => {
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}
function ipv4Octets(s) {
  const t = s.trim();
  if (!isIpv4(t)) return null;
  const parts = t.split('.').map((p) => Number(p));
  return [parts[0], parts[1], parts[2], parts[3]];
}
function isPrivateOrNonRoutableIpv4(ip) {
  const p = ipv4Octets(ip);
  if (!p) return false;
  const [a, b] = p;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}
function vtSkippedPrivateIpResult(ip) {
  const trimmed = ip.trim();
  return {
    ip: trimmed,
    ok: true,
    guiUrl: guiIpUrl(trimmed),
    skipReason: 'private_ip',
  };
}
function isValidVtDomainHost(host) {
  const s = host.trim().toLowerCase();
  if (s.length < 3 || s.length > 253) return false;
  if (isIpv4(s)) return false;
  if (s.includes('..') || s.startsWith('.') || s.endsWith('.')) return false;
  return /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(s);
}

let vtRequestChain = Promise.resolve();
let lastVtApiRequestEnd = 0;
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchVtIp(apiKey, ip) {
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
    const j = await r.json();
    const s = j?.data?.attributes?.last_analysis_stats ?? {};
    const malicious = Number(s.malicious ?? 0);
    const suspicious = Number(s.suspicious ?? 0);
    const harmless = Number(s.harmless ?? 0);
    const undetected = Number(s.undetected ?? 0);
    const timeout =
      Number(s.timeout ?? 0) + Number(s['confirmed-timeout'] ?? 0);
    const stats = { malicious, suspicious, harmless, undetected, timeout };
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

async function fetchVtDomain(apiKey, domain) {
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
    const j = await r.json();
    const s = j?.data?.attributes?.last_analysis_stats ?? {};
    const malicious = Number(s.malicious ?? 0);
    const suspicious = Number(s.suspicious ?? 0);
    const harmless = Number(s.harmless ?? 0);
    const undetected = Number(s.undetected ?? 0);
    const timeout =
      Number(s.timeout ?? 0) + Number(s['confirmed-timeout'] ?? 0);
    const stats = { malicious, suspicious, harmless, undetected, timeout };
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

function fetchVtIpThrottled(apiKey, ip, minIntervalMs) {
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

function fetchVtDomainThrottled(apiKey, domain, minIntervalMs) {
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

/**
 * @param {{ apiKey?: string; minIntervalMs?: number }} opts
 */
export function createVirusTotalRouter(opts) {
  const rawKey = opts.apiKey?.trim();
  // Treat the .env.example placeholder (and empty string) as "no key", so the
  // dashboard reports VT as unconfigured instead of enabling lookups that all
  // fail with HTTP 401 against VirusTotal.
  const key = rawKey && rawKey !== 'YOUR_API_KEY_HERE' ? rawKey : undefined;
  const minIntervalMs = Math.max(1000, Number(opts.minIntervalMs) || 15_000);
  const router = express.Router();

  router.get('/status', (_req, res) => {
    res.json({ ok: true, configured: Boolean(key) });
  });

  router.get('/health', async (_req, res) => {
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
    res.json({
      ok: true,
      configured: Boolean(key),
      virustotalPortalReachable,
    });
  });

  router.get('/lookup-ip', async (req, res) => {
    const ip = (req.query.ip ?? '').toString().trim();
    if (!isIpv4(ip)) {
      return res.status(400).json({ ok: false, error: 'ip must be a valid IPv4 address.' });
    }
    if (!key) {
      return res.json({
        ok: true,
        configured: false,
        result: { ip, guiUrl: guiIpUrl(ip) },
      });
    }
    try {
      if (isPrivateOrNonRoutableIpv4(ip)) {
        return res.json({
          ok: true,
          configured: true,
          result: vtSkippedPrivateIpResult(ip),
        });
      }
      const result = await fetchVtIpThrottled(key, ip, minIntervalMs);
      return res.json({ ok: true, configured: true, result });
    } catch (e) {
      return res.status(500).json({
        ok: false,
        error: e instanceof Error ? e.message : 'lookup-ip failed',
      });
    }
  });

  router.get('/lookup', async (req, res) => {
    const src = (req.query.src ?? '').toString().trim();
    const dst = (req.query.dst ?? '').toString().trim();
    if (!isIpv4(src) || !isIpv4(dst)) {
      return res.status(400).json({ ok: false, error: 'src and dst must be IPv4 addresses.' });
    }
    if (!key) {
      return res.json({
        ok: true,
        configured: false,
        src: { ip: src, guiUrl: guiIpUrl(src) },
        dst: { ip: dst, guiUrl: guiIpUrl(dst) },
      });
    }
    try {
      const a = isPrivateOrNonRoutableIpv4(src)
        ? vtSkippedPrivateIpResult(src)
        : await fetchVtIpThrottled(key, src, minIntervalMs);
      const b = isPrivateOrNonRoutableIpv4(dst)
        ? vtSkippedPrivateIpResult(dst)
        : await fetchVtIpThrottled(key, dst, minIntervalMs);
      return res.json({ ok: true, configured: true, src: a, dst: b });
    } catch (e) {
      return res.status(500).json({
        ok: false,
        error: e instanceof Error ? e.message : 'lookup failed',
      });
    }
  });

  router.get('/lookup-domain', async (req, res) => {
    const host = (req.query.host ?? '').toString().trim();
    if (!isValidVtDomainHost(host)) {
      return res.status(400).json({
        ok: false,
        error: 'host must be a public-looking domain (not IPv4, not empty).',
      });
    }
    if (!key) {
      return res.json({
        ok: true,
        configured: false,
        result: { domain: host.toLowerCase(), guiUrl: guiDomainUrl(host) },
      });
    }
    try {
      const result = await fetchVtDomainThrottled(key, host, minIntervalMs);
      return res.json({ ok: true, configured: true, result });
    } catch (e) {
      return res.status(500).json({
        ok: false,
        error: e instanceof Error ? e.message : 'lookup-domain failed',
      });
    }
  });

  return router;
}
