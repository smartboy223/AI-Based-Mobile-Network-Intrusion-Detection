import type { TrafficLog } from '../types';
import { normalizeHostForVt } from './flowDeepParse';

/** VirusTotal GUI deep link for an IPv4 (browser only; no API quota). */
export function vtGuiIpUrl(ip: string): string {
  return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip.trim())}`;
}

/** VirusTotal GUI deep link for a domain / hostname. */
export function vtGuiDomainUrl(domain: string): string {
  return `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain.trim().toLowerCase())}`;
}

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function ipv4Octets(s: string): [number, number, number, number] | null {
  const t = s.trim();
  if (!IPV4_RE.test(t)) return null;
  const parts = t.split('.').map((p) => Number(p));
  if (parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  return [parts[0], parts[1], parts[2], parts[3]];
}

/**
 * RFC1918, loopback, link-local, and CGNAT — VT IP reports are meaningless (often “clean”).
 */
export function isPrivateOrNonRoutableIpv4(ip: string): boolean {
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

export type VtStatsPayload = {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
};

export type VtIpClientResult = {
  ip: string;
  ok: boolean;
  guiUrl: string;
  stats?: VtStatsPayload;
  totalEngines?: number;
  /** Detections flagged malicious + suspicious (for display ratio) */
  flagged?: number;
  error?: string;
  /** No VT API call — private/reserved IPv4; do not treat as a reputation verdict */
  skipReason?: 'private_ip';
};

export type VtLookupResponse =
  | {
      ok: true;
      configured: false;
      src: { ip: string; guiUrl: string };
      dst: { ip: string; guiUrl: string };
    }
  | {
      ok: true;
      configured: true;
      src: VtIpClientResult;
      dst: VtIpClientResult;
    }
  | { ok: false; error: string };

export function enrichVtClientResult(r: VtIpClientResult): VtIpClientResult {
  if (r.skipReason === 'private_ip') return r;
  if (!r.stats) return r;
  const flagged = r.stats.malicious + r.stats.suspicious;
  return { ...r, flagged };
}

/** True if we already have a stored verdict for this IP (private skip, completed API response, or recorded error). No new VT API call needed. */
export function isVtResultComplete(rep: VtIpClientResult | undefined): boolean {
  if (rep == null) return false;
  if (rep.skipReason === 'private_ip') return true;
  if (!rep.ok) return Boolean(rep.error && rep.error.length > 0);
  return typeof rep.totalEngines === 'number';
}

/** Client/server: placeholder when VT must not be queried for this address. */
export function vtSkippedPrivateIpResult(ip: string): VtIpClientResult {
  const trimmed = ip.trim();
  return {
    ip: trimmed,
    ok: true,
    guiUrl: vtGuiIpUrl(trimmed),
    skipReason: 'private_ip',
  };
}

export async function fetchVtStatus(): Promise<{ configured: boolean }> {
  try {
    const res = await fetch('/api/vt/status');
    const j = (await res.json()) as { ok?: boolean; configured?: boolean };
    return { configured: Boolean(j.configured) };
  } catch {
    return { configured: false };
  }
}

/** Dev-server check: portal reachability + whether VIRUSTOTAL_API_KEY is loaded (key is never exposed). */
export async function fetchVtHealth(): Promise<{
  ok: boolean;
  configured: boolean;
  virustotalPortalReachable: boolean;
}> {
  try {
    const res = await fetch('/api/vt/health');
    const j = (await res.json()) as {
      ok?: boolean;
      configured?: boolean;
      virustotalPortalReachable?: boolean;
    };
    return {
      ok: Boolean(j.ok),
      configured: Boolean(j.configured),
      virustotalPortalReachable: Boolean(j.virustotalPortalReachable),
    };
  } catch {
    return { ok: false, configured: false, virustotalPortalReachable: false };
  }
}

export type MutateVtRep = (
  fn: (prev: Record<string, VtIpClientResult>) => Record<string, VtIpClientResult>,
) => void;

/** One public IPv4 lookup (throttled on server). Private IPs should use ensureVtForTrafficRow / client skip. */
export async function fetchVtLookupSingleIp(
  ip: string,
  signal?: AbortSignal,
): Promise<
  | { ok: true; configured: true; result: VtIpClientResult }
  | { ok: true; configured: false; result: { ip: string; guiUrl: string } }
  | { ok: false; error: string }
> {
  const res = await fetch(`/api/vt/lookup-ip?${new URLSearchParams({ ip: ip.trim() })}`, {
    signal,
  });
  let body: {
    ok?: boolean;
    error?: string;
    configured?: boolean;
    result?: VtIpClientResult | { ip: string; guiUrl: string };
  };
  try {
    body = (await res.json()) as typeof body;
  } catch {
    return { ok: false, error: `HTTP ${res.status}` };
  }
  if (!body.ok) return { ok: false, error: body.error ?? `HTTP ${res.status}` };
  if (!body.configured && body.result && 'guiUrl' in body.result && !('ok' in body.result)) {
    return { ok: true, configured: false, result: body.result as { ip: string; guiUrl: string } };
  }
  if (body.configured && body.result && typeof body.result === 'object' && 'ok' in body.result) {
    return {
      ok: true,
      configured: true,
      result: enrichVtClientResult(body.result as VtIpClientResult),
    };
  }
  return { ok: false, error: 'Unexpected VirusTotal lookup-ip response' };
}

/**
 * Fills vtIpRep for src/dst without redundant VT API calls: private/reserved IPs are stored locally
 * (no network, no quota). Public IPs already in rep with a complete result are skipped.
 */
export async function ensureVtForTrafficRow(
  sourceIP: string,
  destIP: string,
  getVtRep: () => Record<string, VtIpClientResult>,
  mutateVtRep: MutateVtRep,
  vtApiConfigured: boolean,
  signal?: AbortSignal,
): Promise<void> {
  async function touchIp(ip: string) {
    const trimmed = ip.trim();
    if (isPrivateOrNonRoutableIpv4(trimmed)) {
      if (!isVtResultComplete(getVtRep()[trimmed])) {
        const v = enrichVtClientResult(vtSkippedPrivateIpResult(trimmed));
        mutateVtRep((p) => (isVtResultComplete(p[trimmed]) ? p : { ...p, [trimmed]: v }));
      }
      return;
    }
    if (isVtResultComplete(getVtRep()[trimmed])) return;
    if (!vtApiConfigured) return;
    const out = await fetchVtLookupSingleIp(trimmed, signal);
    if (!out.ok) {
      mutateVtRep((p) =>
        isVtResultComplete(p[trimmed])
          ? p
          : {
              ...p,
              [trimmed]: enrichVtClientResult({
                ip: trimmed,
                ok: false,
                guiUrl: vtGuiIpUrl(trimmed),
                error: out.error,
              }),
            },
      );
      return;
    }
    if (!out.configured) return;
    mutateVtRep((p) =>
      isVtResultComplete(p[trimmed]) ? p : { ...p, [trimmed]: out.result },
    );
  }

  await touchIp(sourceIP);
  await touchIp(destIP);
}

export async function fetchVtLookupForRow(sourceIP: string, destIP: string): Promise<VtLookupResponse> {
  const q = new URLSearchParams({ src: sourceIP, dst: destIP });
  const res = await fetch(`/api/vt/lookup?${q.toString()}`);
  let body: {
    ok?: boolean;
    error?: string;
    configured?: boolean;
    src?: VtIpClientResult;
    dst?: VtIpClientResult;
  };
  try {
    body = (await res.json()) as typeof body;
  } catch {
    return { ok: false, error: `HTTP ${res.status}` };
  }
  if (!body.ok) {
    return { ok: false, error: body.error ?? `HTTP ${res.status}` };
  }
  if (!body.configured && body.src && body.dst) {
    return { ok: true, configured: false, src: body.src, dst: body.dst };
  }
  if (body.configured && body.src && body.dst) {
    return {
      ok: true,
      configured: true,
      src: enrichVtClientResult(body.src),
      dst: enrichVtClientResult(body.dst),
    };
  }
  return { ok: false, error: 'Unexpected VirusTotal response' };
}

export function vtIpCellClass(rep: VtIpClientResult | undefined, density: 'default' | 'compact' = 'default'): string {
  const pad = density === 'compact' ? 'px-1 py-0.5' : 'px-1.5 py-0.5';
  if (!rep) return '';
  if (rep.skipReason === 'private_ip') {
    return `rounded ${pad} bg-[#2a2a32]/60 text-[#9a9aa8] ring-1 ring-[#3d3d48]`;
  }
  if (!rep.ok || rep.error) {
    return `rounded ${pad} bg-[var(--surface-hover)]/50 text-[var(--text-secondary)] ring-1 ring-[var(--border-strong)]`;
  }
  const m = rep.stats?.malicious ?? 0;
  const s = rep.stats?.suspicious ?? 0;
  if (m > 0) return `rounded ${pad} bg-red-500/25 text-red-900 ring-1 ring-red-500/40`;
  if (s > 0) return `rounded ${pad} bg-amber-500/20 text-amber-950 ring-1 ring-amber-500/35`;
  const total = rep.totalEngines ?? 0;
  if (total > 0) return `rounded ${pad} bg-emerald-500/15 text-emerald-900 ring-1 ring-emerald-500/25`;
  return '';
}

/** VirusTotal GUI style: verdict + malicious-or-role count over total engines (e.g. Malicious 15/94). */
export function vtVerdictScoreLine(rep: VtIpClientResult | undefined): string | null {
  if (rep?.skipReason === 'private_ip') return null;
  if (!rep?.ok || rep.error) return null;
  const m = rep.stats?.malicious ?? 0;
  const s = rep.stats?.suspicious ?? 0;
  const t = rep.totalEngines ?? 0;
  if (t <= 0) return null;
  if (m > 0) return `Malicious ${m}/${t}`;
  if (s > 0) return `Suspicious ${s}/${t}`;
  return `Clean 0/${t}`;
}

export type VtIpFieldFooter = {
  tag: string;
  line: string;
  lineClassName: string;
};

/** Src/Dst column footer after a VT lookup: “Analyzed” + VT-style line (e.g. Malicious 15/94). */
export function vtIpFieldFooter(rep: VtIpClientResult | undefined): VtIpFieldFooter {
  if (!rep) {
    return { tag: '—', line: 'Not analyzed', lineClassName: 'text-[#5c5c66]' };
  }
  if (rep.skipReason === 'private_ip') {
    return {
      tag: 'Skipped',
      line: 'Private / reserved IP — VirusTotal not used',
      lineClassName: 'text-[#8b8b96] truncate',
    };
  }
  if (!rep.ok || rep.error) {
    return {
      tag: 'Analyzed',
      line: rep.error ?? 'Error',
      lineClassName: 'text-amber-900 truncate',
    };
  }
  const line = vtVerdictScoreLine(rep);
  if (!line) {
    return {
      tag: 'Analyzed',
      line: 'No engine data',
      lineClassName: 'text-[var(--text-secondary)]',
    };
  }
  const m = rep.stats?.malicious ?? 0;
  const s = rep.stats?.suspicious ?? 0;
  let lineClassName = 'text-emerald-800 font-semibold';
  if (m > 0) lineClassName = 'text-red-800 font-semibold';
  else if (s > 0) lineClassName = 'text-amber-900 font-semibold';
  return { tag: 'Analyzed', line, lineClassName };
}

/** Per-domain VirusTotal client result (same stats shape as IPv4). */
export type VtDomainClientResult = {
  domain: string;
  ok: boolean;
  guiUrl: string;
  stats?: VtStatsPayload;
  totalEngines?: number;
  flagged?: number;
  error?: string;
};

export function enrichVtDomainResult(r: VtDomainClientResult): VtDomainClientResult {
  if (!r.stats) return r;
  const flagged = r.stats.malicious + r.stats.suspicious;
  return { ...r, flagged };
}

export function isVtDomainResultComplete(rep: VtDomainClientResult | undefined): boolean {
  if (rep == null) return false;
  if (!rep.ok) return Boolean(rep.error && rep.error.length > 0);
  return typeof rep.totalEngines === 'number';
}

export async function fetchVtLookupSingleDomain(
  domain: string,
  signal?: AbortSignal,
): Promise<
  | { ok: true; configured: true; result: VtDomainClientResult }
  | { ok: true; configured: false; result: { domain: string; guiUrl: string } }
  | { ok: false; error: string }
> {
  const res = await fetch(`/api/vt/lookup-domain?${new URLSearchParams({ host: domain.trim() })}`, {
    signal,
  });
  let body: {
    ok?: boolean;
    error?: string;
    configured?: boolean;
    result?: VtDomainClientResult | { domain: string; guiUrl: string };
  };
  try {
    body = (await res.json()) as typeof body;
  } catch {
    return { ok: false, error: `HTTP ${res.status}` };
  }
  if (!body.ok) return { ok: false, error: body.error ?? `HTTP ${res.status}` };
  if (!body.configured && body.result && 'guiUrl' in body.result && !('ok' in body.result)) {
    return {
      ok: true,
      configured: false,
      result: body.result as { domain: string; guiUrl: string },
    };
  }
  if (body.configured && body.result && typeof body.result === 'object' && 'ok' in body.result) {
    return {
      ok: true,
      configured: true,
      result: enrichVtDomainResult(body.result as VtDomainClientResult),
    };
  }
  return { ok: false, error: 'Unexpected VirusTotal lookup-domain response' };
}

export type MutateVtDomainRep = (
  fn: (prev: Record<string, VtDomainClientResult>) => Record<string, VtDomainClientResult>,
) => void;

/**
 * Domains worth VT lookup for a row: HTTP Host first, then DNS QNAMEs, de-duplicated, capped (quota-smart).
 * Skips localhost, .local, IPv4-looking hosts, etc. via normalizeHostForVt.
 */
export function collectVtDomainTargetsFromLog(log: TrafficLog, maxDomains = 2): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (raw: string | null | undefined) => {
    const n = raw ? normalizeHostForVt(raw) : null;
    if (!n || seen.has(n)) return;
    seen.add(n);
    out.push(n);
  };
  add(log.httpHost);
  for (const d of log.dnsQueryNames ?? []) add(d);
  return out.slice(0, maxDomains);
}

/**
 * Fills vtDomainRep only for public-looking domains on the row; skips when none; reuses complete cache entries.
 */
export async function ensureVtDomainsForLog(
  log: TrafficLog,
  getVtDomainRep: () => Record<string, VtDomainClientResult>,
  mutateVtDomainRep: MutateVtDomainRep,
  vtApiConfigured: boolean,
  opts?: { maxDomains?: number; signal?: AbortSignal },
): Promise<void> {
  if (!vtApiConfigured) return;
  const targets = collectVtDomainTargetsFromLog(log, opts?.maxDomains ?? 2);
  if (targets.length === 0) return;

  for (const host of targets) {
    const trimmed = host.trim().toLowerCase();
    if (isVtDomainResultComplete(getVtDomainRep()[trimmed])) continue;
    const out = await fetchVtLookupSingleDomain(trimmed, opts?.signal);
    if (!out.ok) {
      mutateVtDomainRep((p) =>
        isVtDomainResultComplete(p[trimmed])
          ? p
          : {
              ...p,
              [trimmed]: enrichVtDomainResult({
                domain: trimmed,
                ok: false,
                guiUrl: vtGuiDomainUrl(trimmed),
                error: out.error,
              }),
            },
      );
      continue;
    }
    if (!out.configured) continue;
    mutateVtDomainRep((p) =>
      isVtDomainResultComplete(p[trimmed]) ? p : { ...p, [trimmed]: out.result },
    );
  }
}
