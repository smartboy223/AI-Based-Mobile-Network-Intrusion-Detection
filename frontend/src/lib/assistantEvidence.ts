import type { SystemStats, TrafficLog } from '../types';
import { trafficStatusLabel } from '../types';
import type { VtDomainClientResult, VtIpClientResult } from './virusTotal';
import { vtVerdictScoreLine } from './virusTotal';

export const EVIDENCE_ROW_LIMIT = 22;

function buildIpOccurrences(logs: TrafficLog[]): Record<
  string,
  { asSource: number; asDestination: number; rowsTouchingIp: number }
> {
  const ips = new Set<string>();
  for (const l of logs) {
    ips.add(l.sourceIP);
    ips.add(l.destIP);
  }
  const out: Record<string, { asSource: number; asDestination: number; rowsTouchingIp: number }> = {};
  for (const ip of ips) {
    let asSource = 0;
    let asDestination = 0;
    let rowsTouchingIp = 0;
    for (const l of logs) {
      if (l.sourceIP === ip) asSource += 1;
      if (l.destIP === ip) asDestination += 1;
      if (l.sourceIP === ip || l.destIP === ip) rowsTouchingIp += 1;
    }
    out[ip] = { asSource, asDestination, rowsTouchingIp };
  }
  return out;
}

function topSourceIps(logs: TrafficLog[], limit: number) {
  const m = new Map<string, { rows: number; malicious: number; suspicious: number }>();
  for (const l of logs.slice(0, 120)) {
    const cur = m.get(l.sourceIP) ?? { rows: 0, malicious: 0, suspicious: 0 };
    cur.rows += 1;
    if (l.status === 'Malicious') cur.malicious += 1;
    if (l.status === 'Suspicious') cur.suspicious += 1;
    m.set(l.sourceIP, cur);
  }
  return [...m.entries()]
    .sort((a, b) => b[1].rows - a[1].rows)
    .slice(0, limit)
    .map(([ip, v]) => ({
      ip,
      rowsInTable: v.rows,
      maliciousRows: v.malicious,
      suspiciousRows: v.suspicious,
    }));
}

export function serializeTrafficRowForEvidence(l: TrafficLog) {
  return {
    id: l.id,
    timestamp: l.timestamp,
    sourceIP: l.sourceIP,
    destIP: l.destIP,
    protocol: l.protocol,
    packetSize: l.packetSize,
    duration: l.duration,
    status: l.status,
    statusUiLabel: trafficStatusLabel(l.status),
    attackType: l.attackType ?? null,
    confidence: l.confidence,
    radioAccess: l.radioAccess ?? null,
    upfInterface: l.upfInterface ?? null,
    dnnSlice: l.dnnSlice ?? null,
    fiveQi: l.fiveQi ?? null,
    pduSessionId: l.pduSessionId ?? null,
    ngapNasHint: l.ngapNasHint ?? null,
    trafficPlane: l.trafficPlane ?? null,
    sessionBearerKey: l.sessionBearerKey ?? null,
    operationalCategory: l.operationalCategory ?? null,
    engineeringNote: l.engineeringNote ?? null,
    gtpuTeidHex: l.gtpuTeidHex ?? null,
    innerUeIpv4: l.innerUeIpv4 ?? null,
    rawFrameSample: l.rawFrameSample ?? null,
    analystNote: l.analystNote ?? null,
    analystStatusLocked: l.analystStatusLocked === true,
    dnsQueryNames: l.dnsQueryNames ?? [],
    httpHost: l.httpHost ?? null,
    ja3: l.ja3 ?? null,
    ja3s: l.ja3s ?? null,
    ja3Raw: l.ja3Raw ?? null,
    ja3sRaw: l.ja3sRaw ?? null,
  };
}

function serializeVtForEvidence(r: VtIpClientResult): Record<string, unknown> {
  if (r.skipReason === 'private_ip') {
    return {
      skipReason: 'private_ip',
      ip: r.ip,
      note: 'VirusTotal not queried for private/reserved IPv4.',
    };
  }
  if (!r.ok) {
    return { ip: r.ip, ok: false, error: r.error ?? 'lookup failed' };
  }
  return {
    ip: r.ip,
    ok: true,
    stats: r.stats ?? null,
    totalEngines: r.totalEngines ?? 0,
    malicious: r.stats?.malicious ?? 0,
    suspicious: r.stats?.suspicious ?? 0,
    flaggedVendorCount: r.flagged ?? (r.stats ? r.stats.malicious + r.stats.suspicious : 0),
    verdictLine: vtVerdictScoreLine(r),
  };
}

function vtDomainVerdictLine(r: VtDomainClientResult): string | null {
  if (!r.ok || r.error) return null;
  const m = r.stats?.malicious ?? 0;
  const s = r.stats?.suspicious ?? 0;
  const t = r.totalEngines ?? 0;
  if (t <= 0) return null;
  if (m > 0) return `Malicious ${m}/${t}`;
  if (s > 0) return `Suspicious ${s}/${t}`;
  return `Clean 0/${t}`;
}

function serializeVtDomainForEvidence(r: VtDomainClientResult): Record<string, unknown> {
  if (!r.ok) {
    return { domain: r.domain, ok: false, error: r.error ?? 'lookup failed' };
  }
  return {
    domain: r.domain,
    ok: true,
    stats: r.stats ?? null,
    totalEngines: r.totalEngines ?? 0,
    malicious: r.stats?.malicious ?? 0,
    suspicious: r.stats?.suspicious ?? 0,
    flaggedVendorCount: r.flagged ?? (r.stats ? r.stats.malicious + r.stats.suspicious : 0),
    verdictLine: vtDomainVerdictLine(r),
  };
}

function buildVirusTotalEvidenceMap(
  logs: TrafficLog[],
  vtIpReputation: Record<string, VtIpClientResult>,
): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  const ips = new Set<string>();
  for (const l of logs) {
    ips.add(l.sourceIP);
    ips.add(l.destIP);
  }
  for (const ip of ips) {
    const r = vtIpReputation[ip];
    if (r) out[ip] = serializeVtForEvidence(r);
  }
  return out;
}

function buildVirusTotalDomainEvidenceMap(
  logs: TrafficLog[],
  vtDomainReputation: Record<string, VtDomainClientResult>,
): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  const hosts = new Set<string>();
  for (const l of logs) {
    if (l.httpHost) hosts.add(l.httpHost.trim().toLowerCase());
    for (const d of l.dnsQueryNames ?? []) hosts.add(d.trim().toLowerCase());
  }
  for (const h of hosts) {
    const r = vtDomainReputation[h];
    if (r) out[h] = serializeVtDomainForEvidence(r);
  }
  return out;
}

/**
 * JSON string sent to the LLM as dashboard evidence (traffic slice, optional VT per IP/domain).
 */
export function buildAssistantEvidenceJson(
  logs: TrafficLog[],
  stats: Pick<SystemStats, 'totalTraffic' | 'attacksDetected' | 'suspiciousFlagged'>,
  sessionSavedAt: number | null,
  pinnedTrafficRow: TrafficLog | null,
  vtIpReputation: Record<string, VtIpClientResult>,
  vtDomainReputation: Record<string, VtDomainClientResult> = {},
): string {
  const slice = logs.slice(0, EVIDENCE_ROW_LIMIT);
  const maliciousInTable = logs.filter((l) => l.status === 'Malicious').length;
  const suspiciousInTable = logs.filter((l) => l.status === 'Suspicious').length;
  const virusTotalByIp = buildVirusTotalEvidenceMap(logs, vtIpReputation);
  const virusTotalByDomain = buildVirusTotalDomainEvidenceMap(logs, vtDomainReputation);
  return JSON.stringify(
    {
      summary: {
        rowsInEvidence: slice.length,
        rowsInFullTable: logs.length,
        maliciousRowsInFullTable: maliciousInTable,
        suspiciousRowsInFullTable: suspiciousInTable,
        totalTrafficCounter: stats.totalTraffic,
        attacksDetectedCounter: stats.attacksDetected,
        suspiciousFlaggedCounter: stats.suspiciousFlagged,
        sessionLastSavedIso:
          sessionSavedAt != null ? new Date(sessionSavedAt).toISOString() : null,
        dataSourceNote:
          '5G IDS: dashboard traffic table and PCAP-derived flows in this browser—detection and analysis only, no inline blocking. trafficRows is the first slice only; ipOccurrencesInFullTable covers every row in the full table.',
      },
      virusTotalByIp,
      virusTotalByDomain,
      virusTotalNote:
        'Per-IPv4 VirusTotal last_analysis_stats when the analyst ran VT on this session. Keys are IP strings. Private/reserved IPs appear with skipReason private_ip (no API call, no quota). Already-looked-up public IPs are reused from this map—no duplicate VT requests until you clear session data.',
      virusTotalDomainNote:
        'Per-domain/host VirusTotal stats only for domains that appeared on flows (httpHost, dnsQueryNames) and were looked up (e.g. per-row VT). Bulk Suspicious triage does not auto-query domains to save quota. Keys are lowercase hostnames.',
      pinnedTrafficRow: pinnedTrafficRow ? serializeTrafficRowForEvidence(pinnedTrafficRow) : null,
      pinnedTrafficRowNote: pinnedTrafficRow
        ? 'User attached this single flow for classification help. Prefer this object for row-specific questions.'
        : null,
      mnidsPatchFormatHint:
        'To update the traffic table, output ```mnids-patch { "flowId": "<id>", "patch": { ... } } ```, ```json with the same object, any ``` fenced JSON, or a raw line/object with flowId + patch. When flowId matches the pinned row at send time, the app applies the patch immediately and persists to localStorage.',
      terminologyForAssistant:
        'trafficRows[].status uses "Benign" internally; statusUiLabel uses "Clean" for the same. In natural language to the user, always say Clean, never Benign.',
      ipOccurrencesInFullTable: buildIpOccurrences(logs),
      topSourceIps: topSourceIps(logs, 8),
      trafficRows: slice.map((l) => serializeTrafficRowForEvidence(l)),
    },
    null,
    2,
  );
}
