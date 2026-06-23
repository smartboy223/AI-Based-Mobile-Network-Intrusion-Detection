/**
 * Suspicious-flow triage from VirusTotal + lab ML scores (RF / IF / AE) — no external LLM.
 * Aligns with MNIDS “machine learning and flow” analysis; optional DeepSeek is only for chat / exports.
 */
import type { ParsedMnidsPatch, TrafficRowAiPatch } from './assistantPatch';
import type { TrafficLog, TrafficStatus } from '../types';
import { isPrivateOrNonRoutableIpv4, isVtResultComplete, type VtIpClientResult } from './virusTotal';

const IF_HIGH = 0.72;
const AE_HIGH = 0.72;
const IF_EXTREME = 0.88;
const AE_EXTREME = 0.88;

/** Public IPv4 has completed VT with 0 malicious + 0 suspicious (engines ran). */
function publicIpVtIsClean(ip: string, vt: Record<string, VtIpClientResult>): boolean {
  if (isPrivateOrNonRoutableIpv4(ip)) return true;
  const r = vt[ip];
  if (!isVtResultComplete(r)) return false;
  if (r.skipReason === 'private_ip') return true;
  if (!r.ok) return false;
  const t = r.totalEngines ?? 0;
  if (t <= 0) return false;
  const m = r.stats?.malicious ?? 0;
  const s = r.stats?.suspicious ?? 0;
  return m === 0 && s === 0;
}

/** True when we can treat both endpoints as non-threatening from VT (private OK; public must be clean when resolved). */
function vtEndpointsAllowBenign(log: TrafficLog, vt: Record<string, VtIpClientResult>): boolean {
  const srcOk = publicIpVtIsClean(log.sourceIP, vt);
  const dstOk = publicIpVtIsClean(log.destIP, vt);
  return srcOk && dstOk;
}

/** Any public IP has VT populated with malicious or suspicious hits. */
function vtShowsMaliciousHit(log: TrafficLog, vt: Record<string, VtIpClientResult>): boolean {
  for (const ip of [log.sourceIP, log.destIP]) {
    if (isPrivateOrNonRoutableIpv4(ip)) continue;
    const r = vt[ip];
    if (!isVtResultComplete(r) || !r.ok || !r.stats) continue;
    if ((r.stats.malicious ?? 0) + (r.stats.suspicious ?? 0) > 0) return true;
  }
  return false;
}

/** Public endpoint(s) missing a finished VT verdict (rate limit / offline). */
function vtIncompleteAnyPublic(log: TrafficLog, vt: Record<string, VtIpClientResult>): boolean {
  for (const ip of [log.sourceIP, log.destIP]) {
    if (isPrivateOrNonRoutableIpv4(ip)) continue;
    const r = vt[ip];
    if (!isVtResultComplete(r)) return true;
  }
  return false;
}

function decideStatus(log: TrafficLog, vt: Record<string, VtIpClientResult>): {
  status: TrafficStatus;
  note: string;
  confidence: number;
} {
  const rf = log.mlRandomForestStatus;
  const rfc = log.mlRandomForestConfidence ?? 0;
  const ifs = log.mlIsolationAnomalyScore;
  const aes = log.mlAutoencoderAnomalyScore;
  const vtBenignOk = vtEndpointsAllowBenign(log, vt);
  const vtBad = vtShowsMaliciousHit(log, vt);

  const ifHigh = ifs != null && ifs >= IF_HIGH;
  const aeHigh = aes != null && aes >= AE_HIGH;
  const ifExtreme = ifs != null && ifs >= IF_EXTREME;
  const aeExtreme = aes != null && aes >= AE_EXTREME;

  if (vtBad) {
    return {
      status: 'Malicious',
      note:
        'VirusTotal reported malicious or suspicious detections on at least one public IP; escalation recommended.',
      confidence: 0.88,
    };
  }

  if (rf === 'Malicious' && rfc >= 0.42) {
    return {
      status: 'Malicious',
      note: `Lab Random Forest suggests Malicious (confidence ${rfc.toFixed(2)}); align analyst view with VirusTotal when available.`,
      confidence: Math.min(0.95, 0.55 + rfc * 0.4),
    };
  }

  if (ifExtreme || aeExtreme || (ifHigh && aeHigh)) {
    return {
      status: 'Malicious',
      note: `High anomaly scores (Isolation Forest ${ifs?.toFixed(3) ?? 'n/a'}, autoencoder ${aes?.toFixed(3) ?? 'n/a'}); treat as high risk.`,
      confidence: 0.82,
    };
  }

  if (vtBenignOk && rf === 'Benign' && !ifHigh && !aeHigh) {
    return {
      status: 'Benign',
      note:
        'VirusTotal shows no detections on resolved public IPs; ML classifier Benign and anomaly scores low — closed as Clean (review if context changes).',
      confidence: 0.86,
    };
  }

  if (vtBenignOk && rf !== 'Malicious' && (ifs == null || ifs < 0.55) && (aes == null || aes < 0.55)) {
    return {
      status: 'Benign',
      note:
        'VT clean on public IPs and no strong ML anomaly signal; downgraded to Clean with analyst review suggested if traffic pattern shifts.',
      confidence: 0.78,
    };
  }

  const vtIncomplete = vtIncompleteAnyPublic(log, vt);
  const note =
    vtIncomplete || !vtBenignOk
      ? `Escalated (conservative): VirusTotal incomplete or unresolved on one or more public IPs — cannot safely close as Clean. RF=${rf ?? 'n/a'} (conf ${rfc.toFixed(2)}), IF=${ifs?.toFixed(3) ?? 'n/a'}, AE=${aes?.toFixed(3) ?? 'n/a'}. Retry VT when rate limits allow, then re-triage row.`
      : `Escalated by policy (no lingering Suspicious state): RF=${rf ?? 'n/a'} (conf ${rfc.toFixed(2)}), IF=${ifs?.toFixed(3) ?? 'n/a'}, AE=${aes?.toFixed(3) ?? 'n/a'}; VT clean on resolved public IPs but ML signal inconclusive for Clean closure — confirm manually if needed.`;
  return {
    status: 'Malicious',
    note,
    confidence: 0.62,
  };
}

export function triageSuspiciousWithMlAndVt(
  log: TrafficLog,
  vtIp: Record<string, VtIpClientResult>,
): { markdown: string; parsed: ParsedMnidsPatch | null } {
  const { status, note, confidence } = decideStatus(log, vtIp);

  const patch: TrafficRowAiPatch = {
    status,
    analystNote: `[ML + flow triage] ${note}`,
    confidence,
    attackType:
      status === 'Benign'
        ? 'Closed as Clean (ML + VT)'
        : status === 'Malicious'
          ? 'Escalated (ML + VT)'
          : 'Review — ML + VT inconclusive',
  };

  const payload: ParsedMnidsPatch = { flowId: log.id, patch };
  const lines = [
    '### Auto triage (VirusTotal + ML flows)',
    '',
    'This recommendation uses **VirusTotal** (when keys/cache allow) and **lab ML scores** on this row (Random Forest, Isolation Forest, autoencoder). No external LLM is required.',
    '',
    `- **Source → dest:** \`${log.sourceIP}\` → \`${log.destIP}\``,
    `- **RF:** ${log.mlRandomForestStatus ?? '—'}${log.mlRandomForestConfidence != null ? ` (conf ${log.mlRandomForestConfidence.toFixed(2)})` : ''}`,
    `- **IF anomaly:** ${log.mlIsolationAnomalyScore != null ? log.mlIsolationAnomalyScore.toFixed(3) : '—'}`,
    `- **AE anomaly:** ${log.mlAutoencoderAnomalyScore != null ? log.mlAutoencoderAnomalyScore.toFixed(3) : '—'}`,
    '',
    `**Suggested status:** **${status === 'Benign' ? 'Clean (Benign)' : status}**`,
    '',
    '```mnids-patch',
    JSON.stringify(payload, null, 2),
    '```',
    '',
  ];

  return { markdown: lines.join('\n'), parsed: payload };
}

/** When bulk triage runs without an LLM, produce a short ML-focused summary from outcomes. */
export function bulkTriageSummaryPlaceholder(
  rows: Array<{ log: TrafficLog; parsed: ParsedMnidsPatch | null }>,
): string {
  const lines = [
    '## Consolidated triage summary (template — no LLM)',
    '',
    'Review each flow’s analyst notes and ML scores in the table. This section summarizes suggested outcomes when external LLM narrative is unavailable.',
    '',
    ...rows.map((r, i) => {
      const st = r.parsed?.patch.status ?? r.log.status;
      return `${i + 1}. \`${r.log.sourceIP}\` → \`${r.log.destIP}\` → **${st}** (flow \`${r.log.id}\`)`;
    }),
  ];
  return lines.join('\n');
}
