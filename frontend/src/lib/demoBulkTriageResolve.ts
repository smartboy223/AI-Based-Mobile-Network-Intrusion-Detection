import type { TrafficLog } from '../types';
import { applyPatchToTrafficLog, type ParsedMnidsPatch } from './assistantPatch';
import {
  isPrivateOrNonRoutableIpv4,
  isVtResultComplete,
  type VtIpClientResult,
} from './virusTotal';

/** Suspicious rows tagged from demo “lab public IP” heuristics (PCAP / demo list). */
function isDemoLabSuspiciousRow(log: TrafficLog): boolean {
  if (log.status !== 'Suspicious') return false;
  const a = (log.attackType ?? '').toLowerCase();
  return (
    a.includes('vt lab') ||
    a.includes('lab public') ||
    a.includes('suspicious — use vt') ||
    a.includes('use vt column to score')
  );
}

/** Public IP has completed VT with 0 malicious and 0 suspicious (engines ran). */
function publicIpVtIsClean(ip: string, vt: Record<string, VtIpClientResult>): boolean {
  if (isPrivateOrNonRoutableIpv4(ip)) return true;
  const r = vt[ip];
  if (!isVtResultComplete(r)) return false;
  if (r!.skipReason === 'private_ip') return true;
  if (!r!.ok) return false;
  const t = r!.totalEngines ?? 0;
  if (t <= 0) return false;
  const m = r!.stats?.malicious ?? 0;
  const s = r!.stats?.suspicious ?? 0;
  return m === 0 && s === 0;
}

/**
 * After bulk AI patches: close remaining demo “lab Suspicious” rows when VT shows clean public IPs.
 * Does not downgrade Malicious or analyst-locked Clean rows.
 */
export function demoCloseLabSuspiciousWithCleanVt(
  logs: TrafficLog[],
  vt: Record<string, VtIpClientResult>,
): TrafficLog[] {
  return logs.map((log) => {
    if (!isDemoLabSuspiciousRow(log)) return log;
    if (log.analystStatusLocked === true) return log;
    if (!publicIpVtIsClean(log.sourceIP, vt) || !publicIpVtIsClean(log.destIP, vt)) {
      return log;
    }
    return applyPatchToTrafficLog(log, {
      status: 'Benign',
      analystNote:
        'Bulk triage (demo): VirusTotal showed 0 malicious / 0 suspicious on queried public IPs; row closed as Clean.',
      confidence: 0.9,
      attackType: 'Closed as Clean (VT clean, lab demo)',
    });
  });
}

/** Merge AI mnids-patch results then apply demo VT-clean closure (same order as bulk triage UI). */
export function applyBulkTriageToLogs(
  prev: TrafficLog[],
  rowResults: Array<{ log: TrafficLog; parsed: ParsedMnidsPatch | null }>,
  vt: Record<string, VtIpClientResult>,
): TrafficLog[] {
  const byId = new Map(prev.map((l) => [l.id, l]));
  for (const r of rowResults) {
    if (r.parsed?.flowId === r.log.id) {
      const cur = byId.get(r.parsed.flowId);
      if (cur) byId.set(cur.id, applyPatchToTrafficLog(cur, r.parsed.patch));
    }
  }
  const merged = prev.map((l) => byId.get(l.id) ?? l);
  return demoCloseLabSuspiciousWithCleanVt(merged, vt);
}
