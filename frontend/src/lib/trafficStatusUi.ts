import type { TrafficLog, TrafficStatus } from '../types';

/** Plain-language line for the traffic table status column. */
export function trafficStatusLabel(log: TrafficLog): string {
  if (log.status === 'Malicious') return `ALERT: ${log.attackType ?? 'Threat detected'}`;
  if (log.status === 'Suspicious') return `REVIEW: ${log.attackType ?? 'Unusual pattern'}`;
  return 'Clean';
}

export function trafficStatusDotClass(status: TrafficStatus): string {
  if (status === 'Malicious') return 'bg-[#f72585] animate-pulse';
  if (status === 'Suspicious') return 'bg-[#fbbf24] animate-pulse';
  return 'bg-[#4ade80]';
}

export function trafficStatusTextClass(status: TrafficStatus): string {
  if (status === 'Malicious') return 'text-[#f72585]';
  if (status === 'Suspicious') return 'text-[#fbbf24]';
  return 'text-[#4ade80]';
}

export function trafficStatusRowClass(status: TrafficStatus): string {
  if (status === 'Malicious') return 'bg-red-500/5';
  if (status === 'Suspicious') return 'bg-amber-500/5';
  return '';
}

export function trafficConfBarClass(status: TrafficStatus): string {
  if (status === 'Malicious') return 'bg-[#f72585]';
  if (status === 'Suspicious') return 'bg-[#fbbf24]';
  return 'bg-[#4ade80]';
}

/** Excel / export-friendly status word (keeps types distinct from UI wording). */
export function trafficStatusExportWord(status: TrafficStatus): string {
  if (status === 'Malicious') return 'MALICIOUS';
  if (status === 'Suspicious') return 'SUSPICIOUS';
  return 'CLEAN';
}
