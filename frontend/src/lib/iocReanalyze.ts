import type { TrafficLog } from '../types';
import { ensureTelecomFields } from './telecom5gFields';

/**
 * Older saves: Clean + note mentioning AI triage → enable lock so Scan respects analyst sign-off.
 */
export function migrateLegacyAnalystCleanLocks(logs: TrafficLog[]): TrafficLog[] {
  return logs.map((l) => {
    let x = l;
    if (l.analystStatusLocked !== true && l.status === 'Benign') {
      const n = (l.analystNote ?? '').toLowerCase();
      if (
        n.includes('edited by ai') ||
        n.includes('by ai') ||
        n.includes('ai review') ||
        n.includes('ai triage') ||
        n.includes('changed by ai')
      ) {
        x = { ...l, analystStatusLocked: true };
      }
    }
    return ensureTelecomFields(x);
  });
}
