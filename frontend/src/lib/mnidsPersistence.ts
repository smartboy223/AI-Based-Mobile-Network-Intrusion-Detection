import type { TrafficLog, SystemStats } from '../types';
import type { VtDomainClientResult, VtIpClientResult } from './virusTotal';

const STORAGE_KEY = 'mnids-dashboard-v1';

/**
 * Data is saved after every ingest / edit / refresh into localStorage. Auto-
 * restore on browser F5 is gated by `serverBootId`: the snapshot is paired
 * with the boot ID that `/api/health` returned at save time, and we only
 * auto-restore when the live server reports the same ID. A server restart
 * (a fresh START.bat run) mints a new boot ID and the snapshot is treated
 * as stale — so refreshing the browser preserves results, but closing the
 * launcher window clears them. The `?fresh=1` URL param still force-wipes,
 * and `?restore=1` still works for cross-server-life manual recovery.
 */
export const MNIDS_TAB_SESSION_KEY = 'mnids-tab-session';

export type MnidsPersistedV1 = {
  v: 1;
  logs: TrafficLog[];
  chartData: { time: string; traffic: number; attacks: number; suspicious?: number }[];
  stats: Pick<SystemStats, 'totalTraffic' | 'attacksDetected' | 'suspiciousFlagged'>;
  /** Saved VirusTotal lookups keyed by IPv4; restored on load. */
  vtIpReputation?: Record<string, VtIpClientResult>;
  /** Saved VirusTotal domain lookups keyed by lowercase hostname. */
  vtDomainReputation?: Record<string, VtDomainClientResult>;
  savedAt: number;
  /** Boot ID of the Express backend at save time. Compared against /api/health.serverBootId on next load. */
  serverBootId?: string;
};

function normalizePersistedLog(log: TrafficLog): TrafficLog {
  // Backward compatibility: drop fields removed from older IOC-driven builds.
  const legacy = log as TrafficLog & { matchedRules?: unknown };
  if ('matchedRules' in legacy) {
    const { matchedRules: _removed, ...rest } = legacy;
    return rest as TrafficLog;
  }
  return log;
}

export function loadMnidsPersisted(): MnidsPersistedV1 | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as MnidsPersistedV1;
    if (parsed?.v !== 1 || !Array.isArray(parsed.logs)) return null;
    return {
      ...parsed,
      logs: parsed.logs.map((l) => normalizePersistedLog(l)),
    };
  } catch {
    return null;
  }
}

export function saveMnidsPersisted(payload: Omit<MnidsPersistedV1, 'v'>) {
  try {
    const data: MnidsPersistedV1 = { v: 1, ...payload, savedAt: payload.savedAt };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {
    /* quota / private mode */
  }
}

export function clearMnidsPersisted() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

/**
 * Fetch the live backend's boot ID from /api/health.
 *
 * Used at app boot to decide whether the cached localStorage snapshot still
 * belongs to the running server. We swallow errors so a transient network
 * failure doesn't accidentally wipe the user's data — when the boot ID is
 * unknown we leave the snapshot alone and let the normal restore prompt flow
 * handle it (the snapshot's own metadata already has the previous boot ID
 * so a later compare still works).
 */
export async function fetchServerBootId(signal?: AbortSignal): Promise<string | null> {
  try {
    const r = await fetch('/api/health', { cache: 'no-store', signal });
    if (!r.ok) return null;
    const j = (await r.json()) as { serverBootId?: string };
    return typeof j.serverBootId === 'string' && j.serverBootId.length > 0
      ? j.serverBootId
      : null;
  } catch {
    return null;
  }
}
