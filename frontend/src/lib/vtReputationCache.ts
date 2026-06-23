import type { VtDomainClientResult, VtIpClientResult } from './virusTotal';

const STORAGE_KEY = 'mnids-vt-reputation-cache-v1';

type VtCachePayload = {
  v: 1;
  ip: Record<string, VtIpClientResult>;
  domain: Record<string, VtDomainClientResult>;
  savedAt: number;
};

/**
 * Long-lived VT results (separate from dashboard save). Reset dashboard clears this so the UI can
 * stay “fresh” until triage; new lookups repopulate cache and persist again.
 */
export function loadVtReputationCache(): { ip: Record<string, VtIpClientResult>; domain: Record<string, VtDomainClientResult> } | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const p = JSON.parse(raw) as VtCachePayload;
    if (p?.v !== 1 || typeof p.ip !== 'object' || typeof p.domain !== 'object') return null;
    return { ip: p.ip ?? {}, domain: p.domain ?? {} };
  } catch {
    return null;
  }
}

export function saveVtReputationCache(
  ip: Record<string, VtIpClientResult>,
  domain: Record<string, VtDomainClientResult>,
): void {
  try {
    const payload: VtCachePayload = {
      v: 1,
      ip,
      domain,
      savedAt: Date.now(),
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
  } catch {
    /* quota */
  }
}

/** Clear long-lived VT cache (Reset dashboard also clears this for a clean demo). */
export function clearVtReputationCache(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
}
