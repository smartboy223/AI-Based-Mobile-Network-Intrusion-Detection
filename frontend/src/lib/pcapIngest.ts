import { parsePcapToTrafficLogs } from './pcapParser';
import type { TrafficLog } from '../types';

export type PcapListResponse = { ok: boolean; files: string[]; error?: string };

export async function fetchPcapList(): Promise<PcapListResponse> {
  try {
    const res = await fetch('/api/pcap/list', { cache: 'no-store' });
    if (!res.ok) {
      return { ok: false, files: [], error: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as PcapListResponse;
    return { ok: data.ok !== false, files: data.files ?? [], error: data.error };
  } catch {
    return { ok: false, files: [], error: 'Network error (is the dev server running?)' };
  }
}

export async function fetchTrainedPcapList(): Promise<PcapListResponse> {
  try {
    const res = await fetch('/api/pcap/trained-list', { cache: 'no-store' });
    if (!res.ok) {
      return { ok: false, files: [], error: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as PcapListResponse;
    return { ok: data.ok !== false, files: data.files ?? [], error: data.error };
  } catch {
    return { ok: false, files: [], error: 'Network error' };
  }
}

export async function fetchPcapBytes(name: string): Promise<ArrayBuffer> {
  const res = await fetch(`/api/pcap/file/${encodeURIComponent(name)}`, { cache: 'no-store' });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(t || `HTTP ${res.status}`);
  }
  return res.arrayBuffer();
}

export async function fetchTrainedPcapBytes(name: string): Promise<ArrayBuffer> {
  const res = await fetch(`/api/pcap/trained-file/${encodeURIComponent(name)}`, { cache: 'no-store' });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(t || `HTTP ${res.status}`);
  }
  return res.arrayBuffer();
}

export function parsePcapBuffer(buf: ArrayBuffer, sourceLabel: string) {
  return parsePcapToTrafficLogs(buf, sourceLabel);
}

export async function ingestPcapFromServerFile(name: string): Promise<
  | { ok: true; flows: TrafficLog[]; warnings: string[] }
  | { ok: false; error: string }
> {
  try {
    const buf = await fetchPcapBytes(name);
    const parsed = parsePcapBuffer(buf, name);
    if (parsed.ok === false) return { ok: false, error: parsed.error };
    return { ok: true, flows: parsed.flows, warnings: parsed.warnings };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'Ingest failed' };
  }
}
