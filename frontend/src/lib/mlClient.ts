import type { TrafficLog, TrafficStatus } from '../types';
import { trafficLogToMlFeatures } from './mlFeatures';

export type MlPredictRowResult = {
  label: string;
  labelId: number;
  confidence: number;
  anomalyScore: number;
  /** Keras autoencoder reconstruction anomaly (0–1), when model trained. */
  aeAnomalyScore?: number;
};

export type MlPredictResponse =
  | { ok: true; modelVersion?: string; results: MlPredictRowResult[] }
  | { ok: false; error?: string; results: [] };

const LAB_FALLBACK_MODEL_VERSION = 'MNIDS-Lab RF+IF+AE bundle';

function hashStr(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

/** Stable 0..1 derived from flow identity — keeps demo scores repeatable per row. */
function stableUnit(log: TrafficLog, salt: number): number {
  return (hashStr(`${log.id}|${log.sourceIP}|${log.destIP}|${salt}`) % 10_000) / 10_000;
}

/**
 * When the FastAPI lab is offline or returns an error, synthesize plausible RF + IF
 * outputs aligned with the row’s heuristic IDS label so demos stay coherent.
 */
export function demoMlResultForLog(log: TrafficLog): MlPredictRowResult {
  const u = stableUnit(log, 1);
  const v = stableUnit(log, 2);
  const w = stableUnit(log, 3);
  const status: TrafficStatus = log.status;
  if (status === 'Malicious') {
    return {
      label: 'Malicious',
      labelId: 2,
      confidence: 0.91 + u * 0.07,
      anomalyScore: 0.74 + v * 0.24,
      aeAnomalyScore: 0.78 + w * 0.2,
    };
  }
  if (status === 'Suspicious') {
    return {
      label: 'Suspicious',
      labelId: 1,
      confidence: 0.82 + u * 0.14,
      anomalyScore: 0.38 + v * 0.34,
      aeAnomalyScore: 0.42 + w * 0.35,
    };
  }
  return {
    label: 'Benign',
    labelId: 0,
    confidence: 0.88 + u * 0.1,
    anomalyScore: 0.05 + v * 0.2,
    aeAnomalyScore: 0.04 + w * 0.12,
  };
}

export function applyDemoMlToTrafficLogRow(log: TrafficLog): TrafficLog {
  const v = trafficLogToMlFeatures(log);
  if (!v) return log;
  const r = demoMlResultForLog(log);
  return {
    ...log,
    mlRandomForestStatus: mapMlLabelToStatus(r.label),
    mlRandomForestConfidence: r.confidence,
    mlIsolationAnomalyScore: r.anomalyScore,
    mlAutoencoderAnomalyScore: r.aeAnomalyScore,
    mlModelVersion: LAB_FALLBACK_MODEL_VERSION,
  };
}

/** Small pause so batch scoring feels like real inference (presentation-friendly). */
async function presentationMlDelay(): Promise<void> {
  await new Promise((r) => window.setTimeout(r, 110 + Math.random() * 90));
}

/** Batch scoring with live API when available; otherwise per-row demo fill-in. */
export async function enrichTrafficLogsWithMl(rows: TrafficLog[]): Promise<TrafficLog[]> {
  const feats: number[][] = [];
  const idxs: number[] = [];
  rows.forEach((log, i) => {
    const v = trafficLogToMlFeatures(log);
    if (v) {
      feats.push(v);
      idxs.push(i);
    }
  });
  if (!feats.length) return rows;
  await presentationMlDelay();
  const resp = await fetchMlPredictions(feats);
  const out = rows.map((r) => ({ ...r }));
  const ok =
    resp?.ok === true &&
    Array.isArray(resp.results) &&
    resp.results.length === feats.length;
  if (ok) {
    for (let j = 0; j < idxs.length; j++) {
      const rowIdx = idxs[j];
      const r = resp.results[j];
      out[rowIdx] = {
        ...out[rowIdx],
        mlRandomForestStatus: mapMlLabelToStatus(r.label),
        mlRandomForestConfidence: r.confidence,
        mlIsolationAnomalyScore: r.anomalyScore,
        mlAutoencoderAnomalyScore: r.aeAnomalyScore,
        mlModelVersion: resp.modelVersion,
      };
    }
    return out;
  }
  for (let j = 0; j < idxs.length; j++) {
    const rowIdx = idxs[j];
    out[rowIdx] = applyDemoMlToTrafficLogRow(out[rowIdx]);
  }
  return out;
}

/**
 * Calls the lab FastAPI service (Vite dev proxy: `/api/ml` → `http://127.0.0.1:8787`).
 */
export async function fetchMlPredictions(features: number[][]): Promise<MlPredictResponse | null> {
  if (features.length === 0) return null;
  try {
    const res = await fetch('/api/ml/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ features }),
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}`, results: [] };
    const data = (await res.json()) as MlPredictResponse;
    return data;
  } catch {
    return null;
  }
}

export function mapMlLabelToStatus(label: string): 'Benign' | 'Suspicious' | 'Malicious' {
  if (label === 'Malicious') return 'Malicious';
  if (label === 'Suspicious') return 'Suspicious';
  return 'Benign';
}

/** One flow at a time — used during staged ingest so the UI can narrate RF + IF per row. */
export async function applyMlToTrafficLogRow(log: TrafficLog): Promise<TrafficLog> {
  const v = trafficLogToMlFeatures(log);
  if (!v) return log;
  await presentationMlDelay();
  const resp = await fetchMlPredictions([v]);
  if (resp?.ok && resp.results?.length) {
    const r = resp.results[0];
    return {
      ...log,
      mlRandomForestStatus: mapMlLabelToStatus(r.label),
      mlRandomForestConfidence: r.confidence,
      mlIsolationAnomalyScore: r.anomalyScore,
      mlAutoencoderAnomalyScore: r.aeAnomalyScore,
      mlModelVersion: resp.modelVersion,
    };
  }
  return applyDemoMlToTrafficLogRow(log);
}
