import type { TrafficTableSortKey } from '../types';

export type TrafficDataColumnId =
  | 'timestamp'
  | 'sourceIP'
  | 'destIP'
  | 'protocol'
  | 'trafficPlane'
  | 'upfInterface'
  | 'sessionBearerKey'
  | 'operationalCategory'
  | 'packetSize'
  | 'packetCount'
  | 'byteTotal'
  | 'status'
  | 'confidence'
  | 'mlRandomForestStatus'
  | 'mlIsolationAnomalyScore'
  | 'mlAutoencoderAnomalyScore'
  | 'radioAccess'
  | 'fiveQi'
  | 'dnnSlice'
  | 'ngapNasHint'
  | 'analystNote';

export const ALL_TRAFFIC_DATA_COLUMN_IDS: TrafficDataColumnId[] = [
  'timestamp',
  'sourceIP',
  'destIP',
  'protocol',
  'trafficPlane',
  'upfInterface',
  'sessionBearerKey',
  'operationalCategory',
  'packetSize',
  'packetCount',
  'byteTotal',
  'status',
  'confidence',
  'mlRandomForestStatus',
  'mlIsolationAnomalyScore',
  'mlAutoencoderAnomalyScore',
  'radioAccess',
  'fiveQi',
  'dnnSlice',
  'ngapNasHint',
  'analystNote',
];

export const TRAFFIC_COLUMN_LABELS: Record<TrafficDataColumnId, string> = {
  timestamp: 'Time',
  sourceIP: 'Src',
  destIP: 'Dst',
  protocol: 'Proto',
  trafficPlane: 'Plane',
  upfInterface: 'IF (N3/N6)',
  sessionBearerKey: 'Session',
  operationalCategory: 'Operating profile',
  packetSize: 'Size',
  packetCount: 'Pkts',
  byteTotal: 'Bytes',
  status: 'Status',
  confidence: 'Conf.',
  mlRandomForestStatus: 'ML (RF)',
  mlIsolationAnomalyScore: 'IF anom.',
  mlAutoencoderAnomalyScore: 'AE anom.',
  radioAccess: '5G / RAN',
  fiveQi: '5QI',
  dnnSlice: 'DNN / slice',
  ngapNasHint: 'NGAP / NAS / GTP',
  analystNote: 'Comment',
};

export const TRAFFIC_COLUMN_SORT_KEY: Record<TrafficDataColumnId, TrafficTableSortKey | null> = {
  timestamp: 'timestamp',
  sourceIP: 'sourceIP',
  destIP: 'destIP',
  protocol: 'protocol',
  trafficPlane: 'trafficPlane',
  upfInterface: 'upfInterface',
  sessionBearerKey: 'sessionBearerKey',
  operationalCategory: 'operationalCategory',
  packetSize: 'packetSize',
  packetCount: 'packetCount',
  byteTotal: 'byteTotal',
  status: 'status',
  confidence: 'confidence',
  mlRandomForestStatus: 'mlRandomForestStatus',
  mlIsolationAnomalyScore: 'mlIsolationAnomalyScore',
  mlAutoencoderAnomalyScore: 'mlAutoencoderAnomalyScore',
  radioAccess: 'radioAccess',
  fiveQi: 'fiveQi',
  dnnSlice: 'dnnSlice',
  ngapNasHint: 'ngapNasHint',
  analystNote: 'analystNote',
};

/** Default column order (all data columns). Actions column is always last in the UI. */
export const DEFAULT_TRAFFIC_COLUMN_ORDER: TrafficDataColumnId[] = [
  'timestamp',
  'sourceIP',
  'destIP',
  'protocol',
  'trafficPlane',
  'upfInterface',
  'sessionBearerKey',
  'operationalCategory',
  'packetSize',
  'packetCount',
  'byteTotal',
  'status',
  'confidence',
  'mlRandomForestStatus',
  'mlIsolationAnomalyScore',
  'mlAutoencoderAnomalyScore',
  'radioAccess',
  'fiveQi',
  'dnnSlice',
  'ngapNasHint',
  'analystNote',
];

/** Shown by default — core triage; long session / profile strings live under Columns or on Analytics. */
export const DEFAULT_TRAFFIC_COLUMN_VISIBLE: Record<TrafficDataColumnId, boolean> = {
  timestamp: true,
  sourceIP: true,
  destIP: true,
  protocol: true,
  trafficPlane: true,
  upfInterface: true,
  sessionBearerKey: false,
  operationalCategory: false,
  packetSize: true,
  packetCount: false,
  byteTotal: false,
  status: true,
  confidence: true,
  mlRandomForestStatus: true,
  mlIsolationAnomalyScore: true,
  mlAutoencoderAnomalyScore: true,
  radioAccess: false,
  fiveQi: false,
  dnnSlice: false,
  ngapNasHint: false,
  analystNote: false,
};

const STORAGE_KEY = 'mnids-traffic-table-cols-v2';

export type TrafficColumnPrefs = {
  order: TrafficDataColumnId[];
  visible: Record<TrafficDataColumnId, boolean>;
};

function isDataColumnId(s: string): s is TrafficDataColumnId {
  return (ALL_TRAFFIC_DATA_COLUMN_IDS as string[]).includes(s);
}

export function loadTrafficColumnPrefs(): TrafficColumnPrefs {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return {
        order: [...DEFAULT_TRAFFIC_COLUMN_ORDER],
        visible: { ...DEFAULT_TRAFFIC_COLUMN_VISIBLE },
      };
    }
    const p = JSON.parse(raw) as { order?: string[]; visible?: Record<string, boolean> };
    const orderIn = Array.isArray(p.order) ? p.order.filter(isDataColumnId) : [];
    const mergedOrder: TrafficDataColumnId[] = [];
    const seen = new Set<TrafficDataColumnId>();
    for (const id of orderIn) {
      if (!seen.has(id)) {
        seen.add(id);
        mergedOrder.push(id);
      }
    }
    for (const id of DEFAULT_TRAFFIC_COLUMN_ORDER) {
      if (!seen.has(id)) mergedOrder.push(id);
    }
    const visible = { ...DEFAULT_TRAFFIC_COLUMN_VISIBLE };
    if (p.visible && typeof p.visible === 'object') {
      for (const id of ALL_TRAFFIC_DATA_COLUMN_IDS) {
        if (typeof p.visible[id] === 'boolean') visible[id] = p.visible[id]!;
      }
    }
    return { order: mergedOrder, visible };
  } catch {
    return {
      order: [...DEFAULT_TRAFFIC_COLUMN_ORDER],
      visible: { ...DEFAULT_TRAFFIC_COLUMN_VISIBLE },
    };
  }
}

export function saveTrafficColumnPrefs(prefs: TrafficColumnPrefs): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    /* ignore */
  }
}

export function getVisibleColumnOrder(prefs: TrafficColumnPrefs): TrafficDataColumnId[] {
  return prefs.order.filter((id) => prefs.visible[id] !== false);
}
