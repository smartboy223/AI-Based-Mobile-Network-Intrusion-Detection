import type { TrafficLog } from '../types';

/**
 * Must match `backend/train_models.py` and `dataset/mnids_synthetic_flows.csv`.
 */
export const ML_FEATURE_NAMES = [
  'log_duration',
  'log_bytes',
  'log_packets',
  'avg_pkt',
  'sport_n',
  'dport_n',
  'is_tcp',
  'is_udp',
  'is_sctp',
  'is_gtpu',
  'is_ssh',
  'is_dns',
  'log_bytes_per_sec',
  'log_pkts_per_sec',
] as const;

export type MlFeatureName = (typeof ML_FEATURE_NAMES)[number];

function log1p(x: number): number {
  return Math.log(1 + Math.max(x, 0));
}

function protoFlags(ipProto?: number): { tcp: number; udp: number; sctp: number } {
  if (ipProto === 6) return { tcp: 1, udp: 0, sctp: 0 };
  if (ipProto === 17) return { tcp: 0, udp: 1, sctp: 0 };
  if (ipProto === 132) return { tcp: 0, udp: 0, sctp: 1 };
  const p = ipProto ?? -1;
  if (p === 1 || p === 58) return { tcp: 0, udp: 0, sctp: 0 };
  return { tcp: 0, udp: 0, sctp: 0 };
}

/**
 * Builds the lab feature vector for the MNIDS Random Forest / Isolation Forest.
 * Returns null if PCAP totals are missing.
 */
export function trafficLogToMlFeatures(log: TrafficLog): number[] | null {
  const bytes = log.byteTotal;
  const packets = log.packetCount;
  if (bytes == null || packets == null || packets < 1) return null;

  const duration = Math.max(log.duration, 1e-6);
  const sport = log.sourcePort ?? 0;
  const dport = log.destPort ?? 0;
  const { tcp, udp, sctp } = protoFlags(log.ipProtocol);

  const avgPkt = bytes / packets;
  const bps = bytes / duration;
  const pps = packets / duration;
  const isGtpu = log.protocol === 'GTP-U' || sport === 2152 || dport === 2152 ? 1 : 0;
  const isSsh = dport === 22 || sport === 22 ? 1 : 0;
  const isDns = dport === 53 || sport === 53 ? 1 : 0;

  return [
    log1p(duration),
    log1p(bytes),
    log1p(packets),
    avgPkt,
    sport / 65535,
    dport / 65535,
    tcp,
    udp,
    sctp,
    isGtpu,
    isSsh,
    isDns,
    log1p(bps),
    log1p(pps),
  ];
}
