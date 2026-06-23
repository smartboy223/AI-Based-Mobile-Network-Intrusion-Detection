export type TrafficStatus = 'Benign' | 'Suspicious' | 'Malicious';

/** UI and assistant-facing copy: internal value remains `Benign`. */
export function trafficStatusLabel(status: TrafficStatus): string {
  return status === 'Benign' ? 'Clean' : status;
}

export type RadioAccess = '5G-SA-NR' | '5G-NSA' | 'LTE-ANCHOR' | 'EN-DC';

export type UpfInterface = 'N3' | 'N6' | 'N9' | 'GTP-U' | 'Non-3GPP';

/** User plane (GTP-U), control / signaling, or breakout / general IP path. */
export type TrafficPlane = 'USER_PLANE' | 'CONTROL_PLANE' | 'BREAKOUT_AND_IP';

/** Sort keys for the dashboard traffic table (subset of TrafficLog fields + status). */
export type TrafficTableSortKey =
  | 'timestamp'
  | 'sourceIP'
  | 'destIP'
  | 'protocol'
  | 'trafficPlane'
  | 'sessionBearerKey'
  | 'radioAccess'
  | 'upfInterface'
  | 'fiveQi'
  | 'dnnSlice'
  | 'ngapNasHint'
  | 'operationalCategory'
  | 'packetSize'
  | 'duration'
  | 'status'
  | 'analystNote'
  | 'confidence'
  | 'packetCount'
  | 'byteTotal'
  | 'mlRandomForestStatus'
  | 'mlRandomForestConfidence'
  | 'mlIsolationAnomalyScore'
  | 'mlAutoencoderAnomalyScore';

export interface TrafficLog {
  id: string;
  timestamp: string;
  sourceIP: string;
  destIP: string;
  /** L4 source port when known (e.g. PCAP flows). */
  sourcePort?: number;
  /** L4 destination port when known (e.g. PCAP flows). */
  destPort?: number;
  /** IPv4 protocol number when known (6 TCP, 17 UDP, 132 SCTP, …). */
  ipProtocol?: number;
  protocol: 'TCP' | 'UDP' | 'SCTP' | 'HTTP/2' | 'QUIC' | 'ICMP' | 'GTP-U' | 'NGAP' | 'NAS-5G' | 'OTHER';
  packetSize: number;
  /** Flow lifetime in seconds (PCAP aggregate first/last packet time). */
  duration: number;
  /** Total bytes summed from PCAP incl_len per packet in this flow (when known). */
  byteTotal?: number;
  /** Number of packets aggregated into this flow (when known). */
  packetCount?: number;
  status: TrafficStatus;
  attackType?: string;
  /** Analyst / AI triage note (shown in table when set). */
  analystNote?: string;
  /**
   * When true, per-row Scan / bulk re-analyze skips automated rule overlay so Clean stays Clean.
   * Set when status is **Clean (Benign)** from the AI patch or from the status dropdown.
   */
  analystStatusLocked?: boolean;
  confidence: number;
  /** 5G / core-facing context (demo raw fields until real PCAP is ingested) */
  radioAccess?: RadioAccess;
  upfInterface?: UpfInterface;
  dnnSlice?: string;
  fiveQi?: number;
  pduSessionId?: number;
  ngapNasHint?: string;
  /** GTP-U TEID (hex), when extracted from T-PDU. */
  gtpuTeidHex?: string;
  /** Inner UE IPv4 from GTP-U T-PDU payload, when parseable. */
  innerUeIpv4?: string | null;
  /** QoS Flow Identifier when signaled in GTP-U extension (optional). */
  qfi?: number | null;
  /** Dual lens: USER_PLANE | CONTROL_PLANE | BREAKOUT_AND_IP */
  trafficPlane?: TrafficPlane;
  /** Telecom-oriented finding class (NOC / SOC joint review). */
  operationalCategory?: string;
  /** Misconfiguration vs attack–style engineering guidance. */
  engineeringNote?: string;
  /** Session / bearer grouping (TEID, inner UE, or PDU + DNN). */
  sessionBearerKey?: string;
  /** Short synthetic hex-like snippet for audit / future PCAP mapping */
  rawFrameSample?: string;
  /** DNS QNAMEs observed on this flow (PCAP deep parse). */
  dnsQueryNames?: string[];
  /** HTTP Host header when parseable from cleartext TCP. */
  httpHost?: string | null;
  /** TLS JA3 fingerprint (MD5 of JA3 string; standard JA3). */
  ja3?: string | null;
  /** TLS JA3S fingerprint (MD5; server hello). */
  ja3s?: string | null;
  /** Raw JA3 comma-separated tuple (forensics / assistant). */
  ja3Raw?: string | null;
  ja3sRaw?: string | null;
  /**
   * Lab Random Forest classifier (trained on synthetic MNIDS dataset; optional when ML server runs).
   */
  mlRandomForestStatus?: TrafficStatus;
  /** Max class probability from RF (0–1). */
  mlRandomForestConfidence?: number;
  /** Isolation Forest decision-derived score in ~0–1 (higher = more anomalous) from lab training. */
  mlIsolationAnomalyScore?: number;
  /** Keras autoencoder reconstruction anomaly score ~0–1 (higher = more anomalous). */
  mlAutoencoderAnomalyScore?: number;
  /** From `cnn_model/meta.json` after training. */
  mlModelVersion?: string;
}

export interface SystemStats {
  totalTraffic: number;
  attacksDetected: number;
  /** Rows flagged as worth analyst review (not a confirmed alert). */
  suspiciousFlagged: number;
}

