/**
 * Canonical MNIDS architecture — aligned with report §5.3 (pipeline stages),
 * traffic categories, and detection mechanisms. Single source for UI copy and thesis wording.
 */

export type PipelineStageId =
  | 'data_sources'
  | 'preprocess'
  | 'detection'
  | 'intelligence'
  | 'visualization'
  | 'outputs';

export type TrafficCategoryId =
  | 'user_plane_ip'
  | 'control_gtpu'
  | 'signaling_sctp'
  | 'dns_udp'
  | 'web_tls'
  | 'other';

export type DetectionMechanismId =
  | 'parser_heuristic'
  | 'flow_behavior'
  | 'ml_lab'
  | 'intel_vt'
  | 'assist_llm';

/** Five main stages from the report (§5.3), plus explicit output emphasis. */
export const PIPELINE_STAGES: ReadonlyArray<{
  id: PipelineStageId;
  order: number;
  title: string;
  shortTitle: string;
  description: string;
  implementationNote: string;
}> = [
  {
    id: 'data_sources',
    order: 1,
    title: 'Data sources and acquisition',
    shortTitle: 'Sources',
    description: 'PCAP upload or library — standard libpcap format for browser parsing.',
    implementationNote:
      'PcapLibraryPanel: dashboard lists three lab demos `mnids-lab-01|02|03-traffic.pcap`; ML Lab loads `mnids-lab-ml-synthetic.pcap` directly.',
  },
  {
    id: 'preprocess',
    order: 2,
    title: 'Preprocessing and feature extraction',
    shortTitle: 'Preprocess',
    description: 'Flows aggregated in-browser; numeric features and optional HTTP/DNS/GTP-U fields.',
    implementationNote: '`parsePcapToTrafficLogs`, `flowDeepParse`, `mlFeatures.ts`.',
  },
  {
    id: 'detection',
    order: 3,
    title: 'Detection',
    shortTitle: 'Detection',
    description: 'Flow features feed ML inference; parser heuristics act as a fallback when ML is unavailable.',
    implementationNote:
      '`classifyFlow`, `mlFeatures.ts`, `mlClient.ts`, FastAPI `inference_server.py`.',
  },
  {
    id: 'intelligence',
    order: 4,
    title: 'Intelligence and analysis',
    shortTitle: 'Intelligence',
    description: 'Optional VirusTotal enrichment and optional LLM analyst guidance.',
    implementationNote: '`virusTotal.ts`, `deepseek.ts`, row triage and bulk pipeline.',
  },
  {
    id: 'visualization',
    order: 5,
    title: 'Visualization and reporting',
    shortTitle: 'Dashboard',
    description: 'Table, analytics, filters, Excel export.',
    implementationNote: '`TrafficDataTable`, `AnalyticsView`, `export`.',
  },
  {
    id: 'outputs',
    order: 6,
    title: 'Outputs',
    shortTitle: 'Outputs',
    description: 'Classified flows with audit fields; analysis only (no inline blocking).',
    implementationNote: '`TrafficLog`, Excel export, persisted session.',
  },
];

/** Representative traffic classes for mobile/core context (report: user vs core plane). */
export const TRAFFIC_CATEGORIES: ReadonlyArray<{
  id: TrafficCategoryId;
  label: string;
  plane: string;
  typicalProtocols: string;
  howDetected: string;
}> = [
  {
    id: 'user_plane_ip',
    label: 'User IPv4 (N6-style)',
    plane: 'USER / breakout',
    typicalProtocols: 'TCP/UDP · 80, 443, 53',
    howDetected: 'Flows + rates + DNS/HTTP',
  },
  {
    id: 'control_gtpu',
    label: 'GTP-U (N3-style)',
    plane: 'USER',
    typicalProtocols: 'UDP/2152',
    howDetected: 'TEID / inner IP',
  },
  {
    id: 'signaling_sctp',
    label: 'SCTP signaling',
    plane: 'CONTROL',
    typicalProtocols: 'SCTP',
    howDetected: 'Keys + rules',
  },
  {
    id: 'dns_udp',
    label: 'DNS / UDP',
    plane: 'USER / core',
    typicalProtocols: 'UDP/53',
    howDetected: 'QNAME + behaviour',
  },
  {
    id: 'web_tls',
    label: 'Web / TLS',
    plane: 'USER',
    typicalProtocols: 'TCP/443, 80',
    howDetected: 'HTTP / JA3 / volume',
  },
  {
    id: 'other',
    label: 'Other IPv4',
    plane: 'Mixed',
    typicalProtocols: '—',
    howDetected: 'Generic features + ML',
  },
];

/** Detection and analysis mechanisms — order is layered explanation, not runtime order. */
export const DETECTION_MECHANISMS: ReadonlyArray<{
  id: DetectionMechanismId;
  layer: string;
  name: string;
  role: string;
  requiredIntegration: boolean;
}> = [
  {
    id: 'parser_heuristic',
    layer: 'Core',
    name: 'Parser & heuristics',
    role: 'Rates, GTP-U, SSH, bursts.',
    requiredIntegration: false,
  },
  {
    id: 'flow_behavior',
    layer: 'Core',
    name: 'Flow behaviour heuristics',
    role: 'Packet/byte rates, GTP-U and SSH burst patterns.',
    requiredIntegration: false,
  },
  {
    id: 'ml_lab',
    layer: 'Optional ML',
    name: 'ML stack (RF + IF + AE)',
    role: 'Flow-feature classification & anomaly scores when API is running.',
    requiredIntegration: true,
  },
  {
    id: 'intel_vt',
    layer: 'Optional intel',
    name: 'VirusTotal',
    role: 'IP/domain reputation.',
    requiredIntegration: true,
  },
  {
    id: 'assist_llm',
    layer: 'Optional assist',
    name: 'LLM assistant',
    role: 'Triage hints & rule text — analyst approves.',
    requiredIntegration: true,
  },
];

export const MNIDS_SCOPE_NOTE =
  '5G IDS: analysis only — no blocking from this UI.';

/** Short summary for Architecture modal (no ML algorithm names — see ML tab). */
export const PIPELINE_ONE_LINER =
  'PCAP → flow features → ML detection (heuristic fallback) → optional VT / assist → table & export.';

/** Single-line traffic hint (replaces per-category cards in simplified UI). */
export const TRAFFIC_SUMMARY_LINE =
  'User & control planes: IPv4, GTP-U, SCTP, DNS, TLS, and generic flows.';
