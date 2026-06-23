/** Progress for PCAP fetch/parse/apply — drives the dashboard pipeline bar. */
export type PcapIngestProgress = { pct: number; label: string; etaSec: number | null };
