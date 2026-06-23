import type { TrafficLog } from '../types';
import { ensureTelecomFields } from './telecom5gFields';

const PROTOCOLS = ['TCP', 'UDP', 'SCTP', 'HTTP/2', 'QUIC', 'ICMP', 'GTP-U', 'NGAP', 'NAS-5G'] as const;
const ATTACK_TYPES = [
  'DDoS (UDP Flood)',
  'Brute Force (SSH)',
  'Port Scan (Nmap)',
  'Botnet (Mirai)',
  'Infiltration',
  'Ransomware Callback',
  'SQL Injection',
  'XSS Attempt',
  'Man-in-the-Middle',
  'Signaling Storm (NGAP)',
  'GTP-U Tunnel Abuse',
];

/** Lower-severity findings: not an automatic alert, worth human review. */
const SUSPICIOUS_HINTS = [
  'Unusual burst vs baseline',
  'Rare protocol mix for this slice (review)',
  'GTP-U TEID churn higher than typical (review)',
  'NAS/NGAP timing anomaly (review)',
  'N6 asymmetry vs peer flows (review)',
  'Low-and-slow scan-like spacing (review)',
];

const RADIOS = ['5G-SA-NR', '5G-NSA', 'LTE-ANCHOR', 'EN-DC'] as const;
const INTERFACES = ['N3', 'N6', 'N9', 'GTP-U', 'Non-3GPP'] as const;
const DNNS = ['internet.mnc001.mcc001.gprs', 'ims.mnc001.mcc001.gprs', 'slice.emb.eMBB.5gc', 'sst1-sd010203'];

function hexSnippet(seed: number): string {
  const hex = '0123456789abcdef';
  let s = '';
  for (let i = 0; i < 24; i++) s += hex[(seed * (i + 7)) % 16];
  return `${s.slice(0, 8)}…${s.slice(-6)}`;
}

function getRandomIP() {
  return Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join('.');
}

/** Weighted toward 5G SA / GTP-U style traffic for MNIDS synthetic rows. */
export function generateMockLog(): TrafficLog {
  const roll = Math.random();
  const isMalicious = roll < 0.14;
  const isSuspicious = !isMalicious && roll < 0.14 + 0.16;
  const sourceIP = Math.random() < 0.28 ? `192.168.1.${Math.floor(Math.random() * 255)}` : getRandomIP();

  const protoRoll = Math.random();
  const p: TrafficLog['protocol'] =
    protoRoll < 0.32
      ? 'GTP-U'
      : protoRoll < 0.46
        ? 'NGAP'
        : protoRoll < 0.58
          ? 'NAS-5G'
          : PROTOCOLS[Math.floor(Math.random() * 6)];

  const fiveQi = [1, 2, 5, 6, 7, 8, 9, 65, 66, 67, 69, 70, 71, 72, 73, 74, 75, 76, 79, 80, 82, 83, 84, 85][
    Math.floor(Math.random() * 24)
  ];

  return ensureTelecomFields({
    id: Math.random().toString(36).substring(7),
    timestamp: new Date().toLocaleTimeString(),
    sourceIP,
    destIP: Math.random() < 0.4 ? `10.45.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}` : '10.0.5.22',
    protocol: p,
    packetSize: Math.floor(Math.random() * 1500) + 64,
    duration: parseFloat((Math.random() * 5).toFixed(3)),
    status: isMalicious ? 'Malicious' : isSuspicious ? 'Suspicious' : 'Benign',
    attackType: isMalicious
      ? ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)]
      : isSuspicious
        ? SUSPICIOUS_HINTS[Math.floor(Math.random() * SUSPICIOUS_HINTS.length)]
        : undefined,
    confidence: parseFloat(
      (isSuspicious ? 0.55 + Math.random() * 0.22 : 0.75 + Math.random() * 0.24).toFixed(3),
    ),
    radioAccess: RADIOS[Math.floor(Math.random() * RADIOS.length)],
    upfInterface: INTERFACES[Math.floor(Math.random() * INTERFACES.length)],
    dnnSlice: DNNS[Math.floor(Math.random() * DNNS.length)],
    fiveQi,
    pduSessionId: Math.floor(Math.random() * 15) + 1,
    ngapNasHint:
      p === 'NGAP'
        ? `InitialUEMessage, RAN UE NGAP ID ${100 + Math.floor(Math.random() * 900)}`
        : p === 'NAS-5G'
          ? `RegistrationRequest, 5GMM cause=${Math.random() < 0.1 ? '0x15' : '0x00'}`
          : `TEID 0x${(Math.random() * 0xfffffff).toString(16).slice(0, 7)} · QFI ${Math.floor(Math.random() * 8)}`,
    rawFrameSample: hexSnippet(Math.floor(Math.random() * 1e6)),
  });
}

/** Optional demo 5G session rows (e.g. tests / future “Load sample”); dashboard no longer auto-fills from this. */
const BUNDLED_5G_SESSION_ROWS: TrafficLog[] = [
  {
    id: 'demo-5g-001',
    timestamp: '12:00:01',
    sourceIP: '10.201.44.12',
    destIP: '10.45.0.1',
    protocol: 'GTP-U',
    packetSize: 1420,
    duration: 0.004,
    status: 'Benign',
    confidence: 0.91,
    radioAccess: '5G-SA-NR',
    upfInterface: 'N3',
    dnnSlice: 'internet.mnc001.mcc001.gprs',
    fiveQi: 9,
    pduSessionId: 3,
    ngapNasHint: 'GTP-U T-PDU · TEID 0x4a2f901 · QFI 1 · UDP/2152',
    gtpuTeidHex: '0x4a2f901',
    innerUeIpv4: '10.60.0.44',
    rawFrameSample: '34ff00…4500a1',
  },
  {
    id: 'demo-5g-002',
    timestamp: '12:00:02',
    sourceIP: '10.201.44.18',
    destIP: '10.45.0.1',
    protocol: 'NGAP',
    packetSize: 896,
    duration: 0.812,
    status: 'Suspicious',
    attackType: 'Signaling volume above usual baseline (review)',
    confidence: 0.62,
    radioAccess: '5G-SA-NR',
    upfInterface: 'N3',
    dnnSlice: 'ims.mnc001.mcc001.gprs',
    fiveQi: 5,
    pduSessionId: 2,
    ngapNasHint: 'DownlinkNASTransport, AMF UE NGAP ID 44012',
    rawFrameSample: '001500…6e67ap',
  },
  {
    id: 'demo-5g-003',
    timestamp: '12:00:03',
    sourceIP: '192.0.2.88',
    destIP: '10.45.0.3',
    protocol: 'NAS-5G',
    packetSize: 412,
    duration: 0.095,
    status: 'Malicious',
    attackType: 'Signaling Storm (NGAP)',
    confidence: 0.86,
    radioAccess: '5G-SA-NR',
    upfInterface: 'N3',
    dnnSlice: 'slice.emb.eMBB.5gc',
    fiveQi: 69,
    pduSessionId: 7,
    ngapNasHint: 'ServiceRequest burst x240/min toward AMF',
    rawFrameSample: '7e02ff…9c11ab',
  },
  {
    id: 'demo-5g-004',
    timestamp: '12:00:04',
    sourceIP: '10.201.44.2',
    destIP: '203.0.113.50',
    protocol: 'GTP-U',
    packetSize: 1500,
    duration: 0.002,
    status: 'Benign',
    confidence: 0.93,
    radioAccess: 'EN-DC',
    upfInterface: 'N6',
    dnnSlice: 'internet.mnc001.mcc001.gprs',
    fiveQi: 8,
    pduSessionId: 1,
    ngapNasHint: 'N6 outbound · IPv4 /24 routed',
    rawFrameSample: '450000…080045',
    dnsQueryNames: ['cdn.example-lab.test', 'api.example-lab.test'],
    httpHost: 'api.example-lab.test',
    ja3: 'e7d705a3286e1ea8fc2ce8765a9633b2',
    ja3s: 'ae4edc6faf64d08308082ad26be60767',
  },
  {
    id: 'demo-5g-005',
    timestamp: '12:00:05',
    sourceIP: '198.51.100.20',
    destIP: '10.45.0.1',
    protocol: 'UDP',
    packetSize: 128,
    duration: 0.001,
    status: 'Malicious',
    attackType: 'GTP-U Tunnel Abuse',
    confidence: 0.79,
    radioAccess: '5G-NSA',
    upfInterface: 'GTP-U',
    dnnSlice: 'internet.mnc001.mcc001.gprs',
    fiveQi: 65,
    pduSessionId: 4,
    gtpuTeidHex: '0xdead01',
    innerUeIpv4: '10.60.0.99',
    ngapNasHint: 'Malformed GTP-U extension header · integrity check failed',
    rawFrameSample: '32ff11…dead01',
  },
  {
    id: 'demo-5g-006',
    timestamp: '12:00:06',
    sourceIP: '10.201.44.5',
    destIP: '10.45.0.2',
    protocol: 'TCP',
    packetSize: 536,
    duration: 1.204,
    status: 'Benign',
    confidence: 0.9,
    radioAccess: '5G-SA-NR',
    upfInterface: 'N9',
    dnnSlice: 'sst1-sd010203',
    fiveQi: 6,
    pduSessionId: 5,
    ngapNasHint: 'PSA UPF handover session continuity',
    rawFrameSample: '0badf0…00c0ff',
  },
  {
    id: 'demo-5g-007',
    timestamp: '12:00:07',
    sourceIP: '10.201.44.33',
    destIP: '10.45.0.1',
    protocol: 'HTTP/2',
    packetSize: 722,
    duration: 0.156,
    status: 'Suspicious',
    attackType: 'Request pacing unlike typical handset (review)',
    confidence: 0.58,
    radioAccess: '5G-SA-NR',
    upfInterface: 'N6',
    dnnSlice: 'internet.mnc001.mcc001.gprs',
    fiveQi: 9,
    pduSessionId: 3,
    ngapNasHint: ':method GET :path /api/health',
    rawFrameSample: '485454…02004',
  },
  {
    id: 'demo-5g-008',
    timestamp: '12:00:08',
    sourceIP: '10.201.44.40',
    destIP: '10.45.0.1',
    protocol: 'QUIC',
    packetSize: 1300,
    duration: 0.008,
    status: 'Benign',
    confidence: 0.92,
    radioAccess: '5G-SA-NR',
    upfInterface: 'N3',
    dnnSlice: 'internet.mnc001.mcc001.gprs',
    fiveQi: 8,
    pduSessionId: 6,
    ngapNasHint: 'QUIC v1 short header · spin bit 0',
    rawFrameSample: 'c0ffee…d00d5a',
  },
  {
    id: 'demo-5g-009',
    timestamp: '12:00:09',
    sourceIP: '10.201.44.7',
    destIP: '10.45.0.4',
    protocol: 'SCTP',
    packetSize: 364,
    duration: 0.421,
    status: 'Benign',
    confidence: 0.85,
    radioAccess: 'LTE-ANCHOR',
    upfInterface: 'Non-3GPP',
    dnnSlice: 'ims.mnc001.mcc001.gprs',
    fiveQi: 5,
    pduSessionId: 2,
    ngapNasHint: 'SCTP PPID 60 · NGAP over SCTP (anchor)',
    rawFrameSample: '1a2b3c…4d5e6f',
  },
  {
    id: 'demo-5g-010',
    timestamp: '12:00:10',
    sourceIP: '192.168.50.10',
    destIP: '10.45.0.1',
    protocol: 'ICMP',
    packetSize: 84,
    duration: 0.003,
    status: 'Malicious',
    attackType: 'DDoS (UDP Flood)',
    confidence: 0.82,
    radioAccess: '5G-SA-NR',
    upfInterface: 'N3',
    dnnSlice: 'internet.mnc001.mcc001.gprs',
    fiveQi: 79,
    pduSessionId: 8,
    ngapNasHint: 'ICMP echo toward UPF inner IP scope',
    rawFrameSample: '080045…aabbcc',
  },
  {
    id: 'demo-5g-011',
    timestamp: '12:00:11',
    sourceIP: '10.201.44.22',
    destIP: '10.45.0.1',
    protocol: 'NAS-5G',
    packetSize: 288,
    duration: 0.067,
    status: 'Benign',
    confidence: 0.89,
    radioAccess: '5G-SA-NR',
    upfInterface: 'N3',
    dnnSlice: 'slice.emb.eMBB.5gc',
    fiveQi: 70,
    pduSessionId: 9,
    ngapNasHint: 'RegistrationComplete, 5GMM cause=0x00',
    rawFrameSample: '7e0045…00ff11',
  },
  {
    id: 'demo-5g-012',
    timestamp: '12:00:12',
    sourceIP: '10.201.44.55',
    destIP: '10.45.0.2',
    protocol: 'GTP-U',
    packetSize: 1488,
    duration: 0.001,
    status: 'Benign',
    confidence: 0.94,
    radioAccess: 'EN-DC',
    upfInterface: 'N9',
    dnnSlice: 'internet.mnc001.mcc001.gprs',
    fiveQi: 71,
    pduSessionId: 10,
    ngapNasHint: 'EPS fallback bearer trace (NSA)',
    gtpuTeidHex: '0x8c01eed',
    innerUeIpv4: '10.60.0.12',
    rawFrameSample: 'feed00…beefa1',
  },
];

export const SAMPLE_5G_RAW_LOGS: TrafficLog[] = BUNDLED_5G_SESSION_ROWS.map((r) => ensureTelecomFields(r));
