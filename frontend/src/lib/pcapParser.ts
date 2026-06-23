import type { TrafficLog, TrafficStatus } from '../types';
import { ensureTelecomFields } from './telecom5gFields';
import {
  emptyFlowEnrichment,
  enrichFlowFromPayload,
  enrichmentToLogFields,
  type FlowEnrichment,
} from './flowDeepParse';

export type PcapParseResult =
  | { ok: true; flows: TrafficLog[]; warnings: string[] }
  | { ok: false; error: string };

type FlowAgg = {
  firstTs: number;
  lastTs: number;
  bytes: number;
  packets: number;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  ipProto: number;
};

type GtpuMeta = {
  teid: number;
  innerSrc?: string;
  innerDst?: string;
};

function readU16BE(d: Uint8Array, o: number): number {
  return (d[o] << 8) | d[o + 1];
}

function ipv4(d: Uint8Array, o: number): string | null {
  if (o + 20 > d.length) return null;
  return `${d[o + 12]}.${d[o + 13]}.${d[o + 14]}.${d[o + 15]}`;
}

function ipv4Dst(d: Uint8Array, o: number): string | null {
  if (o + 20 > d.length) return null;
  return `${d[o + 16]}.${d[o + 17]}.${d[o + 18]}.${d[o + 19]}`;
}

/** Parse Ethernet / Linux SLL / RAW to IPv4 flow key parts. Returns null if not IPv4. */
function parseIpv4Payload(
  linkType: number,
  pkt: Uint8Array,
): { src: string; dst: string; ipProto: number; sport: number; dport: number; ipOff: number; ihl: number } | null {
  let o = 0;
  let etherType = 0;

  if (linkType === 1) {
    // DLT_EN10MB
    if (pkt.length < 14) return null;
    etherType = readU16BE(pkt, 12);
    o = 14;
    if (etherType === 0x8100) {
      if (pkt.length < 18) return null;
      etherType = readU16BE(pkt, 16);
      o = 18;
    }
  } else if (linkType === 113) {
    // DLT_LINUX_SLL
    if (pkt.length < 16) return null;
    etherType = readU16BE(pkt, 14);
    o = 16;
  } else if (linkType === 12) {
    // DLT_RAW — IPv4/6 first byte
    o = 0;
    etherType = 0x0800;
  } else {
    return null;
  }

  if (etherType !== 0x0800) return null;
  if (o + 20 > pkt.length) return null;
  const ver = pkt[o] >> 4;
  if (ver !== 4) return null;
  const ihl = (pkt[o] & 0xf) * 4;
  if (ihl < 20 || o + ihl > pkt.length) return null;
  const ipProto = pkt[o + 9];
  const src = ipv4(pkt, o);
  const dst = ipv4Dst(pkt, o);
  if (!src || !dst) return null;

  const ipPayload = o + ihl;
  let sport = 0;
  let dport = 0;
  if (ipProto === 6 || ipProto === 17) {
    if (ipPayload + 4 > pkt.length) return { src, dst, ipProto, sport: 0, dport: 0, ipOff: o, ihl };
    sport = readU16BE(pkt, ipPayload);
    dport = readU16BE(pkt, ipPayload + 2);
  }

  return { src, dst, ipProto, sport, dport, ipOff: o, ihl };
}

function l4PayloadTcp(pkt: Uint8Array, ipOff: number, ihl: number): Uint8Array | null {
  if (pkt[ipOff + 9] !== 6) return null;
  const ipPayload = ipOff + ihl;
  if (ipPayload + 20 > pkt.length) return null;
  const thl = (pkt[ipPayload + 12] >> 4) * 4;
  if (thl < 20 || ipPayload + thl > pkt.length) return null;
  return pkt.subarray(ipPayload + thl);
}

function l4PayloadUdp(pkt: Uint8Array, ipOff: number, ihl: number): Uint8Array | null {
  if (pkt[ipOff + 9] !== 17) return null;
  const ipPayload = ipOff + ihl;
  if (ipPayload + 8 > pkt.length) return null;
  return pkt.subarray(ipPayload + 8);
}

function mapProto(p: number): TrafficLog['protocol'] {
  switch (p) {
    case 6:
      return 'TCP';
    case 17:
      return 'UDP';
    case 1:
      return 'ICMP';
    case 132:
      return 'SCTP';
    case 58:
      return 'ICMP'; // ICMPv6 mapped loosely for display
    default:
      return 'OTHER';
  }
}

function flowKey(src: string, dst: string, ipProto: number, sport: number, dport: number): string {
  if (ipProto === 132) return `${src}|${dst}|132`;
  return `${src}|${dst}|${ipProto}|${sport}|${dport}`;
}

/** GTPv1-U T-PDU (msg type 0xFF): TEID + inner IPv4 when present. */
function tryParseGtpuTpdu(udpPayload: Uint8Array): GtpuMeta | null {
  if (udpPayload.length < 8) return null;
  const b0 = udpPayload[0];
  const version = (b0 >> 5) & 0x7;
  if (version !== 1) return null;
  if (((b0 >> 4) & 1) !== 1) return null;
  if (udpPayload[1] !== 0xff) return null;
  const teid =
    (udpPayload[4] << 24) | (udpPayload[5] << 16) | (udpPayload[6] << 8) | udpPayload[7];
  let off = 8;
  const e = (b0 >> 2) & 1;
  const s = (b0 >> 1) & 1;
  const pn = b0 & 1;
  if (s && off + 4 <= udpPayload.length) off += 4;
  if (pn && off + 1 <= udpPayload.length) off += 1;
  if (e) {
    while (off + 2 <= udpPayload.length) {
      const extLen = udpPayload[off + 1];
      const step = Math.max(4, 4 * extLen);
      const nh = udpPayload[off];
      off += step;
      if (nh === 0) break;
      if (off >= udpPayload.length) break;
    }
  }
  if (off + 20 > udpPayload.length) return { teid: teid >>> 0 };
  const verIp = udpPayload[off] >> 4;
  if (verIp !== 4) return { teid: teid >>> 0 };
  const ihl = (udpPayload[off] & 0xf) * 4;
  if (ihl < 20 || off + ihl > udpPayload.length) return { teid: teid >>> 0 };
  const innerSrc = `${udpPayload[off + 12]}.${udpPayload[off + 13]}.${udpPayload[off + 14]}.${udpPayload[off + 15]}`;
  const innerDst = `${udpPayload[off + 16]}.${udpPayload[off + 17]}.${udpPayload[off + 18]}.${udpPayload[off + 19]}`;
  return { teid: teid >>> 0, innerSrc, innerDst };
}

/** Deterministic 0..1 from flow shape (no Math.random — stable across re-parses). */
function stableUnitFromFlowAgg(f: FlowAgg): number {
  const s = `${f.src}|${f.dst}|${f.sport}|${f.dport}|${f.ipProto}|${f.packets}|${Math.round(f.bytes)}`;
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h % 10_000) / 10_000;
}

function classifyFlow(f: FlowAgg): { status: TrafficStatus; attack?: string; confidence: number } {
  const duration = Math.max(0.0001, f.lastTs - f.firstTs);
  const pps = f.packets / duration;
  const bps = f.bytes / duration;
  const avgPkt = f.bytes / Math.max(1, f.packets);

  if (f.ipProto === 17 && (f.sport === 2152 || f.dport === 2152) && (pps > 800 || f.packets > 4000)) {
    return { status: 'Malicious', attack: 'GTP-U flood / high-rate user plane', confidence: 0.88 };
  }
  if (f.ipProto === 6 && f.dport === 22 && f.packets > 120 && duration < 30) {
    return { status: 'Malicious', attack: 'Brute Force (SSH) — high packet count', confidence: 0.84 };
  }
  if (pps > 2500 && avgPkt < 200) {
    return { status: 'Malicious', attack: 'Possible volumetric flood', confidence: 0.81 };
  }
  if (bps > 4e6 && duration < 3) {
    return { status: 'Malicious', attack: 'Bursty high throughput', confidence: 0.8 };
  }

  if (f.ipProto === 17 && (f.sport === 2152 || f.dport === 2152) && (pps > 200 || f.packets > 800)) {
    return { status: 'Suspicious', attack: 'Elevated GTP-U rate (review)', confidence: 0.72 };
  }
  if (f.ipProto === 6 && f.dport === 22 && f.packets > 40 && duration < 45) {
    return { status: 'Suspicious', attack: 'Possible SSH probing (review)', confidence: 0.68 };
  }
  if (pps > 800 && avgPkt < 250) {
    return { status: 'Suspicious', attack: 'Spiky small-packet volume (review)', confidence: 0.7 };
  }
  if (bps > 1.5e6 && duration < 8) {
    return { status: 'Suspicious', attack: 'Unusually bursty flow (review)', confidence: 0.65 };
  }

  return {
    status: 'Benign',
    confidence: parseFloat((0.86 + stableUnitFromFlowAgg(f) * 0.12).toFixed(3)),
  };
}

type FiveGHintFields = Pick<
  TrafficLog,
  'protocol' | 'radioAccess' | 'upfInterface' | 'dnnSlice' | 'fiveQi' | 'pduSessionId' | 'ngapNasHint'
> & { innerUeIpv4?: string | null; qfi?: number | null; gtpuTeidHex?: string };

function fiveGHints(f: FlowAgg, gtpu?: GtpuMeta | null): FiveGHintFields {
  const baseProto = mapProto(f.ipProto);
  if (f.ipProto === 17 && (f.sport === 2152 || f.dport === 2152)) {
    const teidHex = gtpu ? `0x${gtpu.teid.toString(16)}` : `0x${(f.bytes % 0xfffffff).toString(16)}`;
    const inner = gtpu?.innerSrc && gtpu?.innerDst ? `${gtpu.innerSrc} → ${gtpu.innerDst}` : null;
    return {
      protocol: 'GTP-U',
      radioAccess: '5G-SA-NR',
      upfInterface: 'N3',
      dnnSlice: 'internet.mnc001.mcc001.gprs',
      fiveQi: f.dport === 2152 ? 9 : 8,
      pduSessionId: (f.sport + f.dport) % 14 || 1,
      ngapNasHint: inner
        ? `GTP-U T-PDU · TEID ${teidHex} · inner ${inner} · ${f.packets} pkts`
        : `GTP-U UDP/2152 · TEID ${teidHex} · ${f.packets} pkts`,
      gtpuTeidHex: teidHex,
      innerUeIpv4: gtpu?.innerSrc ?? null,
      qfi: null,
    };
  }
  if (f.ipProto === 132) {
    return {
      protocol: 'SCTP',
      radioAccess: '5G-SA-NR',
      upfInterface: 'N3',
      dnnSlice: 'signaling.sctp.5gc',
      fiveQi: 5,
      pduSessionId: 1,
      ngapNasHint: 'SCTP · NGAP carrier candidate (PPID 60)',
      innerUeIpv4: null,
      qfi: null,
    };
  }
  return {
    protocol: baseProto,
    radioAccess: f.bytes > 50000 ? '5G-NSA' : 'LTE-ANCHOR',
    upfInterface: f.dport === 80 || f.dport === 443 ? 'N6' : 'N3',
    dnnSlice: f.dport === 80 || f.dport === 443 ? 'internet.mnc001.mcc001.gprs' : 'core-ip.pcap.5gc',
    fiveQi: f.ipProto === 6 ? 6 : 9,
    pduSessionId: (f.src.length + f.dst.length) % 11 || 1,
    ngapNasHint: `${baseProto} · ${f.packets} pkts`,
    innerUeIpv4: null,
    qfi: null,
  };
}

/**
 * Classic libpcap (micro/nano LE). PCAP-NG not supported.
 */
export function parsePcapToTrafficLogs(buffer: ArrayBuffer, sourceName: string): PcapParseResult {
  const warnings: string[] = [];
  if (buffer.byteLength < 24) {
    return { ok: false, error: 'File too small to be a PCAP.' };
  }

  const head = new Uint8Array(buffer, 0, 4);
  const sig = (head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3];
  if (sig === 0x0a0d0d0a) {
    return {
      ok: false,
      error:
        'PCAP-NG (.pcapng) is not parsed in-browser yet. Convert to classic PCAP: tcpdump -r in.pcapng -w out.pcap -F pcap (or Wireshark “Save as pcap”).',
    };
  }

  const view = new DataView(buffer);
  const magic = view.getUint32(0, false);
  let le = true;
  let nano = false;
  if (magic === 0xd4c3b2a1) {
    le = true;
    nano = false;
  } else if (magic === 0xa1b2c3d4) {
    le = false;
    nano = false;
  } else if (magic === 0x4d3cb2a1) {
    le = true;
    nano = true;
  } else if (magic === 0xa1b2cd34) {
    le = false;
    nano = true;
  } else {
    return { ok: false, error: `Unknown PCAP magic 0x${magic.toString(16)}.` };
  }

  const linkType = view.getUint32(20, le);
  if (linkType !== 1 && linkType !== 113 && linkType !== 12) {
    warnings.push(`Link-layer type ${linkType} — only Ethernet(1), Linux SLL(113), RAW(12) IPv4 paths are handled.`);
  }

  const flows = new Map<string, FlowAgg>();
  const enrichByFlow = new Map<string, FlowEnrichment>();
  const gtpuByFlow = new Map<string, GtpuMeta>();
  let offset = 24;
  let pktIndex = 0;
  const tScale = nano ? 1e9 : 1e6;

  while (offset + 16 <= buffer.byteLength) {
    const tsSec = view.getUint32(offset, le);
    const tsSub = view.getUint32(offset + 4, le);
    const inclLen = view.getUint32(offset + 8, le);
    const offset0 = offset + 16;
    offset = offset0 + inclLen;
    if (inclLen < 0 || offset0 + inclLen > buffer.byteLength) {
      warnings.push('Truncated PCAP or invalid incl_len; stopped early.');
      break;
    }

    const ts = tsSec + tsSub / tScale;
    const pkt = new Uint8Array(buffer, offset0, inclLen);
    pktIndex++;

    const parsed = parseIpv4Payload(linkType, pkt);
    if (!parsed) continue;

    const key = flowKey(parsed.src, parsed.dst, parsed.ipProto, parsed.sport, parsed.dport);
    const prev = flows.get(key);
    if (prev) {
      prev.lastTs = Math.max(prev.lastTs, ts);
      prev.firstTs = Math.min(prev.firstTs, ts);
      prev.bytes += inclLen;
      prev.packets += 1;
    } else {
      flows.set(key, {
        firstTs: ts,
        lastTs: ts,
        bytes: inclLen,
        packets: 1,
        src: parsed.src,
        dst: parsed.dst,
        sport: parsed.sport,
        dport: parsed.dport,
        ipProto: parsed.ipProto,
      });
    }

    let pay = new Uint8Array(0);
    if (parsed.ipProto === 6) {
      const p = l4PayloadTcp(pkt, parsed.ipOff, parsed.ihl);
      if (p) pay = p;
    } else if (parsed.ipProto === 17) {
      const p = l4PayloadUdp(pkt, parsed.ipOff, parsed.ihl);
      if (p) {
        pay = p;
        if (
          (parsed.sport === 2152 || parsed.dport === 2152) &&
          p.length >= 8 &&
          !gtpuByFlow.has(key)
        ) {
          const g = tryParseGtpuTpdu(p);
          if (g) gtpuByFlow.set(key, g);
        }
      }
    }
    if (pay.length > 0) {
      let en = enrichByFlow.get(key);
      if (!en) {
        en = emptyFlowEnrichment();
        enrichByFlow.set(key, en);
      }
      enrichFlowFromPayload(en, parsed.ipProto, parsed.sport, parsed.dport, pay);
    }
  }

  if (flows.size === 0) {
    return {
      ok: false,
      error:
        'No IPv4 flows extracted. Try a PCAP with Ethernet or Linux “cooked” captures, or convert to IPv4 PCAP.',
    };
  }

  const sorted = [...flows.values()].sort((a, b) => b.bytes - a.bytes);

  /** Keep highest-volume flows for dashboard responsiveness. */
  const baseBudget = 60;
  const hardCap = 120;
  const budget = Math.min(hardCap, Math.max(baseBudget, sorted.length));
  const selected = sorted.slice(0, budget);

  if (sorted.length > budget) {
    warnings.push(
      `Aggregated ${sorted.length} flows; showing top ${selected.length} by volume (cap ${hardCap}).`,
    );
  }

  /** Stable per-flow suffix so the same PCAP yields the same row ids (assistant patches + localStorage survive re-ingest). */
  const flowKeySuffix = (f: FlowAgg) => {
    const key = `${f.src}|${f.dst}|${f.ipProto}|${f.sport}|${f.dport}|${f.packets}|${Math.round(f.bytes)}`;
    let h = 5381;
    for (let k = 0; k < key.length; k++) h = ((h << 5) + h) ^ key.charCodeAt(k);
    return (h >>> 0).toString(36).slice(0, 9);
  };

  const out: TrafficLog[] = selected.map((f, i) => {
    const { status, attack, confidence } = classifyFlow(f);
    const fk = flowKey(f.src, f.dst, f.ipProto, f.sport, f.dport);
    const gtpu = gtpuByFlow.get(fk) ?? null;
    const hints = fiveGHints(f, gtpu);
    const duration = Math.max(0.001, f.lastTs - f.firstTs);
    const en = enrichByFlow.get(fk);
    const deep = en ? enrichmentToLogFields(en) : null;
    const base: TrafficLog = {
      id: `pcap-${sourceName.replace(/[^a-z0-9_-]/gi, '_')}-${i}-${flowKeySuffix(f)}`,
      timestamp: new Date(f.firstTs * 1000).toLocaleTimeString(),
      sourceIP: f.src,
      destIP: f.dst,
      sourcePort: f.sport,
      destPort: f.dport,
      ipProtocol: f.ipProto,
      protocol: hints.protocol,
      packetSize: Math.round(f.bytes / f.packets),
      duration: parseFloat(duration.toFixed(3)),
      byteTotal: f.bytes,
      packetCount: f.packets,
      status,
      attackType: attack,
      confidence: parseFloat(confidence.toFixed(3)),
      radioAccess: hints.radioAccess,
      upfInterface: hints.upfInterface,
      dnnSlice: hints.dnnSlice,
      fiveQi: hints.fiveQi,
      pduSessionId: hints.pduSessionId,
      ngapNasHint: hints.ngapNasHint,
      rawFrameSample: `${f.packets.toString(16)}pk…${(f.bytes % 0xffff).toString(16).padStart(4, '0')}`,
      ...(hints.gtpuTeidHex ? { gtpuTeidHex: hints.gtpuTeidHex } : {}),
      innerUeIpv4: hints.innerUeIpv4 ?? null,
      qfi: hints.qfi ?? null,
      ...(deep && deep.dnsQueryNames.length > 0 ? { dnsQueryNames: deep.dnsQueryNames } : {}),
      ...(deep?.httpHost ? { httpHost: deep.httpHost } : {}),
      ...(deep?.ja3 ? { ja3: deep.ja3, ja3Raw: deep.ja3Raw } : {}),
      ...(deep?.ja3s ? { ja3s: deep.ja3s, ja3sRaw: deep.ja3sRaw } : {}),
    };
    return ensureTelecomFields(base);
  });

  if (pktIndex === 0) {
    return { ok: false, error: 'No packets read from PCAP.' };
  }

  warnings.push(`Parsed ${pktIndex} packets → ${flows.size} flows (source: ${sourceName}).`);
  return { ok: true, flows: out, warnings };
}
