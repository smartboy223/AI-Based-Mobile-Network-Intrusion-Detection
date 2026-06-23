import { md5Hex } from './md5hex';

/** IPv4 private / non-VT ranges (same idea as virusTotal.ts). */
export function isPrivateOrNonVtIpv4(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return true;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 255 && b === 255 && Number(m[3]) === 255 && Number(m[4]) === 255) return true;
  return false;
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function looksLikeIpv4(s: string): boolean {
  return IPV4_RE.test(s.trim());
}

/** Domains we should not send to VT (noise / local). */
export function shouldSkipVtDomain(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, '');
  if (!h || h === 'localhost' || h.endsWith('.local') || h.endsWith('.lan')) return true;
  if (h === '_' || h.startsWith('wpad.') || h.startsWith('isatap.')) return true;
  if (looksLikeIpv4(h.split(':')[0])) return true;
  if (h.endsWith('.arpa')) return true;
  if (h.endsWith('.internal') || h.endsWith('.corp') || h.endsWith('.home')) return true;
  return false;
}

/** Normalize host: strip port, lowercase, IDNA-ish ASCII only for VT. */
export function normalizeHostForVt(raw: string): string | null {
  const s = raw.trim().toLowerCase();
  if (!s) return null;
  const noPort = s.includes(']') ? s : s.split(':')[0];
  const h = noPort.replace(/^\./, '').replace(/\.$/, '');
  if (!h || h.length > 253) return null;
  if (shouldSkipVtDomain(h)) return null;
  return h;
}

export type FlowEnrichment = {
  dnsQueryNames: Set<string>;
  httpHosts: Set<string>;
  ja3Md5: string | null;
  ja3Raw: string | null;
  ja3sMd5: string | null;
  ja3sRaw: string | null;
};

export function emptyFlowEnrichment(): FlowEnrichment {
  return {
    dnsQueryNames: new Set(),
    httpHosts: new Set(),
    ja3Md5: null,
    ja3Raw: null,
    ja3sMd5: null,
    ja3sRaw: null,
  };
}

function readDnsQnames(payload: Uint8Array): string[] {
  if (payload.length < 12) return [];
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const qdcount = view.getUint16(4, false);
  if (qdcount < 1) return [];
  let off = 12;
  const names: string[] = [];
  for (let q = 0; q < qdcount && off < payload.length; q++) {
    const labels: string[] = [];
    for (let guard = 0; guard < 128; guard++) {
      const len = payload[off];
      if (len === 0) {
        off++;
        break;
      }
      if ((len & 0xc0) === 0xc0) {
        if (off + 1 >= payload.length) return names;
        const ptr = ((len & 0x3f) << 8) | payload[off + 1];
        off += 2;
        let p = ptr;
        for (let g2 = 0; g2 < 64; g2++) {
          const l2 = payload[p];
          if (l2 === 0) break;
          if ((l2 & 0xc0) === 0xc0) return names;
          if (p + 1 + l2 > payload.length) return names;
          labels.push(
            new TextDecoder('utf-8', { fatal: false }).decode(payload.subarray(p + 1, p + 1 + l2)),
          );
          p += 1 + l2;
        }
        break;
      }
      if (len > 63 || off + 1 + len > payload.length) return names;
      labels.push(
        new TextDecoder('utf-8', { fatal: false }).decode(payload.subarray(off + 1, off + 1 + len)),
      );
      off += 1 + len;
    }
    if (off + 4 <= payload.length) off += 4;
    const fq = labels.join('.').replace(/\.$/, '');
    if (fq && fq.length <= 253) names.push(fq.toLowerCase());
  }
  return names;
}

function extractHttpHost(payload: Uint8Array, maxScan = 2048): string | null {
  const n = Math.min(payload.length, maxScan);
  let start = -1;
  for (let i = 0; i <= n - 4; i++) {
    if (
      payload[i] === 0x47 &&
      payload[i + 1] === 0x45 &&
      payload[i + 2] === 0x54 &&
      payload[i + 3] === 0x20
    ) {
      start = i;
      break;
    }
    if (
      payload[i] === 0x50 &&
      payload[i + 1] === 0x4f &&
      payload[i + 2] === 0x53 &&
      payload[i + 3] === 0x54
    ) {
      start = i;
      break;
    }
    if (
      payload[i] === 0x48 &&
      payload[i + 1] === 0x45 &&
      payload[i + 2] === 0x41 &&
      payload[i + 3] === 0x44
    ) {
      start = i;
      break;
    }
  }
  if (start < 0) return null;
  const chunk = payload.subarray(start, n);
  const text = new TextDecoder('latin1', { fatal: false }).decode(chunk);
  const m = text.match(/\r\nHost:\s*([^\r\n]+)/i);
  if (!m) return null;
  return m[1].trim();
}

function readUint16BE(buf: Uint8Array, o: number): number {
  return (buf[o] << 8) | buf[o + 1];
}

function readUint24BE(buf: Uint8Array, o: number): number {
  return (buf[o] << 16) | (buf[o + 1] << 8) | buf[o + 2];
}

/** Parse TLS ClientHello → JA3 string + MD5 hash (best-effort). */
function parseJa3FromClientHello(hs: Uint8Array): { ja3: string; ja3Hash: string } | null {
  if (hs.length < 38) return null;
  let o = 0;
  if (hs[o++] !== 1) return null;
  const hsLen = readUint24BE(hs, o);
  o += 3;
  if (o + hsLen > hs.length) return null;
  const end = o + hsLen;
  const legacyVersion = readUint16BE(hs, o);
  o += 2 + 32;
  if (o >= end) return null;
  const sidLen = hs[o++];
  o += sidLen;
  if (o + 2 > end) return null;
  const csLen = readUint16BE(hs, o);
  o += 2;
  if (o + csLen > end || csLen % 2 !== 0) return null;
  const ciphers: string[] = [];
  for (let i = 0; i < csLen; i += 2) {
    ciphers.push(readUint16BE(hs, o + i).toString());
  }
  o += csLen;
  if (o >= end) return null;
  const compLen = hs[o++];
  o += compLen;
  if (o + 2 > end) return null;
  const extLen = readUint16BE(hs, o);
  o += 2;
  const extEnd = o + extLen;
  if (extEnd > end) return null;
  const extTypes: string[] = [];
  const curves: string[] = [];
  const ecpf: string[] = [];
  while (o + 4 <= extEnd) {
    const et = readUint16BE(hs, o);
    o += 2;
    const el = readUint16BE(hs, o);
    o += 2;
    if (o + el > extEnd) break;
    extTypes.push(et.toString());
    if (et === 10 && el >= 2) {
      const gl = readUint16BE(hs, o);
      let p = o + 2;
      for (let i = 0; i < gl && p + 2 <= o + el; i += 2) {
        curves.push(readUint16BE(hs, p).toString());
        p += 2;
      }
    }
    if (et === 11 && el >= 1) {
      const count = hs[o];
      let p = o + 1;
      for (let i = 0; i < count && p < o + el; i++, p++) {
        ecpf.push(hs[p].toString());
      }
    }
    o += el;
  }
  const ja3 = `${legacyVersion},${ciphers.join('-')},${extTypes.join('-')},${curves.join('-')},${ecpf.join('-')}`;
  return { ja3, ja3Hash: md5Hex(ja3) };
}

/** Parse TLS ServerHello → JA3S string + MD5. */
function parseJa3sFromServerHello(hs: Uint8Array): { ja3s: string; ja3sHash: string } | null {
  if (hs.length < 38) return null;
  let o = 0;
  if (hs[o++] !== 2) return null;
  const hsLen = readUint24BE(hs, o);
  o += 3;
  if (o + hsLen > hs.length) return null;
  const end = o + hsLen;
  const legacyVersion = readUint16BE(hs, o);
  o += 2 + 32;
  if (o + 1 > end) return null;
  const sidLen = hs[o++];
  o += sidLen;
  if (o + 2 > end) return null;
  const cipher = readUint16BE(hs, o);
  o += 2;
  if (o + 1 > end) return null;
  const comp = hs[o++];
  if (o + 2 > end) return null;
  const extLen = readUint16BE(hs, o);
  o += 2;
  const extEnd = o + extLen;
  if (extEnd > end) return null;
  const extTypes: string[] = [];
  while (o + 4 <= extEnd) {
    const et = readUint16BE(hs, o);
    o += 2;
    const el = readUint16BE(hs, o);
    o += 2;
    if (o + el > extEnd) break;
    extTypes.push(et.toString());
    o += el;
  }
  const ja3s = `${legacyVersion},${cipher},${extTypes.join('-')}`;
  return { ja3s, ja3sHash: md5Hex(ja3s) };
}

function scanTlsForJa3IntoEnrich(payload: Uint8Array, enrich: FlowEnrichment): void {
  let i = 0;
  while (i + 5 <= payload.length) {
    const ct = payload[i];
    const recLen = readUint16BE(payload, i + 3);
    i += 5;
    if (recLen <= 0 || i + recLen > payload.length) break;
    const frag = payload.subarray(i, i + recLen);
    i += recLen;
    if (ct !== 22) continue;
    let j = 0;
    while (j + 4 <= frag.length) {
      const ht = frag[j];
      const hl = readUint24BE(frag, j + 1);
      j += 4;
      if (hl <= 0 || j + hl > frag.length) break;
      const body = frag.subarray(j, j + hl);
      j += hl;
      if (ht === 1 && !enrich.ja3Md5) {
        const p = parseJa3FromClientHello(body);
        if (p) {
          enrich.ja3Md5 = p.ja3Hash;
          enrich.ja3Raw = p.ja3;
        }
      }
      if (ht === 2 && !enrich.ja3sMd5) {
        const p = parseJa3sFromServerHello(body);
        if (p) {
          enrich.ja3sMd5 = p.ja3sHash;
          enrich.ja3sRaw = p.ja3s;
        }
      }
    }
  }
}

/**
 * Enrich a flow from L4 payload (UDP DNS, TCP HTTP/TLS).
 */
export function enrichFlowFromPayload(
  enrich: FlowEnrichment,
  proto: number,
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): void {
  if (payload.length === 0) return;
  if (proto === 17 && (srcPort === 53 || dstPort === 53)) {
    for (const q of readDnsQnames(payload)) {
      if (q && !q.startsWith('_')) enrich.dnsQueryNames.add(q);
    }
    return;
  }
  if (proto === 6) {
    const host = extractHttpHost(payload);
    if (host) {
      const n = normalizeHostForVt(host) ?? host.trim().toLowerCase();
      if (n) enrich.httpHosts.add(n);
    }
    scanTlsForJa3IntoEnrich(payload, enrich);
  }
}

export function enrichmentToLogFields(e: FlowEnrichment): {
  dnsQueryNames: string[];
  httpHost: string | null;
  ja3: string | null;
  ja3s: string | null;
  ja3Raw: string | null;
  ja3sRaw: string | null;
} {
  const dns = [...e.dnsQueryNames].sort();
  const hosts = [...e.httpHosts].sort();
  return {
    dnsQueryNames: dns,
    httpHost: hosts[0] ?? null,
    ja3: e.ja3Md5,
    ja3s: e.ja3sMd5,
    ja3Raw: e.ja3Raw,
    ja3sRaw: e.ja3sRaw,
  };
}
