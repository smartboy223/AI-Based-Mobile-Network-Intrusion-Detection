/**
 * Builds three classic PCAPs under dataset/pcap/:
 *   mnids-lab-01-traffic.pcap … mnids-lab-03-traffic.pcap
 * Profile goals:
 *   01 = mixed traffic (existing baseline + IOC + suspicious-lab mix)
 *   02 = clean-only traffic
 *   03 = malicious-only traffic
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(__dirname, '..', '..', 'dataset', 'pcap');
const iocPath = path.join(__dirname, '..', '..', 'frontend', 'src', 'data', 'demo-ioc-ips.json');

function ipParse(s) {
  return Buffer.from(s.split('.').map((x) => Number(x) & 0xff));
}

function u32le(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

function u16be(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff, 0);
  return b;
}

/** Minimal DNS query (UDP/53) so MNIDS PCAP parser extracts QNAMEs. */
function buildDnsQuery(hostname) {
  const labels = hostname.split('.').filter(Boolean);
  let qname = Buffer.alloc(0);
  for (const lab of labels) {
    const b = Buffer.from(lab, 'utf8');
    if (b.length > 63) throw new Error(`DNS label too long: ${lab}`);
    qname = Buffer.concat([qname, Buffer.from([b.length]), b]);
  }
  qname = Buffer.concat([qname, Buffer.from([0])]);
  const header = Buffer.concat([
    u16be(0xace1),
    u16be(0x0100),
    u16be(1),
    u16be(0),
    u16be(0),
    u16be(0),
  ]);
  return Buffer.concat([header, qname, u16be(1), u16be(1)]);
}

/** Cleartext HTTP with Host: so flow parser can populate httpHost. */
function httpGet(host, path) {
  return Buffer.from(
    `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: MNIDS-IDS/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
    'utf8',
  );
}

/** GTPv1-U T-PDU (0xFF) + inner IPv4 datagram (N3 user plane). */
function buildGtpuTpdu(teid, innerIpv4Payload) {
  const gtp = Buffer.alloc(8);
  gtp[0] = 0x30;
  gtp[1] = 0xff;
  gtp.writeUInt16BE(innerIpv4Payload.length, 2);
  gtp.writeUInt32BE(teid >>> 0, 4);
  return Buffer.concat([gtp, innerIpv4Payload]);
}

function ipChecksum(ipHeader20) {
  let sum = 0;
  for (let i = 0; i < 20; i += 2) {
    sum += ipHeader20.readUInt16BE(i);
  }
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

function buildIpv4(src, dst, proto, payload) {
  const total = 20 + payload.length;
  const ip = Buffer.alloc(20);
  ip[0] = 0x45;
  ip[1] = 0;
  ip.writeUInt16BE(total, 2);
  ip.writeUInt16BE(0x4d6e, 4);
  ip.writeUInt16BE(0x4000, 6);
  ip[8] = 64;
  ip[9] = proto;
  ip.writeUInt16BE(0, 10);
  src.copy(ip, 12);
  dst.copy(ip, 16);
  ip.writeUInt16BE(ipChecksum(ip), 10);
  return Buffer.concat([ip, payload]);
}

function udpPacket(sport, dport, payload) {
  const len = 8 + payload.length;
  const u = Buffer.alloc(len);
  u.writeUInt16BE(sport & 0xffff, 0);
  u.writeUInt16BE(dport & 0xffff, 2);
  u.writeUInt16BE(len, 4);
  u.writeUInt16BE(0, 6);
  payload.copy(u, 8);
  return u;
}

function tcpPacket(sport, dport, payload) {
  const hlen = 20;
  const t = Buffer.alloc(hlen + payload.length);
  t.writeUInt16BE(sport & 0xffff, 0);
  t.writeUInt16BE(dport & 0xffff, 2);
  t.writeUInt32BE(0xdead0001, 4);
  t.writeUInt32BE(0, 8);
  t[12] = 0x50;
  t[13] = payload.length ? 0x18 : 0x02;
  t.writeUInt16BE(0xffff, 14);
  t.writeUInt16BE(0, 16);
  t.writeUInt16BE(0, 18);
  payload.copy(t, hlen);
  return t;
}

function eth(ipPayload) {
  const dst = Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
  const src = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
  return Buffer.concat([dst, src, Buffer.from([0x08, 0x00]), ipPayload]);
}

function pcapRecord(tsSec, tsUsec, frame) {
  return Buffer.concat([u32le(tsSec), u32le(tsUsec), u32le(frame.length), u32le(frame.length), frame]);
}

const SRC_GTP = ipParse('10.201.44.12');
const UPF = ipParse('10.45.0.1');
const SRC_WEB = ipParse('10.201.44.18');
const ATT_SIG = ipParse('192.0.2.88');
const DST_SIG = ipParse('10.45.0.3');
const ATT_SSH = ipParse('192.168.50.10');
const ATT_GTP = ipParse('198.51.100.20');
const WEB_DST = ipParse('203.0.113.50');
const INNER_UE = ipParse('10.60.0.44');
const INNER_UPF = ipParse('8.8.4.4');
const GTP_TEID_BASELINE = 0x04a2f901;
const GTP_TEID_ABUSE = 0xfeed0011;

const iocJson = JSON.parse(fs.readFileSync(iocPath, 'utf8'));
const IOC_PARTS = iocJson.parts;
const SUS_PARTS = iocJson.suspiciousParts ?? [];
const SUS_LABELS = iocJson.suspiciousPartLabels ?? [];

function createRecorder(tsBase) {
  const records = [];
  let ts = tsBase;
  let tsU = 0;
  function pushFrame(ipPayload) {
    const frame = eth(ipPayload);
    records.push(pcapRecord(ts, tsU, frame));
    tsU += 4000;
    if (tsU >= 1_000_000) {
      ts += 1;
      tsU = 0;
    }
  }
  return { records, pushFrame };
}

function appendBaseline(pushFrame) {
  for (let i = 0; i < 18; i++) {
    const inner = buildIpv4(
      INNER_UE,
      INNER_UPF,
      17,
      udpPacket(33400 + i, 443, Buffer.alloc(12 + (i % 5), 0x3c)),
    );
    const gtp = buildGtpuTpdu(GTP_TEID_BASELINE, inner);
    pushFrame(buildIpv4(SRC_GTP, UPF, 17, udpPacket(45000 + i, 2152, gtp)));
  }
  for (let i = 0; i < 12; i++) {
    pushFrame(
      buildIpv4(SRC_WEB, WEB_DST, 6, tcpPacket(49152 + i, 443, httpGet('cdn.demo.mnids', '/health'))),
    );
  }
  for (let i = 0; i < 220; i++) {
    pushFrame(buildIpv4(ATT_SIG, DST_SIG, 17, udpPacket(30000 + (i % 200), 47808, Buffer.alloc(48, i & 0xff))));
  }
  for (let i = 0; i < 160; i++) {
    pushFrame(buildIpv4(ATT_SSH, UPF, 6, tcpPacket(40000 + i, 22, Buffer.alloc(0))));
  }
  for (let i = 0; i < 95; i++) {
    const innerAbuse = buildIpv4(
      INNER_UE,
      INNER_UPF,
      17,
      udpPacket(44000 + (i % 40), 53, Buffer.alloc(64, 0xab)),
    );
    const gtpAbuse = buildGtpuTpdu(GTP_TEID_ABUSE, innerAbuse);
    pushFrame(buildIpv4(ATT_GTP, UPF, 17, udpPacket(31000, 2152, gtpAbuse)));
  }
  const sctpPayload = Buffer.alloc(24, 0xcd);
  for (let i = 0; i < 25; i++) {
    pushFrame(buildIpv4(SRC_WEB, UPF, 132, sctpPayload));
  }
  for (let i = 0; i < 15; i++) {
    pushFrame(
      buildIpv4(ipParse('10.201.44.7'), UPF, 6, tcpPacket(50000 + i, 80, httpGet('upf-internal.demo', '/'))),
    );
  }
}

/**
 * Clean-only profile:
 * - No SSH brute-force signatures
 * - No high-rate GTP-U signatures
 * - No single-packet flows (single-packet flow => very high pps by duration floor)
 */
function appendCleanProfile(pushFrame) {
  const cleanWebSrc = ipParse('10.210.10.11');
  const cleanWebDst = ipParse('203.0.113.77');
  const cleanDnsSrc = ipParse('10.210.10.15');
  const cleanDnsDst = ipParse('8.8.8.8');
  const cleanCoreSrc = ipParse('10.210.10.21');
  const cleanCoreDst = ipParse('10.45.0.9');

  // Flow A: stable HTTPS-like web traffic.
  for (let i = 0; i < 26; i++) {
    pushFrame(
      buildIpv4(cleanWebSrc, cleanWebDst, 6, tcpPacket(51100, 443, httpGet('portal.demo.mnids', '/home'))),
    );
  }

  // Flow B: normal DNS activity.
  for (let i = 0; i < 18; i++) {
    pushFrame(
      buildIpv4(
        cleanDnsSrc,
        cleanDnsDst,
        17,
        udpPacket(53001, 53, buildDnsQuery(`clean-${i % 4}.lab.mnids`)),
      ),
    );
  }

  // Flow C: internal HTTP service checks (still benign).
  for (let i = 0; i < 22; i++) {
    pushFrame(
      buildIpv4(
        cleanCoreSrc,
        cleanCoreDst,
        6,
        tcpPacket(52001, 80, httpGet('core-health.demo.mnids', '/status')),
      ),
    );
  }
}

/**
 * Malicious-only profile:
 * Each flow is engineered to satisfy parser malicious heuristics.
 * Primary trigger used: TCP/22 with >120 packets in short duration.
 */
function appendMaliciousProfile(pushFrame) {
  const att1 = ipParse('192.168.77.10');
  const att2 = ipParse('192.168.77.11');
  const att3 = ipParse('192.168.77.12');
  const tgt1 = ipParse('10.45.0.20');
  const tgt2 = ipParse('10.45.0.21');
  const tgt3 = ipParse('10.45.0.22');

  // Flow A: SSH brute-force pattern.
  for (let i = 0; i < 180; i++) {
    pushFrame(buildIpv4(att1, tgt1, 6, tcpPacket(46001, 22, Buffer.alloc(0))));
  }
  // Flow B: second SSH campaign.
  for (let i = 0; i < 160; i++) {
    pushFrame(buildIpv4(att2, tgt2, 6, tcpPacket(46002, 22, Buffer.alloc(0))));
  }
  // Flow C: third SSH campaign.
  for (let i = 0; i < 140; i++) {
    pushFrame(buildIpv4(att3, tgt3, 6, tcpPacket(46003, 22, Buffer.alloc(0))));
  }
}

/** IOC flows only for IPs in this part (parser tags these as Malicious via demo-ioc-ips.json). */
function appendIocForPart(pushFrame, ipStrings) {
  const bufs = ipStrings.map((s) => ipParse(s));
  const n = 20;
  for (let i = 0; i < n; i++) {
    const vt = bufs[i % bufs.length];
    const peer = i % 3 === 0 ? UPF : i % 3 === 1 ? SRC_WEB : WEB_DST;
    if (i % 2 === 0) {
      pushFrame(
        buildIpv4(vt, peer, 6, tcpPacket(42000 + i, 443, httpGet('ioc-vt.demo.mnids', '/vt-demo'))),
      );
    } else {
      pushFrame(
        buildIpv4(peer, vt, 17, udpPacket(43000 + i, 53, buildDnsQuery(`vt-ioc-${i % 4}.demo.mnids`))),
      );
    }
  }
}

/** Suspicious-lab public IPs (parser → Suspicious). Distinct ports from malicious IOC block. */
function appendSuspiciousLabForPart(pushFrame, ipStrings, labFrameCount = 16) {
  if (!ipStrings?.length) return;
  const bufs = ipStrings.map((s) => ipParse(s));
  const n = labFrameCount;
  for (let i = 0; i < n; i++) {
    const pub = bufs[i % bufs.length];
    const peer = i % 3 === 0 ? UPF : i % 3 === 1 ? SRC_WEB : WEB_DST;
    if (i % 2 === 0) {
      pushFrame(
        buildIpv4(pub, peer, 6, tcpPacket(41000 + i, 8443, httpGet('suspicious.lab.demo.mnids', '/sus-lab'))),
      );
    } else {
      pushFrame(
        buildIpv4(peer, pub, 17, udpPacket(41500 + i, 53, buildDnsQuery(`sus-lab-${i % 3}.query.demo`))),
      );
    }
  }
}

function writePcap(filename, records) {
  const globalHeader = Buffer.concat([
    u32le(0xa1b2c3d4),
    Buffer.from([0x02, 0x00, 0x04, 0x00]),
    u32le(0),
    u32le(0),
    u32le(0xffff),
    u32le(1),
  ]);
  const body = Buffer.concat([globalHeader, ...records]);
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, filename);
  fs.writeFileSync(outFile, body);
  return { outFile, bytes: body.length, count: records.length };
}

const baseTs = 1_700_000_000;
const outputs = [];

for (let p = 0; p < 3; p++) {
  const { records, pushFrame } = createRecorder(baseTs + p * 50);

  if (p === 0) {
    // Keep file 01 behavior as mixed traffic.
    appendBaseline(pushFrame);
    appendIocForPart(pushFrame, IOC_PARTS[p]);
    const susN = 4;
    appendSuspiciousLabForPart(pushFrame, SUS_PARTS[p] ?? [], susN);
  } else if (p === 1) {
    // File 02: clean-only profile.
    appendCleanProfile(pushFrame);
  } else {
    // File 03: malicious-only profile.
    appendMaliciousProfile(pushFrame);
  }

  const name = `mnids-lab-0${p + 1}-traffic.pcap`;
  const meta = writePcap(name, records);
  const profile = p === 0 ? 'mixed-profile' : p === 1 ? 'clean-only-profile' : 'malicious-only-profile';
  outputs.push(`${meta.count} pkts → ${meta.outFile} (${meta.bytes} B) [${profile}]`);
}

for (const legacyName of [
  'demo.pcap',
  'demo-part-1.pcap',
  'demo-part-2.pcap',
  'demo-part-3.pcap',
  'logs1.pcap',
  'logs2.pcap',
  'logs3.pcap',
]) {
  const legacy = path.join(outDir, legacyName);
  if (fs.existsSync(legacy)) {
    fs.unlinkSync(legacy);
    outputs.push(`Removed legacy ${legacyName}.`);
  }
}

console.log(outputs.join('\n'));
