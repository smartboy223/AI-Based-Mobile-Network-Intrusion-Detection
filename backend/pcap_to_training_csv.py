#!/usr/bin/env python3
"""
Convert a PCAP file into MNIDS training CSV rows (flow-level features).

Why this script:
- Presentation-friendly: one command from PCAP -> training_template-style CSV
- No extra pip deps required (uses Python stdlib + existing feature_schema)

Output columns:
  log_duration,log_bytes,log_packets,avg_pkt,sport_n,dport_n,is_tcp,is_udp,is_sctp,
  is_gtpu,is_ssh,is_dns,log_bytes_per_sec,log_pkts_per_sec,label_id

Examples:
  python mnids/backend/pcap_to_training_csv.py ^
    --pcap mnids/dataset/pcap/mnids-lab-01-traffic.pcap ^
    --out mnids/dataset/samples/from_pcap.csv ^
    --auto-label

  python mnids/backend/pcap_to_training_csv.py ^
    --pcap mnids/dataset/pcap/mnids-lab-01-traffic.pcap ^
    --out mnids/dataset/samples/from_pcap_clean.csv ^
    --default-label 0
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Tuple

from feature_schema import FEATURE_NAMES, row_vector


@dataclass
class FlowAgg:
    first_ts: float
    last_ts: float
    packets: int
    total_bytes: int
    sport: int
    dport: int
    ip_proto: int


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="PCAP -> MNIDS training CSV")
    ap.add_argument("--pcap", required=True, help="Input .pcap path")
    ap.add_argument("--out", required=True, help="Output CSV path")
    ap.add_argument(
        "--auto-label",
        action="store_true",
        help="Use simple demo heuristics to set label_id (0/1/2)",
    )
    ap.add_argument(
        "--default-label",
        type=int,
        choices=[0, 1, 2],
        default=0,
        help="Label used when --auto-label is not set (default: 0 = Clean)",
    )
    return ap.parse_args()


def _read_pcap_packets(pcap_path: Path) -> Iterable[Tuple[float, bytes]]:
    with pcap_path.open("rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise RuntimeError("Invalid PCAP: global header too short")

        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"  # little-endian
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"  # big-endian
        else:
            raise RuntimeError("Unsupported PCAP magic header")

        pkt_hdr_fmt = endian + "IIII"
        pkt_hdr_sz = struct.calcsize(pkt_hdr_fmt)

        while True:
            ph = f.read(pkt_hdr_sz)
            if not ph:
                break
            if len(ph) < pkt_hdr_sz:
                break
            ts_sec, ts_subsec, incl_len, _orig_len = struct.unpack(pkt_hdr_fmt, ph)
            frame = f.read(incl_len)
            if len(frame) < incl_len:
                break
            ts = float(ts_sec) + (float(ts_subsec) / 1_000_000.0)
            yield ts, frame


def _parse_ipv4_tuple(frame: bytes) -> Tuple[str, str, int, int, int, int] | None:
    # Ethernet offset
    if len(frame) < 14:
        return None
    off = 14
    eth_type = struct.unpack("!H", frame[12:14])[0]

    # Optional single VLAN tag
    if eth_type == 0x8100:
        if len(frame) < 18:
            return None
        eth_type = struct.unpack("!H", frame[16:18])[0]
        off = 18

    if eth_type != 0x0800:  # IPv4
        return None
    if len(frame) < off + 20:
        return None

    vihl = frame[off]
    ver = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if ver != 4 or ihl < 20 or len(frame) < off + ihl:
        return None

    ip_proto = frame[off + 9]
    src_ip = str(ipaddress.IPv4Address(frame[off + 12 : off + 16]))
    dst_ip = str(ipaddress.IPv4Address(frame[off + 16 : off + 20]))

    l4 = off + ihl
    sport = 0
    dport = 0
    if ip_proto in (6, 17, 132) and len(frame) >= l4 + 4:  # TCP/UDP/SCTP
        sport, dport = struct.unpack("!HH", frame[l4 : l4 + 4])

    return src_ip, dst_ip, sport, dport, ip_proto, len(frame)


def _auto_label(sport: int, dport: int, ip_proto: int, packets: int, duration: float) -> int:
    # Simple, explainable demo heuristics (presentation use)
    if (dport == 22 and packets >= 120) or (packets >= 500 and duration <= 2.0):
        return 2  # Malicious
    if (ip_proto == 17 and packets >= 120) or (dport not in {22, 53, 80, 443, 2152} and packets >= 40):
        return 1  # Suspicious
    return 0  # Clean


def main() -> None:
    args = _parse_args()
    pcap_path = Path(args.pcap).resolve()
    out_path = Path(args.out).resolve()
    if not pcap_path.exists():
        raise SystemExit(f"PCAP not found: {pcap_path}")

    flows: Dict[Tuple[str, str, int, int, int], FlowAgg] = {}

    for ts, frame in _read_pcap_packets(pcap_path):
        parsed = _parse_ipv4_tuple(frame)
        if parsed is None:
            continue
        src_ip, dst_ip, sport, dport, ip_proto, frame_len = parsed
        k = (src_ip, dst_ip, sport, dport, ip_proto)
        cur = flows.get(k)
        if cur is None:
            flows[k] = FlowAgg(
                first_ts=ts,
                last_ts=ts,
                packets=1,
                total_bytes=frame_len,
                sport=sport,
                dport=dport,
                ip_proto=ip_proto,
            )
        else:
            cur.last_ts = ts
            cur.packets += 1
            cur.total_bytes += frame_len

    out_path.parent.mkdir(parents=True, exist_ok=True)
    cols = FEATURE_NAMES + ["label_id"]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for flow in flows.values():
            duration = max(flow.last_ts - flow.first_ts, 1e-6)
            feats = row_vector(
                duration=duration,
                total_bytes=flow.total_bytes,
                packets=flow.packets,
                sport=flow.sport,
                dport=flow.dport,
                ip_proto=flow.ip_proto,
            )
            label_id = (
                _auto_label(flow.sport, flow.dport, flow.ip_proto, flow.packets, duration)
                if args.auto_label
                else int(args.default_label)
            )
            w.writerow([*feats, label_id])

    print(f"Wrote {out_path}")
    print(f"Rows: {len(flows)}")
    print(f"Columns: {', '.join(cols)}")


if __name__ == "__main__":
    main()

