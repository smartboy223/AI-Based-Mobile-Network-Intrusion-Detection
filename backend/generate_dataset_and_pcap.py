#!/usr/bin/env python3
"""
Build synthetic flow CSV + PCAP for MNIDS lab demos.
Outputs: dataset/mnids_synthetic_flows.csv, dataset/ground_truth_manifest.json,
         dataset/pcap/mnids-lab-ml-synthetic.pcap

Run from repo root:  python mnids/backend/generate_dataset_and_pcap.py
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from feature_schema import FEATURE_NAMES, label_name, row_vector

ROOT = Path(__file__).resolve().parents[1]
OUT_CSV = ROOT / "dataset" / "mnids_synthetic_flows.csv"
OUT_MANIFEST = ROOT / "dataset" / "ground_truth_manifest.json"
OUT_PCAP = ROOT / "dataset" / "pcap" / "mnids-lab-ml-synthetic.pcap"

N_FLOWS = 96
RNG_SEED = 42


def u32le(n: int) -> bytes:
    return struct.pack("<I", n & 0xFFFFFFFF)


def ip_parse(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def ip_checksum(hdr20: bytes) -> int:
    s = 0
    for i in range(0, 20, 2):
        s += int.from_bytes(hdr20[i : i + 2], "big")
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_ipv4(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[1] = 0
    struct.pack_into(">H", ip, 2, total)
    struct.pack_into(">H", ip, 4, 0x4D6E)
    struct.pack_into(">H", ip, 6, 0x4000)
    ip[8] = 64
    ip[9] = proto
    ip[10:12] = b"\x00\x00"
    ip[12:16] = src
    ip[16:20] = dst
    struct.pack_into(">H", ip, 10, ip_checksum(bytes(ip)))
    return bytes(ip) + payload


def udp_packet(sport: int, dport: int, payload: bytes) -> bytes:
    ln = 8 + len(payload)
    return struct.pack(">HHHH", sport & 0xFFFF, dport & 0xFFFF, ln, 0) + payload


def tcp_packet(sport: int, dport: int, payload: bytes) -> bytes:
    hlen = 20
    t = bytearray(hlen + len(payload))
    struct.pack_into(">HH", t, 0, sport & 0xFFFF, dport & 0xFFFF)
    struct.pack_into(">II", t, 4, 0xDEAD0001, 0)
    t[12] = 0x50
    t[13] = 0x18 if len(payload) else 0x02
    struct.pack_into(">HH", t, 14, 0xFFFF, 0)
    t[18:20] = b"\x00\x00"
    t[hlen:] = payload
    return bytes(t)


def sctp_packet(payload: bytes) -> bytes:
    return bytes(payload)


def eth_frame(ip_payload: bytes) -> bytes:
    dst = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    src = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    return dst + src + b"\x08\x00" + ip_payload


def pcap_record(ts_sec: int, ts_usec: int, frame: bytes) -> bytes:
    return u32le(ts_sec) + u32le(ts_usec) + u32le(len(frame)) + u32le(len(frame)) + frame


def build_gtpu_tpdu(teid: int, inner_ipv4: bytes) -> bytes:
    gtp = bytearray(8)
    gtp[0] = 0x30
    gtp[1] = 0xFF
    struct.pack_into(">H", gtp, 2, len(inner_ipv4))
    struct.pack_into(">I", gtp, 4, teid & 0xFFFFFFFF)
    return bytes(gtp) + inner_ipv4


@dataclass
class FlowSpec:
    flow_id: int
    label: int
    src: str
    dst: str
    sport: int
    dport: int
    ip_proto: int
    packets: int
    duration: float
    total_bytes: int


def flow_ips_unique(idx: int, rng: np.random.Generator) -> tuple[bytes, bytes, str, str]:
    """Unique /24 per flow so SCTP (no port in flow key) stays separated."""
    a = f"10.{(idx % 180) + 20}.{((idx * 3) % 200) + 1}.{int(rng.integers(10, 240))}"
    b = f"10.45.{((idx * 7) % 160) + 10}.{int(rng.integers(10, 240))}"
    return ip_parse(a), ip_parse(b), a, b


def frames_to_flow_metrics(frames: list[bytes]) -> tuple[float, int, int]:
    """Derive duration, total capture bytes, and packet count from PCAP records (same as sample_flow)."""
    ts_list = [(struct.unpack_from("<II", rec, 0)) for rec in frames]
    incl_lens = [struct.unpack_from("<I", rec, 8)[0] for rec in frames]
    ts0 = ts_list[0][0] + ts_list[0][1] / 1e6
    ts1 = ts_list[-1][0] + ts_list[-1][1] / 1e6
    duration = max(ts1 - ts0, 1e-6)
    total_bytes = sum(incl_lens)
    return float(duration), int(total_bytes), len(frames)


def emit_linear_timeline_frames(
    src_b: bytes,
    dst_b: bytes,
    ip_proto: int,
    sport: int,
    dport: int,
    build_payload: object,
    n_packets: int,
    t_start: float,
    duration_sec: float,
) -> list[bytes]:
    """Spread packets evenly over [t_start, t_start+duration] for realistic volumetric / calm demos."""
    frames: list[bytes] = []
    dur = max(float(duration_sec), 1e-6)
    for i in range(n_packets):
        frac = i / max(n_packets - 1, 1)
        t = t_start + frac * dur
        ts_sec = int(t)
        ts_usec = int(round((t - ts_sec) * 1_000_000))
        if ts_usec >= 1_000_000:
            ts_sec += ts_usec // 1_000_000
            ts_usec %= 1_000_000
        if isinstance(build_payload, bytes):
            pl: bytes = build_payload
        else:
            pl = build_payload(i)  # type: ignore[operator]
        if ip_proto == 6:
            ip_pl = tcp_packet(sport, dport, pl)
        elif ip_proto == 17:
            ip_pl = udp_packet(sport, dport, pl)
        else:
            ip_pl = sctp_packet(pl)
        fr = eth_frame(build_ipv4(src_b, dst_b, ip_proto, ip_pl))
        frames.append(pcap_record(ts_sec, ts_usec, fr))
    return frames


def behavioral_synthetic_flow(flow_id: int, slot: int) -> tuple[FlowSpec, list[bytes]]:
    """
    Flows 90–95: deterministic behavioral scenarios (volumetric / DDoS-like vs calm baselines).
    Uses private RFC1918 space only — not the IOC reputation list — so ML + rate heuristics drive the story.
    """
    # label: 0 Benign, 1 Suspicious, 2 Malicious
    scenarios: list[tuple[int, int, float, int, int, int, object]] = [
        # Malicious — UDP/53 microburst (amplification / flood pattern)
        (2, 560, 0.17, 41234, 53, 17, lambda _i: bytes(48)),
        # Malicious — UDP toward 443, very high pps
        (2, 520, 0.16, 39876, 443, 17, lambda _i: bytes(56)),
        # Malicious — TCP many small segments (volumetric / handshake abuse pattern)
        (2, 500, 0.17, 35100, 80, 6, lambda _i: b""),
        # Suspicious — elevated UDP (parser: pps > 800 && small avg packet, sub–volumetric-flood)
        (1, 450, 0.48, 29111, 17000, 17, lambda _i: bytes(72)),
        # Benign — steady HTTPS-like
        (0, 42, 4.0, 44102, 443, 6, lambda _i: b"GET /index HTTP/1.1\r\nHost: lab.cdn.mnids\r\n\r\n"),
        # Benign — sparse DNS
        (0, 18, 2.4, 53991, 53, 17, lambda _i: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"),
    ]
    label, n_pkt, duration_sec, sport, dport, ip_proto, payload_fn = scenarios[slot]
    src_s = f"10.200.{90 + slot}.14"
    dst_s = f"10.45.{100 + slot}.9"
    src_b, dst_b = ip_parse(src_s), ip_parse(dst_s)
    t_start = 1_700_000_500.0 + float(flow_id) * 6.0
    frames = emit_linear_timeline_frames(
        src_b, dst_b, ip_proto, sport, dport, payload_fn, n_pkt, t_start, duration_sec
    )
    duration, total_bytes, packets = frames_to_flow_metrics(frames)
    spec = FlowSpec(
        flow_id=flow_id,
        label=label,
        src=src_s,
        dst=dst_s,
        sport=sport,
        dport=dport,
        ip_proto=ip_proto,
        packets=packets,
        duration=duration,
        total_bytes=total_bytes,
    )
    return spec, frames


def attack_taxonomy_for(spec: FlowSpec, style: str) -> str:
    """Loosely inspired by CIC-IDS2018 category names vs 5G-NIDD-style core/user-plane wording (lab synthetic)."""
    if spec.label == 0:
        return "BENIGN_HTTPS_DNS" if style == "cic_ids2018_style" else "5G_BENIGN_UP_GTP_DNS"
    if spec.label == 1:
        return "Infiltration_PortScan_like" if style == "cic_ids2018_style" else "5G_SUSPICIOUS_N3_GTP_RATE"
    return "DoS_BruteForce_like" if style == "cic_ids2018_style" else "5G_MALICIOUS_CORE_FLOOD"


def sample_flow(rng: np.random.Generator, idx: int, style: str) -> tuple[FlowSpec, list[bytes]]:
    if style == "cic_ids2018_style":
        weights = (0.50, 0.32, 0.18)
    else:
        weights = (0.54, 0.28, 0.18)
    label = int(rng.choice([0, 1, 2], p=weights))
    base_a, base_b, src_s, dst_s = flow_ips_unique(idx, rng)

    frames: list[bytes] = []
    ts_sec = 1_700_000_000 + (idx // 8)
    ts_usec = int(rng.integers(0, 400_000))

    def push(ip_payload: bytes) -> None:
        nonlocal ts_sec, ts_usec
        fr = eth_frame(ip_payload)
        frames.append(pcap_record(ts_sec, ts_usec, fr))
        ts_usec += int(rng.integers(800, 12000))
        if ts_usec >= 1_000_000:
            ts_sec += 1
            ts_usec = 0

    sport = dport = 0
    ip_proto = 6

    if label == 0:
        if rng.random() < 0.55:
            sport, dport = int(rng.integers(40000, 50000)), 443
            ip_proto = 6
            n_pkt = int(rng.integers(10, 36))
            body = b"GET /health HTTP/1.1\r\nHost: cdn.lab.mnids\r\n\r\n"
            for _ in range(n_pkt):
                push(build_ipv4(base_a, base_b, 6, tcp_packet(sport, dport, body)))
        else:
            sport, dport = int(rng.integers(30000, 40000)), 53
            ip_proto = 17
            n_pkt = int(rng.integers(6, 22))
            q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
            for _ in range(n_pkt):
                push(build_ipv4(base_a, base_b, 17, udp_packet(sport, dport, q)))
    elif label == 1:
        if rng.random() < 0.6:
            sport = int(rng.integers(20000, 35000))
            dport = int(rng.integers(40000, 55000))
            ip_proto = 17
            n_pkt = int(rng.integers(28, 90))
            pl = bytes(int(rng.integers(0, 256)) for _ in range(int(rng.integers(24, 120))))
            for _ in range(n_pkt):
                push(build_ipv4(base_a, base_b, 17, udp_packet(sport, dport, pl)))
        else:
            sport, dport = int(rng.integers(38000, 50000)), 38412
            ip_proto = 132
            n_pkt = int(rng.integers(14, 40))
            pl = bytes([0xCD]) * int(rng.integers(20, 80))
            for _ in range(n_pkt):
                push(build_ipv4(base_a, base_b, 132, sctp_packet(pl)))
    else:
        if style == "5g_nidd_style":
            mode = str(rng.choice(["gtp", "gtp", "ssh", "flood"]))
        else:
            mode = str(rng.choice(["ssh", "flood", "gtp", "flood"]))
        if mode == "ssh":
            sport, dport = int(rng.integers(35000, 60000)), 22
            ip_proto = 6
            n_pkt = int(rng.integers(55, 160))
            for _ in range(n_pkt):
                push(build_ipv4(base_a, base_b, 6, tcp_packet(sport, dport, b"")))
        elif mode == "gtp":
            sport, dport = int(rng.integers(30000, 32000)), 2152
            ip_proto = 17
            teid = int(rng.integers(0x100000, 0xFEFFFFFF))
            inner_src = ip_parse("10.60.0.44")
            inner_dst = ip_parse("8.8.8.8")
            n_pkt = int(rng.integers(40, 120))
            for _ in range(n_pkt):
                inner = build_ipv4(
                    inner_src,
                    inner_dst,
                    17,
                    udp_packet(
                        int(rng.integers(40000, 45000)),
                        53,
                        bytes(int(rng.integers(0, 256)) for _ in range(48)),
                    ),
                )
                gtp = build_gtpu_tpdu(teid, inner)
                push(build_ipv4(base_a, base_b, 17, udp_packet(sport, dport, gtp)))
        else:
            sport = int(rng.integers(10000, 20000))
            dport = int(rng.integers(20000, 30000))
            ip_proto = 17
            n_pkt = int(rng.integers(80, 200))
            pl = bytes(int(rng.integers(0, 256)) for _ in range(int(rng.integers(40, 90))))
            for _ in range(n_pkt):
                push(build_ipv4(base_a, base_b, 17, udp_packet(sport, dport, pl)))

    ts_list = [(struct.unpack_from("<II", rec, 0)) for rec in frames]
    incl_lens = [struct.unpack_from("<I", rec, 8)[0] for rec in frames]
    ts0 = ts_list[0][0] + ts_list[0][1] / 1e6
    ts1 = ts_list[-1][0] + ts_list[-1][1] / 1e6
    duration = max(ts1 - ts0, 1e-6)
    total_bytes = sum(incl_lens)

    spec = FlowSpec(
        flow_id=idx,
        label=label,
        src=src_s,
        dst=dst_s,
        sport=sport,
        dport=dport,
        ip_proto=ip_proto,
        packets=len(frames),
        duration=float(duration),
        total_bytes=int(total_bytes),
    )
    return spec, frames


def main() -> None:
    rng = np.random.default_rng(RNG_SEED)
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    OUT_PCAP.parent.mkdir(parents=True, exist_ok=True)

    all_records: list[bytes] = []
    rows: list[dict] = []
    manifest_flows: list[dict] = []

    for i in range(N_FLOWS):
        if i >= 90:
            spec, frames = behavioral_synthetic_flow(i, i - 90)
            style_tag = "behavioral_lab"
            tax = f"MNIDS_VOLUMETRIC_LAB_{i - 90}"
        elif i < 45:
            spec, frames = sample_flow(rng, i, "cic_ids2018_style")
            style_tag = "cic_ids2018_style"
            tax = attack_taxonomy_for(spec, "cic_ids2018_style")
        else:
            spec, frames = sample_flow(rng, i, "5g_nidd_style")
            style_tag = "5g_nidd_style"
            tax = attack_taxonomy_for(spec, "5g_nidd_style")
        all_records.extend(frames)
        vec = row_vector(
            spec.duration,
            spec.total_bytes,
            spec.packets,
            spec.sport,
            spec.dport,
            spec.ip_proto,
        )
        row = {k: v for k, v in zip(FEATURE_NAMES, vec)}
        row["label_id"] = spec.label
        row["label"] = label_name(spec.label)
        row["flow_id"] = spec.flow_id
        row["src_ip"] = spec.src
        row["dst_ip"] = spec.dst
        row["sport"] = spec.sport
        row["dport"] = spec.dport
        row["ip_proto"] = spec.ip_proto
        row["packets"] = spec.packets
        row["duration_sec"] = spec.duration
        row["total_bytes"] = spec.total_bytes
        row["dataset_style"] = style_tag
        row["attack_taxonomy"] = tax
        rows.append(row)
        mf: dict = {
            "flow_id": spec.flow_id,
            "ground_truth": label_name(spec.label),
            "packets": spec.packets,
            "duration_sec": round(spec.duration, 6),
            "total_bytes": spec.total_bytes,
            "dataset_style": style_tag,
            "attack_taxonomy": tax,
        }
        if spec.flow_id >= 90:
            mf["behavior_demo"] = "volumetric_ddos_lab_slot_" + str(spec.flow_id - 90)
        manifest_flows.append(mf)

    df = pd.DataFrame(rows)
    df.to_csv(OUT_CSV, index=False)

    manifest = {
        "generator": "mnids_synthetic_lab",
        "rng_seed": RNG_SEED,
        "n_flows": N_FLOWS,
        "pcap_file": "dataset/pcap/mnids-lab-ml-synthetic.pcap",
        "csv_file": "dataset/mnids_synthetic_flows.csv",
        "class_counts": df["label"].value_counts().to_dict(),
        "feature_names": FEATURE_NAMES,
        "dataset_blend_note": (
            "Rows 0–44 emulate CIC-IDS2018-style enterprise attack diversity (naming + port mix); "
            "45–89 emulate 5G-NIDD-style core/user-plane emphasis (GTP-U/SCTP-heavy malicious modes). "
            "Not the original public CSVs — synthetic flows aligned for MNIDS lab training."
        ),
        "behavior_demo_note": (
            "Flows 90–95 are fixed volumetric / calm scenarios (UDP/TCP rates, not IOC IPs). "
            "They train RF+IF+AE on log_bytes_per_sec and log_pkts_per_sec and demo DDoS-like behavior in PCAP ingest."
        ),
        "flows": manifest_flows,
    }
    OUT_MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    global_header = u32le(0xA1B2C3D4) + struct.pack("<HHIIII", 2, 4, 0, 0, 0xFFFF, 1)
    OUT_PCAP.write_bytes(global_header + b"".join(all_records))

    print(f"Wrote {OUT_CSV} ({len(df)} rows)")
    print(f"Wrote {OUT_MANIFEST}")
    print(f"Wrote {OUT_PCAP} ({len(all_records)} packets)")


if __name__ == "__main__":
    main()
