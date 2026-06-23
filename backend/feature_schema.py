"""MNIDS lab features (must match frontend/src/lib/mlFeatures.ts)."""

import math
from typing import List

FEATURE_NAMES: List[str] = [
    "log_duration",
    "log_bytes",
    "log_packets",
    "avg_pkt",
    "sport_n",
    "dport_n",
    "is_tcp",
    "is_udp",
    "is_sctp",
    "is_gtpu",
    "is_ssh",
    "is_dns",
    "log_bytes_per_sec",
    "log_pkts_per_sec",
]


def log1p(x: float) -> float:
    return math.log(1.0 + max(x, 0.0))


def row_vector(
    duration: float,
    total_bytes: int,
    packets: int,
    sport: int,
    dport: int,
    ip_proto: int,
) -> List[float]:
    dur = max(float(duration), 1e-6)
    p = max(int(packets), 1)
    b = max(int(total_bytes), 1)
    avg_pkt = b / p
    tcp = 1.0 if ip_proto == 6 else 0.0
    udp = 1.0 if ip_proto == 17 else 0.0
    sctp = 1.0 if ip_proto == 132 else 0.0
    is_gtpu = 1.0 if (sport == 2152 or dport == 2152) else 0.0
    is_ssh = 1.0 if (sport == 22 or dport == 22) else 0.0
    is_dns = 1.0 if (sport == 53 or dport == 53) else 0.0
    bps = b / dur
    pps = p / dur
    return [
        log1p(dur),
        log1p(b),
        log1p(p),
        float(avg_pkt),
        sport / 65535.0,
        dport / 65535.0,
        tcp,
        udp,
        sctp,
        is_gtpu,
        is_ssh,
        is_dns,
        log1p(bps),
        log1p(pps),
    ]


def label_name(y: int) -> str:
    return ["Benign", "Suspicious", "Malicious"][int(y)]
