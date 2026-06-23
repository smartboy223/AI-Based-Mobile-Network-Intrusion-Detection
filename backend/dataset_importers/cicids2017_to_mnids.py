#!/usr/bin/env python3
"""
Convert CIC-IDS2017 CSV flows into the MNIDS labeled training schema.

CIC-IDS2017 ships eight daily CSVs produced by CICFlowMeter, each with ~80
columns per flow. MNIDS's ML Lab expects a 15-column CSV (REQUIRED_CSV_COLUMNS
in backend/inference_server.py): 14 log-scaled flow features plus a label_id.

This script:
  1. Reads one or more CIC-IDS2017 CSV files (passed as positional args).
  2. Cleans whitespace from column headers (CIC files have leading spaces).
  3. Maps each flow's CICFlowMeter columns onto the MNIDS 14-feature vector
     using the same row_vector formula as backend/feature_schema.py.
  4. Maps CIC attack labels (Benign / DoS Hulk / PortScan / ...) onto MNIDS
     3-class label_ids (0=Benign, 1=Suspicious, 2=Malicious).
  5. Writes the merged result to one MNIDS-ready CSV that you can upload via
     ML Lab → Train (demo).

USAGE
-----
  # Activate the project venv first, then:
  python backend/dataset_importers/cicids2017_to_mnids.py \
      --out dataset/imported/cicids2017_mnids.csv \
      "C:/path/to/CIC-IDS2017/MachineLearningCSV/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv" \
      "C:/path/to/CIC-IDS2017/MachineLearningCSV/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv"

  # Or use the --download-info flag to print where to get the data.

CITATION
--------
Iman Sharafaldin, Arash Habibi Lashkari, Ali A. Ghorbani,
"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic
Characterization", 4th Int. Conf. Information Systems Security and Privacy
(ICISSP), Portugal, January 2018.
Dataset URL: https://www.unb.ca/cic/datasets/ids-2017.html
"""
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Iterable

import pandas as pd


# --- 14 feature columns the MNIDS pipeline trains on (must match
#     backend/feature_schema.py FEATURE_NAMES exactly).
MNIDS_FEATURE_NAMES = [
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
MNIDS_COLUMNS = MNIDS_FEATURE_NAMES + ["label_id"]


# --- Map CIC-IDS2017 attack labels to MNIDS 3-class ids.
# Anything not listed defaults to Suspicious so we never drop a row silently.
# The split between Suspicious and Malicious here is intentional:
#   - "Malicious" = clear adversarial action (DoS, DDoS, brute force, bot,
#     web attacks, infiltration, exploits).
#   - "Suspicious" = reconnaissance / probing that may be Benign or attack
#     depending on context (PortScan).
LABEL_MAP = {
    "BENIGN": 0,
    "Benign": 0,
    "benign": 0,
    "PortScan": 1,
    "Port Scan": 1,
    "DoS Hulk": 2,
    "DoS GoldenEye": 2,
    "DoS slowloris": 2,
    "DoS Slowhttptest": 2,
    "DDoS": 2,
    "FTP-Patator": 2,
    "SSH-Patator": 2,
    "Bot": 2,
    "Heartbleed": 2,
    "Infiltration": 2,
    "Web Attack \x96 Brute Force": 2,
    "Web Attack \x96 XSS": 2,
    "Web Attack \x96 Sql Injection": 2,
    "Web Attack - Brute Force": 2,
    "Web Attack - XSS": 2,
    "Web Attack - Sql Injection": 2,
    "Web Attack Brute Force": 2,
    "Web Attack XSS": 2,
    "Web Attack Sql Injection": 2,
}


def log1p(x: float) -> float:
    return math.log1p(max(x, 0.0))


# --- Resolve the column the CIC CSV uses for each MNIDS feature. CIC files
# have inconsistent leading spaces in headers (e.g. " Flow Duration"); we
# strip them on load.
CIC_DURATION_US = "Flow Duration"          # microseconds in CIC
CIC_BYTES = "Total Length of Fwd Packets"  # bytes; we also add backward
CIC_BYTES_BWD = "Total Length of Bwd Packets"
CIC_PKTS_FWD = "Total Fwd Packets"
CIC_PKTS_BWD = "Total Backward Packets"
CIC_AVG_PKT = "Average Packet Size"
CIC_SPORT = "Source Port"
CIC_DPORT = "Destination Port"
CIC_PROTO = "Protocol"  # IANA protocol number (6=TCP, 17=UDP)
CIC_LABEL = "Label"


def _row_to_mnids(r: pd.Series) -> dict[str, float] | None:
    """Convert one CICFlowMeter row to the 14-feature MNIDS dict (+ label_id).
    Returns None if the row can't be reasonably converted (drops the row)."""
    try:
        dur_us = float(r[CIC_DURATION_US])
    except Exception:
        return None
    dur_s = max(dur_us / 1e6, 1e-6)  # CIC durations are in microseconds

    try:
        total_bytes = float(r[CIC_BYTES]) + float(r.get(CIC_BYTES_BWD, 0))
        total_pkts = float(r[CIC_PKTS_FWD]) + float(r.get(CIC_PKTS_BWD, 0))
    except Exception:
        return None
    total_bytes = max(total_bytes, 1.0)
    total_pkts = max(total_pkts, 1.0)
    avg_pkt = float(r.get(CIC_AVG_PKT, total_bytes / total_pkts))

    sport = int(r.get(CIC_SPORT, 0) or 0)
    dport = int(r.get(CIC_DPORT, 0) or 0)
    ip_proto = int(r.get(CIC_PROTO, 0) or 0)

    is_tcp = 1.0 if ip_proto == 6 else 0.0
    is_udp = 1.0 if ip_proto == 17 else 0.0
    is_sctp = 1.0 if ip_proto == 132 else 0.0
    # CIC is enterprise IT traffic, no GTP-U — the column stays 0, which is
    # exactly the signal that distinguishes IT vs 5G traffic in MNIDS.
    is_gtpu = 0.0
    is_ssh = 1.0 if (sport == 22 or dport == 22) else 0.0
    is_dns = 1.0 if (sport == 53 or dport == 53) else 0.0

    bps = total_bytes / dur_s
    pps = total_pkts / dur_s

    label_raw = str(r.get(CIC_LABEL, "Benign")).strip()
    label_id = LABEL_MAP.get(label_raw)
    if label_id is None:
        # Unknown label — assume Suspicious rather than silently dropping.
        label_id = 1

    return {
        "log_duration": log1p(dur_s),
        "log_bytes": log1p(total_bytes),
        "log_packets": log1p(total_pkts),
        "avg_pkt": float(avg_pkt),
        "sport_n": sport / 65535.0,
        "dport_n": dport / 65535.0,
        "is_tcp": is_tcp,
        "is_udp": is_udp,
        "is_sctp": is_sctp,
        "is_gtpu": is_gtpu,
        "is_ssh": is_ssh,
        "is_dns": is_dns,
        "log_bytes_per_sec": log1p(bps),
        "log_pkts_per_sec": log1p(pps),
        "label_id": int(label_id),
    }


def load_one_cic_csv(path: Path) -> pd.DataFrame:
    """Read a CIC-IDS2017 CSV and return it with whitespace-stripped headers."""
    df = pd.read_csv(path, low_memory=False, encoding="latin-1")
    df.columns = [c.strip() for c in df.columns]
    return df


def convert(paths: Iterable[Path], out: Path, sample_per_label: int | None = None) -> None:
    rows: list[dict[str, float]] = []
    per_label_kept: dict[int, int] = {0: 0, 1: 0, 2: 0}
    for p in paths:
        print(f"[importer] reading {p.name} …", flush=True)
        df = load_one_cic_csv(p)
        if CIC_DURATION_US not in df.columns:
            print(
                f"[importer] WARN: skipping {p.name} — does not look like a "
                "CICFlowMeter CSV (no 'Flow Duration' column).",
                file=sys.stderr,
            )
            continue
        kept = 0
        for _, r in df.iterrows():
            out_row = _row_to_mnids(r)
            if out_row is None:
                continue
            lid = out_row["label_id"]
            if sample_per_label is not None and per_label_kept.get(lid, 0) >= sample_per_label:
                continue
            rows.append(out_row)
            per_label_kept[lid] = per_label_kept.get(lid, 0) + 1
            kept += 1
        print(f"[importer]   kept {kept} rows from {p.name}", flush=True)
    if not rows:
        print("[importer] ERROR: no rows produced. Check input file paths.", file=sys.stderr)
        sys.exit(1)
    out_df = pd.DataFrame(rows, columns=MNIDS_COLUMNS)
    out.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out, index=False)
    dist = out_df["label_id"].value_counts().to_dict()
    label_names = {0: "Benign", 1: "Suspicious", 2: "Malicious"}
    pretty = ", ".join(f"{label_names[k]}={v}" for k, v in sorted(dist.items()))
    print(f"[importer] wrote {len(out_df)} rows → {out}", flush=True)
    print(f"[importer] label distribution: {pretty}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Convert CIC-IDS2017 CSVs to MNIDS schema.")
    ap.add_argument("inputs", nargs="*", type=Path, help="One or more CICFlowMeter CSV files.")
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("dataset/imported/cicids2017_mnids.csv"),
        help="Output CSV path (will be created).",
    )
    ap.add_argument(
        "--sample-per-label",
        type=int,
        default=None,
        help=(
            "Optional cap per label_id. CIC-IDS2017 is hugely imbalanced "
            "(millions of benign rows vs thousands of attacks). E.g. "
            "--sample-per-label 20000 keeps at most 20k Benign + 20k "
            "Suspicious + 20k Malicious for a faster, balanced demo train."
        ),
    )
    ap.add_argument(
        "--download-info",
        action="store_true",
        help="Print where to download CIC-IDS2017 and exit.",
    )
    args = ap.parse_args()

    if args.download_info:
        print("CIC-IDS2017 download:")
        print("  https://www.unb.ca/cic/datasets/ids-2017.html")
        print("Click 'MachineLearningCSV.zip' (≈800 MB) → extract to a folder")
        print("of your choice → pass each daily CSV as a positional arg here.")
        print("")
        print("Cite as:")
        print("  Iman Sharafaldin, Arash Habibi Lashkari, Ali A. Ghorbani,")
        print("  'Toward Generating a New Intrusion Detection Dataset and")
        print("  Intrusion Traffic Characterization', ICISSP 2018.")
        return

    if not args.inputs:
        ap.error("provide at least one CICFlowMeter CSV (or pass --download-info).")
    for p in args.inputs:
        if not p.is_file():
            ap.error(f"input not found: {p}")

    convert(args.inputs, args.out, sample_per_label=args.sample_per_label)


if __name__ == "__main__":
    main()
