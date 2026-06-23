#!/usr/bin/env python3
"""
Optional Suricata + Zeek wrappers for offline PCAP analysis (external binaries).

Install separately:
  - Zeek: https://zeek.org/  (zeek -r capture.pcap)
  - Suricata: https://suricata.io/  (suricata -r capture.pcap -l outdir)

Usage (from repo root):
  python mnids/backend/ids_tools.py mnids/dataset/pcap/mnids-lab-ml-synthetic.pcap

Writes dataset/exports/suricata_zeek_summary.json with paths to logs or "not_installed".
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORT_DIR = ROOT / "dataset" / "exports"


def _which(cmd: str) -> str | None:
    return shutil.which(cmd)


def run_zeek(pcap: Path, work: Path) -> dict:
    zeek = _which("zeek")
    if not zeek:
        return {"ok": False, "tool": "zeek", "error": "zeek not in PATH"}
    try:
        subprocess.run(
            [zeek, "-r", str(pcap.resolve())],
            cwd=str(work),
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "tool": "zeek", "error": str(e)}
    conn = work / "conn.log"
    files = sorted(work.glob("*.log"))
    return {
        "ok": True,
        "tool": "zeek",
        "working_dir": str(work),
        "log_files": [f.name for f in files],
        "conn_log_bytes": conn.stat().st_size if conn.is_file() else 0,
    }


def run_suricata(pcap: Path, work: Path) -> dict:
    suri = _which("suricata")
    if not suri:
        return {"ok": False, "tool": "suricata", "error": "suricata not in PATH"}
    out = work / "suricata_out"
    out.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [suri, "-r", str(pcap.resolve()), "-l", str(out)],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "tool": "suricata", "error": str(e)}
    ev = list(out.rglob("eve.json*"))
    return {
        "ok": True,
        "tool": "suricata",
        "output_dir": str(out),
        "eve_json_files": [str(f.relative_to(out)) for f in ev[:20]],
    }


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python backend/ids_tools.py <path/to/file.pcap>")
        sys.exit(1)
    pcap = Path(sys.argv[1])
    if not pcap.is_file():
        print("Not a file:", pcap)
        sys.exit(1)

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    summary: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pcap": str(pcap.resolve()),
        "zeek": {},
        "suricata": {},
    }

    with tempfile.TemporaryDirectory(prefix="mnids_zeek_") as zd:
        summary["zeek"] = run_zeek(pcap, Path(zd))
    with tempfile.TemporaryDirectory(prefix="mnids_suri_") as sd:
        summary["suricata"] = run_suricata(pcap, Path(sd))

    out = EXPORT_DIR / "suricata_zeek_summary.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("Wrote", out)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
