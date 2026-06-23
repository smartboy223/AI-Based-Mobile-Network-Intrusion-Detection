#!/usr/bin/env python3
"""Regenerate synthetic data and retrain all MNIDS lab models (RF, IF, AE). Run from repo root."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    py = sys.executable
    subprocess.check_call([py, str(ROOT / "backend" / "generate_dataset_and_pcap.py")], cwd=str(ROOT))
    subprocess.check_call([py, str(ROOT / "backend" / "train_models.py")], cwd=str(ROOT))
    print("Retrain pipeline OK:", ROOT / "cnn_model")


if __name__ == "__main__":
    main()
