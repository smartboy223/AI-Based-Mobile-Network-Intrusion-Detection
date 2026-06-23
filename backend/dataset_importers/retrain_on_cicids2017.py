#!/usr/bin/env python3
"""
One-click retrain of the live MNIDS model.

DEFAULT (offline): generate a CIC-IDS2017-style realistic labeled dataset
locally using generate_realistic_dataset.py (no download, no internet),
then run the full train + validate + replace pipeline.

OPT-IN (real CIC-IDS2017): pass --use-cicids2017 to fetch the actual
800 MB MachineLearningCSV.zip from a mirror, convert it via
cicids2017_to_mnids.py, and train on that. We default to OFFLINE because
the public CIC mirrors have been intermittently serving HTML landing
pages instead of the zip; the offline generator gives a reproducible,
deterministic, no-network dataset that's defensible for a presentation.

PIPELINE (both modes):
  1. Resolve / generate training CSV.
  2. Back up cnn_model/ → cnn_model.backup-<ts>/.
  3. Run backend/train_models.py against the CSV.
  4. Validate the new artifacts (load + smoke predict + label count).
  5. On any failure, restore the backup so the dashboard never breaks.

USAGE
-----
  RETRAIN_FROM_CICIDS2017.bat                          (offline, default)
  RETRAIN_FROM_CICIDS2017.bat --rows-per-class 30000   (offline, bigger)
  RETRAIN_FROM_CICIDS2017.bat --use-cicids2017         (real download)
  RETRAIN_FROM_CICIDS2017.bat --use-cicids2017 --zip "C:/path/to/file.zip"

The offline generator is deterministic (seeded RNG). Re-running with the
same --seed and --rows-per-class produces a byte-identical CSV — meaning
the trained model is also reproducible, which is what you want for a
dissertation or college presentation.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
import zipfile
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "dataset" / "raw" / "CIC-IDS2017"
IMPORTED_DIR = ROOT / "dataset" / "imported"
ART_DIR = ROOT / "cnn_model"
DEFAULT_OFFLINE_CSV = IMPORTED_DIR / "cicids2017_style_realistic.csv"
DEFAULT_REAL_CSV = IMPORTED_DIR / "cicids2017_mnids.csv"
ZIP_LOCAL = RAW_DIR / "MachineLearningCSV.zip"

DOWNLOAD_MIRRORS = [
    "https://intrusion-detection.distrinet-research.be/CICIDS2017/MachineLearningCVE.zip",
    "http://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/CSVs/MachineLearningCSV.zip",
]
OFFICIAL_LANDING = "https://www.unb.ca/cic/datasets/ids-2017.html"
MIN_PLAUSIBLE_ZIP_BYTES = 100 * 1024 * 1024


def _log(msg: str) -> None:
    print(f"[retrain] {msg}", flush=True)


def _err(msg: str) -> None:
    print(f"[retrain] ERROR: {msg}", file=sys.stderr, flush=True)


def _delete_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


# --- Offline generator path -------------------------------------------------


def generate_offline_csv(out_csv: Path, rows_per_class: int, seed: int) -> Path:
    gen = ROOT / "backend" / "dataset_importers" / "generate_realistic_dataset.py"
    if not gen.is_file():
        _err(f"missing generator: {gen}")
        sys.exit(4)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-u", str(gen),
        "--out", str(out_csv),
        "--rows-per-class", str(rows_per_class),
        "--seed", str(seed),
    ]
    _log(f"generating offline CIC-IDS2017-style dataset ({rows_per_class * 3} rows, seed={seed}) …")
    res = subprocess.run(cmd, cwd=str(ROOT))
    if res.returncode != 0:
        _err("offline generator failed (see lines above).")
        sys.exit(res.returncode)
    if not out_csv.is_file():
        _err(f"generator reported success but no CSV at {out_csv}")
        sys.exit(5)
    return out_csv


# --- Real-download path (opt-in) -------------------------------------------


def _looks_like_real_zip(path: Path) -> tuple[bool, str]:
    if not path.is_file():
        return False, "file does not exist"
    sz = path.stat().st_size
    if sz == 0:
        return False, "file is empty"
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError as e:
        return False, f"unreadable: {e}"
    if head[:2] != b"PK":
        try:
            with open(path, "rb") as f:
                preview = f.read(200).decode("utf-8", errors="replace").strip()
        except OSError:
            preview = "<unreadable>"
        return False, (
            f"first bytes are not the ZIP magic (got {head!r}). "
            f"Mirror returned non-zip response. Preview: {preview[:160]!r}"
        )
    if sz < MIN_PLAUSIBLE_ZIP_BYTES:
        return False, (
            f"file is only {sz / (1024 * 1024):.1f} MB — too small to be CIC-IDS2017"
        )
    try:
        with zipfile.ZipFile(path) as zf:
            bad = zf.testzip()
            if bad is not None:
                return False, f"corrupt zip member: {bad}"
    except Exception as e:
        return False, f"zipfile can't open it: {e}"
    return True, "ok"


def _download_one(url: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    _log(f"trying {url}")
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "application/zip,application/octet-stream,*/*;q=0.9",
                "Accept-Encoding": "identity",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "html" in ctype:
                _err(f"mirror returned HTML Content-Type ({ctype!r}); skipping.")
                return False
            total = resp.headers.get("Content-Length")
            total_int = int(total) if total and total.isdigit() else None
            if total_int is not None and total_int < MIN_PLAUSIBLE_ZIP_BYTES:
                _err(
                    f"mirror Content-Length: {total_int / (1024 * 1024):.1f} MB — too small."
                )
                return False
            chunk = 1024 * 256
            seen = 0
            last_log_at = 0
            with open(tmp, "wb") as f:
                while True:
                    buf = resp.read(chunk)
                    if not buf:
                        break
                    f.write(buf)
                    seen += len(buf)
                    if seen - last_log_at >= 25 * 1024 * 1024:
                        last_log_at = seen
                        if total_int:
                            pct = 100 * seen / total_int
                            _log(
                                f"  …{seen // (1024 * 1024)} MB / "
                                f"{total_int // (1024 * 1024)} MB ({pct:.1f}%)"
                            )
                        else:
                            _log(f"  …{seen // (1024 * 1024)} MB downloaded")
        tmp.replace(dest)
    except Exception as e:
        _err(f"download failed: {e}")
        _delete_quietly(tmp)
        return False
    ok, reason = _looks_like_real_zip(dest)
    if not ok:
        _err(f"downloaded file rejected: {reason}")
        _delete_quietly(dest)
        return False
    _log(
        f"downloaded → {dest} "
        f"({dest.stat().st_size / (1024 * 1024):.0f} MB, zip OK)"
    )
    return True


def _csvs_present_under(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    return sorted(folder.glob("**/*.pcap_ISCX.csv"))


def ensure_real_cicids2017(zip_override: Optional[Path], url_override: Optional[str]) -> list[Path]:
    found = _csvs_present_under(RAW_DIR)
    if found:
        _log(f"using {len(found)} CIC CSV(s) already under {RAW_DIR.relative_to(ROOT)}")
        return found

    candidate_zip: Optional[Path] = None
    if zip_override is not None:
        if not zip_override.is_file():
            _err(f"--zip path does not exist: {zip_override}")
            sys.exit(1)
        ok, reason = _looks_like_real_zip(zip_override)
        if not ok:
            _err(f"--zip {zip_override} isn't a real zip: {reason}")
            sys.exit(1)
        candidate_zip = zip_override

    if candidate_zip is None and ZIP_LOCAL.is_file():
        ok, reason = _looks_like_real_zip(ZIP_LOCAL)
        if ok:
            _log(f"reusing cached zip {ZIP_LOCAL.relative_to(ROOT)}")
            candidate_zip = ZIP_LOCAL
        else:
            _log(f"cached zip is bad ({reason}). Deleting.")
            _delete_quietly(ZIP_LOCAL)

    if candidate_zip is None:
        ZIP_LOCAL.parent.mkdir(parents=True, exist_ok=True)
        mirrors = [url_override] if url_override else list(DOWNLOAD_MIRRORS)
        for url in mirrors:
            if not url:
                continue
            if _download_one(url, ZIP_LOCAL):
                candidate_zip = ZIP_LOCAL
                break
            _delete_quietly(ZIP_LOCAL)

    if candidate_zip is None:
        _err("Could not auto-download CIC-IDS2017 from any mirror.")
        print(
            "\nThe public CIC mirrors are intermittently returning HTML landing\n"
            "pages instead of the zip. Three ways forward:\n\n"
            "  A) Easiest — use the OFFLINE realistic generator instead:\n"
            "       RETRAIN_FROM_CICIDS2017.bat\n"
            "     (without --use-cicids2017). It's deterministic, reproducible,\n"
            "     and defensible for a presentation. See docs/DATASETS.md.\n\n"
            "  B) Manual download:\n"
            f"     1. Open {OFFICIAL_LANDING}\n"
            "     2. Fill in the name/email gate.\n"
            "     3. Click 'MachineLearningCSV.zip' (~800 MB).\n"
            f"     4. Save it anywhere, then re-run:\n"
            "          RETRAIN_FROM_CICIDS2017.bat --use-cicids2017 \\\n"
            "              --zip \"C:/Users/YOU/Downloads/MachineLearningCSV.zip\"\n\n"
            "  C) Mirror override:\n"
            "       RETRAIN_FROM_CICIDS2017.bat --use-cicids2017 --url <url>\n",
            flush=True,
        )
        sys.exit(2)

    _log(f"extracting {candidate_zip.name} → {RAW_DIR.relative_to(ROOT)}/")
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(candidate_zip) as zf:
            zf.extractall(RAW_DIR)
    except zipfile.BadZipFile as e:
        _err(f"zip extraction failed: {e}")
        _delete_quietly(candidate_zip)
        sys.exit(3)
    found = _csvs_present_under(RAW_DIR)
    if not found:
        _err("extraction produced no *.pcap_ISCX.csv files")
        sys.exit(3)
    _log(f"extracted {len(found)} CIC CSV(s)")
    return found


def convert_real_csvs(csv_paths: list[Path], out_csv: Path, sample_per_label: int) -> Path:
    importer = ROOT / "backend" / "dataset_importers" / "cicids2017_to_mnids.py"
    if not importer.is_file():
        _err(f"missing importer: {importer}")
        sys.exit(4)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-u", str(importer),
        "--out", str(out_csv),
        "--sample-per-label", str(sample_per_label),
    ] + [str(p) for p in csv_paths]
    _log(f"converting {len(csv_paths)} CSV(s) with --sample-per-label {sample_per_label}")
    res = subprocess.run(cmd, cwd=str(ROOT))
    if res.returncode != 0:
        _err("importer failed.")
        sys.exit(res.returncode)
    if not out_csv.is_file():
        _err(f"no CSV at {out_csv}")
        sys.exit(5)
    return out_csv


# --- Backup / restore / train / validate (shared) --------------------------


def backup_artifacts() -> Optional[Path]:
    if not ART_DIR.is_dir():
        _log("no existing cnn_model/ to back up (skipping)")
        return None
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = ART_DIR.with_name(f"cnn_model.backup-{ts}")
    _log(f"backing up cnn_model/ → {backup.name}/")
    shutil.copytree(ART_DIR, backup, dirs_exist_ok=False)
    return backup


def restore_backup(backup: Optional[Path]) -> None:
    if backup is None or not backup.is_dir():
        _err("nothing to restore")
        return
    _log(f"restoring backup from {backup.name}/ …")
    if ART_DIR.is_dir():
        shutil.rmtree(ART_DIR)
    shutil.copytree(backup, ART_DIR)
    _log("restore complete — previous model is live again.")


def run_training(csv: Path) -> int:
    trainer = ROOT / "backend" / "train_models.py"
    if not trainer.is_file():
        _err(f"missing trainer: {trainer}")
        return 6
    cmd = [sys.executable, "-u", str(trainer), "--csv", str(csv)]
    _log("running train_models.py — longest step (1-3 minutes)…")
    res = subprocess.run(cmd, cwd=str(ROOT))
    return res.returncode


def validate_artifacts() -> bool:
    needed = [
        ART_DIR / "rf_pipeline.joblib",
        ART_DIR / "iforest_pipeline.joblib",
        ART_DIR / "meta.json",
    ]
    for p in needed:
        if not p.is_file():
            _err(f"missing artifact: {p.relative_to(ROOT)}")
            return False
    try:
        meta = json.loads((ART_DIR / "meta.json").read_text(encoding="utf-8"))
    except Exception as e:
        _err(f"meta.json unreadable: {e}")
        return False
    labels = meta.get("labels") or []
    if len(labels) < 2:
        _err(f"only {len(labels)} label(s) — refusing to keep degenerate model")
        return False
    _log(f"meta.json labels: {labels}")
    try:
        import joblib
        rf = joblib.load(ART_DIR / "rf_pipeline.joblib")
        feats = [
            [0.09, 6.85, 2.71, 71.0, 0.52, 0.0, 1, 0, 0, 0, 0, 0, 9.38, 5.13],
            [0.15, 8.4,  4.02, 82.0, 0.61, 0.02, 1, 0, 0, 1, 0, 0, 10.2, 5.9],
            [0.13, 10.21, 6.25, 54.0, 0.54, 0.01, 1, 0, 0, 0, 0, 0, 11.95, 8.04],
        ]
        preds = rf.predict(feats)
        _log(f"smoke predict OK — RF says {list(preds)}")
    except Exception as e:
        _err(f"smoke predict failed: {e}")
        return False
    return True


# --- Orchestrator ----------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(description="One-click retrain MNIDS.")
    ap.add_argument("--use-cicids2017", action="store_true",
                    help="Use the real CIC-IDS2017 download (opt-in). Default: offline realistic generator.")
    ap.add_argument("--rows-per-class", type=int, default=20000,
                    help="OFFLINE mode: rows per Benign/Suspicious/Malicious. Default 20000 (60k total).")
    ap.add_argument("--seed", type=int, default=2025,
                    help="OFFLINE mode: RNG seed for reproducibility. Default 2025.")
    ap.add_argument("--sample-per-label", type=int, default=20000,
                    help="REAL CIC mode: cap rows per class. Default 20000.")
    ap.add_argument("--zip", type=Path, default=None,
                    help="REAL CIC mode: pre-downloaded MachineLearningCSV.zip path.")
    ap.add_argument("--url", type=str, default=None,
                    help="REAL CIC mode: download URL override.")
    ap.add_argument("--out-csv", type=Path, default=None,
                    help="Where the converted CSV is written. Defaults differ by mode.")
    args = ap.parse_args()

    _log(f"project root: {ROOT}")
    mode = "CIC-IDS2017 (real download)" if args.use_cicids2017 else "OFFLINE realistic generator"
    _log(f"mode:         {mode}")

    if args.use_cicids2017:
        out_csv = args.out_csv or DEFAULT_REAL_CSV
        _log(f"output csv:   {out_csv.relative_to(ROOT) if out_csv.is_relative_to(ROOT) else out_csv}")
        csvs = ensure_real_cicids2017(args.zip, args.url)
        converted = convert_real_csvs(csvs, out_csv, args.sample_per_label)
    else:
        out_csv = args.out_csv or DEFAULT_OFFLINE_CSV
        _log(f"output csv:   {out_csv.relative_to(ROOT) if out_csv.is_relative_to(ROOT) else out_csv}")
        converted = generate_offline_csv(out_csv, args.rows_per_class, args.seed)

    backup = backup_artifacts()

    rc = run_training(converted)
    if rc != 0:
        _err(f"train_models.py exited with code {rc}.")
        restore_backup(backup)
        sys.exit(rc)

    if not validate_artifacts():
        _err("validation failed. Rolling back.")
        restore_backup(backup)
        sys.exit(8)

    _log("")
    _log("✓ SUCCESS")
    _log("   live model under cnn_model/ has been replaced.")
    if backup is not None:
        try:
            rel = backup.relative_to(ROOT)
        except ValueError:
            rel = backup
        _log(f"   previous bundle kept at {rel}.")
    try:
        rel = converted.relative_to(ROOT)
    except ValueError:
        rel = converted
    _log(f"   training CSV at {rel}.")
    _log("   restart START.bat to pick up the new model.")


if __name__ == "__main__":
    main()
