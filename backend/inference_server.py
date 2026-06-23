#!/usr/bin/env python3
"""
FastAPI server for MNIDS lab ML inference.
  POST /predict  JSON body: { "features": [[...14 floats], ...] }
  POST /validate-data-file  pre-flight multipart validation (CSV schema / PCAP magic)
  POST /retrain-stream       SSE streaming training (multipart file OR ?dataset=name OR ?baseline=true OR ?demo=true with file/dataset)
  POST /retrain-stream-multi SSE streaming training from N multipart files (?demo=true supported);
                             CSV files are concatenated; PCAPs are auto-converted to CSV first
  POST /retrain-from-data-file  optional ?dataset=name or multipart upload
  GET  /training-datasets    list uploads under dataset/uploads
  GET  /training-csv-template  download accepted CSV template (≥6 example rows + header)

Run: python backend/inference_server.py  (default port 8787)
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import subprocess
import sys
import time
import uuid
from asyncio.subprocess import PIPE, STDOUT
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, AsyncIterator, List, Optional

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from feature_schema import label_name

ROOT = Path(__file__).resolve().parents[1]
ART_DIR = ROOT / "cnn_model"
UPLOAD_DIR = ROOT / "dataset" / "uploads"
DEFAULT_REALISTIC_CSV = ROOT / "dataset" / "samples" / "ml_lab_upload_realistic.csv"
TEMPLATE_CSV_ACCEPTED = ROOT / "dataset" / "samples" / "ml_lab_accepted_training_template.csv"
BASE_SYNTHETIC_CSV = ROOT / "dataset" / "mnids_synthetic_flows.csv"
MIN_CSV_ROWS = 6

REQUIRED_CSV_COLUMNS = [
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
    "label_id",
]

app = FastAPI(title="MNIDS Lab ML")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_rf = None
_if = None
_ae_tf = None  # Keras model when ONNX not used
_ae_ort: tuple[Any, str, str] | None = None  # (onnxruntime session, input name, output name)
_ae_scaler = None
_ae_p10 = 0.0
_ae_p90 = 1.0
_meta: dict[str, Any] = {}
_if_lo = 0.0
_if_hi = 1.0


def _anomaly_score_if(raw: float) -> float:
    x = (-float(raw) - _if_lo) / max(_if_hi - _if_lo, 1e-9)
    return float(max(0.0, min(1.0, x)))


def _ae_score_from_mse(mse: np.ndarray) -> np.ndarray:
    span = max(_ae_p90 - _ae_p10, 1e-9)
    z = (mse - _ae_p10) / span
    return np.clip(z, 0.0, 1.0)


def _ae_predict_reconstruction(Xs: np.ndarray) -> np.ndarray | None:
    """Reconstructed scaled features; same contract as Keras predict (N x n_features)."""
    if _ae_ort is not None:
        sess, in_name, out_name = _ae_ort
        x = np.asarray(Xs, dtype=np.float32)
        out = sess.run([out_name], {in_name: x})
        return np.asarray(out[0], dtype=np.float64)
    if _ae_tf is not None:
        return np.asarray(_ae_tf.predict(Xs, verbose=0), dtype=np.float64)
    return None


def load_models() -> None:
    global _rf, _if, _ae_tf, _ae_ort, _ae_scaler, _ae_p10, _ae_p90, _meta, _if_lo, _if_hi
    # Clear any prior startup error: callers (retrain endpoints) reload the
    # bundle after a successful train, so a previously-degraded /health should
    # flip back to ok=true.
    try:
        globals()["_startup_error"] = None
    except Exception:
        pass
    rf_path = ART_DIR / "rf_pipeline.joblib"
    if_path = ART_DIR / "iforest_pipeline.joblib"
    meta_path = ART_DIR / "meta.json"
    if not rf_path.exists() or not if_path.exists():
        raise RuntimeError(
            f"Missing ML artifacts under {ART_DIR}. Run:\n"
            "  python mnids/backend/retrain_pipeline.py\n"
            "  or: npm run ml:build --prefix mnids"
        )
    _rf = joblib.load(rf_path)
    _if = joblib.load(if_path)
    _meta = json.loads(meta_path.read_text(encoding="utf-8"))
    iso = _meta.get("isolation_forest", {})
    _if_lo = float(iso.get("decision_min", -1.0))
    _if_hi = float(iso.get("decision_max", 1.0))

    _ae_tf = None
    _ae_ort = None
    _ae_scaler = None
    ae_keras = ART_DIR / "ae_model.keras"
    ae_onnx = ART_DIR / "ae_model.onnx"
    ae_scaler_p = ART_DIR / "ae_scaler.joblib"
    ae_meta = _meta.get("autoencoder") if isinstance(_meta.get("autoencoder"), dict) else None
    _ae_p10 = float(ae_meta.get("mse_percentile_10", 0.0)) if ae_meta else 0.0
    _ae_p90 = float(ae_meta.get("mse_percentile_90", 1.0)) if ae_meta else 1.0

    if ae_scaler_p.exists():
        try:
            _ae_scaler = joblib.load(ae_scaler_p)
        except Exception as e:
            print("WARN: AE scaler load failed:", e)
            _ae_scaler = None

    if _ae_scaler is not None and ae_onnx.exists():
        try:
            import onnxruntime as ort

            sess = ort.InferenceSession(str(ae_onnx), providers=["CPUExecutionProvider"])
            in_name = sess.get_inputs()[0].name
            out_name = sess.get_outputs()[0].name
            _ae_ort = (sess, in_name, out_name)
        except ImportError as e:
            print(
                "WARN: ae_model.onnx is present but onnxruntime is not installed (pip install onnxruntime):",
                e,
                flush=True,
            )
            _ae_ort = None
        except Exception as e:
            print(
                "WARN: ONNX autoencoder (ae_model.onnx) failed to load (corrupt graph, opset, or ORT error);",
                e,
                flush=True,
            )
            _ae_ort = None

    if _ae_scaler is not None and _ae_ort is None and ae_keras.exists():
        # Guard the TF import behind an explicit opt-out AND a subprocess probe.
        # TensorFlow can hard-crash this process at import time on Windows boxes
        # missing the right VC++ runtime / AVX2 — that crash is a native access
        # violation (Windows exit code 0xC0000005), not a Python exception, so
        # try/except inside this function does NOT catch it. Probing in a child
        # process means a crash there only loses the AE; FastAPI still binds :8787
        # and RF + IF stay online.
        if os.environ.get("MNIDS_DISABLE_TF") == "1":
            print(
                "INFO: MNIDS_DISABLE_TF=1 — skipping TensorFlow / Keras autoencoder load. "
                "RF and Isolation Forest remain active.",
                flush=True,
            )
            _ae_tf = None
        else:
            try:
                probe = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "import tensorflow as tf; "
                        "import sys; "
                        "sys.stdout.write(tf.__version__)",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except Exception as e:
                print(
                    "WARN: TensorFlow probe failed to launch; skipping Keras autoencoder:",
                    e,
                    flush=True,
                )
                probe = None

            if probe is None or probe.returncode != 0:
                rc = probe.returncode if probe is not None else "n/a"
                tail = (probe.stderr or "")[-400:] if probe is not None else ""
                print(
                    f"WARN: TensorFlow probe exited with code {rc} — Keras autoencoder "
                    "disabled. RF + IF still active. To silence this and run faster, set "
                    "MNIDS_DISABLE_TF=1 in backend/.env. Probe stderr tail: "
                    f"{tail}",
                    flush=True,
                )
                _ae_tf = None
            else:
                try:
                    import tensorflow as tf

                    _ae_tf = tf.keras.models.load_model(ae_keras)
                except Exception as e:
                    print(
                        "WARN: Keras autoencoder (ae_model.keras) failed; TensorFlow missing or broken:",
                        e,
                        flush=True,
                    )
                    _ae_tf = None

    if _ae_scaler is None and (ae_onnx.exists() or ae_keras.exists()):
        print(
            "INFO: Autoencoder offline: ae_scaler.joblib missing or unloadable under",
            ART_DIR,
            "(RF and Isolation Forest still active).",
            flush=True,
        )
    elif _ae_scaler is not None and _ae_ort is None and _ae_tf is None:
        has_onnx = ae_onnx.exists()
        has_keras = ae_keras.exists()
        if has_onnx and has_keras:
            print(
                "INFO: Autoencoder offline: ONNX load failed and Keras/TensorFlow load failed. "
                "Fix onnxruntime + ae_model.onnx, or install TensorFlow for ae_model.keras. "
                "See mnids/README.md (Choose your install).",
                flush=True,
            )
        elif has_onnx and not has_keras:
            print(
                "INFO: Autoencoder offline: ae_model.onnx failed to load and no ae_model.keras fallback. "
                "Repair ONNX/onnxruntime or add Keras weights + TensorFlow.",
                flush=True,
            )
        elif has_keras and not has_onnx:
            print(
                "INFO: Autoencoder offline: only ae_model.keras present but TensorFlow did not load it. "
                "Install/repair TensorFlow (mnids/backend/requirements.txt) or export ae_model.onnx for inference without TF.",
                flush=True,
            )
        elif not has_onnx and not has_keras:
            print(
                "INFO: Autoencoder offline: neither ae_model.onnx nor ae_model.keras under",
                str(ART_DIR),
                "(RF and Isolation Forest still active).",
                flush=True,
            )


def _ensure_default_realistic_csv() -> None:
    """
    Keep a ready-to-use labeled CSV for ML Lab one-click retrain.

    Tries, in order:
      1. dataset/samples/ml_lab_upload_realistic.csv (if already shipped)
      2. dataset/mnids_synthetic_flows.csv          (project synthetic dataset)
      3. dataset/trained/sample_normal.csv + sample_attack.csv (3-class concat)

    Any of these is sufficient to build a 3-class baseline. If none exist we
    raise a clear error so the SSE stream surfaces it to the ML Lab UI instead
    of taking down the whole FastAPI process.
    """
    if DEFAULT_REALISTIC_CSV.exists():
        return

    samples_dir = DEFAULT_REALISTIC_CSV.parent
    samples_dir.mkdir(parents=True, exist_ok=True)

    import pandas as pd

    # Source #1 — the original synthetic flows CSV.
    if BASE_SYNTHETIC_CSV.exists():
        df = pd.read_csv(BASE_SYNTHETIC_CSV)
        missing = [c for c in REQUIRED_CSV_COLUMNS if c not in df.columns]
        if not missing:
            df[REQUIRED_CSV_COLUMNS].to_csv(DEFAULT_REALISTIC_CSV, index=False)
            return

    # Source #2 — concatenated benign + attack sample CSVs under dataset/trained/.
    trained_dir = ROOT / "dataset" / "trained"
    normal = trained_dir / "sample_normal.csv"
    attack = trained_dir / "sample_attack.csv"
    if normal.exists() and attack.exists():
        parts: list[pd.DataFrame] = []
        for p in (normal, attack):
            try:
                d = pd.read_csv(p)
            except Exception:
                continue
            keep = [c for c in REQUIRED_CSV_COLUMNS if c in d.columns]
            if "label_id" not in keep:
                continue
            parts.append(d[keep])
        if parts:
            combined = pd.concat(parts, ignore_index=True)
            missing = [c for c in REQUIRED_CSV_COLUMNS if c not in combined.columns]
            if not missing:
                combined[REQUIRED_CSV_COLUMNS].to_csv(DEFAULT_REALISTIC_CSV, index=False)
                return

    # Source #3 — the imported CICIDS2017-style realistic CSV. This file already
    # carries exactly REQUIRED_CSV_COLUMNS (3-class), so it is the most reliable
    # fallback for fresh checkouts where dataset/samples/ ships empty and the
    # synthetic CSV was never generated.
    imported = ROOT / "dataset" / "imported" / "cicids2017_style_realistic.csv"
    if imported.exists():
        try:
            df = pd.read_csv(imported)
        except Exception:
            df = None
        if df is not None:
            missing = [c for c in REQUIRED_CSV_COLUMNS if c not in df.columns]
            if not missing:
                df[REQUIRED_CSV_COLUMNS].to_csv(DEFAULT_REALISTIC_CSV, index=False)
                return

    raise RuntimeError(
        "Cannot build the default Baseline CSV. None of the following exist with the "
        "required columns: "
        f"{BASE_SYNTHETIC_CSV.name}, dataset/trained/sample_normal.csv + sample_attack.csv, "
        "dataset/imported/cicids2017_style_realistic.csv. "
        "Place a labeled CSV at "
        f"{DEFAULT_REALISTIC_CSV.relative_to(ROOT)} with columns: "
        + ", ".join(REQUIRED_CSV_COLUMNS)
    )


def _sse_bytes(obj: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n".encode("utf-8")


def _safe_upload_resolve(filename: str) -> Path | None:
    """Return path under dataset/uploads only; None if unsafe or missing."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    name = Path(filename).name
    if not name or name in {".", ".."}:
        return None
    cand = (UPLOAD_DIR / name).resolve()
    upload_resolved = UPLOAD_DIR.resolve()
    try:
        cand.relative_to(upload_resolved)
    except ValueError:
        return None
    return cand if cand.is_file() else None


def _looks_like_pcap_extension(name: str) -> bool:
    low = (name or "").lower()
    return low.endswith(".pcap") or low.endswith(".cap")


# Minimum number of distinct labels required to retrain. The lab classifier is a
# 3-class model (Benign / Suspicious / Malicious); we require at least 2 distinct
# classes so the active model is never overwritten with a degenerate single-class fit
# (e.g. a PCAP whose auto-labeler tagged everything as Benign).
MIN_RETRAIN_CLASSES = 2


def _count_csv_classes(csv_path: Path) -> tuple[int, dict[str, int], str | None]:
    """Quickly inspect a training CSV's label column.

    Returns (num_distinct_classes, distribution_by_name, error_or_None).
    The distribution is keyed by Benign/Suspicious/Malicious where label_ids are 0/1/2.
    """
    try:
        df = pd.read_csv(csv_path, usecols=["label_id"])
    except Exception as e:
        return 0, {}, f"Could not read label_id from training CSV: {e}"
    if "label_id" not in df.columns or df.empty:
        return 0, {}, "Training CSV has no label_id rows."
    valid = df["label_id"].dropna()
    try:
        valid_ids = valid.astype(int)
    except Exception:
        valid_ids = pd.to_numeric(valid, errors="coerce").dropna().astype(int)
    valid_ids = valid_ids[valid_ids.isin([0, 1, 2])]
    if valid_ids.empty:
        return 0, {}, "Training CSV has no valid label_id values in {0,1,2}."
    distinct = sorted(set(int(v) for v in valid_ids))
    dist: dict[str, int] = {}
    for lid, cnt in valid_ids.value_counts().items():
        try:
            dist[label_name(int(lid))] = int(cnt)
        except (IndexError, ValueError, TypeError):
            dist[str(lid)] = int(cnt)
    return len(distinct), dist, None


def _sniff_training_csv_header(raw: bytes) -> bool:
    chunk = raw[:8192].lstrip(b"\xef\xbb\xbf")
    if not chunk:
        return False
    nl = chunk.find(b"\n")
    if nl < 0:
        nl = len(chunk)
    line = chunk[:nl].decode("utf-8", errors="ignore").strip("\r")
    return "log_duration" in line and "label_id" in line


def _classify_training_upload(filename: str, raw: bytes) -> tuple[str, str]:
    """
    Decide whether bytes are CSV or classic PCAP training input.
    Returns ("csv"|"pcap"|"unknown", file_suffix_for_disk e.g. ".pcap").
    """
    low = (filename or "").lower()
    if low.endswith(".csv"):
        return ("csv", ".csv")
    if _looks_like_pcap_extension(filename):
        return ("pcap", ".cap" if low.endswith(".cap") else ".pcap")

    pcap_quick = _validate_pcap_magic(raw[:256])
    if pcap_quick.get("ok"):
        return ("pcap", ".pcap")
    if _sniff_training_csv_header(raw):
        return ("csv", ".csv")
    return ("unknown", "")


def _validate_pcap_magic(data: bytes) -> dict[str, Any]:
    if len(data) >= 2 and data[:2] == b"\x1f\x8b":
        return {
            "ok": False,
            "error": "File looks gzip-compressed (.gz). Extract the PCAP and upload the raw classic .pcap file.",
        }
    if len(data) < 4:
        return {"ok": False, "error": "File too small to be a PCAP."}
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return {"ok": False, "error": "PCAP-NG (.pcapng) is not supported. Convert to classic PCAP."}
    le = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    be = (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
    if data[:4] in le or data[:4] in be:
        return {"ok": True, "format": "classic_pcap", "notes": "Magic header OK (libpcap)."}
    return {
        "ok": False,
        "error": (
            f"Not a classic libpcap file (magic 0x{int.from_bytes(data[:4], 'big'):08x}). "
            "Export from Wireshark or tcpdump as classic PCAP (.pcap, not PCAP-NG / .pcapng). "
            "Gzip-compressed dumps must be extracted first."
        ),
    }


def _validate_csv_buffer(data: bytes) -> dict[str, Any]:
    try:
        df = pd.read_csv(io.BytesIO(data))
    except Exception as e:
        return {"ok": False, "error": f"Cannot read CSV: {e}"}
    missing = [c for c in REQUIRED_CSV_COLUMNS if c not in df.columns]
    if missing:
        return {"ok": False, "error": "Missing required columns.", "missing_cols": missing}
    rows = int(len(df))
    if rows < MIN_CSV_ROWS:
        return {
            "ok": False,
            "error": f"Need at least {MIN_CSV_ROWS} data rows (found {rows}).",
            "rows": rows,
        }
    warnings: list[str] = []
    bad_mask = ~df["label_id"].isin([0, 1, 2])
    if bool(bad_mask.any()):
        n_bad = int(bad_mask.sum())
        warnings.append(f"{n_bad} row(s) have label_id outside {{0,1,2}}; training may still run or fail.")
    dist: dict[str, int] = {}
    for lid, cnt in df["label_id"].value_counts().items():
        try:
            dist[label_name(int(lid))] = int(cnt)
        except (IndexError, ValueError, TypeError):
            dist[str(lid)] = int(cnt)
    return {
        "ok": True,
        "rows": rows,
        "label_distribution": dist,
        "warnings": warnings,
    }


async def _stream_subprocess(
    label: str, cmd: list[str], cwd: str
) -> AsyncIterator[bytes]:
    # Force the child Python (and child-of-child TF) to emit UTF-8 on stdout/stderr so
    # non-ASCII separators in our [PHASE] prints aren't mangled by the Windows cp1252
    # default and don't show up as � in the live UI log.
    child_env = {
        **os.environ,
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdout=PIPE,
        stderr=STDOUT,
        env=child_env,
    )
    assert proc.stdout is not None
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode("utf-8", errors="replace").rstrip()
        if text:
            yield _sse_bytes({"type": "log", "text": f"[{label}] {text}"})
    rc = await proc.wait()
    if rc != 0:
        yield _sse_bytes({"type": "error", "text": f"{label} subprocess exited with code {rc}"})
        raise subprocess.CalledProcessError(rc, cmd)


_startup_error: str | None = None


@app.on_event("startup")
def startup_load() -> None:
    """Load models at startup, but never let a load failure crash uvicorn.

    Express's /api/ml/* proxy returns 502 when this process is unreachable.
    If we crashed on startup, ML Lab would show an opaque 502 with no log.
    Instead, keep FastAPI listening on :8787 and surface the failure through
    /health so the ML Lab UI can render an actionable message.
    """
    global _startup_error
    try:
        load_models()
        _startup_error = None
    except Exception as e:  # noqa: BLE001 — we want a broad safety net here
        _startup_error = str(e)
        print(
            f"[MNIDS] ML startup load failed (server stays up to report it): {e}",
            flush=True,
        )


class PredictBody(BaseModel):
    features: List[List[float]] = Field(..., description="Rows of 14 floats in FEATURE_NAMES order")


@app.get("/health")
def health() -> dict[str, Any]:
    if _startup_error is not None or _rf is None or _if is None:
        # Report degraded health (200, not 5xx) so the Express proxy doesn't
        # mask the message as a generic 502. ML Lab keys off `ok` to decide
        # whether to enable training / inference controls.
        return {
            "ok": False,
            "error": _startup_error or "Models not loaded — run ml:build or click Restore safe model.",
            "modelVersion": _meta.get("model_version", "unknown"),
            "autoencoder": False,
        }
    ev = _meta.get("evaluation") if isinstance(_meta.get("evaluation"), dict) else {}
    cv = ev.get("cross_validation_rf") if isinstance(ev.get("cross_validation_rf"), dict) else {}
    timing = ev.get("timing_ms") if isinstance(ev.get("timing_ms"), dict) else {}
    m = _meta.get("metrics") if isinstance(_meta.get("metrics"), dict) else {}
    return {
        "ok": True,
        "modelVersion": _meta.get("model_version", "unknown"),
        "autoencoder": (_ae_tf is not None or _ae_ort is not None),
        "evaluation": {
            "f1MacroHoldout": m.get("f1_macro_holdout"),
            "fprMacroAvgHoldout": m.get("fpr_macro_avg_holdout"),
            "cvFolds": cv.get("n_splits"),
            "cvAccuracyMean": cv.get("accuracy_mean"),
            "rfInferMsPerRow": timing.get("rf_predict_per_row_mean"),
        },
    }


@app.get("/training-csv-template")
def download_training_csv_template() -> FileResponse:
    """Stable labeled CSV skeleton (≥6 rows) matching REQUIRED_CSV_COLUMNS — passes validate-data-file.

    If the canonical template file is missing from dataset/samples/, synthesize one
    from the baseline (which itself self-heals from dataset/trained/*). This keeps
    the ML Lab "Download CSV template" button working in fresh checkouts.
    """
    if not TEMPLATE_CSV_ACCEPTED.is_file():
        try:
            _ensure_default_realistic_csv()
            import pandas as pd

            df = pd.read_csv(DEFAULT_REALISTIC_CSV)
            TEMPLATE_CSV_ACCEPTED.parent.mkdir(parents=True, exist_ok=True)
            # Keep a small, label-balanced slice as the canonical template.
            sample_per_class: list[pd.DataFrame] = []
            for lid in (0, 1, 2):
                rows = df[df["label_id"] == lid].head(3)
                if not rows.empty:
                    sample_per_class.append(rows)
            if sample_per_class:
                pd.concat(sample_per_class, ignore_index=True).to_csv(
                    TEMPLATE_CSV_ACCEPTED, index=False
                )
            else:
                df.head(max(MIN_CSV_ROWS, 6)).to_csv(TEMPLATE_CSV_ACCEPTED, index=False)
        except Exception as e:
            raise HTTPException(
                status_code=404,
                detail=(
                    "Template CSV missing and could not be regenerated: "
                    f"{e}. Place a labeled CSV at "
                    f"{TEMPLATE_CSV_ACCEPTED.relative_to(ROOT)}."
                ),
            ) from e
    return FileResponse(
        path=str(TEMPLATE_CSV_ACCEPTED),
        filename="mnids_ml_training_template.csv",
        media_type="text/csv; charset=utf-8",
    )


@app.post("/retrain")
def retrain() -> dict[str, Any]:
    """Regenerate synthetic CSV/PCAP and retrain all models (~tens of seconds)."""
    try:
        subprocess.check_call(
            [sys.executable, str(ROOT / "backend" / "retrain_pipeline.py")],
            cwd=str(ROOT),
        )
        load_models()
        return {"ok": True, "modelVersion": _meta.get("model_version")}
    except subprocess.CalledProcessError as e:
        return {"ok": False, "error": str(e)}


@app.post("/validate-data-file")
async def validate_data_file(file: UploadFile = File(...)) -> dict[str, Any]:
    """Pre-flight CSV schema / PCAP magic check; does not train."""
    name = file.filename or "upload"
    raw = await file.read()
    base = {"filename": Path(name).name}
    if len(raw) == 0:
        return {"ok": False, "error": "Empty file.", **base}

    low = name.lower()
    if low.endswith(".csv"):
        out = _validate_csv_buffer(raw)
        out.update(base)
        return out
    if _looks_like_pcap_extension(name):
        out = _validate_pcap_magic(raw[:256])
        out.update(base)
        return out

    pcap_try = _validate_pcap_magic(raw[:256])
    if pcap_try.get("ok"):
        out = dict(pcap_try)
        base_note = (out.get("notes") or "").strip()
        extra = "Detected classic PCAP from file contents (rename with .pcap if helpful)."
        out["notes"] = f"{base_note} {extra}".strip()
        out.update(base)
        return out
    if _sniff_training_csv_header(raw):
        out = _validate_csv_buffer(raw)
        out.update(base)
        return out

    return {
        "ok": False,
        **base,
        "error": (
            "Not a valid ML training CSV and not a classic libpcap capture. "
            "Use GET /training-csv-template for an accepted CSV example, "
            "or upload Wireshark/tcpdump classic .pcap / .cap (not PCAP-NG)."
        ),
        "pcap_magic_hint": pcap_try.get("error"),
    }


def _training_dataset_file_entry(path: Path) -> dict[str, Any]:
    """Metadata for ML Lab uploads list — keeps bad files from breaking the listing."""
    st = path.stat()
    entry: dict[str, Any] = {
        "name": path.name,
        "size_kb": round(st.st_size / 1024.0, 2),
        "mtime_iso": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
    }
    suff = path.suffix.lower()
    if suff == ".csv":
        entry["kind"] = "csv"
        try:
            df = pd.read_csv(path)
            entry["rows"] = int(len(df))
            if "label_id" in df.columns:
                dist: dict[str, int] = {}
                for lid, cnt in df["label_id"].value_counts().items():
                    try:
                        dist[label_name(int(lid))] = int(cnt)
                    except (IndexError, ValueError, TypeError):
                        dist[str(lid)] = int(cnt)
                entry["label_distribution"] = dist
        except Exception:
            entry["rows"] = None
            try:
                n = sum(1 for _ in path.open("rb")) - 1
                entry["rows"] = max(0, n)
            except OSError:
                pass
    elif suff in {".pcap", ".cap"}:
        entry["kind"] = "pcap"
        try:
            with path.open("rb") as fh:
                head = fh.read(min(256, max(4, path.stat().st_size)))
            vm = _validate_pcap_magic(head)
            entry["format"] = vm.get("format") if vm.get("ok") else "unknown"
            if not vm.get("ok") and vm.get("error"):
                entry["format_note"] = str(vm["error"])[:280]
        except OSError:
            entry["format"] = "unknown"
    return entry


@app.get("/training-datasets")
def training_datasets_list() -> dict[str, Any]:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    files: list[dict[str, Any]] = []
    for p in sorted(UPLOAD_DIR.iterdir()):
        if not p.is_file():
            continue
        suff = p.suffix.lower()
        if suff not in {".csv", ".pcap", ".cap"}:
            continue
        try:
            files.append(_training_dataset_file_entry(p))
        except OSError:
            continue
    return {"ok": True, "files": files}


@app.delete("/training-datasets/{filename}")
def training_datasets_delete(filename: str) -> dict[str, Any]:
    p = _safe_upload_resolve(filename)
    if p is None:
        return {"ok": False, "error": "Not found or invalid path."}
    try:
        p.unlink()
        return {"ok": True}
    except OSError as e:
        return {"ok": False, "error": str(e)}


@app.post("/retrain-from-csv")
async def retrain_from_csv(file: UploadFile = File(...)) -> dict[str, Any]:
    """
    Retrain models from an uploaded labeled CSV.
    Required columns: FEATURE_NAMES + label_id
    """
    name = file.filename or ""
    if not name.lower().endswith(".csv"):
        return {"ok": False, "error": "Please upload a .csv file."}
    try:
        upload_dir = ROOT / "dataset" / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        safe_name = f"uploaded_{int(np.floor(np.random.rand() * 1e12))}.csv"
        target = upload_dir / safe_name
        data = await file.read()
        target.write_bytes(data)

        subprocess.check_call(
            [
                sys.executable,
                str(ROOT / "backend" / "train_models.py"),
                "--csv",
                str(target),
            ],
            cwd=str(ROOT),
        )
        load_models()
        return {
            "ok": True,
            "modelVersion": _meta.get("model_version"),
            "training_dataset_csv": str(target),
        }
    except subprocess.CalledProcessError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/retrain-from-data-file")
async def retrain_from_data_file(
    dataset: Annotated[Optional[str], Query()] = None,
    file: Annotated[Optional[UploadFile], File()] = None,
) -> dict[str, Any]:
    """
    Retrain from uploads: multipart PCAP/CSV, or ?dataset=<filename> under dataset/uploads/.
    """
    has_file = file is not None and bool(file.filename)
    if dataset and has_file:
        return {"ok": False, "error": "Provide either ?dataset= or uploaded file, not both."}
    if not dataset and not has_file:
        return {"ok": False, "error": "Missing file or ?dataset= parameter."}

    upload_dir = UPLOAD_DIR
    upload_dir.mkdir(parents=True, exist_ok=True)
    uniq = int(np.floor(np.random.rand() * 1e12))

    try:
        if dataset:
            saved = _safe_upload_resolve(dataset)
            if saved is None:
                return {"ok": False, "error": "Dataset not found in uploads or invalid name."}
            low = saved.name.lower()
        else:
            assert file is not None
            name = file.filename or "upload.bin"
            low = name.lower()
            data = await file.read()
            if low.endswith(".csv"):
                saved = upload_dir / f"lab_{uniq}_{Path(name).name}"
                if saved.suffix.lower() != ".csv":
                    saved = saved.with_suffix(".csv")
                saved.write_bytes(data)
            else:
                kind, ext = _classify_training_upload(name, data)
                if kind == "unknown":
                    return {
                        "ok": False,
                        "error": "Unsupported file type. Upload a labeled .csv or classic libpcap .pcap / .cap.",
                    }
                if kind == "csv":
                    saved = upload_dir / f"lab_{uniq}_{Path(name).name}"
                    if saved.suffix.lower() != ".csv":
                        saved = saved.with_suffix(".csv")
                    saved.write_bytes(data)
                else:
                    stem = Path(name).stem or "capture"
                    outp = upload_dir / f"lab_{uniq}_{stem}{ext}"
                    outp.write_bytes(data)
                    saved = outp

        saved_low = saved.name.lower()
        if saved_low.endswith(".csv"):
            subprocess.check_call(
                [
                    sys.executable,
                    str(ROOT / "backend" / "train_models.py"),
                    "--csv",
                    str(saved),
                ],
                cwd=str(ROOT),
            )
            load_models()
            return {
                "ok": True,
                "modelVersion": _meta.get("model_version"),
                "source": "csv",
                "training_dataset_csv": str(saved.resolve()),
                "notes": "",
            }

        if _looks_like_pcap_extension(saved.name):
            derived_csv = upload_dir / f"lab_{uniq}_from_pcap_training.csv"
            subprocess.check_call(
                [
                    sys.executable,
                    str(ROOT / "backend" / "pcap_to_training_csv.py"),
                    "--pcap",
                    str(saved),
                    "--out",
                    str(derived_csv),
                    "--auto-label",
                ],
                cwd=str(ROOT),
            )
            subprocess.check_call(
                [
                    sys.executable,
                    str(ROOT / "backend" / "train_models.py"),
                    "--csv",
                    str(derived_csv),
                ],
                cwd=str(ROOT),
            )
            load_models()
            return {
                "ok": True,
                "modelVersion": _meta.get("model_version"),
                "source": "pcap",
                "uploaded_pcap": str(saved.resolve()),
                "training_dataset_csv": str(derived_csv.resolve()),
                "notes": (
                    "PCAP flows were labeled with MNIDS demo auto-label rules (see pcap_to_training_csv.py)."
                ),
            }

        return {
            "ok": False,
            "error": "Unsupported file type. Upload a classic .pcap or a labeled .csv.",
        }
    except subprocess.CalledProcessError as e:
        return {
            "ok": False,
            "error": f"training pipeline failed ({e.returncode}); check PCAP format (classic .pcap) or CSV columns.",
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/retrain-stream")
async def retrain_stream(
    baseline: Annotated[bool, Query()] = False,
    dataset: Annotated[Optional[str], Query()] = None,
    demo: Annotated[bool, Query()] = False,
    file: Annotated[Optional[UploadFile], File()] = None,
) -> StreamingResponse:
    """Stream training logs as SSE. Use baseline=true, or ?dataset=name, or multipart file.

    Use ?demo=true **only** with multipart file or ?dataset=... to write models under
    ``cnn_model/demo_runs/`` without reloading the live inference bundle. Not valid with
    baseline=true (baseline always deploys to cnn_model/).
    """
    has_file = file is not None and bool(file.filename)

    async def events() -> AsyncIterator[bytes]:
        if demo and baseline:
            yield _sse_bytes(
                {
                    "type": "error",
                    "text": "demo=true cannot be combined with baseline=true — baseline retrains "
                    "the live cnn_model/ bundle. Use demo=true only with a file upload or ?dataset=...",
                }
            )
            return

        if sum([baseline, bool(dataset), has_file]) != 1:
            yield _sse_bytes(
                {
                    "type": "error",
                    "text": "Provide exactly one of: ?baseline=true, ?dataset=file_in_uploads, or multipart file.",
                }
            )
            return

        csv_train: Path | None = None
        uploaded_pcap: Path | None = None
        source = "csv"
        notes_final = ""

        try:
            if baseline:
                yield _sse_bytes(
                    {"type": "log", "text": "[MNIDS] Using baseline CSV (samples/ml_lab_upload_realistic.csv)"}
                )
                _ensure_default_realistic_csv()
                csv_train = DEFAULT_REALISTIC_CSV
                source = "baseline"
            elif dataset:
                resolved = _safe_upload_resolve(dataset)
                if resolved is None:
                    yield _sse_bytes({"type": "error", "text": "Dataset not found in uploads."})
                    return
                dn = resolved.name.lower()
                if dn.endswith(".csv"):
                    csv_train = resolved
                elif _looks_like_pcap_extension(resolved.name):
                    uploaded_pcap = resolved
                    derived = UPLOAD_DIR / f"stream_{resolved.stem}_{int(np.floor(np.random.rand() * 1e9))}_from_pcap.csv"
                    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                    try:
                        async for pkt in _stream_subprocess(
                            "pcap_to_training_csv",
                            [
                                sys.executable,
                                "-u",
                                str(ROOT / "backend" / "pcap_to_training_csv.py"),
                                "--pcap",
                                str(resolved),
                                "--out",
                                str(derived),
                                "--auto-label",
                            ],
                            str(ROOT),
                        ):
                            yield pkt
                    except subprocess.CalledProcessError:
                        return
                    csv_train = derived
                    source = "pcap"
                    notes_final = (
                        "PCAP labels are demo auto-labels (see pcap_to_training_csv.py)."
                    )
                else:
                    yield _sse_bytes({"type": "error", "text": "Upload must be .csv or classic .pcap / .cap."})
                    return
            else:
                assert file is not None and file.filename
                name = file.filename
                raw = await file.read()
                low = (name or "").lower()
                UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                u = int(np.floor(np.random.rand() * 1e12))
                if low.endswith(".csv"):
                    outp = UPLOAD_DIR / f"lab_stream_{u}_{Path(name).name}"
                    if outp.suffix.lower() != ".csv":
                        outp = outp.with_suffix(".csv")
                    outp.write_bytes(raw)
                    csv_train = outp
                    source = "csv"
                else:
                    kind, ext = _classify_training_upload(name, raw)
                    if kind == "unknown":
                        yield _sse_bytes(
                            {
                                "type": "error",
                                "text": "Upload a labeled .csv or classic libpcap .pcap / .cap (not PCAP-NG). "
                                "Download the CSV template from GET /training-csv-template if needed.",
                            }
                        )
                        return
                    if kind == "csv":
                        outp = UPLOAD_DIR / f"lab_stream_{u}_{Path(name).name}"
                        if outp.suffix.lower() != ".csv":
                            outp = outp.with_suffix(".csv")
                        outp.write_bytes(raw)
                        csv_train = outp
                        source = "csv"
                    else:
                        stem = Path(name).stem or "capture"
                        outp = UPLOAD_DIR / f"lab_stream_{u}_{stem}{ext}"
                        outp.write_bytes(raw)
                        derived = UPLOAD_DIR / f"lab_stream_{u}_from_pcap_training.csv"
                        try:
                            async for pkt in _stream_subprocess(
                                "pcap_to_training_csv",
                                [
                                    sys.executable,
                                    "-u",
                                    str(ROOT / "backend" / "pcap_to_training_csv.py"),
                                    "--pcap",
                                    str(outp),
                                    "--out",
                                    str(derived),
                                    "--auto-label",
                                ],
                                str(ROOT),
                            ):
                                yield pkt
                        except subprocess.CalledProcessError:
                            return
                        csv_train = derived
                        uploaded_pcap = outp
                        source = "pcap"
                        notes_final = "PCAP flows were labeled with MNIDS demo auto-label rules."

            if csv_train is None:
                yield _sse_bytes({"type": "error", "text": "Internal error: no training CSV path."})
                return

            # Hard guard: never overwrite the active live model with a degenerate fit.
            # If the resolved training CSV has fewer than MIN_RETRAIN_CLASSES distinct
            # label_id values, we abort BEFORE invoking train_models.py so the on-disk
            # artifacts in cnn_model/ are preserved exactly as they were. This protects
            # against the common "train on a benign-only PCAP" footgun.
            n_classes, class_dist, label_err = _count_csv_classes(csv_train)
            if label_err is not None:
                yield _sse_bytes({"type": "log", "text": f"[guard] {label_err}"})
            yield _sse_bytes(
                {
                    "type": "log",
                    "text": (
                        f"[guard] training CSV class distribution: "
                        f"{', '.join(f'{k}={v}' for k, v in class_dist.items()) or 'none'}"
                    ),
                }
            )

            demo_artifact_dir: Path | None = None
            if demo:
                demo_root = ROOT / "cnn_model" / "demo_runs"
                demo_root.mkdir(parents=True, exist_ok=True)
                demo_artifact_dir = demo_root / f"run_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
                yield _sse_bytes(
                    {
                        "type": "log",
                        "text": (
                            f"[MNIDS] demo=true — writing artifacts to {demo_artifact_dir.relative_to(ROOT)}; "
                            "the live inference bundle under cnn_model/ will not be reloaded."
                        ),
                    }
                )

            if n_classes < MIN_RETRAIN_CLASSES:
                if not demo:
                    yield _sse_bytes(
                        {
                            "type": "error",
                            "text": (
                                "Refusing to overwrite the active model: training CSV has "
                                f"only {n_classes} distinct class(es) "
                                f"({', '.join(class_dist) or 'none'}). "
                                "The lab classifier is 3-class (Benign / Suspicious / Malicious) and "
                                "needs at least 2 distinct labels to learn anything useful. "
                                "Use the locked Baseline dataset (Train on the Baseline row), "
                                "enable “Demo train (artifacts only)” for PCAP/single-class demos, "
                                "or upload a labeled CSV with at least 2 classes. Live model on disk is unchanged."
                            ),
                        }
                    )
                    return
                yield _sse_bytes(
                    {
                        "type": "log",
                        "text": (
                            "[guard] demo mode: single-class or sparse labels allowed — "
                            "RF will be degenerate; this run is for demonstration only."
                        ),
                    }
                )

            train_cmd = [
                sys.executable,
                "-u",
                str(ROOT / "backend" / "train_models.py"),
                "--csv",
                str(csv_train),
            ]
            if demo_artifact_dir is not None:
                train_cmd.extend(["--artifact-dir", str(demo_artifact_dir)])

            try:
                async for pkt in _stream_subprocess("train_models", train_cmd, str(ROOT)):
                    yield pkt
            except subprocess.CalledProcessError:
                return

            if demo_artifact_dir is None:
                load_models()
            else:
                yield _sse_bytes(
                    {
                        "type": "log",
                        "text": "[MNIDS] demo complete — live models were not reloaded; dashboard still uses the active cnn_model/ bundle.",
                    }
                )

            done: dict[str, Any] = {
                "type": "done",
                "modelVersion": _meta.get("model_version"),
                "source": source,
                "training_dataset_csv": str(csv_train.resolve()),
            }
            if uploaded_pcap is not None:
                done["uploaded_pcap"] = str(uploaded_pcap.resolve())
            note_parts: list[str] = []
            if notes_final:
                note_parts.append(notes_final)
            if demo_artifact_dir is not None:
                done["demoMode"] = True
                done["liveModelUnchanged"] = True
                done["demoArtifactDir"] = str(demo_artifact_dir.resolve())
                note_parts.append(
                    f"Demo artifacts written under {demo_artifact_dir.relative_to(ROOT)} — "
                    "inference still uses the official cnn_model/ bundle."
                )
            if note_parts:
                done["notes"] = " ".join(note_parts)
            yield _sse_bytes(done)
        except Exception as e:
            yield _sse_bytes({"type": "error", "text": str(e)})

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )



@app.post("/retrain-stream-multi")
async def retrain_stream_multi(
    demo: Annotated[bool, Query()] = False,
    files: Annotated[List[UploadFile], File()] = [],
) -> StreamingResponse:
    """Stream training logs as SSE for a multi-file upload.

    Accepts one or more files in the same POST. Each file may be:
      - a labeled training CSV (REQUIRED_CSV_COLUMNS), OR
      - a classic libpcap .pcap / .cap capture

    PCAPs are converted to CSV via pcap_to_training_csv.py (with --auto-label),
    then ALL resulting CSVs are concatenated into one merged training CSV and
    train_models.py runs ONCE on the merged dataset.

    With ?demo=true (default in the UI), artifacts land under
    cnn_model/demo_runs/run_<ts>_<uuid>/ and the live cnn_model/ bundle is NOT
    reloaded — same demo-isolation contract as /retrain-stream.
    """
    # FastAPI's multipart parser already consumed the request body; capture each
    # file's bytes + name eagerly so we can stream them through asyncio without
    # holding open the request stream across subprocess hops.
    if not files:
        async def _empty() -> AsyncIterator[bytes]:
            yield _sse_bytes(
                {"type": "error", "text": "No files in the upload. Attach one or more CSV / PCAP files."}
            )
        return StreamingResponse(_empty(), media_type="text/event-stream")

    captured: list[tuple[str, bytes]] = []
    for uf in files:
        if not uf.filename:
            continue
        data = await uf.read()
        if not data:
            continue
        captured.append((uf.filename, data))

    async def events() -> AsyncIterator[bytes]:
        if not captured:
            yield _sse_bytes(
                {"type": "error", "text": "All uploaded files were empty or unnamed."}
            )
            return

        yield _sse_bytes(
            {"type": "log", "text": f"[MNIDS-multi] received {len(captured)} file(s) for training"}
        )

        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        batch_id = f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"

        # Stage 1 — persist each file and turn PCAPs into CSVs.
        per_file_csvs: list[Path] = []
        per_file_pcaps: list[Path] = []
        for idx, (orig_name, raw) in enumerate(captured, start=1):
            stem_safe = Path(orig_name).stem or f"upload_{idx}"
            low = (orig_name or "").lower()
            yield _sse_bytes(
                {"type": "log", "text": f"[MNIDS-multi] ({idx}/{len(captured)}) inspecting {Path(orig_name).name}"}
            )

            if low.endswith(".csv"):
                outp = UPLOAD_DIR / f"multi_{batch_id}_{idx:02d}_{stem_safe}.csv"
                outp.write_bytes(raw)
                # Validate schema before we waste time on training.
                check = _validate_csv_buffer(raw)
                if not check.get("ok"):
                    yield _sse_bytes(
                        {
                            "type": "error",
                            "text": (
                                f"File '{orig_name}' failed CSV validation: "
                                f"{check.get('error') or 'unknown error'}"
                            ),
                        }
                    )
                    return
                per_file_csvs.append(outp)
                continue

            kind, ext = _classify_training_upload(orig_name, raw)
            if kind == "csv":
                outp = UPLOAD_DIR / f"multi_{batch_id}_{idx:02d}_{stem_safe}.csv"
                outp.write_bytes(raw)
                check = _validate_csv_buffer(raw)
                if not check.get("ok"):
                    yield _sse_bytes(
                        {
                            "type": "error",
                            "text": (
                                f"File '{orig_name}' looks like CSV but failed validation: "
                                f"{check.get('error') or 'unknown error'}"
                            ),
                        }
                    )
                    return
                per_file_csvs.append(outp)
                continue

            if kind == "pcap":
                pcap_path = UPLOAD_DIR / f"multi_{batch_id}_{idx:02d}_{stem_safe}{ext}"
                pcap_path.write_bytes(raw)
                per_file_pcaps.append(pcap_path)
                derived = UPLOAD_DIR / f"multi_{batch_id}_{idx:02d}_{stem_safe}_from_pcap.csv"
                yield _sse_bytes(
                    {"type": "log", "text": f"[MNIDS-multi] converting PCAP → CSV for {pcap_path.name}"}
                )
                try:
                    async for pkt in _stream_subprocess(
                        "pcap_to_training_csv",
                        [
                            sys.executable,
                            "-u",
                            str(ROOT / "backend" / "pcap_to_training_csv.py"),
                            "--pcap",
                            str(pcap_path),
                            "--out",
                            str(derived),
                            "--auto-label",
                        ],
                        str(ROOT),
                    ):
                        yield pkt
                except subprocess.CalledProcessError:
                    yield _sse_bytes(
                        {
                            "type": "error",
                            "text": f"PCAP conversion failed for {orig_name}; aborting multi-file training.",
                        }
                    )
                    return
                if not derived.exists():
                    yield _sse_bytes(
                        {
                            "type": "error",
                            "text": f"PCAP conversion produced no CSV for {orig_name}.",
                        }
                    )
                    return
                per_file_csvs.append(derived)
                continue

            yield _sse_bytes(
                {
                    "type": "error",
                    "text": (
                        f"File '{orig_name}' is neither a recognized CSV nor a classic libpcap capture. "
                        "Allowed: .csv with REQUIRED_CSV_COLUMNS, or .pcap / .cap (not PCAP-NG)."
                    ),
                }
            )
            return

        if not per_file_csvs:
            yield _sse_bytes({"type": "error", "text": "No usable training CSVs after preprocessing."})
            return

        # Stage 2 — concatenate every CSV (header-aware) into one merged CSV.
        merged_csv = UPLOAD_DIR / f"multi_{batch_id}_merged.csv"
        yield _sse_bytes(
            {
                "type": "log",
                "text": f"[MNIDS-multi] merging {len(per_file_csvs)} CSV(s) into {merged_csv.name}",
            }
        )

        merged_rows = 0
        try:
            frames: list[pd.DataFrame] = []
            for csvp in per_file_csvs:
                df = pd.read_csv(csvp)
                missing = [c for c in REQUIRED_CSV_COLUMNS if c not in df.columns]
                if missing:
                    yield _sse_bytes(
                        {
                            "type": "error",
                            "text": (
                                f"CSV {csvp.name} is missing columns: {', '.join(missing)}. "
                                "All uploads must share the labeled-flow schema."
                            ),
                        }
                    )
                    return
                frames.append(df[REQUIRED_CSV_COLUMNS])
                merged_rows += len(df)
            combined = pd.concat(frames, ignore_index=True)
            combined.to_csv(merged_csv, index=False)
        except Exception as e:
            yield _sse_bytes({"type": "error", "text": f"Merge failed: {e}"})
            return

        yield _sse_bytes(
            {"type": "log", "text": f"[MNIDS-multi] merged dataset: {merged_rows} rows total"}
        )

        # Stage 3 — class-count guard. Same contract as /retrain-stream: at
        # least 2 distinct label_ids unless demo=true.
        n_classes, class_dist, label_err = _count_csv_classes(merged_csv)
        if label_err is not None:
            yield _sse_bytes({"type": "log", "text": f"[guard] {label_err}"})
        yield _sse_bytes(
            {
                "type": "log",
                "text": (
                    f"[guard] merged class distribution: "
                    f"{', '.join(f'{k}={v}' for k, v in class_dist.items()) or 'none'}"
                ),
            }
        )

        demo_artifact_dir: Path | None = None
        if demo:
            demo_root = ROOT / "cnn_model" / "demo_runs"
            demo_root.mkdir(parents=True, exist_ok=True)
            demo_artifact_dir = demo_root / f"run_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
            yield _sse_bytes(
                {
                    "type": "log",
                    "text": (
                        f"[MNIDS-multi] demo=true — writing artifacts to {demo_artifact_dir.relative_to(ROOT)}; "
                        "the live inference bundle under cnn_model/ will not be reloaded."
                    ),
                }
            )

        if n_classes < MIN_RETRAIN_CLASSES and not demo:
            yield _sse_bytes(
                {
                    "type": "error",
                    "text": (
                        "Refusing to overwrite the active model: merged dataset has "
                        f"only {n_classes} distinct class(es) "
                        f"({', '.join(class_dist) or 'none'}). "
                        "Use ?demo=true (the default in the ML Lab UI) or upload files that "
                        "together cover at least 2 of {Benign, Suspicious, Malicious}."
                    ),
                }
            )
            return

        # Stage 4 — train once on the merged CSV.
        train_cmd = [
            sys.executable,
            "-u",
            str(ROOT / "backend" / "train_models.py"),
            "--csv",
            str(merged_csv),
        ]
        if demo_artifact_dir is not None:
            train_cmd.extend(["--artifact-dir", str(demo_artifact_dir)])

        try:
            async for pkt in _stream_subprocess("train_models", train_cmd, str(ROOT)):
                yield pkt
        except subprocess.CalledProcessError:
            return

        if demo_artifact_dir is None:
            load_models()
        else:
            yield _sse_bytes(
                {
                    "type": "log",
                    "text": (
                        "[MNIDS-multi] demo complete — live models were not reloaded; "
                        "dashboard still uses the active cnn_model/ bundle."
                    ),
                }
            )

        done: dict[str, Any] = {
            "type": "done",
            "modelVersion": _meta.get("model_version"),
            "source": "multi",
            "training_dataset_csv": str(merged_csv.resolve()),
            "input_file_count": len(captured),
            "merged_rows": merged_rows,
        }
        if per_file_pcaps:
            done["uploaded_pcaps"] = [str(p.resolve()) for p in per_file_pcaps]
        if demo_artifact_dir is not None:
            done["demoMode"] = True
            done["liveModelUnchanged"] = True
            done["demoArtifactDir"] = str(demo_artifact_dir.resolve())
            done["notes"] = (
                f"Demo artifacts written under {demo_artifact_dir.relative_to(ROOT)} — "
                "inference still uses the official cnn_model/ bundle."
            )
        yield _sse_bytes(done)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

@app.post("/retrain-realistic-csv")
def retrain_realistic_csv() -> dict[str, Any]:
    """Retrain from the built-in realistic labeled CSV shipped with the project."""
    try:
        _ensure_default_realistic_csv()
        subprocess.check_call(
            [
                sys.executable,
                str(ROOT / "backend" / "train_models.py"),
                "--csv",
                str(DEFAULT_REALISTIC_CSV),
            ],
            cwd=str(ROOT),
        )
        load_models()
        return {
            "ok": True,
            "modelVersion": _meta.get("model_version"),
            "training_dataset_csv": str(DEFAULT_REALISTIC_CSV),
        }
    except subprocess.CalledProcessError as e:
        return {"ok": False, "error": str(e)}


@app.post("/predict")
def predict(body: PredictBody) -> dict[str, Any]:
    if not body.features:
        return {"ok": False, "error": "empty features", "results": []}
    if _rf is None or _if is None:
        return {
            "ok": False,
            "error": _startup_error or "Models not loaded — train or restore the baseline first.",
            "results": [],
        }
    X = np.asarray(body.features, dtype=np.float64)
    nfeat = len(_meta.get("feature_names", []))
    if X.ndim != 2 or X.shape[1] != nfeat:
        return {
            "ok": False,
            "error": f"expected N x {nfeat} matrix",
            "results": [],
        }
    proba = _rf.predict_proba(X)
    pred = _rf.predict(X)
    if_raw = _if.decision_function(X)
    labels = _meta.get("labels", ["Benign", "Suspicious", "Malicious"])

    ae_scores: np.ndarray | None = None
    if _ae_scaler is not None and (_ae_tf is not None or _ae_ort is not None):
        Xs = _ae_scaler.transform(X)
        pred_ae = _ae_predict_reconstruction(Xs)
        if pred_ae is not None:
            mse = np.mean((Xs - pred_ae) ** 2, axis=1)
            ae_scores = _ae_score_from_mse(mse)

    results = []
    for i in range(X.shape[0]):
        lid = int(pred[i])
        conf = float(np.max(proba[i]))
        row: dict[str, Any] = {
            "label": labels[lid] if 0 <= lid < len(labels) else str(lid),
            "labelId": lid,
            "confidence": conf,
            "anomalyScore": _anomaly_score_if(if_raw[i]),
        }
        if ae_scores is not None:
            row["aeAnomalyScore"] = float(ae_scores[i])
        results.append(row)
    return {"ok": True, "modelVersion": _meta.get("model_version"), "results": results}


def main() -> None:
    import os
    import uvicorn

    port = int(os.environ.get("ML_SERVER_PORT", "8787"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
