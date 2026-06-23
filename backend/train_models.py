#!/usr/bin/env python3
"""Train RF + IsolationForest + Keras Autoencoder on dataset CSV; write models and plots to cnn_model/."""
from __future__ import annotations

import json
import os
import time
import argparse
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from feature_schema import FEATURE_NAMES, label_name

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "dataset" / "mnids_synthetic_flows.csv"
ART_DIR = ROOT / "cnn_model"

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")


def _plot_confusion_mat(y_true: np.ndarray, y_pred: np.ndarray, labels: list[str], out: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(labels))))
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    ax.set_xticks(np.arange(cm.shape[1]))
    ax.set_yticks(np.arange(cm.shape[0]))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticklabels(labels)
    ax.set_ylabel("True")
    ax.set_xlabel("Predicted")
    thresh = cm.max() / 2.0 if cm.size else 0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], "d"), ha="center", va="center", color="w" if cm[i, j] > thresh else "black")
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def _plot_ae_loss(history: Any, out: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(5, 3))
    ax.plot(history.history["loss"], label="train")
    if "val_loss" in history.history:
        ax.plot(history.history["val_loss"], label="val")
    ax.set_xlabel("Epoch")
    ax.set_ylabel("MSE")
    ax.set_title("Autoencoder training loss")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def _per_class_fpr(cm: np.ndarray) -> dict[str, float]:
    """Multiclass one-vs-rest false positive rate per predicted class (compliance-style reporting)."""
    n = int(cm.sum())
    if n == 0 or cm.size == 0:
        return {}
    out: dict[str, float] = {}
    for i in range(cm.shape[0]):
        tp = float(cm[i, i])
        fp = float(cm[:, i].sum() - tp)
        fn = float(cm[i, :].sum() - tp)
        tn = float(n - tp - fp - fn)
        fpr = fp / (fp + tn) if (fp + tn) > 1e-12 else 0.0
        out[label_name(i)] = round(fpr, 4)
    return out


def _rf_pipeline() -> Pipeline:
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                RandomForestClassifier(
                    n_estimators=64,
                    max_depth=14,
                    min_samples_leaf=2,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def _run_stratified_cv(X: np.ndarray, y: np.ndarray) -> dict[str, Any]:
    """Stratified k-fold CV for RF (reporting rigor); reduces k if classes are too small."""
    _, counts = np.unique(y, return_counts=True)
    min_class = int(counts.min())
    n_samples = len(y)
    for n_splits in (5, 4, 3, 2):
        if n_splits < 2 or min_class < n_splits:
            continue
        if n_samples < n_splits * 2:
            continue
        try:
            skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
            pipe = _rf_pipeline()
            acc = cross_val_score(clone(pipe), X, y, cv=skf, scoring="accuracy", n_jobs=-1)
            f1m = cross_val_score(clone(pipe), X, y, cv=skf, scoring="f1_macro", n_jobs=-1)
            return {
                "n_splits": n_splits,
                "accuracy_mean": round(float(acc.mean()), 4),
                "accuracy_std": round(float(acc.std()), 4),
                "f1_macro_mean": round(float(f1m.mean()), 4),
                "f1_macro_std": round(float(f1m.std()), 4),
                "method": "StratifiedKFold · same RF hyperparameters as holdout model",
            }
        except ValueError:
            continue
    return {
        "n_splits": 0,
        "skipped": True,
        "reason": "Dataset too small or class imbalance prevents stratified k-fold (need ≥k samples per class for chosen k).",
    }


def _plotly_dashboard(
    meta_block: dict[str, Any],
    out: Path,
) -> None:
    from plotly.subplots import make_subplots
    import plotly.graph_objects as go

    m = meta_block.get("metrics", {})
    acc = float(m.get("accuracy_holdout", 0))
    f1 = float(m.get("f1_macro_holdout", 0))
    f1w = float(m.get("f1_weighted_holdout", 0))
    has_ae = isinstance(meta_block.get("autoencoder"), dict)
    ev = meta_block.get("evaluation") if isinstance(meta_block.get("evaluation"), dict) else {}
    cv = ev.get("cross_validation_rf") if isinstance(ev.get("cross_validation_rf"), dict) else {}
    _cv_ok = bool(cv.get("n_splits", 0)) and not cv.get("skipped")

    rows = 2 if _cv_ok else 1
    fig = make_subplots(
        rows=rows,
        cols=1,
        row_heights=[0.55, 0.45] if rows == 2 else [1.0],
        subplot_titles=(
            "Holdout (test split)",
            "Stratified cross-validation (Random Forest · full dataset)",
        )
        if rows == 2
        else ("Holdout (test split) · per-class metrics in meta.json",),
        vertical_spacing=0.14,
    )
    fig.add_trace(
        go.Bar(
            name="Holdout",
            x=["Accuracy", "F1 macro", "F1 weighted"],
            y=[acc, f1, f1w],
            marker_color=["#4cc9f0", "#a855f7", "#c084fc"],
            showlegend=False,
        ),
        row=1,
        col=1,
    )
    if rows == 2:
        fig.add_trace(
            go.Bar(
                name="CV",
                x=["Accuracy μ", "F1 macro μ"],
                y=[
                    float(cv.get("accuracy_mean", 0)),
                    float(cv.get("f1_macro_mean", 0)),
                ],
                error_y=dict(
                    type="data",
                    array=[
                        float(cv.get("accuracy_std", 0)),
                        float(cv.get("f1_macro_std", 0)),
                    ],
                    visible=True,
                ),
                marker_color=["#22d3ee", "#e879f9"],
                showlegend=False,
            ),
            row=2,
            col=1,
        )

    timing = ev.get("timing_ms") if isinstance(ev.get("timing_ms"), dict) else {}
    t_ann = ""
    if timing:
        parts = []
        if timing.get("rf_train") is not None:
            parts.append(f"RF train: {timing['rf_train']:.1f} ms")
        if timing.get("rf_predict_per_row_mean") is not None:
            parts.append(f"RF infer/row: {timing['rf_predict_per_row_mean']:.4f} ms")
        if timing.get("ae_train") is not None:
            parts.append(f"AE train: {timing['ae_train']:.1f} ms")
        t_ann = " · ".join(parts)

    fig.update_layout(
        title_text="MNIDS lab — RF / IF" + (" / AE (Keras)" if has_ae else "") + " · evaluation",
        height=720 if rows == 2 else 420,
        showlegend=False,
        margin=dict(t=80, b=60),
    )
    fig.update_yaxes(title_text="Score (0–1)", row=1, col=1)
    if rows == 2:
        fig.update_yaxes(title_text="Score (0–1)", row=2, col=1)
    if t_ann:
        fig.add_annotation(
            text=t_ann,
            xref="paper",
            yref="paper",
            x=0.5,
            y=-0.06,
            showarrow=False,
            font=dict(size=11, color="#8b8b96"),
            xanchor="center",
        )
    fig.write_html(out, include_plotlyjs="cdn")


def _train_autoencoder(
    X: np.ndarray,
    y: np.ndarray,
    X_train: np.ndarray,
    y_train: np.ndarray,
    out_dir: Path,
) -> dict[str, Any] | None:
    print("[PHASE] Autoencoder · importing TensorFlow / Keras", flush=True)
    try:
        import tensorflow as tf
        from tensorflow import keras
        from tensorflow.keras import layers
    except ImportError:
        print("WARNING: tensorflow not installed; skipping Autoencoder. pip install tensorflow", flush=True)
        return None

    benign = y_train == 0
    Xb = X_train[benign]
    if Xb.shape[0] < 8:
        Xb = X_train
    scaler = StandardScaler()
    Xs = scaler.fit_transform(Xb)
    n_feat = Xs.shape[1]
    inp = keras.Input(shape=(n_feat,))
    x = layers.Dense(max(32, n_feat * 2), activation="relu")(inp)
    x = layers.Dense(16, activation="relu")(x)
    x = layers.Dense(8, activation="relu")(x)
    x = layers.Dense(16, activation="relu")(x)
    out = layers.Dense(n_feat, activation="linear")(x)
    model = keras.Model(inp, out)
    model.compile(optimizer=keras.optimizers.Adam(1e-3), loss="mse")
    es = keras.callbacks.EarlyStopping(monitor="val_loss", patience=12, restore_best_weights=True)
    print(
        f"[PHASE] Autoencoder · fitting on {Xb.shape[0]} benign rows "
        f"(epochs<=120, early-stop patience=12, Adam(1e-3), MSE)",
        flush=True,
    )
    t_ae0 = time.perf_counter()
    history = model.fit(
        Xs,
        Xs,
        epochs=120,
        batch_size=min(32, len(Xs)),
        validation_split=0.15,
        verbose=0,
        callbacks=[es],
    )
    ae_train_ms = (time.perf_counter() - t_ae0) * 1000.0
    epochs_run = len(history.history.get("loss", []))
    print(
        f"[PHASE] Autoencoder · trained in {ae_train_ms / 1000.0:.2f} s "
        f"({epochs_run} epoch(s) actually run)",
        flush=True,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    model.save(out_dir / "ae_model.keras")
    joblib.dump(scaler, out_dir / "ae_scaler.joblib")

    X_all = scaler.transform(X)
    t_inf0 = time.perf_counter()
    pred = model.predict(X_all, verbose=0)
    n_inf = max(1, len(X_all))
    ae_predict_ms_per_row = (time.perf_counter() - t_inf0) * 1000.0 / float(n_inf)
    mse = np.mean((X_all - pred) ** 2, axis=1)
    p10, p90 = float(np.percentile(mse, 10)), float(np.percentile(mse, 90))
    span = max(p90 - p10, 1e-9)

    _plot_ae_loss(history, out_dir / "ae_training_loss.png")

    return {
        "keras_path": "ae_model.keras",
        "scaler_path": "ae_scaler.joblib",
        "trained_on": "benign-only rows in training split (fallback: all train if too few benign)",
        "mse_percentile_10": p10,
        "mse_percentile_90": p90,
        "anomaly_score_formula": "(mse - p10) / (p90 - p10) clipped to [0,1]",
        "train_wall_ms": round(ae_train_ms, 2),
        "predict_ms_per_row_mean_full_fit": round(float(ae_predict_ms_per_row), 6),
    }


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Train MNIDS RF/IF/AE models")
    ap.add_argument(
        "--csv",
        type=str,
        default=str(CSV_PATH),
        help="Path to labeled CSV dataset (default: dataset/mnids_synthetic_flows.csv)",
    )
    ap.add_argument(
        "--artifact-dir",
        type=str,
        default="",
        help="Write rf/if/ae/meta/plots here instead of mnids/cnn_model (demo runs).",
    )
    return ap.parse_args()


def main() -> None:
    args = _parse_args()
    csv_path = Path(args.csv).resolve()
    if not csv_path.exists():
        raise SystemExit(f"Missing {csv_path} — provide --csv <path> or generate lab dataset first.")

    raw_art = (getattr(args, "artifact_dir", None) or "").strip()
    out_dir = Path(raw_art).resolve() if raw_art else ART_DIR

    print(
        "[PHASE] Stack · scikit-learn RandomForest + IsolationForest, "
        "TensorFlow/Keras Autoencoder",
        flush=True,
    )
    print(f"[PHASE] Artifact directory · {out_dir}", flush=True)
    print(f"[PHASE] Loading CSV · {csv_path}", flush=True)
    df = pd.read_csv(csv_path)
    missing = [c for c in FEATURE_NAMES if c not in df.columns]
    if "label_id" not in df.columns:
        missing.append("label_id")
    if missing:
        raise SystemExit(
            "CSV missing required columns: "
            + ", ".join(missing)
            + ". Expected FEATURE_NAMES + label_id."
        )
    X = df[FEATURE_NAMES].values.astype(np.float64)
    y = df["label_id"].values.astype(np.int64)
    classes_present = sorted(set(int(v) for v in y))
    print(
        f"[PHASE] Loaded · rows={len(df)} features={len(FEATURE_NAMES)} "
        f"classes={classes_present}",
        flush=True,
    )
    if len(classes_present) < 2:
        print(
            "WARNING: only one class present in dataset (likely PCAP auto-label fallback). "
            "Random Forest will be degenerate; upload a labeled CSV with all 3 classes "
            "(Benign / Suspicious / Malicious) for a realistic training run.",
            flush=True,
        )

    print("[PHASE] Random Forest · stratified k-fold cross-validation (sklearn)", flush=True)
    cv_block = _run_stratified_cv(X, y)
    if cv_block.get("n_splits"):
        print(
            f"[PHASE] CV done · folds={cv_block['n_splits']} "
            f"acc_mean={cv_block.get('accuracy_mean')} f1_mean={cv_block.get('f1_macro_mean')}",
            flush=True,
        )
    else:
        print(f"[PHASE] CV skipped · {cv_block.get('reason', 'unknown reason')}", flush=True)

    print("[PHASE] Holdout split · stratified train/test (test=22%)", flush=True)
    stratify_arg: np.ndarray | None = y if len(classes_present) >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.22, random_state=42, stratify=stratify_arg
    )
    print(f"[PHASE] Split done · train={len(X_train)} test={len(X_test)}", flush=True)

    print(
        "[PHASE] Random Forest · fitting (sklearn RandomForestClassifier "
        "n_estimators=64, max_depth=14)",
        flush=True,
    )
    rf = _rf_pipeline()
    t_rf0 = time.perf_counter()
    rf.fit(X_train, y_train)
    rf_train_ms = (time.perf_counter() - t_rf0) * 1000.0
    print(f"[PHASE] RF fit done · {rf_train_ms / 1000.0:.2f} s", flush=True)

    print("[PHASE] Random Forest · benchmarking holdout inference (10× warm)", flush=True)
    _ = rf.predict(X_test[: min(3, len(X_test))])
    t_inf = time.perf_counter()
    for _ in range(10):
        pred = rf.predict(X_test)
    rf_pred_ms_per_row = (time.perf_counter() - t_inf) / 10.0 / max(len(X_test), 1) * 1000.0

    acc = accuracy_score(y_test, pred)
    f1m = f1_score(y_test, pred, average="macro")
    f1w = f1_score(y_test, pred, average="weighted")
    print(
        f"[PHASE] RF holdout · acc={acc:.3f} f1_macro={f1m:.3f} "
        f"f1_weighted={f1w:.3f} · ~{rf_pred_ms_per_row:.2f} ms/row",
        flush=True,
    )

    print(
        "[PHASE] Isolation Forest · fitting (sklearn IsolationForest "
        "n_estimators=80, contamination=0.18)",
        flush=True,
    )
    iforest = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "if",
                IsolationForest(
                    n_estimators=80,
                    contamination=0.18,
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    iforest.fit(X)
    raw_scores = iforest.decision_function(X)
    lo, hi = float(raw_scores.min()), float(raw_scores.max())
    print(
        f"[PHASE] IF fit done · decision range [{lo:.3f}, {hi:.3f}]",
        flush=True,
    )

    print("[PHASE] Persisting RF + IF (joblib)", flush=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, out_dir / "rf_pipeline.joblib")
    joblib.dump(iforest, out_dir / "iforest_pipeline.joblib")

    labels = [label_name(i) for i in range(3)]
    _plot_confusion_mat(y_test, pred, labels, out_dir / "rf_confusion_matrix.png")

    lab_ids = list(range(3))
    cm = confusion_matrix(y_test, pred, labels=lab_ids)
    fpr_map = _per_class_fpr(cm)
    prec, rec, f1_each, sup = precision_recall_fscore_support(
        y_test, pred, labels=lab_ids, zero_division=0
    )
    per_class_metrics: dict[str, Any] = {}
    for i, name in enumerate(labels):
        per_class_metrics[name] = {
            "precision": round(float(prec[i]), 4),
            "recall": round(float(rec[i]), 4),
            "f1": round(float(f1_each[i]), 4),
            "support": int(sup[i]),
            "fpr_one_vs_rest": fpr_map.get(name, 0.0),
        }
    macro_fpr = round(float(np.mean([per_class_metrics[n]["fpr_one_vs_rest"] for n in labels])), 4)

    print("[PHASE] Autoencoder · TensorFlow / Keras starting", flush=True)
    ae_info = _train_autoencoder(X, y, X_train, y_train, out_dir)

    timing_ms: dict[str, Any] = {
        "rf_train": round(rf_train_ms, 2),
        "rf_predict_per_row_mean": round(float(rf_pred_ms_per_row), 6),
        "note": "RF predict: mean ms per row over 10× holdout batch (warm). AE: full-dataset encode once.",
    }
    if ae_info and ae_info.get("train_wall_ms") is not None:
        timing_ms["ae_train"] = ae_info.get("train_wall_ms")
    if ae_info and ae_info.get("predict_ms_per_row_mean_full_fit") is not None:
        timing_ms["ae_predict_per_row_mean"] = ae_info.get("predict_ms_per_row_mean_full_fit")

    meta: dict[str, Any] = {
        "model_version": "mnids-lab-hybrid-rf-if-ae-2.1-eval",
        "feature_names": FEATURE_NAMES,
        "labels": labels,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "total_rows": int(len(X)),
        "metrics": {
            "accuracy_holdout": round(acc, 4),
            "f1_macro_holdout": round(f1m, 4),
            "f1_weighted_holdout": round(float(f1w), 4),
            "fpr_macro_avg_holdout": macro_fpr,
        },
        "evaluation": {
            "holdout_per_class": per_class_metrics,
            "cross_validation_rf": cv_block,
            "timing_ms": timing_ms,
            "standards_note": "Holdout = stratified train/test split. FPR is one-vs-rest (multiclass). CV = StratifiedKFold on full data before holdout fit. Latency = lab batch timing (not production wire latency).",
        },
        "isolation_forest": {
            "decision_min": lo,
            "decision_max": hi,
            "anomaly_score_formula": "(-decision - min) / (max - min) clipped to [0,1]",
        },
        "classification_report_holdout": classification_report(
            y_test,
            pred,
            labels=lab_ids,
            target_names=labels,
            zero_division=0,
        ),
        "artifacts": {
            "matplotlib_plots": ["rf_confusion_matrix.png"]
            + (["ae_training_loss.png"] if ae_info else []),
            "plotly_report": "metrics_dashboard.html",
        },
        "training_dataset_csv": str(csv_path),
    }
    if ae_info:
        meta["autoencoder"] = ae_info
    if out_dir.resolve() != ART_DIR.resolve():
        meta["mnids_demo_artifact_run"] = True
        meta["artifact_output_dir"] = str(out_dir)

    print("[PHASE] Writing plots + meta.json", flush=True)
    _plotly_dashboard(meta, out_dir / "metrics_dashboard.html")

    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print("Saved", out_dir / "rf_pipeline.joblib", flush=True)
    print("Saved", out_dir / "iforest_pipeline.joblib", flush=True)
    if ae_info:
        print("Saved", out_dir / "ae_model.keras", out_dir / "ae_scaler.joblib", flush=True)
    print(
        "Saved plots:",
        out_dir / "rf_confusion_matrix.png",
        out_dir / "ae_training_loss.png",
        out_dir / "metrics_dashboard.html",
        flush=True,
    )
    print("Saved", out_dir / "meta.json", flush=True)
    print(
        f"Holdout accuracy={acc:.3f} f1_macro={f1m:.3f} f1_weighted={f1w:.3f} "
        f"fpr_macro_avg={macro_fpr:.4f} cv_folds={cv_block.get('n_splits', 0)}",
        flush=True,
    )
    print(
        f"[DONE] Training complete · acc={acc:.3f} f1_macro={f1m:.3f} "
        f"fpr_macro={macro_fpr:.4f} ae={'yes' if ae_info else 'skipped'}",
        flush=True,
    )


if __name__ == "__main__":
    main()
