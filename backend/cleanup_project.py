#!/usr/bin/env python3
"""
Clean up the project folder so you get a tidy final deliverable.

WHAT IT TOUCHES (and why)
-------------------------
ARCHIVE — moved into _archive/<timestamp>/ instead of being deleted.
  Reason: these are valuable for audit + rollback, just not on the active
  path. The folder is named so the dissertation appendix can reference it.

  * cnn_model.backup-*/   — every previous trained-model snapshot. The
                            latest one stays archived; older ones too.

DELETE — actually removed.
  Reason: regeneratable, machine-specific, or pure cache.

  * cnn_model/demo_runs/run_*       (old ML Lab demo runs)
  * dataset/raw/CIC-IDS2017/*.zip   (downloaded zips; can re-download)
  * dataset/uploads/*               (file-upload staging; ML Lab makes them)
  * backend/__pycache__/            (Python bytecode)
  * frontend/.vite/                 (Vite dev cache)
  * any empty directory listed below after the above cleanup

KEEP — never touched.
  * cnn_model/                        (live trained bundle)
  * dataset/imported/*.csv            (training data — small + reproducible)
  * dataset/trained/                  (shipped demo PCAPs)
  * dataset/pcap/                     (user-loaded PCAPs)
  * dataset/not_trained/              (test fixtures)
  * .venv/ / node_modules/            (handled by START.bat's gitignore;
                                       don't wipe them mid-cleanup)
  * source files, package.json, etc.

USAGE
-----
  # Default: DRY RUN — print what would change without touching anything.
  CLEANUP.bat

  # Apply for real (asks for confirmation):
  CLEANUP.bat --apply

  # Apply, no prompt (use in scripts):
  CLEANUP.bat --apply --yes
"""
from __future__ import annotations

import argparse
import datetime as _dt
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_ROOT = ROOT / "_archive"

# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

def _backup_dirs() -> list[Path]:
    return sorted(p for p in ROOT.iterdir() if p.is_dir() and p.name.startswith("cnn_model.backup-"))


def _demo_run_dirs() -> list[Path]:
    d = ROOT / "cnn_model" / "demo_runs"
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.is_dir() and p.name.startswith("run_"))


def _zip_caches() -> list[Path]:
    found: list[Path] = []
    raw = ROOT / "dataset" / "raw"
    if raw.is_dir():
        for p in raw.rglob("*.zip"):
            if p.is_file():
                found.append(p)
        for p in raw.rglob("*.zip.part"):
            if p.is_file():
                found.append(p)
    return found


def _upload_files() -> list[Path]:
    d = ROOT / "dataset" / "uploads"
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.is_file())


def _bytecode_dirs() -> list[Path]:
    return sorted(
        p for p in ROOT.rglob("__pycache__")
        if p.is_dir()
        and ".venv" not in p.parts
        and "node_modules" not in p.parts
    )


def _vite_cache() -> list[Path]:
    out: list[Path] = []
    v = ROOT / "frontend" / ".vite"
    if v.is_dir():
        out.append(v)
    return out


def _orphan_root_files() -> list[Path]:
    """Files at the project root that look leftover from earlier iterations.

    server.py — old Flask experiment; the live HTTP server is backend/server.js.
    train.py  — pre-refactor "Step 1 & 2 combined" script; the live trainer is
                backend/train_models.py. Both are unreferenced by any active
                code (.bat / .mjs / package.json / requirements.txt etc.).

    The check is name-exact AND we re-verify nothing in the project (outside
    node_modules / .venv / _archive) references them, so we never delete a
    file that's actually wired up — even if you copy something in later with
    one of these names.
    """
    import re
    candidates = ["server.py", "train.py"]

    # Scan ONLY our own source trees — never node_modules (50k files, slow)
    # or .venv (also huge) or _archive (intentionally frozen old code).
    # ROOT files (the .bat / launch.mjs / package.json) are scanned as a
    # short flat list rather than recursively.
    scan_roots = [
        ROOT / "backend",
        ROOT / "frontend" / "src",
        ROOT / "frontend" / "vite-plugins",
    ]
    root_files = [p for p in ROOT.iterdir() if p.is_file()]
    extensions = {".py", ".mjs", ".js", ".bat", ".json", ".ts", ".tsx"}

    out: list[Path] = []
    for name in candidates:
        p = ROOT / name
        if not p.is_file():
            continue
        # Strict reference: file name must appear as a standalone token.
        # Without word boundaries `server.py` falsely matches `inference_server.py`,
        # the cleanup_project.py self-reference, etc.
        pattern = re.compile(
            r"(?:^|[^A-Za-z0-9_/\\])" + re.escape(name) + r"(?![A-Za-z0-9_/\\])"
        )

        def _file_references(src_file: Path) -> bool:
            if src_file == p or src_file.name == "cleanup_project.py":
                return False
            if src_file.suffix not in extensions:
                return False
            try:
                text = src_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return False
            return bool(pattern.search(text))

        referenced = False
        # Scan root files (cheap — a handful)
        for src_file in root_files:
            if _file_references(src_file):
                referenced = True
                break
        # Scan our source trees if still not found
        if not referenced:
            for root in scan_roots:
                if not root.is_dir():
                    continue
                for src_file in root.rglob("*"):
                    if not src_file.is_file():
                        continue
                    # Skip Python bytecode and any __pycache__ inside trees.
                    if "__pycache__" in src_file.parts or ".vite" in src_file.parts:
                        continue
                    if _file_references(src_file):
                        referenced = True
                        break
                if referenced:
                    break
        if not referenced:
            out.append(p)
    return out


def _empty_dirs() -> list[Path]:
    """Empty-after-cleanup directories we should also remove."""
    candidates = [
        ROOT / "dataset" / "raw" / "CIC-IDS2017",
        ROOT / "dataset" / "raw",
        ROOT / "dataset" / "uploads",
        ROOT / "cnn_model" / "demo_runs",
    ]
    out: list[Path] = []
    for d in candidates:
        if d.is_dir():
            try:
                # An empty dir has no children at all.
                if not any(d.iterdir()):
                    out.append(d)
            except OSError:
                continue
    return out


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _dir_size_bytes(p: Path) -> int:
    total = 0
    if p.is_file():
        try:
            return p.stat().st_size
        except OSError:
            return 0
    if p.is_dir():
        for sub in p.rglob("*"):
            try:
                if sub.is_file():
                    total += sub.stat().st_size
            except OSError:
                continue
    return total


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB"):
        n /= 1024
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} TB"


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------------------
# Action: archive backups
# ---------------------------------------------------------------------------

def archive_backups(backups: list[Path], apply: bool, archive_dir: Path) -> int:
    if not backups:
        return 0
    if apply:
        archive_dir.mkdir(parents=True, exist_ok=True)
    moved = 0
    for src in backups:
        dst = archive_dir / src.name
        size = _dir_size_bytes(src)
        if apply:
            try:
                shutil.move(str(src), str(dst))
                print(f"  ARCHIVE  {_rel(src):60s} → {_rel(dst)}  ({_fmt_size(size)})", flush=True)
                moved += 1
            except OSError as e:
                print(f"  ERROR    couldn't archive {_rel(src)}: {e}", file=sys.stderr, flush=True)
        else:
            print(f"  ARCHIVE  {_rel(src):60s} → {_rel(dst)}  ({_fmt_size(size)})", flush=True)
            moved += 1
    return moved


# ---------------------------------------------------------------------------
# Action: delete
# ---------------------------------------------------------------------------

def delete_path(p: Path, apply: bool) -> tuple[int, int]:
    """Return (bytes_freed, count) tuples for sizing summary."""
    size = _dir_size_bytes(p)
    if apply:
        try:
            if p.is_dir():
                shutil.rmtree(p)
            elif p.is_file():
                p.unlink()
            print(f"  DELETE   {_rel(p):60s} ({_fmt_size(size)})", flush=True)
            return size, 1
        except OSError as e:
            print(f"  ERROR    couldn't delete {_rel(p)}: {e}", file=sys.stderr, flush=True)
            return 0, 0
    else:
        print(f"  DELETE   {_rel(p):60s} ({_fmt_size(size)})", flush=True)
        return size, 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Clean up MNIDS project for final delivery.")
    ap.add_argument("--apply", action="store_true",
                    help="Actually move / delete. Without this it's a dry run.")
    ap.add_argument("--yes", action="store_true",
                    help="Skip the y/N confirmation prompt (use in scripts).")
    ap.add_argument("--keep-backups", action="store_true",
                    help="Don't archive cnn_model.backup-* folders — leave them in place.")
    ap.add_argument("--keep-demo-runs", action="store_true",
                    help="Don't delete cnn_model/demo_runs/ — useful if you want to reference old runs.")
    ap.add_argument("--keep-orphan-root", action="store_true",
                    help="Don't touch orphan root files (server.py / train.py) even if nothing references them.")
    args = ap.parse_args()

    print(f"[cleanup] project root: {ROOT}", flush=True)
    print(f"[cleanup] mode:         {'APPLY (will modify disk)' if args.apply else 'DRY RUN (no changes)'}", flush=True)
    print("", flush=True)

    # Gather the work list.
    backups = [] if args.keep_backups else _backup_dirs()
    demo_runs = [] if args.keep_demo_runs else _demo_run_dirs()
    zips = _zip_caches()
    uploads = _upload_files()
    pycache = _bytecode_dirs()
    vite = _vite_cache()
    orphans = [] if args.keep_orphan_root else _orphan_root_files()

    # Summary header.
    sections: list[tuple[str, list[Path]]] = [
        ("Old model backups → archive", backups),
        ("Old ML Lab demo runs → delete", demo_runs),
        ("Downloaded dataset zips → delete", zips),
        ("ML Lab upload staging → delete", uploads),
        ("Python bytecode caches → delete", pycache),
        ("Vite dev cache → delete", vite),
        ("Orphan root files → delete", orphans),
    ]
    total_items = sum(len(items) for _, items in sections)
    if total_items == 0:
        print("[cleanup] nothing to do — the project is already tidy.", flush=True)
        return

    # Confirm before destructive run.
    if args.apply and not args.yes:
        print("[cleanup] This will modify your project folder.", flush=True)
        print("[cleanup] Press y + Enter to proceed, anything else to cancel.", flush=True)
        try:
            choice = input("[cleanup] continue? [y/N] ").strip().lower()
        except EOFError:
            choice = ""
        if choice != "y":
            print("[cleanup] cancelled — no changes made.", flush=True)
            return

    archive_dir = ARCHIVE_ROOT / _dt.datetime.now().strftime("%Y%m%d-%H%M%S")

    archived = 0
    deleted_count = 0
    deleted_bytes = 0

    # --- Archive ---
    if backups:
        print("== Old model backups → archive ==", flush=True)
        archived += archive_backups(backups, args.apply, archive_dir)
        print("", flush=True)

    # --- Delete ---
    delete_lists = [
        ("Old ML Lab demo runs", demo_runs),
        ("Downloaded dataset zips", zips),
        ("ML Lab upload staging", uploads),
        ("Python bytecode caches", pycache),
        ("Vite dev cache", vite),
        ("Orphan root files (unreferenced legacy scripts)", orphans),
    ]
    for title, items in delete_lists:
        if not items:
            continue
        print(f"== {title} → delete ==", flush=True)
        for p in items:
            sz, n = delete_path(p, args.apply)
            deleted_count += n
            deleted_bytes += sz
        print("", flush=True)

    # --- Empty dirs left behind (after the deletes above) ---
    if args.apply:
        empties = _empty_dirs()
    else:
        empties = _empty_dirs()
    if empties:
        print("== Empty leftover folders → delete ==", flush=True)
        for d in empties:
            if d.exists():
                sz, n = delete_path(d, args.apply)
                deleted_count += n
                deleted_bytes += sz
        print("", flush=True)

    # --- Summary ---
    print("== Summary ==", flush=True)
    print(f"  archived backups: {archived}", flush=True)
    print(f"  deleted items:    {deleted_count}", flush=True)
    print(f"  freed (approx):   {_fmt_size(deleted_bytes)}", flush=True)
    if not args.apply:
        print("", flush=True)
        print("[cleanup] DRY RUN — nothing was changed. Re-run with --apply to do it.", flush=True)
    else:
        print("", flush=True)
        if archived:
            try:
                rel = archive_dir.relative_to(ROOT)
            except ValueError:
                rel = archive_dir
            print(f"[cleanup] Archived backups are at: {rel}/", flush=True)
        print("[cleanup] Done. The project is ready for delivery.", flush=True)


if __name__ == "__main__":
    main()
