import React, { useCallback, useEffect, useRef, useState } from 'react';
import { FolderOpen, RefreshCw, Upload, Play, AlertCircle, Loader2, FolderSymlink, Database } from 'lucide-react';
import { cn } from '../lib/utils';
import { fetchPcapList, fetchPcapBytes, fetchTrainedPcapList, fetchTrainedPcapBytes, parsePcapBuffer } from '../lib/pcapIngest';
import type { PcapIngestProgress } from '../lib/pcapIngestTypes';
import type { TrafficLog } from '../types';

/** Dashboard PCAP library: show every .pcap/.cap/.pcapng file the backend returns. */
export function libraryPcapFilenamesForUi(apiFileList: string[]): string[] {
  return [...apiFileList].sort((a, b) =>
    a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }),
  );
}

function pickDefaultPcap(names: string[]): string {
  return names[0] ?? '';
}

type Props = {
  onApplyFlows: (
    flows: TrafficLog[],
    mode: 'merge' | 'replace',
    opts?: { progressive?: boolean },
  ) => void | Promise<void>;
  onIngestProgress?: (state: PcapIngestProgress | null) => void;
  /** `toolbar` = one compact row (no large card). Default `card` keeps legacy layout. */
  layout?: 'card' | 'toolbar';
};

export function PcapLibraryPanel({ onApplyFlows, onIngestProgress, layout = 'card' }: Props) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<string[]>([]);
  const [trainedFiles, setTrainedFiles] = useState<string[]>([]);
  const [listError, setListError] = useState<string | null>(null);
  const [trainedError, setTrainedError] = useState<string | null>(null);
  const [selected, setSelected] = useState('');
  const [selectedTrained, setSelectedTrained] = useState('');
  /** Default on: each Analyze replaces the traffic table so old rows do not linger (merge is opt-in). */
  const [replaceTable, setReplaceTable] = useState(true);
  const [busy, setBusy] = useState(false);
  const [lastMsg, setLastMsg] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [revealMsg, setRevealMsg] = useState<string | null>(null);

  const refreshList = useCallback(async () => {
    setListError(null);
    setTrainedError(null);
    const r = await fetchPcapList();
    const uiFiles = libraryPcapFilenamesForUi(r.files);
    setFiles(uiFiles);
    if (!r.ok && r.error) setListError(r.error);
    setSelected((prev) => {
      if (uiFiles.length === 0) return '';
      if (prev && uiFiles.includes(prev)) return prev;
      return pickDefaultPcap(uiFiles);
    });
    const tr = await fetchTrainedPcapList();
    // Use all trained files, not just the ones matching the old demo pattern
    setTrainedFiles(tr.files || []);
    if (!tr.ok && tr.error) setTrainedError(tr.error);
    setSelectedTrained((prev) => {
      const allFiles = tr.files || [];
      if (allFiles.length === 0) return '';
      if (prev && allFiles.includes(prev)) return prev;
      return allFiles[0] || '';
    });
  }, []);

  useEffect(() => {
    void refreshList();
  }, [refreshList]);

  const yieldPaint = () =>
    new Promise<void>((resolve) => {
      requestAnimationFrame(() => resolve());
    });

  const applyFromBuffer = useCallback(
    async (label: string, buf: ArrayBuffer) => {
      setLastMsg(null);
      setWarnings([]);
      onIngestProgress?.({ pct: 42, label: `Parsing ${label}…`, etaSec: null });
      await yieldPaint();
      const parsed = parsePcapBuffer(buf, label);
      if (parsed.ok === false) {
        onIngestProgress?.(null);
        setLastMsg(parsed.error);
        return;
      }
      setWarnings(parsed.warnings);
      onIngestProgress?.({ pct: 78, label: 'Applying flows to dashboard…', etaSec: 1 });
      await yieldPaint();
      await Promise.resolve(
        onApplyFlows(parsed.flows, replaceTable ? 'replace' : 'merge', {
          progressive: replaceTable,
        }),
      );
      onIngestProgress?.({
        pct: 100,
        label: `PCAP complete — ${parsed.flows.length} flow row(s).`,
        etaSec: 0,
      });
      setLastMsg(
        `Loaded ${parsed.flows.length} flows from ${label} (${replaceTable ? 'replaced table' : 'merged'}). Inference only — model weights are unchanged.`,
      );
    },
    [onApplyFlows, onIngestProgress, replaceTable],
  );

  const analyzeSelected = async () => {
    if (!selected) return;
    setBusy(true);
    setLastMsg(null);
    setWarnings([]);
    try {
      onIngestProgress?.({
        pct: 12,
        label: `Fetching ${selected} from project pcap folder`,
        etaSec: null,
      });
      const buf = await fetchPcapBytes(selected);
      await applyFromBuffer(selected, buf);
    } catch (e) {
      onIngestProgress?.(null);
      setLastMsg(e instanceof Error ? e.message : 'Ingest failed');
    } finally {
      setBusy(false);
    }
  };

  const analyzeTrainedSelected = async () => {
    if (!selectedTrained) return;
    setBusy(true);
    setLastMsg(null);
    setWarnings([]);
    try {
      onIngestProgress?.({
        pct: 12,
        label: `Fetching ${selectedTrained} from trained dataset`,
        etaSec: null,
      });
      const buf = await fetchTrainedPcapBytes(selectedTrained);
      await applyFromBuffer(selectedTrained, buf);
    } catch (e) {
      onIngestProgress?.(null);
      setLastMsg(e instanceof Error ? e.message : 'Ingest failed');
    } finally {
      setBusy(false);
    }
  };

  const revealPcapFolder = async () => {
    setRevealMsg(null);
    try {
      const res = await fetch('/api/pcap/reveal-folder', { method: 'POST' });
      const data = (await res.json()) as { ok?: boolean; error?: string; path?: string };
      if (!res.ok || data.ok === false) {
        setRevealMsg(data.error ?? `HTTP ${res.status}`);
        return;
      }
      setRevealMsg(data.path ? `Opened: ${data.path}` : 'Folder opened in file manager.');
      window.setTimeout(() => setRevealMsg(null), 4000);
    } catch {
      setRevealMsg('Could not open folder (dev server only).');
    }
  };

  const chooseFileFromDisk = async () => {
    const w = window as Window & {
      showOpenFilePicker?: (opts: {
        multiple?: boolean;
        types?: { description: string; accept: Record<string, string[]> }[];
      }) => Promise<FileSystemFileHandle[]>;
    };
    if (typeof w.showOpenFilePicker === 'function') {
      try {
        const [handle] = await w.showOpenFilePicker({
          multiple: false,
          types: [
            {
              description: 'Packet capture',
              accept: {
                'application/vnd.tcpdump.pcap': ['.pcap', '.cap'],
                'application/octet-stream': ['.pcap', '.cap', '.pcapng', '.dmp'],
              },
            },
          ],
        });
        const file = await handle.getFile();
        await runUploadedFile(file);
        return;
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') return;
      }
    }
    fileInputRef.current?.click();
  };

  const runUploadedFile = async (file: File) => {
    setBusy(true);
    setLastMsg(null);
    setWarnings([]);
    try {
      onIngestProgress?.({ pct: 8, label: `Reading ${file.name}…`, etaSec: null });
      const buf = await file.arrayBuffer();
      onIngestProgress?.({ pct: 22, label: 'File read — parsing…', etaSec: null });
      await applyFromBuffer(file.name, buf);
    } finally {
      setBusy(false);
    }
  };

  const fileInput = (
    <input
      ref={fileInputRef}
      type="file"
      accept=".pcap,.cap,.pcapng,.dmp"
      className="hidden"
      aria-label="Upload PCAP or CAP file from disk"
      onChange={async (e) => {
        const file = e.target.files?.[0];
        e.target.value = '';
        if (!file) return;
        await runUploadedFile(file);
      }}
    />
  );

  const messages = (
    <>
      {revealMsg && (
        <p className="text-xs text-[var(--text-muted)] border border-[var(--border)] rounded px-2 py-1.5 bg-[var(--surface-subtle)]/80">
          {revealMsg}
        </p>
      )}
      {listError && (
        <div className="flex items-start gap-2 text-xs text-amber-950 bg-amber-50 border border-amber-300 rounded-lg p-2">
          <AlertCircle size={12} className="shrink-0 mt-0.5" />
          <span>{listError}</span>
        </div>
      )}
      {lastMsg && (
        <p
          className={cn(
            'text-xs rounded px-2 py-1',
            lastMsg.startsWith('Loaded') ? 'bg-emerald-100 text-emerald-900' : 'bg-red-100 text-red-900',
          )}
        >
          {lastMsg}
        </p>
      )}
      {warnings.length > 0 && (
        <ul className="text-[11px] text-[var(--text-muted)] list-disc list-inside space-y-0.5 max-h-20 overflow-y-auto">
          {warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
    </>
  );

  if (layout === 'toolbar') {
    return (
      <div className="mt-4 space-y-2">
        {messages}
        <div className="flex flex-wrap items-center gap-2 gap-y-2">
          <FolderOpen size={16} className="text-[var(--accent)] shrink-0" aria-hidden />
          <span className="text-[10px] uppercase tracking-wider text-[var(--text-disabled)] shrink-0">PCAP</span>
          <select
            id="pcap-select-toolbar"
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            disabled={busy || files.length === 0}
            className="min-w-[8rem] max-w-[min(100vw-12rem,20rem)] bg-[var(--surface-subtle)] border border-[var(--border)] rounded-md px-2 py-1.5 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
          >
            {files.length === 0 ? (
              <option value="">No files</option>
            ) : (
              files.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))
            )}
          </select>
          <label className="flex items-center gap-1 text-[11px] text-[var(--text-secondary)] cursor-pointer shrink-0" title="Replace table (recommended)">
            <input
              type="checkbox"
              checked={replaceTable}
              onChange={(e) => setReplaceTable(e.target.checked)}
              className="rounded border-[var(--border)] shrink-0"
            />
            Replace
          </label>
          <button
            type="button"
            onClick={() => void analyzeSelected()}
            disabled={busy || !selected || files.length === 0}
            className={cn(
              'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-bold uppercase tracking-wide',
              !busy && selected && files.length > 0
                ? 'bg-[var(--accent)] text-[#121214] hover:bg-[var(--accent-hover)]'
                : 'bg-[var(--surface-hover)] text-[var(--text-disabled)] cursor-not-allowed',
            )}
          >
            {busy ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
            Analyze
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void chooseFileFromDisk()}
            className={cn(
              'inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[11px] font-semibold uppercase border border-[var(--border)]',
              busy ? 'text-[var(--text-disabled)] cursor-not-allowed' : 'text-[var(--text-primary)] hover:bg-[var(--surface-hover)]',
            )}
          >
            <Upload size={12} aria-hidden />
            Upload
          </button>
          <button
            type="button"
            onClick={() => void refreshList()}
            disabled={busy}
            className="p-1.5 rounded-md border border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-hover)] disabled:opacity-50"
            title="Refresh list"
            aria-label="Refresh PCAP list"
          >
            <RefreshCw size={14} className={cn(busy && 'animate-spin')} />
          </button>
          <button
            type="button"
            onClick={() => void revealPcapFolder()}
            disabled={busy}
            className="p-1.5 rounded-md border border-[var(--border)] text-[var(--accent)] hover:bg-[var(--accent)]/10 disabled:opacity-50"
            title="Open dataset/pcap folder"
            aria-label="Open PCAP folder"
          >
            <FolderSymlink size={14} />
          </button>
          {fileInput}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-xl p-5 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2 gap-y-2 mb-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-2 rounded-md bg-[var(--accent)]/10 text-[var(--accent)] shrink-0">
            <FolderOpen size={20} />
          </div>
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-[var(--text-primary)] leading-tight">PCAP</h3>
            <p className="text-xs text-[var(--text-disabled)] mt-0.5">dataset/pcap · Analyze or upload</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2 shrink-0">
          <button
            type="button"
            onClick={() => void revealPcapFolder()}
            disabled={busy}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md border border-[var(--accent)]/35 text-sm font-medium uppercase tracking-wide text-[var(--accent)] hover:bg-[var(--accent)]/10"
          >
            <FolderSymlink size={14} />
            Folder
          </button>
          <button
            type="button"
            onClick={() => void refreshList()}
            disabled={busy}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md border border-[var(--border)] text-sm font-medium uppercase tracking-wide text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"
          >
            <RefreshCw size={14} className={cn(busy && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </div>

      {revealMsg && (
        <p className="mb-2 text-sm text-[var(--text-muted)] border border-[var(--border)] rounded px-3 py-2 bg-[var(--surface-subtle)]/80">
          {revealMsg}
        </p>
      )}

      {listError && (
        <div className="mb-2 flex items-start gap-2 text-sm text-amber-950 bg-amber-50 border border-amber-300 rounded-lg p-2">
          <AlertCircle size={12} className="shrink-0 mt-0.5" />
          <span>{listError}</span>
        </div>
      )}

      <div className="mb-4">
        <div className="flex items-center gap-2 mb-2">
          <Database size={16} className="text-[var(--accent)]" />
          <h4 className="text-sm font-semibold uppercase text-[var(--text-muted)]">Trained Dataset</h4>
        </div>
        {trainedError && (
          <div className="mb-2 flex items-start gap-2 text-sm text-amber-950 bg-amber-50 border border-amber-300 rounded-lg p-2">
            <AlertCircle size={12} className="shrink-0 mt-0.5" />
            <span>{trainedError}</span>
          </div>
        )}
        <div className="flex flex-wrap items-end gap-2">
          <div className="flex-1 min-w-[160px]">
            <select
              value={selectedTrained}
              onChange={(e) => setSelectedTrained(e.target.value)}
              disabled={busy || trainedFiles.length === 0}
              className="w-full bg-[var(--surface-subtle)] border border-[var(--border)] rounded-lg px-3 py-2.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
            >
              {trainedFiles.length === 0 ? (
                <option value="">No trained PCAP files</option>
              ) : (
                trainedFiles.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))
              )}
            </select>
          </div>
          <button
            type="button"
            onClick={() => void analyzeTrainedSelected()}
            disabled={busy || !selectedTrained || trainedFiles.length === 0}
            className={cn(
              'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-bold uppercase tracking-wide',
              !busy && selectedTrained && trainedFiles.length > 0
                ? 'bg-[var(--accent)] text-[#121214] hover:bg-[var(--accent-hover)]'
                : 'bg-[var(--surface-hover)] text-[var(--text-disabled)] cursor-not-allowed',
            )}
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            Test
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-end gap-2 mb-2">
        <div className="flex-1 min-w-[160px]">
          <label htmlFor="pcap-select" className="block text-sm font-medium uppercase text-[var(--text-muted)] mb-1">
            Upload
          </label>
          <select
            id="pcap-select"
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            disabled={busy || files.length === 0}
            className="w-full bg-[var(--surface-subtle)] border border-[var(--border)] rounded-lg px-3 py-2.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
          >
            {files.length === 0 ? (
              <option value="">No .pcap in dataset/pcap</option>
            ) : (
              files.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))
            )}
          </select>
        </div>

        <label
          className="flex items-center gap-1.5 text-sm text-[var(--text-secondary)] cursor-pointer select-none pb-1 max-w-[11rem] leading-snug"
          title="When checked (default), this PCAP becomes the whole traffic table. Uncheck to prepend these flows on top of existing rows (max 50 total)."
        >
          <input
            type="checkbox"
            checked={replaceTable}
            onChange={(e) => setReplaceTable(e.target.checked)}
            className="rounded border-[var(--border)] shrink-0"
          />
          <span>
            Replace table <span className="text-[var(--text-disabled)] font-normal normal-case">(recommended)</span>
          </span>
        </label>

        <button
          type="button"
          onClick={() => void analyzeSelected()}
          disabled={busy || !selected || files.length === 0}
          className={cn(
            'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-bold uppercase tracking-wide',
            !busy && selected && files.length > 0
              ? 'bg-[var(--accent)] text-[#121214] hover:bg-[var(--accent-hover)]'
              : 'bg-[var(--surface-hover)] text-[var(--text-disabled)] cursor-not-allowed',
          )}
        >
          {busy ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
          Analyze
        </button>
      </div>

      <div className="border border-dashed border-[var(--border)] rounded-lg px-3 py-3 bg-[var(--surface-subtle)]/40 flex flex-wrap items-center gap-3">
        <Upload size={16} className="text-[var(--text-disabled)] shrink-0" aria-hidden />
        <button
          type="button"
          disabled={busy}
          onClick={() => void chooseFileFromDisk()}
          className={cn(
            'px-3 py-2 rounded-md text-sm font-semibold uppercase',
            busy ? 'bg-[var(--surface-hover)] text-[var(--text-disabled)] cursor-not-allowed' : 'bg-[var(--accent)] text-[#121214] hover:bg-[var(--accent-hover)]',
          )}
        >
          Upload…
        </button>
        <span className="text-sm text-[var(--text-muted)]">.pcap / .cap / .pcapng</span>
        {fileInput}
      </div>

      {lastMsg && (
        <p
          className={cn(
            'mt-2 text-sm rounded px-2 py-1',
            lastMsg.startsWith('Loaded') ? 'bg-emerald-100 text-emerald-900' : 'bg-red-100 text-red-900',
          )}
        >
          {lastMsg}
        </p>
      )}

      {warnings.length > 0 && (
        <ul className="mt-2 text-sm text-[var(--text-muted)] list-disc list-inside space-y-1 max-h-24 overflow-y-auto">
          {warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
