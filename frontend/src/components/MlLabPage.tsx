import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  BrainCircuit,
  Download,
  LayoutDashboard,
  Loader2,
  Lock,
  PlayCircle,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Upload,
} from 'lucide-react';
import { cn } from '../lib/utils';

type MlEvalPerClass = {
  precision?: number;
  recall?: number;
  f1?: number;
  fpr_one_vs_rest?: number;
  support?: number;
};

type MlEval = {
  holdout_per_class?: Record<string, MlEvalPerClass>;
  cross_validation_rf?: {
    n_splits?: number;
    skipped?: boolean;
    accuracy_mean?: number;
    accuracy_std?: number;
    f1_macro_mean?: number;
    f1_macro_std?: number;
    reason?: string;
  };
  timing_ms?: {
    rf_train?: number;
    rf_predict_per_row_mean?: number;
    ae_train?: number;
    ae_predict_per_row_mean?: number;
    note?: string;
  };
  standards_note?: string;
};

type MlMetaOk = {
  ok: true;
  model_version?: string;
  labels?: string[];
  feature_names?: string[];
  train_rows?: number;
  test_rows?: number;
  total_rows?: number;
  training_dataset_csv?: string;
  classification_report_holdout?: string;
  metrics?: {
    accuracy_holdout?: number;
    f1_macro_holdout?: number;
    f1_weighted_holdout?: number;
    fpr_macro_avg_holdout?: number;
  };
  evaluation?: MlEval;
  saved_artifact_count?: number;
  saved_artifact_files?: string[];
  isolation_forest?: { decision_min?: number; decision_max?: number; anomaly_score_formula?: string };
  autoencoder?: {
    keras_path?: string;
    scaler_path?: string;
    trained_on?: string;
    mse_percentile_10?: number;
    mse_percentile_90?: number;
    train_wall_ms?: number;
    predict_ms_per_row_mean_full_fit?: number;
    anomaly_score_formula?: string;
  };
};

type MlMetaResp = MlMetaOk | { ok: false; error?: string };

type MlHealth = {
  ok?: boolean;
  /** Present when ok=false — surfaced to the user in the lab status banner. */
  error?: string;
  modelVersion?: string;
  autoencoder?: boolean;
  evaluation?: {
    f1MacroHoldout?: number;
    fprMacroAvgHoldout?: number;
    cvFolds?: number;
    cvAccuracyMean?: number;
    rfInferMsPerRow?: number;
  };
};

type ValidationResult =
  | {
      ok: true;
      rows?: number;
      label_distribution?: Record<string, number>;
      warnings?: string[];
      format?: string;
      notes?: string;
      filename?: string;
    }
  | {
      ok: false;
      error?: string;
      missing_cols?: string[];
      rows?: number;
      filename?: string;
      pcap_magic_hint?: string;
    };

type UploadedDatasetRow = {
  name: string;
  size_kb: number;
  mtime_iso: string;
  kind?: string;
  rows?: number | null;
  label_distribution?: Record<string, number>;
  format?: string;
  format_note?: string;
};

type StreamDonePayload = {
  type: 'done';
  modelVersion?: string;
  source?: string;
  training_dataset_csv?: string;
  notes?: string;
  demoMode?: boolean;
  demoArtifactDir?: string;
  liveModelUnchanged?: boolean;
};

type Props = {
  onLoadMlLabPcap: () => Promise<void>;
  mlLabPcapBusy: boolean;
  onOpenDashboard: () => void;
};

/** Feature column order aligned with inference / training pipeline */
const DEFAULT_FEATURE_NAMES = [
  'log_duration',
  'log_bytes',
  'log_packets',
  'avg_pkt',
  'sport_n',
  'dport_n',
  'is_tcp',
  'is_udp',
  'is_sctp',
  'is_gtpu',
  'is_ssh',
  'is_dns',
  'log_bytes_per_sec',
  'log_pkts_per_sec',
] as const;

type LabelId = 0 | 1 | 2;

const DEFAULT_LABELS = ['Benign', 'Suspicious', 'Malicious'];

const FALLBACK_VECTORS: Record<LabelId, number[]> = {
  0: [0.09, 6.85, 2.71, 71.0, 0.52, 0.0, 1, 0, 0, 0, 0, 0, 9.38, 5.13],
  1: [0.15, 8.4, 4.02, 82.0, 0.61, 0.02, 1, 0, 0, 1, 0, 0, 10.2, 5.9],
  2: [0.13, 10.21, 6.25, 54.0, 0.54, 0.01, 1, 0, 0, 0, 0, 0, 11.95, 8.04],
};

function parseCsvPreviewAndVectors(
  text: string,
  featureNames: readonly string[],
): { headers: string[]; previewCells: string[][]; byLabel: Partial<Record<LabelId, number[]>> } | null {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return null;
  const headers = lines[0].split(',').map((h) => h.trim());
  const col: Record<string, number> = {};
  headers.forEach((h, i) => {
    col[h] = i;
  });
  if (col.label_id === undefined) return null;
  for (const fn of featureNames) {
    if (col[fn] === undefined) return null;
  }
  const previewLines = lines.slice(1, 6);
  const previewCells = previewLines.map((line) => line.split(','));
  const byLabel: Partial<Record<LabelId, number[]>> = {};
  for (let i = 1; i < lines.length; i++) {
    const cells = lines[i].split(',');
    const lidRaw = cells[col.label_id]?.trim();
    const lid = Number(lidRaw);
    if (lid !== 0 && lid !== 1 && lid !== 2) continue;
    const key = lid as LabelId;
    if (byLabel[key]) continue;
    const vec = featureNames.map((fn) => Number(cells[col[fn]]?.trim()));
    if (vec.some((x) => Number.isNaN(x))) continue;
    byLabel[key] = vec;
    if (byLabel[0] && byLabel[1] && byLabel[2]) break;
  }
  return { headers, previewCells, byLabel };
}

function LabelDistBar({ dist }: { dist: Record<string, number> }) {
  const keys = ['Benign', 'Suspicious', 'Malicious'];
  const total = keys.reduce((s, k) => s + (dist[k] ?? 0), 0) || 1;
  return (
    <div className="space-y-1.5 mt-2">
      <p className="text-[10px] text-emerald-900 font-medium">Label mix</p>
      <div className="flex h-2.5 rounded-md overflow-hidden border border-emerald-900/45">
        {keys.map((k) => (
          <div
            key={k}
            className={cn(
              k === 'Benign' && 'bg-emerald-600',
              k === 'Suspicious' && 'bg-amber-500',
              k === 'Malicious' && 'bg-rose-500',
            )}
            style={{ width: `${((dist[k] ?? 0) / total) * 100}%`, minWidth: (dist[k] ?? 0) > 0 ? '2px' : 0 }}
            title={`${k}: ${dist[k] ?? 0} (${(((dist[k] ?? 0) / total) * 100).toFixed(1)}%)`}
          />
        ))}
      </div>
      <p className="text-[10px] text-emerald-800 tabular-nums">
        {keys.map((k) => `${k} ${dist[k] ?? 0}`).join(' · ')}
      </p>
    </div>
  );
}

function StatusDot({ live, needTrain, needServe }: { live: boolean; needTrain: boolean; needServe: boolean }) {
  const color = live ? 'bg-emerald-400' : needTrain ? 'bg-amber-400' : needServe ? 'bg-amber-400' : 'bg-[var(--text-disabled)]';
  return <span className={cn('inline-block w-2 h-2 rounded-full shrink-0 mt-1', color)} aria-hidden />;
}

type TrainStatus = 'idle' | 'starting' | 'streaming' | 'complete' | 'failed';

type LogKind = 'phase' | 'done' | 'warn' | 'error' | 'lifecycle' | 'plain';

type TrainSummary = {
  modelVersion?: string;
  source?: string;
  notes?: string;
  durationMs?: number;
  accuracy?: number;
  f1Macro?: number;
  fprMacro?: number;
  aeTrainMs?: number;
};

/** Classify a streamed log line so the UI can colour phases / warnings / done lines distinctly. */
function classifyLogLine(text: string): { kind: LogKind; phase?: string } {
  const stripped = text.replace(/^\[[a-zA-Z_]+\]\s*/, '');
  const m = stripped.match(/^\[PHASE\]\s*(.*)$/);
  if (m) return { kind: 'phase', phase: m[1].trim() };
  if (/^\[DONE\]/.test(stripped)) return { kind: 'done' };
  if (/^WARNING/i.test(stripped)) return { kind: 'warn' };
  if (/^ERROR|exited with code/i.test(stripped)) return { kind: 'error' };
  if (/^▶|^✓|^✗/.test(text)) return { kind: 'lifecycle' };
  return { kind: 'plain' };
}

const TRAIN_STATUS_LABEL: Record<TrainStatus, string> = {
  idle: 'Idle',
  starting: 'Starting…',
  streaming: 'Training…',
  complete: 'Complete',
  failed: 'Failed',
};

function trainStatusClasses(s: TrainStatus): string {
  switch (s) {
    case 'streaming':
      return 'border-cyan-300 text-cyan-900 bg-cyan-50';
    case 'starting':
      return 'border-violet-300 text-violet-900 bg-violet-50';
    case 'complete':
      return 'border-emerald-300 text-emerald-900 bg-emerald-50';
    case 'failed':
      return 'border-rose-300 text-rose-900 bg-rose-50';
    default:
      return 'border-[var(--border)] text-[var(--text-muted)] bg-[var(--surface-subtle)]';
  }
}

function formatDurationMs(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '0.0 s';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

async function consumeRetrainStream(
  response: Response,
  onLog: (text: string) => void,
): Promise<{ kind: 'done'; payload: StreamDonePayload } | { kind: 'error'; message: string }> {
  const reader = response.body?.getReader();
  if (!reader) return { kind: 'error', message: 'No response body' };

  const dec = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (value) buffer += dec.decode(value, { stream: true });

    let sep: number;
    while ((sep = buffer.indexOf('\n\n')) >= 0) {
      const block = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);

      const dataLine = block
        .split('\n')
        .map((l) => l.trimEnd())
        .find((l) => l.startsWith('data:'));

      if (!dataLine) continue;

      let payload: Record<string, unknown>;
      try {
        payload = JSON.parse(dataLine.slice(5).trim()) as Record<string, unknown>;
      } catch {
        continue;
      }

      const ty = payload.type;
      if (ty === 'log' && typeof payload.text === 'string') {
        onLog(payload.text);
      } else if (ty === 'error' && typeof payload.text === 'string') {
        return { kind: 'error', message: payload.text };
      } else if (ty === 'done') {
        return { kind: 'done', payload: payload as unknown as StreamDonePayload };
      }
    }

    if (done) break;
  }

  return { kind: 'error', message: 'Stream ended without a completion event.' };
}

export function MlLabPage({ onLoadMlLabPcap, mlLabPcapBusy, onOpenDashboard }: Props) {
  const [meta, setMeta] = useState<MlMetaResp | null>(null);
  const [metaLoading, setMetaLoading] = useState(true);
  const [health, setHealth] = useState<MlHealth | null>(null);
  const [healthErr, setHealthErr] = useState<string | null>(null);
  const [retrainMsg, setRetrainMsg] = useState<string | null>(null);
  const [mlLabProgressNote, setMlLabProgressNote] = useState<string | null>(null);

  const [uploadedDatasets, setUploadedDatasets] = useState<UploadedDatasetRow[]>([]);
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);
  const [pendingFile, setPendingFile] = useState<File | null>(null);
  /**
   * Multi-file batch queue. Each entry tracks its own validation result so the
   * UI can show per-file status. `pendingFile` (single) is still maintained
   * for the existing CSV preview / inference-vector flow — when the queue has
   * exactly one file, that file is also stored as `pendingFile` for back-compat.
   */
  const [pendingBatch, setPendingBatch] = useState<
    { id: string; file: File; status: 'validating' | 'ok' | 'error'; result?: ValidationResult }[]
  >([]);
  const [validating, setValidating] = useState(false);
  const [csvPeek, setCsvPeek] = useState<{ headers: string[]; rows: string[][] } | null>(null);
  const [streamLog, setStreamLog] = useState<
    { seq: number; ts: string; msg: string; kind: LogKind }[]
  >([]);
  const [streaming, setStreaming] = useState(false);
  const [trainStatus, setTrainStatus] = useState<TrainStatus>('idle');
  const [currentPhase, setCurrentPhase] = useState<string | null>(null);
  const [trainStartMs, setTrainStartMs] = useState<number | null>(null);
  const [trainElapsedMs, setTrainElapsedMs] = useState<number>(0);
  const [lastSummary, setLastSummary] = useState<TrainSummary | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);
  const seqRef = useRef(0);
  const trainFileInputRef = useRef<HTMLInputElement>(null);

  const [inferenceSample, setInferenceSample] = useState<LabelId>(0);
  const [inferFeatures, setInferFeatures] = useState<number[]>(() => [...FALLBACK_VECTORS[0]]);
  const [inferByLabelFromCsv, setInferByLabelFromCsv] = useState<Partial<Record<LabelId, number[]>> | null>(null);
  const [inferBusy, setInferBusy] = useState(false);
  const [inferResult, setInferResult] = useState<{
    label: string;
    labelId: number;
    confidence: number;
    anomalyScore: number;
    aeAnomalyScore?: number;
  } | null>(null);
  const [inferError, setInferError] = useState<string | null>(null);

  /** When true, POST /retrain-stream?demo=true — writes under cnn_model/demo_runs/ without reloading live models. */
  const [demoTrainOnly, setDemoTrainOnly] = useState(true);

  const featureNames = useMemo(() => {
    if (meta && meta.ok && meta.feature_names && meta.feature_names.length === 14) {
      return meta.feature_names;
    }
    return [...DEFAULT_FEATURE_NAMES];
  }, [meta]);

  const loadMeta = useCallback(async () => {
    setMetaLoading(true);
    try {
      const r = await fetch('/api/ml-meta');
      const j = (await r.json()) as MlMetaResp;
      setMeta(j);
    } catch {
      setMeta({ ok: false, error: 'No meta' });
    } finally {
      setMetaLoading(false);
    }
  }, []);

  const pollHealth = useCallback(async () => {
    try {
      const r = await fetch('/api/ml/health');
      if (!r.ok) {
        setHealth(null);
        // Express returns 502 with a JSON body when FastAPI is unreachable;
        // surface its `error` field so the user sees the real cause instead
        // of just "HTTP 502".
        let detail = `HTTP ${r.status}`;
        try {
          const j = (await r.json()) as { error?: string };
          if (j?.error) detail = `HTTP ${r.status} — ${j.error}`;
        } catch {
          /* body wasn't JSON; ignore */
        }
        setHealthErr(detail);
        return;
      }
      const j = (await r.json()) as MlHealth;
      setHealth(j);
      // Even on 200, FastAPI may report ok:false (artifacts missing). Keep
      // the error visible in that case so the banner can render the reason.
      if (j?.ok === false) {
        setHealthErr(j.error ?? 'ML service reported degraded health.');
      } else {
        setHealthErr(null);
      }
    } catch (e) {
      setHealth(null);
      setHealthErr(e instanceof Error ? e.message : 'offline');
    }
  }, []);

  const fetchDatasets = useCallback(async () => {
    try {
      const r = await fetch('/api/ml/training-datasets');
      const j = (await r.json()) as { ok?: boolean; files?: UploadedDatasetRow[] };
      if (j.ok && Array.isArray(j.files)) setUploadedDatasets(j.files);
    } catch {
      /* silent */
    }
  }, []);

  useEffect(() => {
    void loadMeta();
  }, [loadMeta]);

  useEffect(() => {
    void pollHealth();
    const id = window.setInterval(() => void pollHealth(), 8000);
    return () => window.clearInterval(id);
  }, [pollHealth]);

  useEffect(() => {
    void fetchDatasets();
  }, [fetchDatasets]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [streamLog]);

  useEffect(() => {
    const fromCsv = inferByLabelFromCsv?.[inferenceSample];
    const v = fromCsv ?? FALLBACK_VECTORS[inferenceSample];
    setInferFeatures([...v]);
    setInferResult(null);
    setInferError(null);
  }, [inferenceSample, inferByLabelFromCsv]);

  const appendLogLine = useCallback((text: string, kindOverride?: LogKind) => {
    seqRef.current += 1;
    const seq = seqRef.current;
    const ts = new Date().toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
    const { kind, phase } = classifyLogLine(text);
    const finalKind: LogKind = kindOverride ?? kind;
    if (phase) setCurrentPhase(phase);
    setStreamLog((prev) => [...prev, { seq, ts, msg: text, kind: finalKind }]);
  }, []);

  useEffect(() => {
    if (trainStartMs == null || trainStatus !== 'streaming') return;
    const id = window.setInterval(() => {
      setTrainElapsedMs(Date.now() - trainStartMs);
    }, 500);
    return () => window.clearInterval(id);
  }, [trainStartMs, trainStatus]);

  const runRetrainStream = useCallback(
    async (url: string, init?: RequestInit) => {
      if (!health?.ok) {
        setRetrainMsg('Start ML API (:8787) before streaming training.');
        return;
      }
      setStreaming(true);
      setStreamLog([]);
      seqRef.current = 0;
      setRetrainMsg(null);
      setLastSummary(null);
      setCurrentPhase(null);
      setTrainStatus('starting');
      setTrainElapsedMs(0);
      const startedAt = Date.now();
      setTrainStartMs(startedAt);
      setMlLabProgressNote('Streaming training logs…');
      appendLogLine('▶ Sending training request to ML API (:8787) …', 'lifecycle');
      try {
        const r = await fetch(url, { method: 'POST', ...init });
        if (!r.ok) {
          const t = await r.text();
          appendLogLine(`✗ HTTP ${r.status} — ${t.slice(0, 200)}`, 'error');
          setTrainStatus('failed');
          setRetrainMsg(`Training failed (HTTP ${r.status}): ${t.slice(0, 280)}`);
          return;
        }
        const ct = r.headers.get('content-type');
        if (!ct?.includes('text/event-stream')) {
          appendLogLine('✗ Unexpected response (not SSE) — is the ML server on :8787?', 'error');
          setTrainStatus('failed');
          setRetrainMsg('Unexpected response (not SSE). Is the ML server on :8787?');
          return;
        }
        setTrainStatus('streaming');
        appendLogLine('▶ Stream connected — receiving live training logs', 'lifecycle');
        const out = await consumeRetrainStream(r, (t) => appendLogLine(t));
        const durationMs = Date.now() - startedAt;
        setTrainElapsedMs(durationMs);
        if (out.kind === 'error') {
          appendLogLine(`✗ Training stopped: ${out.message}`, 'error');
          setTrainStatus('failed');
          setRetrainMsg(`Training stopped: ${out.message}`);
          return;
        }

        const donePayload = out.payload;

        if (donePayload.demoMode === true) {
          await loadMeta();
          await pollHealth();
          await fetchDatasets();
          setLastSummary({
            source: donePayload.source,
            notes: donePayload.notes,
            durationMs,
          });
          setTrainStatus('complete');
          const pathNote = donePayload.demoArtifactDir
            ? ` Folder: ${donePayload.demoArtifactDir}`
            : '';
          appendLogLine(
            `✓ Demo training finished in ${formatDurationMs(durationMs)} — live inference bundle unchanged.${pathNote}`,
            'lifecycle',
          );
          setRetrainMsg(
            `Demo run complete — artifacts saved; dashboard still uses the official cnn_model/ model.${pathNote ? ` ${pathNote}` : ''}`,
          );
          return;
        }

        await loadMeta();
        await pollHealth();
        await fetchDatasets();
        const refreshed = await fetch('/api/ml-meta')
          .then((r2) => (r2.ok ? (r2.json() as Promise<MlMetaResp>) : null))
          .catch(() => null);
        const summary: TrainSummary = {
          modelVersion: out.payload.modelVersion,
          source: out.payload.source,
          notes: out.payload.notes,
          durationMs,
        };
        if (refreshed && refreshed.ok === true) {
          summary.accuracy = refreshed.metrics?.accuracy_holdout;
          summary.f1Macro = refreshed.metrics?.f1_macro_holdout;
          summary.fprMacro = refreshed.metrics?.fpr_macro_avg_holdout;
          summary.aeTrainMs =
            refreshed.evaluation?.timing_ms?.ae_train ?? refreshed.autoencoder?.train_wall_ms;
        }
        setLastSummary(summary);
        setTrainStatus('complete');
        appendLogLine(
          `✓ Training complete in ${formatDurationMs(durationMs)} · version ${
            summary.modelVersion ?? '—'
          } · source ${summary.source ?? '—'}`,
          'lifecycle',
        );
        const note = summary.notes ? ` ${summary.notes}` : '';
        setRetrainMsg(
          `Training complete · version ${summary.modelVersion ?? '—'} · source ${
            summary.source ?? '—'
          }.${note}`,
        );
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'Training request failed.';
        appendLogLine(`✗ ${msg}`, 'error');
        setTrainStatus('failed');
        setRetrainMsg(msg);
      } finally {
        setStreaming(false);
        setMlLabProgressNote(null);
      }
    },
    [appendLogLine, demoTrainOnly, fetchDatasets, health?.ok, loadMeta, pollHealth],
  );

  /**
   * Handles the file-picker selection. Accepts 1..N files. For each file we
   * call /api/ml/validate-data-file so per-row status (rows, label dist,
   * format) shows up in the queue. When exactly one file is chosen we ALSO
   * populate `pendingFile` + `csvPeek` for the existing CSV-preview /
   * inference-vector flow (no UX regression on the common case).
   */
  const onTrainingFileChosen = useCallback(
    async (filesIn: File[] | null) => {
      const fileList = (filesIn ?? []).filter((f) => Boolean(f && f.name));
      setValidationResult(null);
      setCsvPeek(null);
      setInferByLabelFromCsv(null);
      setPendingFile(fileList.length === 1 ? fileList[0] : null);

      if (fileList.length === 0) {
        setPendingBatch([]);
        return;
      }

      // Seed the queue immediately so the user sees the files appear.
      const seeded = fileList.map((f, i) => ({
        id: `${Date.now()}-${i}-${f.name}`,
        file: f,
        status: 'validating' as const,
      }));
      setPendingBatch(seeded);
      setValidating(true);

      try {
        // Validate files in parallel — endpoint is small + stateless.
        const settled = await Promise.all(
          seeded.map(async (entry) => {
            try {
              const fd = new FormData();
              fd.append('file', entry.file, entry.file.name);
              const r = await fetch('/api/ml/validate-data-file', { method: 'POST', body: fd });
              const j = (await r.json()) as ValidationResult;
              return { ...entry, status: (j.ok ? 'ok' : 'error') as 'ok' | 'error', result: j };
            } catch {
              return {
                ...entry,
                status: 'error' as const,
                result: { ok: false, error: 'Could not reach validation endpoint.' } as ValidationResult,
              };
            }
          }),
        );
        setPendingBatch(settled);

        // Single-file UX preserves the existing preview + inference vector.
        if (fileList.length === 1) {
          const only = settled[0];
          setValidationResult(only.result ?? null);
          if (only.result?.ok && fileList[0].name.toLowerCase().endsWith('.csv')) {
            const text = await fileList[0].text();
            const parsed = parseCsvPreviewAndVectors(text, featureNames);
            if (parsed) {
              setCsvPeek({ headers: parsed.headers, rows: parsed.previewCells });
              if (Object.keys(parsed.byLabel).length > 0) {
                setInferByLabelFromCsv(parsed.byLabel);
              }
            }
          }
        } else {
          // Multi-file: surface an aggregate label distribution + row total in the
          // single-file validation block so the existing UI still shows useful info.
          const totalRows = settled.reduce(
            (s, e) => s + (e.result && 'rows' in e.result ? (e.result.rows ?? 0) : 0),
            0,
          );
          const aggDist: Record<string, number> = {};
          for (const e of settled) {
            const dist = e.result && 'label_distribution' in e.result ? e.result.label_distribution : undefined;
            if (dist) {
              for (const [k, v] of Object.entries(dist)) aggDist[k] = (aggDist[k] ?? 0) + Number(v);
            }
          }
          const allOk = settled.every((e) => e.status === 'ok');
          if (allOk) {
            setValidationResult({
              ok: true,
              rows: totalRows,
              label_distribution: Object.keys(aggDist).length ? aggDist : undefined,
              notes: `Aggregate across ${settled.length} files`,
              format: 'multi-file batch',
            });
          } else {
            const firstErr = settled.find((e) => e.status === 'error');
            setValidationResult({
              ok: false,
              error:
                firstErr?.result && 'error' in firstErr.result
                  ? `${firstErr.file.name}: ${firstErr.result.error ?? 'validation failed'}`
                  : 'One or more files failed validation.',
            });
          }
        }
      } finally {
        setValidating(false);
      }
    },
    [featureNames],
  );

  /** Remove a single queued file by id. */
  const removeFromBatch = useCallback((id: string) => {
    setPendingBatch((prev) => {
      const next = prev.filter((e) => e.id !== id);
      // Re-sync the single-file shims when the queue shrinks to 0 or 1.
      if (next.length === 0) {
        setPendingFile(null);
        setValidationResult(null);
        setCsvPeek(null);
        setInferByLabelFromCsv(null);
      } else if (next.length === 1) {
        setPendingFile(next[0].file);
        setValidationResult(next[0].result ?? null);
      }
      return next;
    });
  }, []);

  const deleteUploadedDataset = useCallback(
    async (name: string) => {
      try {
        const r = await fetch(`/api/ml/training-datasets/${encodeURIComponent(name)}`, {
          method: 'DELETE',
        });
        const j = (await r.json()) as { ok?: boolean; error?: string };
        if (!j.ok) {
          setRetrainMsg(j.error ?? 'Delete failed.');
          return;
        }
        await fetchDatasets();
      } catch (e) {
        setRetrainMsg(e instanceof Error ? e.message : 'Delete failed.');
      }
    },
    [fetchDatasets],
  );

  const runInference = useCallback(async () => {
    if (!health?.ok) {
      setInferError('Inference API offline. Start ML server on :8787.');
      return;
    }
    setInferBusy(true);
    setInferError(null);
    setInferResult(null);
    try {
      const features = [inferFeatures.map((x) => (Number.isFinite(x) ? x : 0))];
      const r = await fetch('/api/ml/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ features }),
      });
      const j = (await r.json()) as {
        ok?: boolean;
        error?: string;
        results?: Array<{
          label?: string;
          labelId?: number;
          confidence?: number;
          anomalyScore?: number;
          aeAnomalyScore?: number;
        }>;
      };
      if (!r.ok || !j.ok || !j.results?.[0]) {
        throw new Error(j.error ?? `HTTP ${r.status}`);
      }
      const row = j.results[0];
      setInferResult({
        label: row.label ?? '—',
        labelId: row.labelId ?? -1,
        confidence: row.confidence ?? 0,
        anomalyScore: row.anomalyScore ?? 0,
        aeAnomalyScore: row.aeAnomalyScore,
      });
    } catch (e) {
      setInferError(e instanceof Error ? e.message : 'Predict failed.');
    } finally {
      setInferBusy(false);
    }
  }, [health?.ok, inferFeatures]);

  const hasTrainedModels = meta != null && meta.ok === true;
  const live = health?.ok === true;
  const needTrain = !metaLoading && !hasTrainedModels;
  const needServe = !metaLoading && hasTrainedModels && !live;

  const cv = hasTrainedModels ? meta.evaluation?.cross_validation_rf : undefined;
  const timing = hasTrainedModels ? meta.evaluation?.timing_ms : undefined;
  const holdoutPc = hasTrainedModels ? meta.evaluation?.holdout_per_class : undefined;
  const aeTrainMs = hasTrainedModels
    ? (timing?.ae_train ?? meta.autoencoder?.train_wall_ms)
    : undefined;

  // A 502/503 from the Express proxy means the ML service didn't answer.
  // Surface that as a distinct, actionable state instead of the generic
  // "Models present — start API" message which doesn't explain anything.
  const proxyDown = !live && /\bHTTP\s*(502|503|504)\b/i.test(healthErr ?? '');
  const statusLabel = metaLoading
    ? 'Loading…'
    : live
      ? 'Inference online'
      : needTrain
        ? 'No trained artifacts — build models first'
        : proxyDown
          ? 'ML service unreachable on :8787'
          : needServe
            ? 'Models present — ML service starting…'
            : 'Check configuration';

  const mv = hasTrainedModels
    ? (meta.model_version ?? health?.modelVersion ?? '—')
    : metaLoading
      ? '…'
      : '—';

  // Multi-file aware: the queue is ready when there's at least one file, all
  // entries have validated successfully, and we're not currently busy.
  const batchAllOk = pendingBatch.length > 0 && pendingBatch.every((e) => e.status === 'ok');
  const canStartFromPicker =
    live &&
    !streaming &&
    !validating &&
    ((pendingBatch.length > 0 && batchAllOk) ||
      // Back-compat: a single pendingFile + ok validation also unlocks Start.
      (pendingBatch.length === 0 && Boolean(pendingFile) && validationResult?.ok === true));

  const inferExpectedLabel = DEFAULT_LABELS[inferenceSample] ?? '';
  const inferMatch =
    inferResult && inferResult.labelId >= 0 && inferResult.labelId === inferenceSample;

  const displayClassLabels =
    hasTrainedModels && Array.isArray(meta.labels) && meta.labels.length > 0 ? meta.labels : DEFAULT_LABELS;

  /**
   * "Active model degraded" detection.
   * The lab classifier is 3-class. If any required class has zero holdout support
   * the active RF can't ever predict it, so detection is effectively broken — even
   * though `meta.ok === true`. Surface this as a top-level banner with a one-click
   * recovery into the locked baseline dataset.
   */
  const degradedMissingClasses: string[] = (() => {
    if (!hasTrainedModels || !holdoutPc) return [];
    const required = ['Benign', 'Suspicious', 'Malicious'];
    return required.filter((c) => (holdoutPc[c]?.support ?? 0) === 0);
  })();
  const isModelDegraded = degradedMissingClasses.length > 0;
  const restoreBaseline = useCallback(() => {
    void runRetrainStream('/api/ml/retrain-stream?baseline=true');
  }, [runRetrainStream]);

  return (
    <div className="w-full max-w-7xl 2xl:max-w-[88rem] mx-auto pb-12 px-0">
      <div className="flex items-start gap-3 mb-4">
        <div className="p-2.5 rounded-xl bg-[var(--accent-soft)] border border-[var(--border-accent)] shrink-0">
          <BrainCircuit className="w-7 h-7 text-[var(--accent)]" aria-hidden />
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="text-lg font-semibold text-[var(--text-primary)] tracking-tight">ML Lab</h2>
          <p className="text-[11px] text-[var(--text-disabled)] mt-0.5">Train · validate · probe RF / IF / AE</p>
        </div>
      </div>

      <div
        className="rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)]/90 p-3 mb-5 flex flex-wrap items-start gap-x-4 gap-y-2"
        role="region"
        aria-label="Lab status"
      >
        <div className="flex items-start gap-2 min-w-[12rem]">
          <StatusDot live={live} needTrain={needTrain} needServe={needServe} />
          <div className="min-w-0">
            <p className="text-xs font-semibold text-[var(--text-primary)]">{statusLabel}</p>
            <p className="text-[10px] text-[var(--text-disabled)] font-mono mt-0.5 break-all">
              {live
                ? 'POST /api/ml/predict ready'
                : proxyDown
                  ? 'Check the ML startup window for errors, then retry.'
                  : healthErr ?? '—'}
            </p>
            {!live && (
              <button
                type="button"
                onClick={() => {
                  void pollHealth();
                  void loadMeta();
                }}
                className="mt-1.5 inline-flex items-center gap-1.5 rounded-md border border-[var(--border)] bg-[var(--surface-subtle)] px-2 py-1 text-[10px] font-medium text-[var(--text-secondary)] hover:bg-[var(--surface)] transition-colors"
              >
                <RefreshCw size={11} aria-hidden /> Retry
              </button>
            )}
          </div>
        </div>
        <div className="text-[11px] space-y-0.5 min-w-[10rem]">
          <p className="text-[var(--text-muted)]">Model version</p>
          <p className="font-mono text-[var(--text-soft)] break-all">{mv}</p>
        </div>
        <div className="text-[11px] space-y-0.5 min-w-[8rem]">
          <p className="text-[var(--text-muted)]">Autoencoder</p>
          <p className={health?.autoencoder ? 'text-emerald-700 font-medium' : 'text-[var(--text-disabled)]'}>
            {health?.autoencoder === true ? 'Loaded' : 'Not loaded'}
          </p>
        </div>
        <div className="text-[11px] space-y-0.5 min-w-[9rem]">
          <p className="text-[var(--text-muted)]">RF latency (eval)</p>
          <p className="font-mono tabular-nums text-[var(--text-soft)]">
            {timing?.rf_predict_per_row_mean != null
              ? `~${timing.rf_predict_per_row_mean.toFixed(2)} ms/row`
              : health?.evaluation?.rfInferMsPerRow != null
                ? `~${health.evaluation.rfInferMsPerRow.toFixed(2)} ms/row`
                : '—'}
          </p>
        </div>
        <div className="text-[11px] space-y-0.5 flex-1 min-w-[12rem]">
          <p className="text-[var(--text-muted)]">Classes</p>
          <div className="flex flex-wrap gap-1">
            {displayClassLabels.map((lab) => (
              <span
                key={lab}
                className="inline-flex rounded-full border border-violet-300 bg-violet-100 px-2 py-0.5 text-[10px] text-violet-900"
              >
                {lab}
              </span>
            ))}
          </div>
        </div>
      </div>

      {isModelDegraded ? (
        <div
          className="rounded-xl border border-rose-300 bg-rose-50 p-3 mb-5 flex flex-wrap items-start gap-3"
          role="alert"
        >
          <ShieldAlert
            className="w-5 h-5 text-rose-700 shrink-0 mt-0.5"
            aria-hidden
          />
          <div className="min-w-0 flex-1 text-[11px] leading-relaxed text-rose-950">
            <p className="font-semibold">
              Active model is degraded — detection is unreliable
            </p>
            <p className="text-rose-900/90 mt-0.5">
              No training support for{' '}
              <span className="font-semibold">{degradedMissingClasses.join(', ')}</span>. RF will
              predict Clean for everything. Restore the locked baseline to fix.
            </p>
          </div>
          <button
            type="button"
            disabled={!live || streaming}
            onClick={restoreBaseline}
            className={cn(
              'shrink-0 inline-flex items-center gap-2 rounded-lg px-3 py-2 border text-[11px] font-semibold uppercase tracking-wide transition-colors',
              live && !streaming
                ? 'border-emerald-500/45 bg-emerald-100 text-emerald-950 hover:bg-emerald-200/90'
                : 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed',
            )}
            title="Retrain on the locked Baseline (3-class) dataset"
          >
            <ShieldCheck className="w-3.5 h-3.5" aria-hidden />
            Restore safe model
          </button>
        </div>
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 lg:gap-8 items-start">
        <div className="space-y-4">
          <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)]/80 p-4 space-y-3">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              Train from PCAP or CSV
            </h3>
            <p className="text-[10px] text-[var(--text-disabled)] leading-relaxed">
              <span className="text-[var(--text-secondary)]">CSV</span>: flow features + <span className="font-mono">label_id</span> (0 = Benign, 1 =
              Suspicious, 2 = Malicious). <span className="text-[var(--text-secondary)]">PCAP</span>: classic libpcap — not PCAP-NG. <span className="text-[var(--text-secondary)]">Multi-file</span>:
              pick several .csv / .pcap files at once and they'll be merged into a single training set server-side.
              Training streams subprocess logs below.
            </p>

            {/*
              Plain-language explainer. Collapsed by default so power users
              aren't slowed down, but visible enough that first-time users
              understand WHAT a PCAP/CSV is and HOW training learns from it.
            */}
            <details className="rounded-lg border border-cyan-300 bg-cyan-50/60 text-[11px] text-cyan-950 group">
              <summary className="cursor-pointer px-3 py-2 font-semibold text-cyan-900 select-none flex items-center gap-2">
                <BrainCircuit className="w-3.5 h-3.5 text-cyan-700" aria-hidden />
                How does training work? (plain-language explainer)
                <span className="ml-auto text-[10px] text-cyan-700 group-open:hidden">click to expand</span>
              </summary>
              <div className="px-3 pb-3 pt-1 space-y-3 leading-relaxed border-t border-cyan-200">
                <div>
                  <p className="font-semibold text-cyan-900">1. What's in the file?</p>
                  <p className="text-cyan-900/90">
                    A <span className="font-mono">.pcap</span> file is a raw recording of network packets — every conversation
                    between phones, towers, and servers, captured live. A <span className="font-mono">.csv</span> file is
                    the same idea but pre-summarized: one row = one network "flow" (e.g.{' '}
                    <span className="font-mono">phone X talked to server Y over TCP for 4 seconds</span>),
                    with 14 numeric columns describing that flow (duration, total bytes, packet count, ports, protocol flags…).
                    Think of each row as one log entry.
                  </p>
                </div>

                <div>
                  <p className="font-semibold text-cyan-900">2. Why "labeled" matters</p>
                  <p className="text-cyan-900/90">
                    The last column, <span className="font-mono">label_id</span>, is the answer key.
                    Every row carries a tag set by you (or by the PCAP auto-labeller):
                    <span className="font-mono"> 0</span> = clean traffic,
                    <span className="font-mono"> 1</span> = suspicious / scanning,
                    <span className="font-mono"> 2</span> = malicious attack.
                    The model can only learn to spot bad behaviour if it has seen examples of <em>both</em> good and bad
                    rows — that's why we require at least 2 distinct labels before training overwrites the live model.
                  </p>
                </div>

                <div>
                  <p className="font-semibold text-cyan-900">3. How does it actually "learn"?</p>
                  <p className="text-cyan-900/90">
                    Three models train in parallel on the same rows, each looking at the problem from a different angle:
                  </p>
                  <ul className="list-disc pl-5 mt-1 space-y-1 text-cyan-900/90">
                    <li>
                      <span className="font-semibold">Random Forest</span> — looks at the labels you provided and learns
                      rules like "if duration is short AND bytes are high AND port is 22, it's usually Malicious".
                      Builds hundreds of small decision trees and votes.
                    </li>
                    <li>
                      <span className="font-semibold">Isolation Forest</span> — ignores the labels. Learns what
                      "average" traffic looks like; anything that stands out as statistically rare gets a high anomaly
                      score. Catches new attack shapes Random Forest has never seen before.
                    </li>
                    <li>
                      <span className="font-semibold">Autoencoder</span> — a small neural network that tries to compress
                      and rebuild each row. If it can rebuild a flow accurately, it looks like training data
                      (benign). If reconstruction fails badly, the flow is unfamiliar — flagged as anomalous.
                    </li>
                  </ul>
                </div>

                <div>
                  <p className="font-semibold text-cyan-900">4. What happens when you click "Start training"?</p>
                  <ol className="list-decimal pl-5 mt-1 space-y-1 text-cyan-900/90">
                    <li>Each uploaded PCAP is converted to a CSV of flows (auto-labelled by simple heuristics).</li>
                    <li>All CSVs are merged into one dataset and split into train / holdout (~80 / 20 %).</li>
                    <li>The three models train on the train slice — usually 5–30 seconds total.</li>
                    <li>Holdout rows the models never saw are used to compute Accuracy, F1 score, and False Positive Rate.</li>
                    <li>With <span className="font-semibold">"Demo train only"</span> ticked (default), results land in a
                      timestamped folder under <span className="font-mono">cnn_model/demo_runs/</span> — your real dashboard
                      keeps using the shipped model. Untick it to deploy the new model live.</li>
                  </ol>
                </div>

                <div>
                  <p className="font-semibold text-cyan-900">5. Predicting on new traffic</p>
                  <p className="text-cyan-900/90">
                    Once trained, each new flow gets three scores: RF's predicted label + confidence,
                    IF's anomaly score (0–1), and AE's reconstruction error (0–1). The dashboard combines
                    these to flag rows that look like attacks. If the model is wrong, upload more labeled
                    examples covering the missed case and re-train — that's the whole loop.
                  </p>
                </div>
              </div>
            </details>
            <div
              className="flex flex-wrap items-center gap-1.5 text-[10px]"
              title="MNIDS hybrid stack: scikit-learn for the supervised classifier and one-class anomaly model, TensorFlow / Keras for the autoencoder reconstruction model."
            >
              <span className="text-[var(--text-muted)] uppercase tracking-wider font-semibold">Stack</span>
              <span className="inline-flex items-center rounded-full border border-violet-300 bg-violet-100 px-2 py-0.5 text-violet-900">
                scikit-learn · Random Forest
              </span>
              <span className="inline-flex items-center rounded-full border border-amber-300 bg-amber-100 px-2 py-0.5 text-amber-950">
                scikit-learn · Isolation Forest
              </span>
              <span className="inline-flex items-center rounded-full border border-cyan-300 bg-cyan-100 px-2 py-0.5 text-cyan-950">
                TensorFlow / Keras · Autoencoder
              </span>
            </div>

            <a
              href="/api/ml/training-csv-template"
              download="mnids_ml_training_template.csv"
              className="inline-flex items-center gap-2 rounded-lg px-3 py-2 border text-[11px] font-semibold uppercase tracking-wide border-cyan-400 text-cyan-900 hover:bg-cyan-100 transition-colors"
            >
              <Download className="w-3.5 h-3.5" aria-hidden />
              Download CSV template
            </a>

            <label className="inline-flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={demoTrainOnly}
                onChange={(e) => setDemoTrainOnly(e.target.checked)}
                disabled={streaming || validating}
                className="rounded border-[var(--border)] shrink-0"
              />
              <span className="text-[11px] text-[var(--text-muted)]">Demo train only</span>
            </label>

            <input
              ref={trainFileInputRef}
              type="file"
              multiple
              accept=".csv,.cap,.pcap,text/csv,application/vnd.tcpdump.pcap,application/octet-stream,capture/*"
              className="hidden"
              aria-label="Choose one or more PCAP / CSV files for validation and training"
              onChange={(e) => {
                const list = e.target.files ? Array.from(e.target.files) : [];
                e.target.value = '';
                void onTrainingFileChosen(list);
              }}
            />
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={validating || streaming}
                onClick={() => trainFileInputRef.current?.click()}
                className={cn(
                  'inline-flex items-center gap-2 rounded-lg px-3 py-2 border text-[11px] font-semibold uppercase tracking-wide transition-colors',
                  !validating && !streaming
                    ? 'border-violet-400 text-violet-900 hover:bg-violet-100'
                    : 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed',
                )}
              >
                {validating ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden /> : <Upload className="w-3.5 h-3.5" aria-hidden />}
                Choose file(s)
              </button>
              <button
                type="button"
                disabled={!canStartFromPicker}
                title={
                  !live
                    ? 'ML API offline'
                    : pendingBatch.length === 0 && !pendingFile
                      ? 'Pick one or more files first'
                      : pendingBatch.length > 0 && !batchAllOk
                        ? 'One or more queued files failed validation'
                        : validationResult?.ok === false
                          ? 'Fix validation errors first'
                          : 'Stream training logs'
                }
                onClick={() => {
                  const q = demoTrainOnly ? '?demo=true' : '';
                  // Multi-file batch path — concatenates server-side.
                  if (pendingBatch.length > 1) {
                    const fd = new FormData();
                    for (const e of pendingBatch) {
                      fd.append('files', e.file, e.file.name);
                    }
                    void runRetrainStream(`/api/ml/retrain-stream-multi${q}`, { body: fd });
                    return;
                  }
                  // Single-file path — preserves the original endpoint.
                  const onlyFile =
                    pendingBatch.length === 1 ? pendingBatch[0].file : pendingFile;
                  if (!onlyFile) return;
                  const fd = new FormData();
                  fd.append('file', onlyFile, onlyFile.name);
                  void runRetrainStream(`/api/ml/retrain-stream${q}`, { body: fd });
                }}
                className={cn(
                  'inline-flex items-center gap-2 rounded-lg px-3 py-2 border text-[11px] font-semibold uppercase tracking-wide transition-colors',
                  canStartFromPicker
                    ? 'border-emerald-500/40 bg-emerald-100 text-emerald-950 hover:bg-emerald-200/85'
                    : 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed',
                )}
              >
                {streaming ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden /> : <PlayCircle className="w-3.5 h-3.5" aria-hidden />}
                Start training
              </button>
            </div>

            {/*
              Single-file "Pending" line — only when exactly one file is
              queued AND the batch panel below would otherwise look redundant.
              Hidden in multi-file mode so users don't mistake the last-picked
              file for the only file being used.
            */}
            {pendingBatch.length === 0 && pendingFile ? (
              <p className="text-[10px] font-mono text-[var(--text-muted)]">
                Pending: <span className="text-[var(--text-soft)]">{pendingFile.name}</span>
              </p>
            ) : null}

            {pendingBatch.length > 0 ? (
              <div
                className={cn(
                  'rounded-xl border-2 p-3 space-y-2',
                  pendingBatch.length > 1
                    ? 'border-violet-400 bg-violet-50/60'
                    : 'border-[var(--border)] bg-[var(--surface-subtle)]/60',
                )}
                role="region"
                aria-label="Training batch file list"
              >
                {/* Big, unambiguous header: how many files are queued. */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Upload
                      className={cn(
                        'w-4 h-4',
                        pendingBatch.length > 1 ? 'text-violet-700' : 'text-[var(--text-muted)]',
                      )}
                      aria-hidden
                    />
                    <p
                      className={cn(
                        'text-sm font-bold tabular-nums',
                        pendingBatch.length > 1 ? 'text-violet-950' : 'text-[var(--text-primary)]',
                      )}
                    >
                      {pendingBatch.length} file{pendingBatch.length === 1 ? '' : 's'} selected
                      {pendingBatch.length > 1 ? ' for batch training' : ''}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 text-[10px]">
                    <span className="rounded-full bg-emerald-200/70 px-2 py-0.5 font-semibold text-emerald-950 tabular-nums">
                      {pendingBatch.filter((e) => e.status === 'ok').length} OK
                    </span>
                    {pendingBatch.some((e) => e.status === 'validating') ? (
                      <span className="rounded-full bg-violet-200/70 px-2 py-0.5 font-semibold text-violet-950 tabular-nums">
                        {pendingBatch.filter((e) => e.status === 'validating').length} validating
                      </span>
                    ) : null}
                    {pendingBatch.some((e) => e.status === 'error') ? (
                      <span className="rounded-full bg-rose-200/70 px-2 py-0.5 font-semibold text-rose-950 tabular-nums">
                        {pendingBatch.filter((e) => e.status === 'error').length} error
                      </span>
                    ) : null}
                  </div>
                </div>

                {/* Aggregate summary card — visible once all files have validated. */}
                {pendingBatch.length > 1 && batchAllOk && validationResult?.ok ? (
                  <div className="rounded-lg border border-emerald-400 bg-emerald-50 px-3 py-2 text-[11px] text-emerald-950 space-y-1">
                    <p className="font-semibold">
                      Ready to train on {pendingBatch.length} merged files
                      {validationResult.rows != null
                        ? ` · ${validationResult.rows.toLocaleString()} rows total`
                        : ''}
                    </p>
                    {validationResult.label_distribution ? (
                      <LabelDistBar dist={validationResult.label_distribution} />
                    ) : null}
                    <p className="text-emerald-800/90 text-[10px]">
                      Server will concatenate all CSVs (PCAPs converted first) and run training
                      once on the combined dataset.
                    </p>
                  </div>
                ) : null}

                <ul className="space-y-1">
                  {pendingBatch.map((entry, idx) => {
                    const rows =
                      entry.result && 'rows' in entry.result ? entry.result.rows ?? null : null;
                    const errMsg =
                      entry.result && 'error' in entry.result ? entry.result.error : undefined;
                    return (
                      <li
                        key={entry.id}
                        className={cn(
                          'flex flex-wrap items-center gap-2 rounded-md border px-2 py-1.5 text-[11px]',
                          entry.status === 'ok'
                            ? 'border-emerald-300 bg-emerald-50 text-emerald-950'
                            : entry.status === 'error'
                              ? 'border-rose-300 bg-rose-50 text-rose-950'
                              : 'border-violet-300 bg-violet-50 text-violet-950',
                        )}
                      >
                        <span className="font-mono tabular-nums text-[var(--text-disabled)] shrink-0 w-5 text-right">
                          {idx + 1}.
                        </span>
                        <span className="font-mono break-all flex-1 min-w-0">{entry.file.name}</span>
                        <span className="tabular-nums text-[var(--text-disabled)] shrink-0 text-[10px]">
                          {(entry.file.size / 1024).toFixed(1)} KB
                        </span>
                        {rows != null ? (
                          <span className="tabular-nums shrink-0 text-[10px]">{rows.toLocaleString()} rows</span>
                        ) : null}
                        <span
                          className={cn(
                            'rounded-full px-2 py-0.5 font-semibold shrink-0 text-[10px]',
                            entry.status === 'ok'
                              ? 'bg-emerald-200/70 text-emerald-950'
                              : entry.status === 'error'
                                ? 'bg-rose-200/70 text-rose-950'
                                : 'bg-violet-200/70 text-violet-950',
                          )}
                        >
                          {entry.status === 'validating'
                            ? 'Validating…'
                            : entry.status === 'ok'
                              ? 'OK'
                              : 'Error'}
                        </span>
                        <button
                          type="button"
                          onClick={() => removeFromBatch(entry.id)}
                          disabled={streaming}
                          className="shrink-0 inline-flex items-center justify-center rounded-md border border-[var(--border)] p-1 text-[var(--text-muted)] hover:bg-[var(--surface-hover)] disabled:opacity-40 disabled:cursor-not-allowed"
                          aria-label={`Remove ${entry.file.name} from training batch`}
                          title="Remove from batch"
                        >
                          <Trash2 className="w-3 h-3" aria-hidden />
                        </button>
                        {errMsg ? (
                          <p className="basis-full font-mono text-[10px] text-rose-800 pl-7">{errMsg}</p>
                        ) : null}
                      </li>
                    );
                  })}
                </ul>
              </div>
            ) : null}

            {/*
              Single-file validation block — suppressed in multi-file mode
              because the batch panel above already renders per-file status
              and an aggregate summary. Showing both would imply the single
              file is "the" file being trained on.
            */}
            {validationResult && pendingBatch.length <= 1 ? (
              <div
                className={cn(
                  'rounded-lg border px-3 py-2 text-[11px] space-y-1',
                  validationResult.ok
                    ? 'border-emerald-500/30 bg-emerald-50 text-emerald-950'
                    : 'border-rose-500/35 bg-rose-50 text-rose-950',
                )}
                role="status"
              >
                {validationResult.ok ? (
                  <>
                    <p className="font-semibold text-emerald-900">Validation passed</p>
                    {validationResult.rows != null ? (
                      <p className="text-emerald-800 tabular-nums">{validationResult.rows} rows</p>
                    ) : null}
                    {validationResult.label_distribution ? <LabelDistBar dist={validationResult.label_distribution} /> : null}
                    {validationResult.format ? (
                      <p className="text-emerald-800">Format: {validationResult.format}</p>
                    ) : null}
                    {validationResult.notes ? (
                      <p className="text-emerald-800/90">{validationResult.notes}</p>
                    ) : null}
                    {validationResult.warnings && validationResult.warnings.length > 0 ? (
                      <ul className="list-disc pl-4 text-amber-900">
                        {validationResult.warnings.map((w, wi) => (
                          <li key={`${w}-${wi}`}>{w}</li>
                        ))}
                      </ul>
                    ) : null}
                  </>
                ) : (
                  <>
                    <p className="font-semibold">Validation failed</p>
                    {validationResult.error ? <p>{validationResult.error}</p> : null}
                    {validationResult.pcap_magic_hint ? (
                      <p className="text-[10px] text-rose-800">{validationResult.pcap_magic_hint}</p>
                    ) : null}
                    {validationResult.missing_cols && validationResult.missing_cols.length > 0 ? (
                      <p className="font-mono text-[10px]">Missing: {validationResult.missing_cols.join(', ')}</p>
                    ) : null}
                  </>
                )}
              </div>
            ) : null}

            {csvPeek && validationResult?.ok && pendingBatch.length <= 1 ? (
              <div className="rounded-lg border border-[var(--border)] overflow-x-auto">
                <p className="text-[10px] text-[var(--text-muted)] px-2 py-1.5 bg-[var(--surface-subtle)]">First rows (preview)</p>
                <table className="w-full text-[10px] text-left border-collapse min-w-[28rem]">
                  <thead className="bg-[var(--table-header-bg)] text-[var(--text-muted)]">
                    <tr>
                      {csvPeek.headers.map((h) => (
                        <th key={h} className="py-1.5 px-1.5 font-medium whitespace-nowrap">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="text-[var(--text-soft)] font-mono">
                    {csvPeek.rows.map((row, ri) => (
                      <tr key={ri} className="border-t border-[var(--border)]/80">
                        {row.map((c, ci) => (
                          <td key={ci} className="py-1 px-1.5 whitespace-nowrap max-w-[8rem] truncate" title={c}>
                            {c}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}

            {(streaming || streamLog.length > 0 || trainStatus !== 'idle') && (
              <details
                className="rounded-xl border border-emerald-200 bg-emerald-50/60 overflow-hidden group"
                open={streaming || trainStatus === 'starting' || trainStatus === 'streaming'}
              >
                <summary className="cursor-pointer list-none px-3 py-2 border-b border-emerald-200 bg-emerald-50/90 text-[10px] flex flex-wrap items-center gap-2 hover:bg-emerald-100/80">
                  <span className="text-[var(--text-muted)] text-[10px] uppercase tracking-wider">Training log</span>
                  <span className="ml-auto text-emerald-700 group-open:hidden">Show</span>
                  <span className="ml-auto text-emerald-700 hidden group-open:inline">Hide</span>
                </summary>
                <div className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-emerald-200 bg-emerald-50/90 text-[10px]">
                  <span
                    className={cn(
                      'inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-semibold uppercase tracking-wide',
                      trainStatusClasses(trainStatus),
                    )}
                  >
                    {(trainStatus === 'starting' || trainStatus === 'streaming') && (
                      <Loader2 className="w-3 h-3 animate-spin" aria-hidden />
                    )}
                    {TRAIN_STATUS_LABEL[trainStatus]}
                  </span>
                  <span className="text-[var(--text-secondary)]">
                    Elapsed{' '}
                    <span className="font-mono tabular-nums text-[var(--text-primary)]">
                      {formatDurationMs(trainElapsedMs)}
                    </span>
                  </span>
                  <span className="text-[var(--text-secondary)]">
                    Lines{' '}
                    <span className="font-mono tabular-nums text-[var(--text-primary)]">{streamLog.length}</span>
                  </span>
                  {currentPhase && trainStatus === 'streaming' ? (
                    <span
                      className="text-cyan-800 truncate max-w-[24rem]"
                      title={currentPhase}
                    >
                      <span className="text-[var(--text-muted)] mr-1">Phase:</span>
                      {currentPhase}
                    </span>
                  ) : null}
                </div>

                <div
                  className="px-3 py-2 max-h-52 sm:max-h-64 lg:max-h-[min(52vh,36rem)] overflow-y-auto min-h-0 font-mono text-[11px] leading-relaxed"
                  role="log"
                  aria-live="polite"
                  aria-label="Training log output"
                >
                  {streamLog.length === 0 ? (
                    <div className="text-emerald-700/80 italic">
                      Waiting for first log line from the ML server …
                    </div>
                  ) : (
                    streamLog.map((line) => {
                      const tone =
                        line.kind === 'phase'
                          ? 'text-cyan-800'
                          : line.kind === 'done'
                            ? 'text-emerald-800 font-semibold'
                            : line.kind === 'warn'
                              ? 'text-amber-800'
                              : line.kind === 'error'
                                ? 'text-rose-700'
                                : line.kind === 'lifecycle'
                                  ? 'text-violet-800'
                                  : 'text-emerald-900';
                      return (
                        <div
                          key={line.seq}
                          className={cn('whitespace-pre-wrap break-all', tone)}
                        >
                          <span
                            className="text-emerald-700 tabular-nums mr-2"
                            title={`Line ${line.seq}`}
                          >
                            {line.ts}
                          </span>
                          <span>{line.msg}</span>
                        </div>
                      );
                    })
                  )}
                  <div ref={logEndRef} />
                </div>

                {lastSummary && (trainStatus === 'complete' || trainStatus === 'failed') ? (
                  <div className="px-3 py-2 border-t border-emerald-200 bg-emerald-50/90 text-[10px] flex flex-wrap gap-x-3 gap-y-1 items-center">
                    <span className="text-emerald-900 font-semibold uppercase tracking-wide">
                      Summary
                    </span>
                    <span className="text-[var(--text-secondary)]">
                      Duration{' '}
                      <span className="font-mono tabular-nums text-[var(--text-primary)]">
                        {formatDurationMs(lastSummary.durationMs ?? 0)}
                      </span>
                    </span>
                    <span className="text-[var(--text-secondary)]">
                      Version{' '}
                      <span className="font-mono text-[var(--text-primary)]">
                        {lastSummary.modelVersion ?? '—'}
                      </span>
                    </span>
                    <span className="text-[var(--text-muted)]">
                      Source{' '}
                      <span className="font-mono text-[var(--text-soft)]">{lastSummary.source ?? '—'}</span>
                    </span>
                    {lastSummary.accuracy != null ? (
                      <span className="text-[var(--text-muted)]">
                        Accuracy{' '}
                        <span className="font-mono tabular-nums text-emerald-800">
                          {(lastSummary.accuracy * 100).toFixed(1)}%
                        </span>
                      </span>
                    ) : null}
                    {lastSummary.f1Macro != null ? (
                      <span className="text-[var(--text-muted)]">
                        F1-macro{' '}
                        <span className="font-mono tabular-nums text-emerald-800">
                          {(lastSummary.f1Macro * 100).toFixed(1)}%
                        </span>
                      </span>
                    ) : null}
                    {lastSummary.fprMacro != null ? (
                      <span className="text-[var(--text-muted)]">
                        FPR-macro{' '}
                        <span className="font-mono tabular-nums text-amber-900">
                          {(lastSummary.fprMacro * 100).toFixed(2)}%
                        </span>
                      </span>
                    ) : null}
                    {lastSummary.aeTrainMs != null ? (
                      <span className="text-[var(--text-muted)]">
                        AE train{' '}
                        <span className="font-mono tabular-nums text-cyan-900">
                          {formatDurationMs(lastSummary.aeTrainMs)}
                        </span>
                      </span>
                    ) : null}
                    {lastSummary.notes ? (
                      <span className="text-amber-950/90 basis-full">
                        Note: {lastSummary.notes}
                      </span>
                    ) : null}
                  </div>
                ) : null}
              </details>
            )}
          </div>

          <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)]/80 p-4 space-y-3">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Uploaded datasets</h3>
            <ul className="space-y-2">
              <li
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-violet-200 bg-violet-50 px-3 py-2"
                title="Locked 3-class lab baseline. Cannot be deleted from this UI; always available as a one-click safe-restore."
              >
                <div className="flex items-start gap-2 min-w-0">
                  <Lock className="w-3.5 h-3.5 text-violet-800 shrink-0 mt-0.5" aria-hidden />
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <p className="text-xs text-[var(--text-soft)] font-medium">Baseline (locked)</p>
                      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-400 bg-emerald-100 px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-emerald-900">
                        <ShieldCheck className="w-2.5 h-2.5" aria-hidden />
                        Safe restore
                      </span>
                    </div>
                    <p className="text-[10px] font-mono text-[var(--text-muted)] truncate mt-0.5">
                      samples/ml_lab_upload_realistic.csv
                    </p>
                    <p className="text-[10px] text-[var(--text-disabled)] mt-0.5">
                      3-class labeled · safe restore
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  disabled={!live || streaming}
                  onClick={() => void runRetrainStream('/api/ml/retrain-stream?baseline=true')}
                  className={cn(
                    'shrink-0 text-[10px] font-semibold uppercase tracking-wide rounded-md px-2 py-1 border transition-colors',
                    live && !streaming
                      ? 'border-emerald-500/40 text-emerald-900 hover:bg-emerald-100'
                      : 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed',
                  )}
                >
                  Train
                </button>
              </li>
              {uploadedDatasets.map((f) => (
                <li
                  key={f.name}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--border)] px-3 py-2"
                >
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-mono text-[var(--text-primary)] truncate" title={f.name}>
                      {f.name}
                    </p>
                    <p className="text-[10px] text-[var(--text-disabled)] tabular-nums">
                      {f.size_kb} KB · {f.mtime_iso.slice(0, 19).replace('T', ' ')}
                    </p>
                    {f.kind === 'csv' && f.rows != null ? (
                      <p className="text-[10px] text-[var(--text-muted)] tabular-nums mt-0.5">{f.rows} rows</p>
                    ) : null}
                    {f.kind === 'csv' && f.label_distribution ? <LabelDistBar dist={f.label_distribution} /> : null}
                    {f.kind === 'pcap' ? (
                      <p className="text-[10px] text-cyan-900 mt-1">
                        PCAP · format: {f.format ?? '—'}
                        {f.format_note ? ` — ${f.format_note}` : ''}
                      </p>
                    ) : null}
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      type="button"
                      disabled={!live || streaming}
                      onClick={() =>
                        void runRetrainStream(
                          `/api/ml/retrain-stream?dataset=${encodeURIComponent(f.name)}${demoTrainOnly ? '&demo=true' : ''}`,
                        )
                      }
                      className={cn(
                        'text-[10px] font-semibold uppercase tracking-wide rounded-md px-2 py-1 border transition-colors',
                        live && !streaming
                          ? 'border-emerald-500/40 text-emerald-900 hover:bg-emerald-100'
                          : 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed',
                      )}
                    >
                      Train
                    </button>
                    <button
                      type="button"
                      disabled={streaming}
                      title="Remove from uploads"
                      onClick={() => void deleteUploadedDataset(f.name)}
                      className={cn(
                        'p-1.5 rounded-md border transition-colors',
                        !streaming
                          ? 'border-rose-400 text-rose-800 hover:bg-rose-100'
                          : 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed',
                      )}
                    >
                      <Trash2 className="w-3.5 h-3.5" aria-hidden />
                      <span className="sr-only">Delete {f.name}</span>
                    </button>
                  </div>
                </li>
              ))}
            </ul>
            {uploadedDatasets.length === 0 ? (
              <p className="text-[10px] text-[var(--text-disabled)]">No files in uploads yet — training saves copies under dataset/uploads.</p>
            ) : null}
          </div>

          <div className="grid grid-cols-1 gap-2">
            {retrainMsg ? (
              <p className="text-xs text-[var(--text-secondary)] rounded-lg border border-[var(--border)] bg-[var(--surface-subtle)]/70 px-3 py-2">{retrainMsg}</p>
            ) : null}
            {(mlLabPcapBusy || streaming || validating || mlLabProgressNote) ? (
              <p className="text-xs text-cyan-950 rounded-lg border border-cyan-300 bg-cyan-50 px-3 py-2">
                {mlLabPcapBusy
                  ? 'Load in progress: parse PCAP → extract flows → send results to Dashboard.'
                  : mlLabProgressNote ?? 'Working...'}
              </p>
            ) : null}
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-subtle)]/70 p-4">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-3">
              Model snapshot (meta.json)
            </h3>
            {metaLoading ? (
              <p className="text-sm text-[var(--text-disabled)]">Loading…</p>
            ) : !hasTrainedModels ? (
              <p className="text-sm text-amber-950">{meta && 'error' in meta ? meta.error : 'Train models to see metrics.'}</p>
            ) : (
              <>
                <div className="text-[11px] space-y-2 mb-4 text-[var(--text-soft)]">
                  <div className="flex justify-between gap-2 border-b border-[var(--border)]/80 pb-2">
                    <span className="text-[var(--text-muted)] shrink-0">Model version</span>
                    <span className="font-mono text-right break-all">{mv}</span>
                  </div>
                  <div className="flex justify-between gap-2 border-b border-[var(--border)]/80 pb-2">
                    <span className="text-[var(--text-muted)] shrink-0">Dataset rows</span>
                    <span className="font-mono text-right tabular-nums">
                      train {meta.train_rows ?? '—'} · test {meta.test_rows ?? '—'} · total {meta.total_rows ?? '—'}
                    </span>
                  </div>
                  <div>
                    <p className="text-[var(--text-muted)] mb-1">RF class labels</p>
                    <div className="flex flex-wrap gap-1">
                      {(meta.labels ?? []).length > 0 ? (
                        meta.labels!.map((lab) => (
                          <span
                            key={lab}
                            className="inline-flex rounded-full border border-violet-300 bg-violet-100 px-2 py-0.5 text-[10px] text-violet-900"
                          >
                            {lab}
                          </span>
                        ))
                      ) : (
                        <span className="text-[var(--text-disabled)]">—</span>
                      )}
                    </div>
                  </div>
                  {meta.saved_artifact_count != null ? (
                    <div className="flex justify-between gap-2 text-[10px] text-[var(--text-disabled)] pt-2">
                      <span>Artifacts in cnn_model/</span>
                      <span title={meta.saved_artifact_files?.join('\n')}>{meta.saved_artifact_count} file(s)</span>
                    </div>
                  ) : null}
                </div>

                {holdoutPc && Object.keys(holdoutPc).length > 0 ? (
                  <div className="mb-4">
                    <h4 className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] mb-2">Per-class holdout</h4>
                    <div className="overflow-x-auto rounded-lg border border-[var(--border)]">
                      <table className="w-full text-[10px] text-left border-collapse tabular-nums">
                        <thead className="bg-[var(--table-header-bg)] text-[var(--text-muted)]">
                          <tr>
                            <th className="py-2 px-2 font-medium">Class</th>
                            <th className="py-2 px-2 font-medium" title="Support: number of holdout rows for this class">
                              n
                            </th>
                            <th className="py-2 px-2 font-medium">P</th>
                            <th className="py-2 px-2 font-medium">R</th>
                            <th className="py-2 px-2 font-medium">F1</th>
                            <th
                              className="py-2 px-2 font-medium"
                              title="One-vs-rest false positive rate for this class on the holdout split"
                            >
                              FPR (ovr)
                            </th>
                          </tr>
                        </thead>
                        <tbody className="text-[var(--text-soft)]">
                          {Object.entries(holdoutPc).map(([cls, m]) => (
                            <tr key={cls} className="border-t border-[var(--border)]/90">
                              <td className="py-1.5 px-2">
                                <span
                                  className={cn(
                                    'inline-flex rounded-full border px-2 py-0.5 text-[9px]',
                                    cls === 'Benign' && 'border-emerald-400 bg-emerald-50 text-emerald-950',
                                    cls === 'Suspicious' && 'border-amber-400 bg-amber-50 text-amber-950',
                                    cls === 'Malicious' && 'border-rose-400 bg-rose-50 text-rose-950',
                                    !['Benign', 'Suspicious', 'Malicious'].includes(cls) &&
                                      'border-[var(--border-strong)] text-[var(--text-soft)]',
                                  )}
                                >
                                  {cls}
                                </span>
                              </td>
                              <td className="py-1.5 px-2 font-mono">{m.support ?? '—'}</td>
                              <td className="py-1.5 px-2 font-mono">
                                {m.precision != null ? `${(m.precision * 100).toFixed(1)}%` : '—'}
                              </td>
                              <td className="py-1.5 px-2 font-mono">
                                {m.recall != null ? `${(m.recall * 100).toFixed(1)}%` : '—'}
                              </td>
                              <td className="py-1.5 px-2 font-mono">{m.f1 != null ? `${(m.f1 * 100).toFixed(1)}%` : '—'}</td>
                              <td className="py-1.5 px-2 font-mono">
                                {m.fpr_one_vs_rest != null ? `${(m.fpr_one_vs_rest * 100).toFixed(2)}%` : '—'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : null}

                {meta.metrics ? (
                  <div className="overflow-x-auto rounded-lg border border-[var(--border)] mb-4">
                    <table className="w-full text-[11px] text-left border-collapse tabular-nums">
                      <thead className="bg-[var(--table-header-bg)] text-[var(--text-muted)]">
                        <tr>
                          <th className="py-2 px-2 font-medium">Metric</th>
                          <th className="py-2 px-2 font-medium">Holdout</th>
                        </tr>
                      </thead>
                      <tbody className="text-[var(--text-soft)]">
                        {meta.metrics.accuracy_holdout != null ? (
                          <tr className="border-t border-[var(--border)]/90">
                            <td className="py-2 px-2 text-[var(--text-secondary)]">Accuracy</td>
                            <td className="py-2 px-2 font-mono">{(meta.metrics.accuracy_holdout * 100).toFixed(1)}%</td>
                          </tr>
                        ) : null}
                        {meta.metrics.f1_macro_holdout != null ? (
                          <tr className="border-t border-[var(--border)]/90">
                            <td
                              className="py-2 px-2 text-[var(--text-secondary)]"
                              title="Unweighted mean of per-class F1 — each class counts equally regardless of prevalence"
                            >
                              F1 macro
                            </td>
                            <td className="py-2 px-2 font-mono">{(meta.metrics.f1_macro_holdout * 100).toFixed(1)}%</td>
                          </tr>
                        ) : null}
                        {meta.metrics.f1_weighted_holdout != null ? (
                          <tr className="border-t border-[var(--border)]/90">
                            <td
                              className="py-2 px-2 text-[var(--text-secondary)]"
                              title="F1 averaged across classes weighted by support — reflects dominant classes more"
                            >
                              F1 weighted
                            </td>
                            <td className="py-2 px-2 font-mono">{(meta.metrics.f1_weighted_holdout * 100).toFixed(1)}%</td>
                          </tr>
                        ) : null}
                        {meta.metrics.fpr_macro_avg_holdout != null ? (
                          <tr className="border-t border-[var(--border)]/90">
                            <td
                              className="py-2 px-2 text-[var(--text-secondary)]"
                              title="Mean one-vs-rest FPR across classes — aggregate false-positive pressure"
                            >
                              FPR macro avg
                            </td>
                            <td className="py-2 px-2 font-mono">{(meta.metrics.fpr_macro_avg_holdout * 100).toFixed(2)}%</td>
                          </tr>
                        ) : null}
                        {cv && !cv.skipped && cv.n_splits ? (
                          <tr className="border-t border-[var(--border)]/90">
                            <td
                              className="py-2 px-2 text-[var(--text-secondary)]"
                              title="Stratified k-fold RF accuracy before final holdout fit — mean ± std across folds"
                            >
                              RF CV folds / mean acc
                            </td>
                            <td className="py-2 px-2 font-mono">
                              {cv.n_splits}-fold · {cv.accuracy_mean != null ? `${(cv.accuracy_mean * 100).toFixed(1)}%` : '—'}
                              {cv.accuracy_std != null ? ` (±${(cv.accuracy_std * 100).toFixed(1)}%)` : ''}
                            </td>
                          </tr>
                        ) : null}
                        {cv && cv.f1_macro_mean != null ? (
                          <tr className="border-t border-[var(--border)]/90">
                            <td className="py-2 px-2 text-[var(--text-secondary)]" title="Macro F1 mean across CV folds">
                              RF CV F1 macro (mean)
                            </td>
                            <td className="py-2 px-2 font-mono">{(cv.f1_macro_mean * 100).toFixed(1)}%</td>
                          </tr>
                        ) : null}
                        {cv?.skipped && cv.reason ? (
                          <tr className="border-t border-[var(--border)]/90">
                            <td className="py-2 px-2 text-[var(--text-secondary)]">CV skipped</td>
                            <td className="py-2 px-2">{cv.reason}</td>
                          </tr>
                        ) : null}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-[11px] text-[var(--text-muted)] mb-4">No holdout metrics in meta — run training.</p>
                )}

                {(timing || meta.isolation_forest || meta.autoencoder) && (
                  <div className="text-[10px] text-[var(--text-disabled)] space-y-2 border-t border-[var(--border)] pt-3 mb-3">
                    {timing?.rf_train != null ? (
                      <p>
                        <span className="text-[var(--text-muted)]">RF train</span>{' '}
                        <span className="font-mono text-[var(--text-secondary)]">{timing.rf_train.toFixed(0)} ms</span>
                      </p>
                    ) : null}
                    {aeTrainMs != null ? (
                      <p>
                        <span className="text-[var(--text-muted)]">AE train (wall)</span>{' '}
                        <span className="font-mono text-[var(--text-secondary)]">
                          {(aeTrainMs >= 1000 ? `${(aeTrainMs / 1000).toFixed(1)} s` : `${aeTrainMs.toFixed(0)} ms`)}
                        </span>
                      </p>
                    ) : null}
                    {timing?.ae_predict_per_row_mean != null || meta.autoencoder?.predict_ms_per_row_mean_full_fit != null ? (
                      <p>
                        <span className="text-[var(--text-muted)]">AE encode (mean / row)</span>{' '}
                        <span className="font-mono text-[var(--text-secondary)]">
                          ~
                          {(timing?.ae_predict_per_row_mean ?? meta.autoencoder!.predict_ms_per_row_mean_full_fit)!.toFixed(3)}{' '}
                          ms
                        </span>
                      </p>
                    ) : null}
                    {meta.isolation_forest?.decision_min != null && meta.isolation_forest?.decision_max != null ? (
                      <p title={meta.isolation_forest.anomaly_score_formula}>
                        <span className="text-[var(--text-muted)]">IF decision range</span>{' '}
                        <span className="font-mono text-[var(--text-secondary)]">
                          [{meta.isolation_forest.decision_min.toFixed(3)}, {meta.isolation_forest.decision_max.toFixed(3)}]
                        </span>
                      </p>
                    ) : null}
                    {meta.autoencoder?.trained_on ? (
                      <p>
                        <span className="text-[var(--text-muted)]">AE trained on</span> {meta.autoencoder.trained_on}
                      </p>
                    ) : null}
                    {meta.autoencoder?.mse_percentile_10 != null && meta.autoencoder?.mse_percentile_90 != null ? (
                      <p title={meta.autoencoder.anomaly_score_formula}>
                        <span className="text-[var(--text-muted)]">AE MSE percentiles</span>{' '}
                        <span className="font-mono text-[var(--text-secondary)]">
                          p10 {meta.autoencoder.mse_percentile_10.toFixed(4)}, p90 {meta.autoencoder.mse_percentile_90.toFixed(4)}
                        </span>
                      </p>
                    ) : null}
                  </div>
                )}

                {meta.classification_report_holdout ? (
                  <details className="rounded-lg border border-[var(--border)] bg-[var(--surface-subtle)]/50 mb-3">
                    <summary className="cursor-pointer px-3 py-2 text-[11px] font-medium text-[var(--text-secondary)] select-none">
                      Sklearn classification report (holdout)
                    </summary>
                    <pre className="text-[10px] text-[var(--text-muted)] whitespace-pre-wrap font-mono p-3 border-t border-[var(--border)] max-h-64 lg:max-h-[min(48vh,28rem)] overflow-auto">
                      {meta.classification_report_holdout}
                    </pre>
                  </details>
                ) : null}

                {timing?.note ? <p className="text-[10px] text-[var(--text-disabled)] border-t border-[var(--border)] pt-3">{timing.note}</p> : null}
                {meta.evaluation?.standards_note ? (
                  <p className="text-[10px] text-[var(--text-disabled)] border-t border-[var(--border)] pt-3 mt-2">{meta.evaluation.standards_note}</p>
                ) : null}
              </>
            )}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)]/80 p-4 mt-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Live inference</h3>
          <p className="text-[10px] text-[var(--text-disabled)]">POST /api/ml/predict · 14 features in trained column order</p>
        </div>

        {!live ? (
          <p className="text-xs text-amber-950">Inference API offline. Start the ML server on port 8787 to run predictions.</p>
        ) : null}

        <div className="flex flex-wrap gap-2">
          {([0, 1, 2] as const).map((id) => (
            <button
              key={id}
              type="button"
              disabled={!live}
              onClick={() => setInferenceSample(id)}
              className={cn(
                'text-[10px] font-semibold uppercase tracking-wide rounded-md px-2.5 py-1.5 border transition-colors',
                inferenceSample === id
                  ? 'border-cyan-500/45 bg-cyan-100 text-cyan-950'
                  : 'border-[var(--border-strong)] text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]',
                !live && 'opacity-50 cursor-not-allowed',
              )}
            >
              {DEFAULT_LABELS[id]} sample
            </button>
          ))}
        </div>
        <p className="text-[10px] text-[var(--text-disabled)]">
          Vectors come from your validated CSV when possible; otherwise bundled template rows. Edit fields, then run.
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-2">
          {featureNames.map((fn, i) => (
            <label key={fn} className="flex flex-col gap-0.5 min-w-0">
              <span className="text-[9px] text-[var(--text-muted)] font-mono truncate" title={fn}>
                {fn}
              </span>
              <input
                type="number"
                step="any"
                className="rounded border border-[var(--border)] bg-[var(--surface-subtle)] px-1.5 py-1 text-[11px] font-mono text-[var(--text-primary)] w-full tabular-nums"
                value={Number.isFinite(inferFeatures[i]) ? inferFeatures[i] : ''}
                onChange={(e) => {
                  const v = parseFloat(e.target.value);
                  setInferFeatures((prev) => {
                    const next = [...prev];
                    next[i] = Number.isFinite(v) ? v : 0;
                    return next;
                  });
                  setInferResult(null);
                }}
              />
            </label>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={!live || inferBusy}
            onClick={() => void runInference()}
            className={cn(
              'inline-flex items-center gap-2 rounded-lg px-3 py-2 border text-[11px] font-semibold uppercase tracking-wide',
              live && !inferBusy
                ? 'border-cyan-500/40 text-cyan-900 hover:bg-cyan-100'
                : 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed',
            )}
          >
            {inferBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden /> : <Activity className="w-3.5 h-3.5" aria-hidden />}
            Run inference
          </button>
          {inferResult ? (
            <div className="flex flex-wrap items-center gap-2 text-[11px]">
              <span className="text-[var(--text-muted)]">RF</span>
              <span className="rounded-md border border-violet-300 bg-violet-100 px-2 py-0.5 font-medium text-violet-900">
                {inferResult.label}
              </span>
              <span className="tabular-nums text-[var(--text-soft)]">{(inferResult.confidence * 100).toFixed(1)}% conf</span>
              <span className="text-[var(--text-muted)]">IF</span>
              <span className="font-mono tabular-nums text-[var(--accent)]">{(inferResult.anomalyScore * 100).toFixed(0)}%</span>
              {inferResult.aeAnomalyScore != null ? (
                <>
                  <span className="text-[var(--text-muted)]">AE</span>
                  <span className="font-mono tabular-nums text-amber-900">{(inferResult.aeAnomalyScore * 100).toFixed(0)}%</span>
                </>
              ) : null}
              <span className="text-[var(--text-disabled)]">expected {inferExpectedLabel}</span>
              <span
                className={cn(
                  'rounded-full px-2 py-0.5 text-[10px] font-semibold',
                  inferMatch ? 'bg-emerald-100 text-emerald-950 border border-emerald-400' : 'bg-rose-100 text-rose-950 border border-rose-400',
                )}
              >
                {inferMatch ? 'Match' : 'Mismatch'}
              </span>
            </div>
          ) : null}
          {inferError ? <p className="text-xs text-rose-800 w-full">{inferError}</p> : null}
        </div>
      </div>

      <div className="mt-6 pt-4 border-t border-[var(--border)] flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => {
            void (async () => {
              setMlLabProgressNote('Load step 1/3: reading selected PCAP...');
              try {
                await onLoadMlLabPcap();
                setMlLabProgressNote('Load step 3/3: analysis finished. Results sent to Dashboard.');
              } catch {
                setMlLabProgressNote('Load failed. Check PCAP format and server status.');
              } finally {
                window.setTimeout(() => setMlLabProgressNote(null), 1500);
              }
            })();
          }}
          disabled={mlLabPcapBusy}
          className={cn(
            'inline-flex items-center gap-2 rounded-lg px-3 py-2 border text-[11px] font-medium transition-colors',
            !mlLabPcapBusy
              ? 'border-[var(--border-strong)] text-[var(--text-soft)] hover:bg-[var(--surface-hover)]'
              : 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed',
          )}
        >
          {mlLabPcapBusy ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : <PlayCircle className="w-4 h-4" aria-hidden />}
          Load lab PCAP → Dashboard
        </button>
        <button
          type="button"
          onClick={onOpenDashboard}
          className="inline-flex items-center gap-2 rounded-lg px-3 py-2 border border-[var(--border-strong)] text-[11px] font-medium text-[var(--text-soft)] hover:bg-[var(--surface-hover)] transition-colors"
        >
          <LayoutDashboard className="w-4 h-4 text-[var(--accent)]" aria-hidden />
          Open Dashboard
        </button>
      </div>

      {hasTrainedModels && meta.training_dataset_csv ? (
        <p className="text-[10px] text-[var(--text-disabled)] mt-4 font-mono break-all" title="Last training CSV path from meta.json">
          Training data: {meta.training_dataset_csv}
        </p>
      ) : null}
    </div>
  );
}
