import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  Activity,
  AlertTriangle,
  Database,
  Terminal,
  BarChart3,
  Search,
  Wifi,
  Sparkles,
  Shield,
  ScanSearch,
  Loader2,
  ChevronLeft,
  ChevronRight,
  FileCode2,
  X,
  CheckCircle2,
  RotateCcw,
  BrainCircuit,
  History,
  MessageCircle,
} from 'lucide-react';
import ChatPanel from './ChatPanel';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from './lib/utils';
import { PROJECT_DISPLAY_NAME } from './lib/appMeta';
import {
  applyPatchToTrafficLog,
  parseMnidsRowPatch,
  type ApplyTrafficRowPatchOpts,
  type ParsedMnidsPatch,
  type TrafficRowAiPatch,
} from './lib/assistantPatch';
import {
  type TrafficPlane,
  type TrafficTableSortKey,
  TrafficLog,
  SystemStats,
  TrafficStatus,
  trafficStatusLabel as trafficStatusEnumLabel,
} from './types';
import {
  loadMnidsPersisted,
  saveMnidsPersisted,
  fetchServerBootId,
  clearMnidsPersisted,
  MNIDS_TAB_SESSION_KEY,
  type MnidsPersistedV1,
} from './lib/mnidsPersistence';
import {
  clearVtReputationCache,
  loadVtReputationCache,
  saveVtReputationCache,
} from './lib/vtReputationCache';
import { exportLogsToExcel } from './lib/export';
import { AssistantPanel } from './components/AssistantPanel';
import { AssistantChatProvider } from './context/AssistantChatContext';
import { AiAssistLauncher } from './components/AiAssistLauncher';
import { FlowAnalysisFeed } from './components/FlowAnalysisFeed';
import { PcapLibraryPanel } from './components/PcapLibraryPanel';
import { MlLabPage } from './components/MlLabPage';
import { AnalyticsView } from './components/AnalyticsView';
import { TrafficDataTable } from './components/TrafficDataTable';
import { TrafficColumnSettingsPanel } from './components/TrafficColumnSettingsPanel';
import { migrateLegacyAnalystCleanLocks } from './lib/iocReanalyze';
import { applyBulkTriageToLogs } from './lib/demoBulkTriageResolve';
import type { PcapIngestProgress } from './lib/pcapIngestTypes';
import { fetchPcapBytes, parsePcapBuffer } from './lib/pcapIngest';
import {
  deepseekBulkSuspiciousTriageNarrative,
  deepseekExcelExportNarrative,
  isDeepSeekConfigured,
  type ExcelAiNarrative,
} from './lib/deepseek';
import { bulkTriageSummaryPlaceholder, triageSuspiciousWithMlAndVt } from './lib/mlFlowTriage';
import { trafficStatusLabel } from './lib/trafficStatusUi';
import { ensureTelecomFields, trafficPlaneLabel } from './lib/telecom5gFields';
import {
  ensureVtDomainsForLog,
  ensureVtForTrafficRow,
  fetchVtHealth,
  fetchVtStatus,
  type VtDomainClientResult,
  type VtIpClientResult,
} from './lib/virusTotal';
import {
  getVisibleColumnOrder,
  loadTrafficColumnPrefs,
  saveTrafficColumnPrefs,
  type TrafficColumnPrefs,
} from './lib/trafficTableColumnPrefs';
import { formatFlowDetectionLogLine, formatMlLogLine } from './lib/flowAnalysisFormat';
import { trafficLogToMlFeatures } from './lib/mlFeatures';
import { applyMlToTrafficLogRow, enrichTrafficLogsWithMl } from './lib/mlClient';

const TRAFFIC_PAGE_SIZE = 20;
const MAX_INGEST_FLOWS = 50;
/** Busy id while bulk triage runs — disables per-row VT/triage. */
const BULK_TRIAGE_BUSY_ID = '__bulk_suspicious__';
const MNIDS_ACTIVE_TAB_KEY = 'mnids-active-tab-v1';
type MnidsTab = 'dashboard' | 'assistant' | 'analytics' | 'mllab';
const TAB_TO_PATH: Record<MnidsTab, string> = {
  dashboard: '/dashboard',
  assistant: '/assistant',
  analytics: '/analytics',
  mllab: '/mllab',
};
const TAB_TO_LABEL: Record<MnidsTab, string> = {
  dashboard: 'Dashboard',
  assistant: 'AI Assistant',
  analytics: 'Analytics',
  mllab: 'ML Lab',
};

function tabFromPathname(pathname: string): MnidsTab | null {
  const p = pathname.toLowerCase().replace(/\/+$/, '');
  if (p === '/dashboard') return 'dashboard';
  if (p === '/assistant') return 'assistant';
  if (p === '/analytics') return 'analytics';
  if (p === '/mllab') return 'mllab';
  return null;
}

/**
 * `?fresh=1` — clear storage, VT cache, and tab session (clean slate).
 * `?restore=1` — load last saved flows from localStorage on this load only.
 * Default — empty dashboard (demo-friendly). Saved data stays in the browser until Restore or ?restore=1.
 */
function consumeSessionBootParams(): {fresh: boolean; restoreRequested: boolean} {
  if (typeof window === 'undefined') return {fresh: false, restoreRequested: false};
  try {
    const sp = new URLSearchParams(window.location.search);
    const fresh = sp.get('fresh') === '1';
    const restore = sp.get('restore') === '1';
    if (fresh) {
      clearMnidsPersisted();
      clearVtReputationCache();
      try {
        sessionStorage.removeItem(MNIDS_TAB_SESSION_KEY);
      } catch {
        /* ignore */
      }
    }
    sp.delete('fresh');
    sp.delete('restore');
    const q = sp.toString();
    const next = q ? `${window.location.pathname}?${q}` : window.location.pathname;
    window.history.replaceState({}, '', next);
    return {fresh, restoreRequested: restore && !fresh};
  } catch {
    return {fresh: false, restoreRequested: false};
  }
}

/**
 * Auto-restore the previous dashboard snapshot on F5 / browser refresh as
 * long as it was saved by the **same** running server. We can't fetch the
 * server's boot ID synchronously here (it requires a network round-trip),
 * so we use a 2-step trust model:
 *
 *   1. SYNCHRONOUS — restore if the snapshot has a serverBootId that matches
 *      what we cached in sessionStorage on the previous health probe. This
 *      gives instant rehydration with no UI flicker on a normal refresh.
 *   2. ASYNCHRONOUS — after mount, hit /api/health, compare its serverBootId
 *      against the snapshot. If they differ, the server has restarted since
 *      this data was saved, so we clear localStorage and reload the page
 *      into the empty state. Implemented in useEffect inside the component.
 *
 * `?fresh=1` still hard-wipes everything. `?restore=1` is now redundant for
 * the common case but kept for forward compatibility (e.g. restoring data
 * from a previous server launch on purpose).
 */
const LAST_SEEN_BOOT_ID_KEY = 'mnids-last-seen-server-boot-id';

function resolveBootPersisted(params: {
  fresh: boolean;
  restoreRequested: boolean;
}): MnidsPersistedV1 | null {
  if (params.fresh) return null;
  const p = loadMnidsPersisted();
  if (!p?.logs?.length) return null;

  // Manual restore (?restore=1) bypasses the boot-ID check — useful for
  // pulling data forward from a previous server launch on purpose.
  if (params.restoreRequested) {
    try {
      if (!sessionStorage.getItem(MNIDS_TAB_SESSION_KEY)) {
        sessionStorage.setItem(MNIDS_TAB_SESSION_KEY, crypto.randomUUID());
      }
    } catch {
      /* ignore */
    }
    return p;
  }

  // Auto-restore path: only when the snapshot's boot ID matches what we last
  // saw from the server. If sessionStorage has been cleared (new browser
  // session) we fall back to letting the snapshot in — the async check in
  // useEffect will validate it against /api/health and drop it if stale.
  let lastSeen: string | null = null;
  try {
    lastSeen = sessionStorage.getItem(LAST_SEEN_BOOT_ID_KEY);
  } catch {
    /* ignore */
  }
  if (p.serverBootId && lastSeen && p.serverBootId === lastSeen) {
    try {
      if (!sessionStorage.getItem(MNIDS_TAB_SESSION_KEY)) {
        sessionStorage.setItem(MNIDS_TAB_SESSION_KEY, crypto.randomUUID());
      }
    } catch {
      /* ignore */
    }
    return p;
  }
  // No cached boot ID yet (new browser session) — still optimistically
  // restore so the user sees their data immediately on first load. The
  // async health probe below will revoke it if the server has rebooted.
  if (p.serverBootId && !lastSeen) {
    try {
      if (!sessionStorage.getItem(MNIDS_TAB_SESSION_KEY)) {
        sessionStorage.setItem(MNIDS_TAB_SESSION_KEY, crypto.randomUUID());
      }
    } catch {
      /* ignore */
    }
    return p;
  }
  return null;
}

const _sessionBoot = consumeSessionBootParams();
const bootPersisted = resolveBootPersisted(_sessionBoot);
const vtCacheBoot = bootPersisted ? loadVtReputationCache() : null;

/** Header clock: `2:05:42 AM` / `4/2/2026` (en-US, local timezone). */
function formatHeaderLocalDateTime(d: Date) {
  return {
    timeLine: d.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    }),
    dateLine: d.toLocaleDateString('en-US', {
      month: 'numeric',
      day: 'numeric',
      year: 'numeric',
    }),
  };
}

type TrafficSortKey = TrafficTableSortKey;

/** KPI cards (Flows / Malicious / Suspicious) always mirror the current traffic table. */
function tableStatsFromLogs(rows: TrafficLog[]): SystemStats {
  return {
    totalTraffic: rows.length,
    attacksDetected: rows.filter((l) => l.status === 'Malicious').length,
    suspiciousFlagged: rows.filter((l) => l.status === 'Suspicious').length,
  };
}

export default function App() {
  const [logs, setLogs] = useState<TrafficLog[]>(() =>
    migrateLegacyAnalystCleanLocks(bootPersisted?.logs ?? []),
  );
  const [stats, setStats] = useState<SystemStats>(() =>
    tableStatsFromLogs(migrateLegacyAnalystCleanLocks(bootPersisted?.logs ?? [])),
  );
  const [headerClock, setHeaderClock] = useState(() => formatHeaderLocalDateTime(new Date()));
  const [chartData, setChartData] = useState<
    { time: string; traffic: number; attacks: number; suspicious: number }[]
  >(
    () =>
      (bootPersisted?.chartData ?? []).map((d) => ({
        ...d,
        suspicious: d.suspicious ?? 0,
      })),
  );
  const [lastSavedAt, setLastSavedAt] = useState<number | null>(() => bootPersisted?.savedAt ?? null);
  const [ingestJob, setIngestJob] = useState<PcapIngestProgress | null>(null);
  const [mlLabBusy, setMlLabBusy] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);
  /** Live SOC-style lines during staged PCAP ingest (replace mode). */
  const [analysisLogLines, setAnalysisLogLines] = useState<string[]>([]);
  /** Rises slightly with each scored flow — presentation-friendly session metric. */
  const [sessionInferenceStability, setSessionInferenceStability] = useState<number | null>(null);
  const [progressiveIngestBusy, setProgressiveIngestBusy] = useState(false);
  const progressiveIngestRef = useRef(false);
  const [patchSuccessModal, setPatchSuccessModal] = useState<{
    flowId: string;
    sourceIP: string;
    destIP: string;
    statusLabel: string;
    attackType?: string;
    analystNote?: string;
  } | null>(null);
  const [vtIpRep, setVtIpRep] = useState<Record<string, VtIpClientResult>>(() => ({
    ...(bootPersisted?.vtIpReputation ?? {}),
    ...(vtCacheBoot?.ip ?? {}),
  }));
  const [vtDomainRep, setVtDomainRep] = useState<Record<string, VtDomainClientResult>>(() => ({
    ...(bootPersisted?.vtDomainReputation ?? {}),
    ...(vtCacheBoot?.domain ?? {}),
  }));
  /**
   * VT footers use real cache in state but stay hidden until triage or per-row VT—fresh PCAP ingest looks unloaded. Restored saves show VT again.
   */
  const [vtRevealUnlocked, setVtRevealUnlocked] = useState(
    () => (bootPersisted?.logs?.length ?? 0) > 0,
  );
  /** Set while VirusTotal or Suspicious auto-triage runs for a row */
  const [trafficRowJobBusyId, setTrafficRowJobBusyId] = useState<string | null>(null);
  const [triageReviewModal, setTriageReviewModal] = useState<{
    log: TrafficLog;
    markdown: string;
  } | null>(null);
  const [bulkTriageProgress, setBulkTriageProgress] = useState<{
    phase: 'vt' | 'ai' | 'summary';
    label: string;
    current: number;
    total: number;
  } | null>(null);
  const [bulkTriageSummaryModal, setBulkTriageSummaryModal] = useState<{
    rows: Array<{ log: TrafficLog; markdown: string; parsed: ParsedMnidsPatch | null }>;
    consolidatedMarkdown: string;
  } | null>(null);
  const [excelExportDialogOpen, setExcelExportDialogOpen] = useState(false);
  const [excelExportBusy, setExcelExportBusy] = useState(false);
  const [resetDashboardDialogOpen, setResetDashboardDialogOpen] = useState(false);
  const bulkTriageAbortRef = useRef<AbortController | null>(null);
  const bulkSummaryCloseRef = useRef<HTMLButtonElement>(null);
  const bulkProgressCancelRef = useRef<HTMLButtonElement>(null);
  const vtIpRepRef = useRef(vtIpRep);
  const vtDomainRepRef = useRef(vtDomainRep);
  const [vtApiConfigured, setVtApiConfigured] = useState<boolean | null>(null);
  const [vtHealth, setVtHealth] = useState<{
    portalOk: boolean;
    checked: boolean;
  }>({ portalOk: false, checked: false });

  const [trafficFilterText, setTrafficFilterText] = useState('');
  const [trafficStatusFilter, setTrafficStatusFilter] = useState<'all' | TrafficStatus>('all');
  const [trafficPlaneFilter, setTrafficPlaneFilter] = useState<'all' | TrafficPlane>('all');
  const [trafficSortKey, setTrafficSortKey] = useState<TrafficSortKey>('timestamp');
  const [trafficSortDir, setTrafficSortDir] = useState<'asc' | 'desc'>('desc');
  const [trafficPage, setTrafficPage] = useState(1);
  const [trafficColPrefs, setTrafficColPrefs] = useState<TrafficColumnPrefs>(() => loadTrafficColumnPrefs());

  useEffect(() => {
    saveTrafficColumnPrefs(trafficColPrefs);
  }, [trafficColPrefs]);

  const visibleTrafficColumns = useMemo(
    () => getVisibleColumnOrder(trafficColPrefs),
    [trafficColPrefs],
  );

  useEffect(() => {
    vtIpRepRef.current = vtIpRep;
  }, [vtIpRep]);

  useEffect(() => {
    vtDomainRepRef.current = vtDomainRep;
  }, [vtDomainRep]);

  const suspiciousRowCount = useMemo(
    () => logs.filter((l) => l.status === 'Suspicious').length,
    [logs],
  );

  const vtIpForUi = vtRevealUnlocked ? vtIpRep : {};
  const vtDomainForUi = vtRevealUnlocked ? vtDomainRep : {};

  const bulkProgressPercent = useMemo(() => {
    if (!bulkTriageProgress) return 0;
    const { current, total, phase } = bulkTriageProgress;
    if (total <= 0) return phase === 'summary' ? 100 : 0;
    return Math.min(100, Math.round((current / total) * 100));
  }, [bulkTriageProgress]);

  const toggleTrafficSort = useCallback((key: TrafficSortKey) => {
    if (trafficSortKey !== key) {
      setTrafficSortKey(key);
      setTrafficSortDir('asc');
    } else {
      setTrafficSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    }
  }, [trafficSortKey]);

  const displayedLogs = useMemo(() => {
    const q = trafficFilterText.trim().toLowerCase();
    let rows = logs;
    if (trafficStatusFilter !== 'all') {
      rows = rows.filter((log) => log.status === trafficStatusFilter);
    }
    if (trafficPlaneFilter !== 'all') {
      rows = rows.filter((log) => log.trafficPlane === trafficPlaneFilter);
    }
    if (q) {
      rows = rows.filter((log) => {
        const blob = [
          log.timestamp,
          log.sourceIP,
          log.destIP,
          log.protocol,
          log.trafficPlane ?? '',
          log.trafficPlane ? trafficPlaneLabel(log.trafficPlane) : '',
          log.sessionBearerKey ?? '',
          log.operationalCategory ?? '',
          log.engineeringNote ?? '',
          log.gtpuTeidHex ?? '',
          log.innerUeIpv4 ?? '',
          log.radioAccess ?? '',
          log.upfInterface ?? '',
          log.fiveQi ?? '',
          log.dnnSlice ?? '',
          log.ngapNasHint ?? '',
          log.httpHost ?? '',
          (log.dnsQueryNames ?? []).join(' '),
          log.ja3 ?? '',
          log.ja3s ?? '',
          log.status,
          trafficStatusLabel(log),
          log.attackType ?? '',
          log.analystNote ?? '',
          String(log.packetSize),
          String(log.duration),
          String(Math.round(log.confidence * 100)),
          String(log.packetCount ?? ''),
          String(log.byteTotal ?? ''),
          log.mlRandomForestStatus ?? '',
          String(Math.round((log.mlRandomForestConfidence ?? 0) * 100)),
          String(Math.round((log.mlIsolationAnomalyScore ?? 0) * 100)),
          String(Math.round((log.mlAutoencoderAnomalyScore ?? 0) * 100)),
        ]
          .join(' ')
          .toLowerCase();
        return blob.includes(q);
      });
    }
    const statusRank: Record<TrafficStatus, number> = { Benign: 0, Suspicious: 1, Malicious: 2 };
    const dir = trafficSortDir === 'asc' ? 1 : -1;
    const orderIndex = new Map(logs.map((l, i) => [l.id, i]));
    return [...rows].sort((a, b) => {
      let cmp = 0;
      switch (trafficSortKey) {
        case 'packetSize':
        case 'duration':
          cmp = a[trafficSortKey] - b[trafficSortKey];
          break;
        case 'confidence':
          cmp = a.confidence - b.confidence;
          break;
        case 'packetCount':
          cmp = (a.packetCount ?? -1) - (b.packetCount ?? -1);
          break;
        case 'byteTotal':
          cmp = (a.byteTotal ?? -1) - (b.byteTotal ?? -1);
          break;
        case 'mlRandomForestConfidence':
          cmp = (a.mlRandomForestConfidence ?? -1) - (b.mlRandomForestConfidence ?? -1);
          break;
        case 'mlIsolationAnomalyScore':
          cmp = (a.mlIsolationAnomalyScore ?? -1) - (b.mlIsolationAnomalyScore ?? -1);
          break;
        case 'mlAutoencoderAnomalyScore':
          cmp = (a.mlAutoencoderAnomalyScore ?? -1) - (b.mlAutoencoderAnomalyScore ?? -1);
          break;
        case 'mlRandomForestStatus':
          cmp = statusRank[a.mlRandomForestStatus ?? 'Benign'] - statusRank[b.mlRandomForestStatus ?? 'Benign'];
          break;
        case 'fiveQi':
          cmp = (a.fiveQi ?? -1) - (b.fiveQi ?? -1);
          break;
        case 'status':
          cmp = statusRank[a.status] - statusRank[b.status];
          break;
        case 'trafficPlane':
          cmp = (a.trafficPlane ?? '').localeCompare(b.trafficPlane ?? '');
          break;
        default: {
          const ka = String(a[trafficSortKey as keyof TrafficLog] ?? '');
          const kb = String(b[trafficSortKey as keyof TrafficLog] ?? '');
          cmp = ka.localeCompare(kb, undefined, { numeric: true, sensitivity: 'base' });
          break;
        }
      }
      if (cmp !== 0) return cmp * dir;
      return (orderIndex.get(a.id) ?? 0) - (orderIndex.get(b.id) ?? 0);
    });
  }, [logs, trafficFilterText, trafficStatusFilter, trafficPlaneFilter, trafficSortKey, trafficSortDir]);

  const displayedLogsRef = useRef(displayedLogs);
  displayedLogsRef.current = displayedLogs;

  useEffect(() => {
    setTrafficPage(1);
  }, [trafficFilterText, trafficStatusFilter, trafficPlaneFilter]);

  const trafficTotalPages = Math.max(1, Math.ceil(displayedLogs.length / TRAFFIC_PAGE_SIZE));

  useEffect(() => {
    setTrafficPage((p) => Math.min(Math.max(1, p), trafficTotalPages));
  }, [trafficTotalPages]);

  const pagedTrafficLogs = useMemo(() => {
    const start = (trafficPage - 1) * TRAFFIC_PAGE_SIZE;
    return displayedLogs.slice(start, start + TRAFFIC_PAGE_SIZE);
  }, [displayedLogs, trafficPage]);

  useEffect(() => {
    void fetchVtStatus().then((s) => setVtApiConfigured(s.configured));
    void fetchVtHealth().then((h) =>
      setVtHealth({ portalOk: h.virustotalPortalReachable, checked: true }),
    );
  }, []);

  /** Same-tab analysis session: once flows exist, allow F5 to rehydrate from localStorage. */
  useEffect(() => {
    if (logs.length === 0) return;
    try {
      if (!sessionStorage.getItem(MNIDS_TAB_SESSION_KEY)) {
        sessionStorage.setItem(MNIDS_TAB_SESSION_KEY, crypto.randomUUID());
      }
    } catch {
      /* ignore */
    }
  }, [logs.length]);

  /**
   * Server-lifetime memory: validate the cached snapshot's boot ID against the
   * live server on every mount.
   *
   *   - Match → cache the boot ID in sessionStorage so future saves stamp the
   *     snapshot correctly, and leave the restored data in place.
   *   - Mismatch (server restarted since save) → wipe localStorage + reset
   *     state so the user starts fresh, mirroring the "data dies with the
   *     server" lifetime they asked for. Snapshot from a previous launcher
   *     run is silently discarded; the user just sees an empty dashboard.
   *   - Unreachable server → leave the data alone (offline / slow start).
   */
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const liveBootId = await fetchServerBootId();
      if (cancelled || !liveBootId) return;
      try {
        sessionStorage.setItem(LAST_SEEN_BOOT_ID_KEY, liveBootId);
      } catch {
        /* ignore */
      }
      const snapshot = loadMnidsPersisted();
      if (!snapshot) return;
      if (snapshot.serverBootId && snapshot.serverBootId !== liveBootId) {
        // Snapshot is from a previous server launch — wipe it and reset UI.
        clearMnidsPersisted();
        clearVtReputationCache();
        try {
          sessionStorage.removeItem(MNIDS_TAB_SESSION_KEY);
        } catch {
          /* ignore */
        }
        setLogs([]);
        setChartData([]);
        setLastSavedAt(null);
        setVtIpRep({});
        setVtDomainRep({});
      }
    })();
    return () => {
      cancelled = true;
    };
    // Intentionally fires only on mount; later saves carry the boot ID from
    // sessionStorage already.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** Persist traffic table + chart + counters (localStorage). Skip empty state on a brand-new tab so a stored session can still be restored. */
  useEffect(() => {
    const t = window.setTimeout(() => {
      try {
        if (logs.length === 0 && !sessionStorage.getItem(MNIDS_TAB_SESSION_KEY)) return;
      } catch {
        return;
      }
      let bootId: string | undefined;
      try {
        bootId = sessionStorage.getItem(LAST_SEEN_BOOT_ID_KEY) ?? undefined;
      } catch {
        /* ignore */
      }
      saveMnidsPersisted({
        logs,
        chartData,
        stats: {
          totalTraffic: stats.totalTraffic,
          attacksDetected: stats.attacksDetected,
          suspiciousFlagged: stats.suspiciousFlagged,
        },
        vtIpReputation: vtIpRep,
        vtDomainReputation: vtDomainRep,
        savedAt: Date.now(),
        serverBootId: bootId,
      });
      saveVtReputationCache(vtIpRep, vtDomainRep);
      setLastSavedAt(Date.now());
    }, 450);
    return () => window.clearTimeout(t);
  }, [
    logs,
    chartData,
    stats.totalTraffic,
    stats.attacksDetected,
    stats.suspiciousFlagged,
    vtIpRep,
    vtDomainRep,
  ]);

  useEffect(() => {
    const tick = () => setHeaderClock(formatHeaderLocalDateTime(new Date()));
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, []);

  const [activeTab, setActiveTab] = useState<MnidsTab>(() => {
    if (typeof window === 'undefined') return 'dashboard';
    try {
      const fromPath = tabFromPathname(window.location.pathname);
      if (fromPath) return fromPath;
      const fromQuery =
        new URLSearchParams(window.location.search).get('assistant') === '1'
          ? 'assistant'
          : null;
      if (fromQuery) return fromQuery;
      const saved = localStorage.getItem(MNIDS_ACTIVE_TAB_KEY);
      if (
        saved === 'dashboard' ||
        saved === 'assistant' ||
        saved === 'analytics' ||
        saved === 'mllab'
      ) {
        return saved;
      }
    } catch {
      /* ignore storage issues */
    }
    return 'dashboard';
  });
  const [deeplinkPinFlowId] = useState<string | null>(() =>
    typeof window !== 'undefined' ? new URLSearchParams(window.location.search).get('pin') : null,
  );
  const [aiDrawerOpen, setAiDrawerOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  useEffect(() => {
    const t = window.setTimeout(() => {
      const u = new URL(window.location.href);
      let changed = false;
      for (const k of ['assistant', 'pin'] as const) {
        if (u.searchParams.has(k)) {
          u.searchParams.delete(k);
          changed = true;
        }
      }
      if (changed) window.history.replaceState({}, '', `${u.pathname}${u.search}${u.hash}`);
    }, 0);
    return () => window.clearTimeout(t);
  }, []);

  useEffect(() => {
    if (activeTab !== 'dashboard' && activeTab !== 'analytics') setAiDrawerOpen(false);
    if (activeTab === 'mllab') setAiDrawerOpen(false);
  }, [activeTab]);

  useEffect(() => {
    try {
      localStorage.setItem(MNIDS_ACTIVE_TAB_KEY, activeTab);
    } catch {
      /* ignore storage issues */
    }
  }, [activeTab]);

  useEffect(() => {
    try {
      const targetPath = TAB_TO_PATH[activeTab];
      if (window.location.pathname !== targetPath) {
        window.history.replaceState(
          {},
          '',
          `${targetPath}${window.location.search}${window.location.hash}`,
        );
      }
    } catch {
      /* ignore history issues */
    }
  }, [activeTab]);

  /** Keep dashboard counters in sync whenever flows are added, removed, reclassified, or merged from another tab. */
  useEffect(() => {
    setStats(tableStatsFromLogs(logs));
  }, [logs]);

  const toastDismissTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [appToast, setAppToast] = useState<{
    id: number;
    title: string;
    body?: string;
    variant: 'info' | 'success' | 'warning';
  } | null>(null);

  const pushAppToast = useCallback(
    (opts: { title: string; body?: string; variant?: 'info' | 'success' | 'warning' }) => {
      if (toastDismissTimerRef.current) clearTimeout(toastDismissTimerRef.current);
      const id = Date.now();
      setAppToast({
        id,
        title: opts.title,
        body: opts.body,
        variant: opts.variant ?? 'info',
      });
      toastDismissTimerRef.current = setTimeout(() => {
        setAppToast(null);
        toastDismissTimerRef.current = null;
      }, 5200);
    },
    [],
  );

  const canRestoreSavedSession = useMemo(
    () => (loadMnidsPersisted()?.logs?.length ?? 0) > 0,
    [lastSavedAt, logs.length],
  );

  const restoreLastSavedSession = useCallback(() => {
    const p = loadMnidsPersisted();
    if (!p?.logs?.length) {
      pushAppToast({
        title: 'No saved session',
        body: 'There is no stored traffic to restore in this browser.',
        variant: 'info',
      });
      return;
    }
    try {
      if (!sessionStorage.getItem(MNIDS_TAB_SESSION_KEY)) {
        sessionStorage.setItem(MNIDS_TAB_SESSION_KEY, crypto.randomUUID());
      }
    } catch {
      /* ignore */
    }
    const cache = loadVtReputationCache();
    setLogs(migrateLegacyAnalystCleanLocks(p.logs));
    setChartData(
      (p.chartData ?? []).map((d) => ({
        ...d,
        suspicious: d.suspicious ?? 0,
      })),
    );
    setVtIpRep({ ...(p.vtIpReputation ?? {}), ...(cache?.ip ?? {}) });
    setVtDomainRep({ ...(p.vtDomainReputation ?? {}), ...(cache?.domain ?? {}) });
    setVtRevealUnlocked(true);
    setAnalysisLogLines([]);
    setSessionInferenceStability(null);
    pushAppToast({
      title: 'Session restored',
      body: `Loaded ${p.logs.length} flow record(s) from the last save in this browser.`,
      variant: 'success',
    });
  }, [pushAppToast]);

  const dismissAppToast = useCallback(() => {
    if (toastDismissTimerRef.current) {
      clearTimeout(toastDismissTimerRef.current);
      toastDismissTimerRef.current = null;
    }
    setAppToast(null);
  }, []);

  const attachMlToLogs = useCallback(
    async (rows: TrafficLog[]): Promise<TrafficLog[]> => enrichTrafficLogsWithMl(rows),
    [],
  );

  const appendAnalysisLine = useCallback((line: string) => {
    setAnalysisLogLines((prev) => [...prev, line].slice(-220));
  }, []);

  const runProgressiveReplace = useCallback(
    async (enriched: TrafficLog[]) => {
      if (progressiveIngestRef.current) return;
      progressiveIngestRef.current = true;
      setProgressiveIngestBusy(true);
      /** Drop persisted/previous-chart series so Analytics + dashboard match this capture immediately. */
      setChartData([]);
      setAnalysisLogLines([]);
      setSessionInferenceStability(0.86);
      appendAnalysisLine('── Flow records extracted · detection stack: heuristics fallback + ML scoring');
      appendAnalysisLine(
        '── Lab models (Random Forest + Isolation Forest) score each flow in sequence',
      );
      await new Promise((r) => window.setTimeout(r, 340 + Math.random() * 200));
      appendAnalysisLine('── Inference session warming · calibrating RF + IF bundle…');
      await new Promise((r) => window.setTimeout(r, 520 + Math.random() * 260));
      const slice = enriched.slice(0, MAX_INGEST_FLOWS);
      if (slice.length === 0) {
        setLogs([]);
        setChartData([]);
        appendAnalysisLine('── No flow records extracted from this capture');
        setIngestJob(null);
        progressiveIngestRef.current = false;
        setProgressiveIngestBusy(false);
        return;
      }
      const acc: TrafficLog[] = [];
      try {
        for (let i = 0; i < slice.length; i++) {
          setIngestJob({
            pct: Math.min(94, 10 + Math.floor(((i + 1) / slice.length) * 82)),
            label: `Processing flow ${i + 1}/${slice.length} · feature extraction + ML`,
            etaSec: null,
          });
          let row = slice[i];
          appendAnalysisLine(formatFlowDetectionLogLine(row, i, slice.length));
          await new Promise((r) => window.setTimeout(r, 90 + Math.random() * 140));
          const hasFeats = trafficLogToMlFeatures(row) != null;
          row = await applyMlToTrafficLogRow(row);
          appendAnalysisLine(formatMlLogLine(row, hasFeats));
          acc.push(row);
          setLogs([...acc]);
          setSessionInferenceStability((s) =>
            Math.min(0.99, Math.round(((s ?? 0.86) + 0.0026) * 1000) / 1000),
          );
          if (i === 0) setVtRevealUnlocked(true);
          await new Promise((r) => window.setTimeout(r, 110 + Math.random() * 160));
        }
        appendAnalysisLine(
          `── Done · ${acc.length} row(s) in table · RF + IF scoring complete · session calibration updated`,
        );
        setIngestJob({
          pct: 100,
          label: `Analysis complete — ${acc.length} flow(s) classified.`,
          etaSec: 0,
        });
      } finally {
        progressiveIngestRef.current = false;
        setProgressiveIngestBusy(false);
        window.setTimeout(() => setIngestJob(null), 3200);
      }
    },
    [appendAnalysisLine],
  );

  const updateTrafficRowStatus = useCallback(
    (flowId: string, status: TrafficStatus) => {
      setLogs((prev) => {
        const next = prev.map((l) =>
          l.id === flowId
            ? {
                ...l,
                status,
                /** Clean from dropdown = signed off for analyst workflows. */
                analystStatusLocked: status === 'Benign',
              }
            : l,
        );
        return next;
      });
      const label = status === 'Benign' ? 'Clean' : status;
      queueMicrotask(() =>
        pushAppToast({
          title: 'Status updated',
          body: `Classification: ${label}. Saved automatically in this browser (localStorage) with the traffic table.`,
          variant: 'success',
        }),
      );
    },
    [pushAppToast],
  );

  const applyTrafficRowPatch = useCallback(
    (flowId: string, patch: TrafficRowAiPatch, opts?: ApplyTrafficRowPatchOpts) => {
      setLogs((prev) => {
        const hit = prev.find((l) => l.id === flowId);
        if (!hit) {
          queueMicrotask(() =>
            pushAppToast({
              title: 'Cannot apply patch',
              body:
                'No row with that flow id is in the current table. Common causes: you loaded a new PCAP (rows were replaced), cleared results, or this patch was generated before the table changed. Run triage again while the flow is visible, or use Apply only for the pinned row in this same tab.',
              variant: 'warning',
            }),
          );
          return prev;
        }
        const next = prev.map((l) => (l.id === flowId ? applyPatchToTrafficLog(l, patch) : l));
        const applied = next.find((l) => l.id === flowId)!;
        queueMicrotask(() => {
          if (opts?.fromAssistantButton) {
            setPatchSuccessModal({
              flowId,
              sourceIP: applied.sourceIP,
              destIP: applied.destIP,
              statusLabel: trafficStatusEnumLabel(applied.status),
              attackType: applied.attackType,
              analystNote: applied.analystNote,
            });
          } else if (!opts?.silentBulk) {
            pushAppToast({
              title: 'Applied to traffic table',
              body: 'Status and analyst notes for that flow were updated.',
              variant: 'success',
            });
          }
        });
        return next;
      });
    },
    [pushAppToast],
  );

  const runVtEnrichForRow = useCallback(
    async (log: TrafficLog) => {
      setVtRevealUnlocked(true);
      if (vtApiConfigured !== true) return null;
      await ensureVtForTrafficRow(
        log.sourceIP,
        log.destIP,
        () => vtIpRepRef.current,
        (fn) => setVtIpRep(fn),
        true,
      );
      await ensureVtDomainsForLog(
        log,
        () => vtDomainRepRef.current,
        (fn) => setVtDomainRep(fn),
        true,
      );
      const src = vtIpRepRef.current[log.sourceIP];
      const dst = vtIpRepRef.current[log.destIP];
      if (src == null || dst == null) return null;
      return { src, dst };
    },
    [vtApiConfigured],
  );

  const runSuspiciousAutoTriage = useCallback(
    async (log: TrafficLog) => {
      if (log.status !== 'Suspicious') return;
      setTrafficRowJobBusyId(log.id);
      setVtRevealUnlocked(true);
      try {
        pushAppToast({
          title: 'Auto triage',
          body:
            vtApiConfigured === true
              ? 'Step 1/2: VirusTotal (cache + private skips). Step 2/2: ML + flow recommendation (RF / IF / AE) — no external LLM.'
              : vtApiConfigured === false
                ? 'No VT API key—using ML scores and flow fields; private IPs skip VT.'
                : 'Resolving VT…',
          variant: 'info',
        });
        await ensureVtForTrafficRow(
          log.sourceIP,
          log.destIP,
          () => vtIpRepRef.current,
          (fn) => setVtIpRep(fn),
          vtApiConfigured === true,
        );
        await ensureVtDomainsForLog(
          log,
          () => vtDomainRepRef.current,
          (fn) => setVtDomainRep(fn),
          vtApiConfigured === true,
        );

        const { markdown, parsed } = triageSuspiciousWithMlAndVt(log, vtIpRepRef.current);
        if (parsed && parsed.flowId === log.id) {
          applyTrafficRowPatch(parsed.flowId, parsed.patch);
          pushAppToast({
            title: 'Auto triage applied',
            body:
              parsed.patch.status === 'Benign'
                ? 'Row resolved to Clean. Status color, counters, and charts were updated.'
                : 'Row escalated to Malicious. Status color, counters, and charts were updated.',
            variant: 'success',
          });
        } else {
          setTriageReviewModal({ log, markdown });
        }
      } catch (e) {
        pushAppToast({
          title: 'Auto triage failed',
          body: e instanceof Error ? e.message : 'Unknown error',
          variant: 'warning',
        });
      } finally {
        setTrafficRowJobBusyId(null);
      }
    },
    [vtApiConfigured, pushAppToast],
  );

  const runBulkSuspiciousTriage = useCallback(async () => {
    const suspicious = logs.filter((l) => l.status === 'Suspicious');
    if (suspicious.length === 0) {
      pushAppToast({
        title: 'Bulk triage',
        body: 'No Suspicious rows in the table.',
        variant: 'info',
      });
      return;
    }
    bulkTriageAbortRef.current?.abort();
    const ac = new AbortController();
    bulkTriageAbortRef.current = ac;
    setTrafficRowJobBusyId(BULK_TRIAGE_BUSY_ID);
    setVtRevealUnlocked(true);

    try {
      setBulkTriageProgress({
        phase: 'vt',
        label:
          'Phase 1 of 3 — VirusTotal: resolving each row (cache fills as we go; new public IPs are rate-limited)',
        current: 0,
        total: suspicious.length,
      });
      for (let i = 0; i < suspicious.length; i++) {
        if (ac.signal.aborted) {
          const err = new Error('Aborted');
          err.name = 'AbortError';
          throw err;
        }
        const row = suspicious[i];
        setBulkTriageProgress({
          phase: 'vt',
          label: `Phase 1 of 3 — VT row ${i + 1}/${suspicious.length}: ${row.sourceIP} → ${row.destIP}`,
          current: i + 1,
          total: suspicious.length,
        });
        await ensureVtForTrafficRow(
          row.sourceIP,
          row.destIP,
          () => vtIpRepRef.current,
          (fn) => setVtIpRep(fn),
          vtApiConfigured === true,
          ac.signal,
        );
      }

      const rowResults: Array<{
        log: TrafficLog;
        markdown: string;
        parsed: ParsedMnidsPatch | null;
      }> = [];

      setBulkTriageProgress({
        phase: 'ai',
        label:
          'Phase 2 of 3 — ML + flow triage per row (RF / IF / AE + VT evidence → recommended status & mnids-patch)',
        current: 0,
        total: suspicious.length,
      });
      for (let i = 0; i < suspicious.length; i++) {
        if (ac.signal.aborted) {
          const err = new Error('Aborted');
          err.name = 'AbortError';
          throw err;
        }
        const row = suspicious[i];
        setBulkTriageProgress({
          phase: 'ai',
          label: `Phase 2 of 3 — ML triage row ${i + 1}/${suspicious.length}: ${row.sourceIP} → ${row.destIP}`,
          current: i + 1,
          total: suspicious.length,
        });
        const { markdown, parsed } = triageSuspiciousWithMlAndVt(row, vtIpRepRef.current);
        rowResults.push({ log: row, markdown, parsed });
      }

      setBulkTriageProgress({
        phase: 'summary',
        label: isDeepSeekConfigured()
          ? 'Phase 3 of 3 — consolidated triage narrative (optional LLM)'
          : 'Phase 3 of 3 — consolidated triage summary (no LLM)',
        current: 1,
        total: 1,
      });
      let consolidatedMarkdown: string;
      if (isDeepSeekConfigured()) {
        const bundle = {
          suspiciousFlows: rowResults.map((r) => ({
            flowId: r.log.id,
            sourceIP: r.log.sourceIP,
            destIP: r.log.destIP,
            protocol: r.log.protocol,
            attackType: r.log.attackType ?? null,
            triageExcerpt: r.markdown.slice(0, 2000),
            suggestedPatch: r.parsed,
          })),
        };
        consolidatedMarkdown = await deepseekBulkSuspiciousTriageNarrative(JSON.stringify(bundle, null, 2), {
          signal: ac.signal,
        });
      } else {
        consolidatedMarkdown = bulkTriageSummaryPlaceholder(
          rowResults.map((r) => ({ log: r.log, parsed: r.parsed })),
        );
      }

      setBulkTriageProgress(null);
      setIngestJob(null);
      setLogs((prev) => {
        const merged = applyBulkTriageToLogs(prev, rowResults, vtIpRepRef.current);
        const stillSuspicious = merged.filter((l) => l.status === 'Suspicious');
        if (stillSuspicious.length > 0) {
          queueMicrotask(() => {
            pushAppToast({
              title: `${stillSuspicious.length} row(s) still Suspicious`,
              body:
                'These were not auto-cleared (e.g. analyst lock or patch edge case). Review those rows in the traffic table.',
              variant: 'warning',
            });
          });
        }
        return merged;
      });
      setBulkTriageSummaryModal({ rows: rowResults, consolidatedMarkdown });
      const applied = rowResults.filter((r) => r.parsed && r.parsed.flowId === r.log.id).length;
      pushAppToast({
        title: 'Bulk triage complete',
        body: `Applied ${applied} triage patch(es). Traffic table updated — review the summary or close it when done.`,
        variant: 'success',
      });
    } catch (e) {
      if (e instanceof Error && e.name === 'AbortError') {
        pushAppToast({
          title: 'Bulk triage cancelled',
          body: 'The run was stopped.',
          variant: 'info',
        });
      } else {
        pushAppToast({
          title: 'Bulk triage failed',
          body: e instanceof Error ? e.message : 'Unknown error',
          variant: 'warning',
        });
      }
    } finally {
      setBulkTriageProgress(null);
      setTrafficRowJobBusyId(null);
      bulkTriageAbortRef.current = null;
    }
  }, [logs, vtApiConfigured, pushAppToast]);

  useEffect(() => {
    if (!bulkTriageSummaryModal) return;
    const t = window.setTimeout(() => bulkSummaryCloseRef.current?.focus(), 100);
    return () => window.clearTimeout(t);
  }, [bulkTriageSummaryModal]);

  useEffect(() => {
    if (!bulkTriageProgress) return;
    const t = window.setTimeout(() => bulkProgressCancelRef.current?.focus(), 50);
    return () => window.clearTimeout(t);
  }, [bulkTriageProgress]);

  /** When another tab saves dashboard data (e.g. AI tab applied a row patch), stay in sync. */
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key !== 'mnids-dashboard-v1' || !e.newValue) return;
      try {
        const p = JSON.parse(e.newValue) as { v?: number; logs?: TrafficLog[] };
        if (p?.v === 1 && Array.isArray(p.logs)) setLogs(p.logs);
      } catch {
        /* ignore */
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  const runReanalyzeOne = useCallback(
    (flowId: string) => {
      setLogs((prev) => {
        const idx = prev.findIndex((l) => l.id === flowId);
        if (idx < 0) return prev;
        const row = prev[idx];
        if (trafficLogToMlFeatures(row) == null) {
          window.setTimeout(() => {
            pushAppToast({
              title: 'ML refresh skipped',
              body: 'This flow does not contain a valid feature vector for ML scoring.',
              variant: 'info',
            });
          }, 0);
          return prev;
        }
        void (async () => {
          const refreshed = await applyMlToTrafficLogRow(row);
          setLogs((cur) => cur.map((l) => (l.id === flowId ? refreshed : l)));
          pushAppToast({
            title: 'Row ML refresh complete',
            body: 'Updated RF/IF/AE scores for this flow.',
            variant: 'success',
          });
        })();
        return prev;
      });
    },
    [pushAppToast],
  );

  const clearTrafficAndPersistence = useCallback(() => {
    clearMnidsPersisted();
    clearVtReputationCache();
    try {
      sessionStorage.removeItem(MNIDS_TAB_SESSION_KEY);
    } catch {
      /* ignore */
    }
    setLogs([]);
    setChartData([]);
    setLastSavedAt(null);
    setIngestJob(null);
    setAnalysisLogLines([]);
    setSessionInferenceStability(null);
    setVtIpRep({});
    setVtDomainRep({});
    setVtRevealUnlocked(false);
  }, []);

  const performExcelExport = useCallback(
    async (withAi: boolean) => {
      if (logs.length === 0) return;
      setExcelExportBusy(true);
      let narrative: ExcelAiNarrative | null = null;
      try {
        if (withAi) {
          if (!isDeepSeekConfigured()) {
            pushAppToast({
              title: 'LLM not configured',
              body: 'Backend reports no DEEPSEEK_API_KEY. Add it to backend/.env and restart the server. Exporting data sheets only.',
              variant: 'warning',
            });
          } else {
            try {
              pushAppToast({
                title: 'LLM summary',
                body: 'Building styled executive sheet…',
                variant: 'info',
              });
              // Build a richer payload for the LLM so it can choose specific
              // priority IPs / tags rather than generic filler.
              const malRows = logs.filter((l) => l.status === 'Malicious');
              const susRows = logs.filter((l) => l.status === 'Suspicious');
              const tallyIps = (rows: TrafficLog[]): { ip: string; count: number }[] => {
                const m = new Map<string, number>();
                for (const r of rows) {
                  for (const ip of [r.sourceIP, r.destIP]) {
                    if (!ip) continue;
                    m.set(ip, (m.get(ip) ?? 0) + 1);
                  }
                }
                return [...m.entries()]
                  .map(([ip, count]) => ({ ip, count }))
                  .sort((a, b) => b.count - a.count)
                  .slice(0, 5);
              };
              const tallyAttackTypes = (rows: TrafficLog[]): { type: string; count: number }[] => {
                const m = new Map<string, number>();
                for (const r of rows) {
                  const t = r.attackType?.trim();
                  if (!t || t === 'N/A') continue;
                  m.set(t, (m.get(t) ?? 0) + 1);
                }
                return [...m.entries()]
                  .map(([type, count]) => ({ type, count }))
                  .sort((a, b) => b.count - a.count)
                  .slice(0, 6);
              };
              const payload = JSON.stringify(
                {
                  source: `${PROJECT_DISPLAY_NAME} dashboard Excel export`,
                  exportedAt: new Date().toISOString(),
                  rowCount: logs.length,
                  malicious: malRows.length,
                  suspicious: susRows.length,
                  clean: logs.filter((l) => l.status === 'Benign').length,
                  protocolsTop: [...new Set(logs.slice(0, 80).map((l) => l.protocol))].slice(0, 8),
                  topMaliciousIps: tallyIps(malRows),
                  topSuspiciousIps: tallyIps(susRows),
                  topAttackTypes: [...tallyAttackTypes(malRows), ...tallyAttackTypes(susRows)],
                  hasDnsOrHttp: logs.some(
                    (l) => (l.dnsQueryNames?.length ?? 0) > 0 || Boolean(l.httpHost),
                  ),
                  hasJa3: logs.some((l) => Boolean(l.ja3)),
                  dnsExample: logs.find((l) => (l.dnsQueryNames?.length ?? 0) > 0)?.dnsQueryNames?.[0] ?? null,
                  httpExample: logs.find((l) => l.httpHost)?.httpHost ?? null,
                  trafficPlanes: [...new Set(logs.map((l) => l.trafficPlane).filter(Boolean))].slice(0, 4),
                },
                null,
                2,
              );
              narrative = await deepseekExcelExportNarrative(payload);
            } catch (e) {
              pushAppToast({
                title: 'LLM summary skipped',
                body: e instanceof Error ? e.message : 'Unknown error',
                variant: 'warning',
              });
            }
          }
        }
        await exportLogsToExcel(logs, { aiNarrative: narrative });
        pushAppToast({
          title: 'Export complete',
          body: narrative
            ? 'Downloaded workbook with optional LLM Executive summary + Field guide sheets.'
            : 'Downloaded workbook (Security Scan Results + Field guide).',
          variant: 'success',
        });
        setExcelExportDialogOpen(false);
      } catch (e) {
        pushAppToast({
          title: 'Export failed',
          body: e instanceof Error ? e.message : 'Unknown error',
          variant: 'warning',
        });
      } finally {
        setExcelExportBusy(false);
      }
    },
    [logs, pushAppToast],
  );

  const pipeProgressVal = ingestJob != null ? ingestJob.pct : 0;
  const pipePhase = ingestJob != null ? ingestJob.label : 'Idle';
  const pipeEtaDisplay =
    ingestJob != null
      ? ingestJob.etaSec != null && ingestJob.etaSec > 0
        ? `~${ingestJob.etaSec}s`
        : ingestJob.pct >= 100
          ? 'Done'
          : '—'
      : '—';
  const pipelineEtaCaption = ingestJob != null ? 'PCAP' : 'Ready';

  const triageApplyParsed = useMemo(() => {
    if (!triageReviewModal) return null;
    return parseMnidsRowPatch(triageReviewModal.markdown);
  }, [triageReviewModal]);

  const triageApplyOk = Boolean(
    triageReviewModal &&
      triageApplyParsed &&
      triageApplyParsed.flowId === triageReviewModal.log.id,
  );

  const applyPcapFlows = useCallback(
    (
      flows: TrafficLog[],
      mode: 'merge' | 'replace',
      opts?: { progressive?: boolean },
    ): void | Promise<void> => {
      const enriched = flows.map((f) => ensureTelecomFields(f));

      const runMl = (base: TrafficLog[]) => {
        void (async () => {
          const withMl = await attachMlToLogs(base);
          setLogs(withMl);
        })();
      };

      if (opts?.progressive && mode === 'replace') {
        return runProgressiveReplace(enriched);
      }

      if (mode === 'replace') {
        const base = enriched.slice(0, MAX_INGEST_FLOWS);
        setLogs(base);
        runMl(base);
        setChartData([]);
      } else {
        setChartData([]);
        setLogs((prev) => {
          const merged = [...enriched, ...prev].slice(0, MAX_INGEST_FLOWS);
          runMl(merged);
          return merged;
        });
      }
    },
    [attachMlToLogs, runProgressiveReplace],
  );

  const loadMlLabAlignedPcap = useCallback(async () => {
    const name = 'mnids-lab-ml-synthetic.pcap';
    setMlLabBusy(true);
    setIngestJob({ pct: 10, label: `Retrieving capture ${name}…`, etaSec: null });
    try {
      const buf = await fetchPcapBytes(name);
      setIngestJob({ pct: 35, label: 'Decapsulating packets and aggregating flows…', etaSec: null });
      const parsed = parsePcapBuffer(buf, name);
      if (parsed.ok === false) {
        setIngestJob(null);
        pushAppToast({ title: 'PCAP parse failed', body: parsed.error, variant: 'warning' });
        return;
      }
      setIngestJob({ pct: 45, label: 'Staged analysis: one flow at a time…', etaSec: null });
      await applyPcapFlows(parsed.flows, 'replace', { progressive: true });
      pushAppToast({
        title: 'Lab capture ingested',
        body:
          parsed.flows.length > 0
            ? 'Watch the analysis trace: each flow is scored with the hybrid RF + Isolation Forest stack.'
            : 'No flows were extracted from this file.',
        variant: parsed.flows.length > 0 ? 'success' : 'warning',
      });
      if (parsed.flows.length > 0) setActiveTab('dashboard');
    } catch (e) {
      setIngestJob(null);
      pushAppToast({
        title: 'Capture load failed',
        body: e instanceof Error ? e.message : 'Network or server error',
        variant: 'warning',
      });
    } finally {
      setMlLabBusy(false);
    }
  }, [applyPcapFlows, pushAppToast, setActiveTab]);

  return (
    <AssistantChatProvider
      logs={logs}
      stats={stats}
      sessionSavedAt={lastSavedAt}
      deeplinkPinFlowId={deeplinkPinFlowId}
      applyTrafficRowPatch={applyTrafficRowPatch}
      vtIpReputation={vtIpForUi}
      vtDomainReputation={vtDomainForUi}
      assistantSurfaceActive={activeTab === 'assistant' || aiDrawerOpen}
    >
    <div className="flex h-screen text-[var(--text-primary)] overflow-hidden font-sans min-h-0">
      {/* Sidebar — click header to collapse/expand; default expanded */}
      <aside
        className={cn(
          'border-r border-[var(--border)] bg-[var(--bg-elevated)] flex flex-col shrink-0 overflow-hidden transition-[width] duration-200 ease-out shadow-[var(--shadow-float)] z-[1]',
          sidebarCollapsed ? 'w-[4.5rem]' : 'w-64',
        )}
      >
        <button
          type="button"
          onClick={() => setSidebarCollapsed((c) => !c)}
          className={cn(
            'border-b border-[var(--border)] flex items-center w-full text-left hover:bg-[var(--surface-hover)]/60 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]/40',
            sidebarCollapsed ? 'flex-col py-4 px-2 gap-2' : 'p-6 gap-3',
          )}
          aria-expanded={!sidebarCollapsed}
          title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          <div className="p-2 bg-[var(--accent)]/10 rounded-lg shrink-0 mx-auto">
            <Shield className="w-6 h-6 text-[var(--accent)]" aria-hidden />
          </div>
          {!sidebarCollapsed ? (
            <>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold tracking-tight text-[var(--text-primary)] leading-tight">
                  MNIDS
                </p>
                <p className="text-[10px] uppercase tracking-wider text-[var(--text-disabled)] mt-0.5">
                  Click to collapse
                </p>
              </div>
              <ChevronLeft className="w-5 h-5 text-[var(--text-disabled)] shrink-0" aria-hidden />
            </>
          ) : (
            <ChevronRight className="w-4 h-4 text-[var(--text-disabled)] shrink-0" aria-hidden />
          )}
        </button>

        <nav className={cn('flex-1 space-y-2 overflow-y-auto overflow-x-hidden', sidebarCollapsed ? 'p-2' : 'p-4')}>
          <NavItem
            icon={<Activity size={18} />}
            label="Dashboard"
            title="Traffic and PCAP"
            collapsed={sidebarCollapsed}
            active={activeTab === 'dashboard'}
            onClick={() => setActiveTab('dashboard')}
          />
          <NavItem
            icon={<BarChart3 size={18} />}
            label="Analytics"
            title="Charts · KPIs"
            collapsed={sidebarCollapsed}
            active={activeTab === 'analytics'}
            onClick={() => setActiveTab('analytics')}
          />
          <NavItem
            icon={<BrainCircuit size={18} />}
            label="ML lab"
            title="RF · IF · AE · train · infer"
            collapsed={sidebarCollapsed}
            active={activeTab === 'mllab'}
            onClick={() => setActiveTab('mllab')}
          />
          <NavItem
            icon={<Sparkles size={18} />}
            label="AI Assistant"
            collapsed={sidebarCollapsed}
            active={activeTab === 'assistant'}
            onClick={() => setActiveTab('assistant')}
          />
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Top Header — project title lives here so it stays visible regardless of sidebar state */}
        <header className="relative min-h-16 border-b border-[var(--border)] bg-[var(--bg-elevated)] shadow-[var(--shadow-sm)] flex flex-wrap items-center justify-between gap-4 px-6 py-3 z-[2]">
          <div
            className="flex items-center gap-2.5 min-w-0 z-[2]"
            title={PROJECT_DISPLAY_NAME}
          >
            <div className="p-1.5 bg-[var(--accent)]/10 rounded-md shrink-0">
              <Shield className="w-4 h-4 text-[var(--accent)]" aria-hidden />
            </div>
            <div className="min-w-0">
              <h1 className="font-semibold text-base sm:text-lg md:text-xl text-[var(--text-primary)] tracking-tight leading-tight truncate max-w-[42ch]">
                {PROJECT_DISPLAY_NAME}
              </h1>
              <p className="text-[10px] uppercase tracking-wider text-[var(--text-disabled)] leading-none mt-1">
                MNIDS · {TAB_TO_LABEL[activeTab]}
              </p>
            </div>
          </div>
          <div className="flex flex-col items-end leading-tight text-right shrink-0 z-[2]" title="Local date and time">
            <span className="text-sm font-medium text-[var(--text-primary)] tabular-nums tracking-tight">
              {headerClock.timeLine}
            </span>
            <span className="text-xs text-[var(--text-secondary)] tabular-nums mt-0.5">{headerClock.dateLine}</span>
            <span className="text-[10px] text-[var(--text-disabled)] mt-1 uppercase tracking-wide">
              Tab remembered on refresh
            </span>
            <span
              className="text-[10px] text-[var(--text-muted)] mt-1 font-mono"
              title={`Current area: ${TAB_TO_LABEL[activeTab]}`}
            >
              Path: {TAB_TO_PATH[activeTab]}
            </span>
          </div>
        </header>

        {/* Main scroll area; assistant tab is full-height chat (no outer scroll) */}
        <div
          className={cn(
            'flex-1 min-h-0',
            activeTab === 'assistant'
              ? 'flex flex-col overflow-hidden'
              : 'overflow-y-auto px-4 py-6 sm:px-6 sm:py-8 lg:px-10 lg:py-10 space-y-8',
          )}
        >
          {activeTab === 'assistant' ? (
            <AssistantPanel />
          ) : activeTab === 'analytics' ? (
            <AnalyticsView
              logs={logs}
              totalTrafficCounter={stats.totalTraffic}
              chartData={chartData}
              stats={{
                totalTraffic: stats.totalTraffic,
                attacksDetected: stats.attacksDetected,
                suspiciousFlagged: stats.suspiciousFlagged,
              }}
              onOpenDashboard={() => setActiveTab('dashboard')}
            />
          ) : activeTab === 'mllab' ? (
            <MlLabPage
              onLoadMlLabPcap={loadMlLabAlignedPcap}
              mlLabPcapBusy={mlLabBusy}
              onOpenDashboard={() => setActiveTab('dashboard')}
            />
          ) : activeTab === 'dashboard' ? (
            <>
              {/* Stats */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <StatCard
                  icon={<Wifi className="text-[var(--accent)]" size={20} />}
                  label="Flows"
                  value={stats.totalTraffic.toLocaleString()}
                  sub="In table"
                />
                <StatCard
                  icon={<AlertTriangle className="text-[#f72585]" size={20} />}
                  label="Malicious"
                  value={stats.attacksDetected.toLocaleString()}
                  sub="Detected"
                  trend={
                    stats.attacksDetected > 0
                      ? 'Elevated'
                      : stats.suspiciousFlagged > 0
                        ? 'Review'
                        : 'Clear'
                  }
                  trendColor={
                    stats.attacksDetected > 0
                      ? 'text-[#f72585]'
                      : stats.suspiciousFlagged > 0
                        ? 'text-[#fbbf24]'
                        : 'text-[#4ade80]'
                  }
                />
                <StatCard
                  icon={<ScanSearch className="text-[#fbbf24]" size={20} />}
                  label="Suspicious"
                  value={stats.suspiciousFlagged.toLocaleString()}
                  sub="Queue"
                  trend={stats.suspiciousFlagged > 0 ? 'Review' : '—'}
                  trendColor={stats.suspiciousFlagged > 0 ? 'text-[#fbbf24]' : 'text-[var(--text-secondary)]'}
                />
              </div>

              {ingestJob != null ? (
                <div className="mt-4 rounded-lg border border-[var(--border)] bg-[var(--bg-elevated)] px-4 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                    <span className="text-xs uppercase tracking-wide text-[var(--text-disabled)]">{pipelineEtaCaption}</span>
                    <span className="text-sm font-mono text-[var(--accent)]">{pipeEtaDisplay}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-[var(--surface-subtle)] overflow-hidden">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-violet-600 to-[var(--accent)] transition-[width] duration-200"
                      style={{ width: `${pipeProgressVal}%` }}
                    />
                  </div>
                  <p className="text-xs text-[var(--text-disabled)] mt-1.5 truncate">{pipePhase}</p>
                </div>
              ) : null}

              <PcapLibraryPanel
                layout="toolbar"
                onApplyFlows={applyPcapFlows}
                onIngestProgress={setIngestJob}
              />

              <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-subtle)]/60 px-3 py-2 text-xs text-[var(--text-secondary)]">
                Analyze in Dashboard = parse PCAP and score flows with the current RF/IF/AE bundle.
                It does not retrain models.
              </div>

              <FlowAnalysisFeed
                lines={analysisLogLines}
                busy={progressiveIngestBusy}
                inferenceStability={sessionInferenceStability}
              />

              {/* Logs Table */}
              <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-xl overflow-hidden">
                <div className="p-5 sm:p-6 border-b border-[var(--border)] flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <h3 className="text-base font-semibold flex items-center gap-2">
                      <Terminal size={18} className="text-[var(--text-secondary)]" />
                      Flows
                    </h3>
                    <p
                      className="text-xs text-[var(--text-disabled)] mt-1"
                      title={
                        vtApiConfigured
                          ? 'VirusTotal API key loaded on server.'
                          : 'Set VIRUSTOTAL_API_KEY in .env for IP/domain API lookups (GUI links always work).'
                      }
                    >
                      {!vtHealth.checked || vtApiConfigured === null ? (
                        <span>…</span>
                      ) : (
                        <>
                          <span className={vtApiConfigured ? 'text-[var(--text-muted)]' : 'text-amber-800 font-medium'}>
                            VT {vtApiConfigured ? 'API' : 'no key'}
                          </span>
                          <span className="text-[#3f3f46] mx-1.5">·</span>
                          <span className="text-[var(--text-muted)]">
                            LLM chat {isDeepSeekConfigured() ? 'on' : 'off'}
                          </span>
                        </>
                      )}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => void runBulkSuspiciousTriage()}
                      disabled={suspiciousRowCount === 0 || trafficRowJobBusyId != null}
                      aria-label={`Triage all Suspicious rows: Phase 1 VirusTotal cache, Phase 2 fixed lab ML scores (RF/IF/AE) fused with VT—does not retrain models; Phase 3 optional LLM narrative if configured. ${suspiciousRowCount} Suspicious rows.`}
                      title={
                        suspiciousRowCount === 0
                          ? 'No Suspicious rows'
                          : 'VT fills reputation cache → per-row fusion with pre-trained RF/IF/AE (weights unchanged); optional consolidated narrative if DEEPSEEK_API_KEY is set'
                      }
                      className={cn(
                        'px-3 py-1.5 rounded text-sm uppercase transition-colors flex items-center gap-2 border',
                        suspiciousRowCount > 0 && trafficRowJobBusyId == null
                          ? 'border-cyan-500/45 bg-cyan-100 text-cyan-950 hover:bg-cyan-200/90'
                          : 'border-[var(--border)] bg-[var(--surface-hover)] text-[var(--text-disabled)] cursor-not-allowed',
                      )}
                    >
                      <Sparkles size={14} aria-hidden />
                      Triage all Suspicious ({suspiciousRowCount})
                    </button>
                    <button
                      type="button"
                      onClick={() => setExcelExportDialogOpen(true)}
                      disabled={logs.length === 0}
                      className={cn(
                        'px-3 py-1.5 rounded text-sm uppercase transition-colors flex items-center gap-2',
                        logs.length > 0
                          ? 'bg-[var(--accent)] text-[#121214] hover:bg-[var(--accent)]/90'
                          : 'bg-[var(--surface-hover)] text-[var(--text-secondary)] cursor-not-allowed',
                      )}
                    >
                      <Database size={12} aria-hidden />
                      Export Excel
                    </button>
                    <button
                      type="button"
                      onClick={() => void restoreLastSavedSession()}
                      disabled={!canRestoreSavedSession}
                      title={
                        canRestoreSavedSession
                          ? 'Load the last saved flow session from this browser (same machine)'
                          : 'No saved traffic in local storage'
                      }
                      className={cn(
                        'px-3 py-1.5 rounded text-sm uppercase transition-colors flex items-center gap-2 border',
                        canRestoreSavedSession
                          ? 'bg-[var(--surface-subtle)] border-[var(--border)] hover:bg-[var(--surface-hover)] text-[var(--text-primary)]'
                          : 'bg-[var(--surface-hover)] border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed',
                      )}
                    >
                      <History size={14} aria-hidden />
                      Restore last session
                    </button>
                    <button
                      type="button"
                      onClick={() => setResetDashboardDialogOpen(true)}
                      title="Clear the traffic table, charts, and saved results"
                      className="px-3 py-1.5 bg-[var(--surface-subtle)] border border-[var(--border)] rounded text-sm uppercase hover:bg-[var(--surface-hover)] transition-colors"
                    >
                      Reset dashboard
                    </button>
                  </div>
                </div>
                {bulkTriageProgress ? (
                  <div
                    className="px-6 pb-4 border-b border-[var(--border)] bg-[var(--surface-subtle)]/50"
                    role="status"
                    aria-live="polite"
                    aria-busy="true"
                    aria-label="Bulk suspicious triage progress"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                      <p className="text-sm text-[var(--text-soft)] min-w-0 flex-1 leading-snug">
                        {bulkTriageProgress.label}
                      </p>
                      <button
                        type="button"
                        ref={bulkProgressCancelRef}
                        onClick={() => bulkTriageAbortRef.current?.abort()}
                        className="shrink-0 text-xs font-semibold uppercase tracking-wide text-amber-900 hover:text-amber-950 border border-amber-400 bg-amber-50 hover:bg-amber-100 rounded-lg px-3 py-1.5"
                        aria-label="Cancel bulk suspicious triage"
                      >
                        Cancel run
                      </button>
                    </div>
                    <div
                      className="h-2.5 rounded-full bg-[var(--surface-subtle)] border border-[var(--border)] overflow-hidden"
                      role="progressbar"
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-valuenow={bulkProgressPercent}
                      aria-valuetext={`${bulkProgressPercent}% complete`}
                      aria-label="Bulk triage progress"
                    >
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-cyan-600 to-violet-500 transition-[width] duration-300 ease-out"
                        style={{ width: `${bulkProgressPercent}%` }}
                      />
                    </div>
                    <p className="sr-only">
                      Phase {bulkTriageProgress.phase === 'vt' ? '1' : bulkTriageProgress.phase === 'ai' ? '2' : '3'} of
                      three. Step {bulkTriageProgress.current} of {bulkTriageProgress.total}.
                    </p>
                  </div>
                ) : null}
                <div className="px-6 py-3 border-b border-[var(--border)] flex flex-wrap gap-3 items-center gap-y-2 bg-[var(--surface-subtle)]/60">
                  <div className="flex items-center gap-2 flex-1 min-w-[min(100%,220px)] max-w-md">
                    <Search size={14} className="text-[var(--text-disabled)] shrink-0" aria-hidden />
                    <input
                      type="search"
                      value={trafficFilterText}
                      onChange={(e) => setTrafficFilterText(e.target.value)}
                      placeholder="Filter (IP, proto, status, notes…)"
                      className="w-full min-w-0 bg-[var(--bg-elevated)] border border-[var(--border)] rounded px-2.5 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-disabled)] focus:outline-none focus:ring-1 focus:ring-[var(--accent)]/50"
                      aria-label="Filter traffic table"
                    />
                  </div>
                  <label className="flex items-center gap-2 text-sm text-[var(--text-secondary)] shrink-0">
                    <span className="uppercase tracking-wider whitespace-nowrap">Plane</span>
                    <select
                      value={trafficPlaneFilter}
                      onChange={(e) =>
                        setTrafficPlaneFilter(e.target.value as 'all' | TrafficPlane)
                      }
                      className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded px-2 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--accent)]/50 max-w-[11rem]"
                    >
                      <option value="all">All planes</option>
                      <option value="USER_PLANE">User plane</option>
                      <option value="CONTROL_PLANE">Control plane</option>
                      <option value="BREAKOUT_AND_IP">Breakout / IP</option>
                    </select>
                  </label>
                  <label className="flex items-center gap-2 text-sm text-[var(--text-secondary)] shrink-0">
                    <span className="uppercase tracking-wider whitespace-nowrap">Status</span>
                    <select
                      value={trafficStatusFilter}
                      onChange={(e) =>
                        setTrafficStatusFilter(e.target.value as 'all' | TrafficStatus)
                      }
                      className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded px-2 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--accent)]/50"
                    >
                      <option value="all">All</option>
                      <option value="Benign">Clean</option>
                      <option value="Suspicious">Suspicious</option>
                      <option value="Malicious">Malicious</option>
                    </select>
                  </label>
                  <span className="text-sm text-[var(--text-disabled)] font-mono whitespace-nowrap">
                    {displayedLogs.length > 0
                      ? `Page ${trafficPage}/${trafficTotalPages} · `
                      : ''}
                    {displayedLogs.length}/{logs.length} rows
                  </span>
                  <TrafficColumnSettingsPanel prefs={trafficColPrefs} onChange={setTrafficColPrefs} />
                </div>
                {logs.length === 0 ? (
                  <div className="px-6 py-14 text-center text-[var(--text-secondary)] border-t border-[var(--border)]">
                    <div className="flex flex-col items-center gap-4 max-w-lg mx-auto">
                      <Activity size={36} className="opacity-25" aria-hidden />
                      <p className="text-base leading-relaxed text-[var(--text-secondary)]">
                        No flows yet. Pick a file in <strong className="text-[var(--text-primary)]">PCAP</strong> and press{' '}
                        <strong className="text-[var(--text-primary)]">Analyze</strong>, or upload a capture.
                      </p>
                    </div>
                  </div>
                ) : logs.length > 0 && displayedLogs.length === 0 ? (
                  <div className="px-6 py-10 text-center text-[var(--text-secondary)] border-t border-[var(--border)]">
                    <p className="max-w-md mx-auto text-sm">
                      No rows match the current filter or status. Clear the search box or set Status to{' '}
                      <strong className="text-[var(--text-primary)]">All</strong>.
                    </p>
                  </div>
                ) : (
                  <TrafficDataTable
                    visibleColumns={visibleTrafficColumns}
                    sortKey={trafficSortKey}
                    sortDir={trafficSortDir}
                    onSort={toggleTrafficSort}
                    logs={pagedTrafficLogs}
                    vtIpForUi={vtIpForUi}
                    trafficRowJobBusyId={trafficRowJobBusyId}
                    bulkBusyId={BULK_TRIAGE_BUSY_ID}
                    vtApiConfigured={vtApiConfigured}
                    onVtApiStart={(id) => setTrafficRowJobBusyId(id)}
                    onVtApiEnd={() => setTrafficRowJobBusyId(null)}
                    runVtEnrichForRow={runVtEnrichForRow}
                    onReanalyzeRow={(id) => runReanalyzeOne(id)}
                    onSuspiciousAutoTriage={(log) => void runSuspiciousAutoTriage(log)}
                    onToast={pushAppToast}
                    updateTrafficRowStatus={updateTrafficRowStatus}
                  />
                )}
                {displayedLogs.length > 0 ? (
                  <div className="px-6 py-3 border-t border-[var(--border)] bg-[var(--surface-subtle)]/40 flex flex-wrap items-center justify-between gap-3 text-sm text-[var(--text-secondary)]">
                    <span className="font-mono tabular-nums">
                      {(trafficPage - 1) * TRAFFIC_PAGE_SIZE + 1}–
                      {Math.min(trafficPage * TRAFFIC_PAGE_SIZE, displayedLogs.length)} of{' '}
                      {displayedLogs.length}
                      {displayedLogs.length !== logs.length ? ` (${logs.length} total)` : ''}
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={trafficPage <= 1}
                        onClick={() => setTrafficPage((p) => Math.max(1, p - 1))}
                        className={cn(
                          'inline-flex items-center gap-1 rounded-lg border px-3 py-1.5 text-xs font-semibold uppercase tracking-wide transition-colors',
                          trafficPage <= 1
                            ? 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed'
                            : 'border-[var(--border-strong)] text-[var(--text-primary)] hover:bg-[var(--surface-hover)]',
                        )}
                      >
                        <ChevronLeft size={16} aria-hidden />
                        Prev
                      </button>
                      <span className="text-xs text-[var(--text-disabled)] px-1">
                        {trafficPage} / {trafficTotalPages}
                      </span>
                      <button
                        type="button"
                        disabled={trafficPage >= trafficTotalPages}
                        onClick={() =>
                          setTrafficPage((p) => {
                            const maxP = Math.max(
                              1,
                              Math.ceil(displayedLogsRef.current.length / TRAFFIC_PAGE_SIZE),
                            );
                            return Math.min(maxP, p + 1);
                          })
                        }
                        className={cn(
                          'inline-flex items-center gap-1 rounded-lg border px-3 py-1.5 text-xs font-semibold uppercase tracking-wide transition-colors',
                          trafficPage >= trafficTotalPages
                            ? 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed'
                            : 'border-[var(--border-strong)] text-[var(--text-primary)] hover:bg-[var(--surface-hover)]',
                        )}
                      >
                        Next
                        <ChevronRight size={16} aria-hidden />
                      </button>
                    </div>
                  </div>
                ) : null}
              </div>
            </>
          ) : null}
        </div>

        <footer
          role="contentinfo"
          aria-label="Application credits"
          className="shrink-0 border-t border-[var(--border)] bg-[var(--bg-elevated)] px-4 py-2.5 text-center text-[10px] sm:text-xs uppercase tracking-wider text-[var(--text-muted)] flex items-center justify-center"
        >
          <span className="font-medium text-[#b4b4be]">MNIDS CONTRIBUTORS</span>
          <span className="mx-2 text-[#4a4a55]" aria-hidden>
            ·
          </span>
          <span className="text-[#9a9aa8]">OPEN-SOURCE SECURITY LAB</span>
          <span className="mx-2 text-[#4a4a55]" aria-hidden>
            ·
          </span>
          <span>5G IDS RESEARCH DEMO</span>
        </footer>
      </main>

      {(activeTab === 'dashboard' || activeTab === 'analytics') && (
        <AiAssistLauncher
          open={aiDrawerOpen}
          onOpen={() => setAiDrawerOpen(true)}
          onClose={() => setAiDrawerOpen(false)}
        />
      )}

      <AnimatePresence>
        {appToast ? (
          <motion.div
            key={appToast.id}
            initial={{ opacity: 0, y: 14, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10 }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
            className={cn(
              'fixed bottom-6 right-6 z-[100] w-[min(100vw-2rem,22rem)] rounded-xl border px-4 py-3 shadow-2xl',
              appToast.variant === 'success' &&
                'border-emerald-200 bg-emerald-50 text-emerald-950',
              appToast.variant === 'warning' &&
                'border-amber-200 bg-amber-50 text-amber-950',
              appToast.variant === 'info' &&
                'border-sky-200 bg-[var(--bg-elevated)] text-[var(--text-primary)] backdrop-blur-md shadow-lg',
            )}
            role="status"
            aria-live="polite"
          >
            <div className="flex gap-3 items-start">
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold leading-snug">{appToast.title}</p>
                {appToast.body ? (
                  <p className="text-sm text-[var(--text-secondary)] mt-2 whitespace-pre-wrap leading-relaxed">
                    {appToast.body}
                  </p>
                ) : null}
              </div>
              <button
                type="button"
                onClick={dismissAppToast}
                className="shrink-0 rounded-lg p-1.5 opacity-75 hover:opacity-100 hover:bg-slate-100 transition-opacity"
                aria-label="Dismiss notification"
              >
                <X size={18} />
              </button>
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      <AnimatePresence>
        {patchSuccessModal ? (
          <motion.div
            key="patch-success-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="patch-success-title"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-[var(--overlay-scrim)] backdrop-blur-sm"
            onClick={() => setPatchSuccessModal(null)}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98, y: 6 }}
              transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
              className="w-full max-w-md rounded-2xl border border-emerald-500/35 bg-[var(--bg-elevated)] shadow-2xl shadow-black/50 p-6"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-xl bg-emerald-500/15 text-emerald-400 shrink-0">
                  <CheckCircle2 size={28} aria-hidden />
                </div>
                <div className="min-w-0 flex-1">
                  <h2
                    id="patch-success-title"
                    className="text-lg font-semibold text-[var(--text-primary)] tracking-tight"
                  >
                    Traffic table updated
                  </h2>
                  <p className="text-sm text-[var(--text-secondary)] mt-2 leading-relaxed">
                    The AI-suggested changes were applied to the dashboard and saved in this browser
                    (localStorage).
                  </p>
                  <dl className="mt-4 space-y-2 text-sm border border-[var(--border)] rounded-xl p-3 bg-[var(--surface-subtle)]/80">
                    <div>
                      <dt className="text-[var(--text-disabled)] uppercase text-xs tracking-wide">Flow</dt>
                      <dd className="font-mono text-[var(--text-primary)] mt-0.5 break-all">
                        {patchSuccessModal.sourceIP} → {patchSuccessModal.destIP}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-[var(--text-disabled)] uppercase text-xs tracking-wide">Status</dt>
                      <dd className="text-[var(--accent)] font-semibold mt-0.5">
                        {patchSuccessModal.statusLabel}
                      </dd>
                    </div>
                    {patchSuccessModal.attackType ? (
                      <div>
                        <dt className="text-[var(--text-disabled)] uppercase text-xs tracking-wide">Attack / type</dt>
                        <dd className="text-[var(--text-soft)] mt-0.5 break-words">{patchSuccessModal.attackType}</dd>
                      </div>
                    ) : null}
                    {patchSuccessModal.analystNote ? (
                      <div>
                        <dt className="text-[var(--text-disabled)] uppercase text-xs tracking-wide">Analyst note</dt>
                        <dd className="text-[var(--text-secondary)] mt-0.5 whitespace-pre-wrap break-words">
                          {patchSuccessModal.analystNote}
                        </dd>
                      </div>
                    ) : null}
                    <div>
                      <dt className="text-[var(--text-disabled)] uppercase text-xs tracking-wide">Row id</dt>
                      <dd className="font-mono text-xs text-[var(--text-disabled)] mt-0.5 break-all">
                        {patchSuccessModal.flowId}
                      </dd>
                    </div>
                  </dl>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setPatchSuccessModal(null)}
                className="mt-6 w-full rounded-xl bg-emerald-600 text-white text-sm font-bold uppercase tracking-wide py-3 hover:bg-emerald-500 transition-colors"
              >
                OK
              </button>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      <AnimatePresence>
        {triageReviewModal ? (
          <motion.div
            key="triage-review-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="triage-review-title"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-[var(--overlay-scrim)] backdrop-blur-sm"
            onClick={() => setTriageReviewModal(null)}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98, y: 6 }}
              transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
              className="w-full max-w-lg rounded-2xl border border-cyan-500/35 bg-[var(--bg-elevated)] shadow-2xl shadow-black/50 p-6 max-h-[min(90vh,640px)] flex flex-col"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-start gap-3 shrink-0">
                <div className="p-2 rounded-xl bg-cyan-500/15 text-cyan-800 shrink-0">
                  <Sparkles size={24} aria-hidden />
                </div>
                <div className="min-w-0 flex-1">
                  <h2
                    id="triage-review-title"
                    className="text-lg font-semibold text-[var(--text-primary)] tracking-tight"
                  >
                    Auto triage (VT + ML flows)
                  </h2>
                  <p className="text-xs text-[var(--text-disabled)] font-mono mt-1 break-all">
                    {triageReviewModal.log.sourceIP} → {triageReviewModal.log.destIP}
                  </p>
                </div>
              </div>
              <div className="mt-4 flex-1 min-h-0 overflow-y-auto rounded-xl border border-[var(--border)] bg-[var(--surface-subtle)]/80 p-3">
                <pre className="text-sm text-[var(--text-soft)] whitespace-pre-wrap break-words font-sans leading-relaxed">
                  {triageReviewModal.markdown}
                </pre>
              </div>
              <p className="text-xs text-[var(--text-muted)] mt-3">
                {triageApplyOk
                  ? 'A row patch was detected for this flow. Apply updates status, note, and confidence in the table.'
                  : 'No machine-readable patch for this row—use the text above or the AI panel to adjust manually.'}
              </p>
              <div className="mt-4 flex flex-wrap gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => setTriageReviewModal(null)}
                  className="flex-1 min-w-[8rem] rounded-xl border border-[var(--border-strong)] bg-[var(--surface-subtle)] text-sm font-semibold uppercase tracking-wide py-3 text-[var(--text-primary)] hover:bg-[var(--surface-hover)] transition-colors"
                  aria-label="Dismiss auto triage dialog without applying"
                >
                  Dismiss
                </button>
                <button
                  type="button"
                  disabled={!triageApplyOk || !triageApplyParsed}
                  onClick={() => {
                    if (!triageApplyParsed || !triageReviewModal) return;
                    if (triageApplyParsed.flowId !== triageReviewModal.log.id) return;
                    applyTrafficRowPatch(triageApplyParsed.flowId, triageApplyParsed.patch, {
                      fromAssistantButton: true,
                    });
                    setTriageReviewModal(null);
                  }}
                  className="flex-1 min-w-[8rem] rounded-xl bg-cyan-600 text-white text-sm font-bold uppercase tracking-wide py-3 hover:bg-cyan-500 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  aria-label="Apply suggested status and note to this traffic row"
                >
                  Apply to row
                </button>
              </div>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      <AnimatePresence>
        {bulkTriageSummaryModal ? (
          <motion.div
            key="bulk-triage-summary-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="bulk-summary-title"
            aria-describedby="bulk-summary-desc"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-[210] flex items-center justify-center p-4 bg-[var(--overlay-scrim)] backdrop-blur-sm"
            onClick={() => setBulkTriageSummaryModal(null)}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.97, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98, y: 8 }}
              transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
              className="w-full max-w-3xl max-h-[min(92vh,720px)] rounded-2xl border border-cyan-500/30 bg-[var(--bg-elevated)] shadow-2xl p-6 flex flex-col"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-start gap-3 shrink-0">
                <div className="p-2 rounded-xl bg-violet-500/15 text-violet-800 shrink-0">
                  <FileCode2 size={26} aria-hidden />
                </div>
                <div className="min-w-0 flex-1">
                  <h2
                    id="bulk-summary-title"
                    className="text-lg font-semibold text-[var(--text-primary)] tracking-tight"
                  >
                    Bulk triage complete
                  </h2>
                  <p
                    className="mt-2 rounded-lg border border-emerald-500/30 bg-emerald-100 px-3 py-2 text-sm text-emerald-950"
                    role="status"
                  >
                    Done — the traffic table was updated from this run. Close this dialog when you finish reviewing,
                    or use <span className="font-semibold">Re-apply parsed patches</span> if you reverted rows after
                    the run.
                  </p>
                  <p id="bulk-summary-desc" className="text-sm text-[var(--text-muted)] mt-2">
                    Triage patches combine VirusTotal with <strong className="text-[var(--text-secondary)]">fixed</strong> lab ML scores
                    (Random Forest, Isolation Forest, autoencoder). This run does <strong className="text-[var(--text-secondary)]">not</strong>{' '}
                    update or retrain those models—they are loaded artefacts. Rows were updated from the fused decision
                    logic (including VT-clean closure where applicable). Use this dialog for review; “Apply all” can
                    re-apply if you reverted rows.
                  </p>
                </div>
              </div>
              <div className="mt-4 flex-1 min-h-0 overflow-y-auto space-y-5 pr-1">
                <section aria-label="Per-row triage results">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-disabled)] mb-2">
                    Suspicious rows ({bulkTriageSummaryModal.rows.length})
                  </h3>
                  <ul className="space-y-3 text-sm">
                    {bulkTriageSummaryModal.rows.map((r) => (
                      <li
                        key={r.log.id}
                        className="rounded-lg border border-[var(--border)] bg-[var(--surface-subtle)]/80 p-3"
                      >
                        <p className="font-mono text-[var(--text-soft)] text-xs break-all">
                          {r.log.sourceIP} → {r.log.destIP}
                        </p>
                        <p className="text-xs text-[var(--text-disabled)] mt-1">
                          {r.parsed && r.parsed.flowId === r.log.id
                            ? `Parsed patch (status token: ${r.parsed.patch.status ?? '—'})`
                            : 'No mnids-patch parsed — review full text in export or AI panel'}
                        </p>
                        <details className="mt-2">
                          <summary className="cursor-pointer text-cyan-800 text-xs font-medium hover:text-cyan-950">
                            Full AI response
                          </summary>
                          <pre className="mt-2 text-xs text-[var(--text-secondary)] whitespace-pre-wrap break-words max-h-40 overflow-y-auto">
                            {r.markdown}
                          </pre>
                        </details>
                      </li>
                    ))}
                  </ul>
                </section>
                <section aria-label="Consolidated triage narrative">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-disabled)] mb-2">
                    Consolidated triage narrative
                  </h3>
                  <pre className="text-xs text-[var(--text-soft)] whitespace-pre-wrap break-words rounded-xl border border-[var(--border)] bg-[var(--surface-subtle)]/90 p-3 max-h-56 overflow-y-auto">
                    {bulkTriageSummaryModal.consolidatedMarkdown}
                  </pre>
                </section>
              </div>
              <div className="mt-4 flex flex-wrap gap-2 shrink-0 pt-2 border-t border-[var(--border)]">
                <button
                  type="button"
                  ref={bulkSummaryCloseRef}
                  onClick={() => setBulkTriageSummaryModal(null)}
                  className="flex-1 min-w-[8rem] rounded-xl border border-[var(--border-strong)] bg-[var(--surface-subtle)] text-sm font-semibold uppercase tracking-wide py-3 text-[var(--text-primary)] hover:bg-[var(--surface-hover)] transition-colors"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const modal = bulkTriageSummaryModal;
                    if (!modal) return;
                    let n = 0;
                    for (const r of modal.rows) {
                      if (r.parsed && r.parsed.flowId === r.log.id) {
                        applyTrafficRowPatch(r.parsed.flowId, r.parsed.patch, { silentBulk: true });
                        n += 1;
                      }
                    }
                    setBulkTriageSummaryModal(null);
                    pushAppToast({
                      title: 'Patches applied',
                      body:
                        n > 0
                          ? `${n} row(s) updated from bulk triage. Review the traffic table.`
                          : 'No matching patches to apply.',
                      variant: n > 0 ? 'success' : 'info',
                    });
                  }}
                  className="flex-1 min-w-[10rem] rounded-xl bg-violet-600 text-white text-sm font-bold uppercase tracking-wide py-3 hover:bg-violet-500 transition-colors"
                >
                  Re-apply parsed patches
                </button>
              </div>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      <AnimatePresence>
        {resetDashboardDialogOpen ? (
          <motion.div
            key="reset-dashboard-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="reset-dashboard-title"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[220] flex items-center justify-center p-4 bg-[var(--overlay-scrim)] backdrop-blur-sm"
            onClick={() => setResetDashboardDialogOpen(false)}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98, y: 6 }}
              transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
              className="w-full max-w-md rounded-2xl border border-amber-500/30 bg-[var(--bg-elevated)] shadow-2xl p-6"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-start gap-3 mb-5">
                <div className="p-2 rounded-xl bg-amber-500/15 text-amber-400 shrink-0">
                  <RotateCcw size={22} aria-hidden />
                </div>
                <div className="min-w-0">
                  <h2 id="reset-dashboard-title" className="text-lg font-semibold text-[var(--text-primary)]">
                    Reset dashboard?
                  </h2>
                  <p className="text-sm text-[var(--text-muted)] mt-1.5 leading-snug">
                    Clears traffic results and saved session. This cannot be undone.
                  </p>
                </div>
              </div>
              <div className="flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() => {
                    clearTrafficAndPersistence();
                    setResetDashboardDialogOpen(false);
                    pushAppToast({
                      title: 'Dashboard reset',
                      body: 'Results cleared. Load a PCAP from the library when you are ready.',
                      variant: 'info',
                    });
                  }}
                  className="w-full rounded-xl py-3 px-4 text-sm font-bold uppercase tracking-wide transition-colors bg-amber-600 text-[#121214] hover:bg-amber-500"
                >
                  Clear all results
                </button>
                <button
                  type="button"
                  onClick={() => setResetDashboardDialogOpen(false)}
                  className="w-full rounded-xl py-2.5 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                >
                  Cancel
                </button>
              </div>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      <AnimatePresence>
        {excelExportDialogOpen ? (
          <motion.div
            key="excel-export-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="excel-export-title"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[220] flex items-center justify-center p-4 bg-[var(--overlay-scrim)] backdrop-blur-sm"
            onClick={() => !excelExportBusy && setExcelExportDialogOpen(false)}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98, y: 6 }}
              transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
              className="w-full max-w-md rounded-2xl border border-[var(--accent)]/35 bg-[var(--bg-elevated)] shadow-2xl p-6"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-start gap-3 mb-4">
                <div className="p-2 rounded-xl bg-[var(--accent)]/15 text-[var(--accent)] shrink-0">
                  <Database size={22} aria-hidden />
                </div>
                <div className="min-w-0">
                  <h2 id="excel-export-title" className="text-lg font-semibold text-[var(--text-primary)]">
                    Export Excel workbook
                  </h2>
                  <p className="text-sm text-[var(--text-muted)] mt-1 leading-snug">
                    Default: data tables + Field guide (no API call). Optionally add an{' '}
                    <span className="text-[var(--accent)]">Executive summary</span> sheet via an OpenAI-compatible LLM (optional
                    key in <span className="font-mono text-[var(--text-secondary)]">.env</span>).
                  </p>
                </div>
              </div>
              <div className="flex flex-col gap-2">
                <button
                  type="button"
                  disabled={excelExportBusy}
                  onClick={() => void performExcelExport(true)}
                  className={cn(
                    'w-full rounded-xl py-3 px-4 text-sm font-bold uppercase tracking-wide transition-colors',
                    excelExportBusy
                      ? 'bg-[var(--surface-hover)] text-[var(--text-disabled)] cursor-not-allowed'
                      : 'bg-gradient-to-r from-cyan-600 to-violet-600 text-white hover:from-cyan-500 hover:to-violet-500',
                  )}
                >
                  {excelExportBusy ? 'Working…' : 'Export with optional LLM summary'}
                </button>
                <button
                  type="button"
                  disabled={excelExportBusy}
                  onClick={() => void performExcelExport(false)}
                  className={cn(
                    'w-full rounded-xl border py-3 px-4 text-sm font-semibold uppercase tracking-wide transition-colors',
                    excelExportBusy
                      ? 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed'
                      : 'border-[var(--accent)]/40 text-[var(--text-soft)] hover:bg-[var(--accent)]/10',
                  )}
                >
                  Spreadsheet only (recommended)
                </button>
                <button
                  type="button"
                  disabled={excelExportBusy}
                  onClick={() => setExcelExportDialogOpen(false)}
                  className="w-full rounded-xl py-2.5 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                >
                  Cancel
                </button>
              </div>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      {/* Chat Button */}
      <button
        onClick={() => setChatOpen(true)}
        className="fixed bottom-4 left-4 bg-blue-500 hover:bg-blue-600 text-white p-3 rounded-full shadow-lg transition"
        title="Open Deepseek Chat"
      >
        <MessageCircle size={24} />
      </button>

      {/* Chat Panel */}
      {chatOpen && <ChatPanel onClose={() => setChatOpen(false)} />}
    </div>
    </AssistantChatProvider>
  );
}

function NavItem({
  icon,
  label,
  subtitle,
  title: navTitle,
  active = false,
  collapsed = false,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  /** Second line when sidebar expanded (e.g. ML tab). */
  subtitle?: string;
  /** Extra tooltip; when collapsed, used for hover if set. */
  title?: string;
  active?: boolean;
  collapsed?: boolean;
  onClick?: () => void;
}) {
  const collapsedTitle = navTitle ?? (subtitle ? `${label} — ${subtitle}` : label);
  return (
    <button
      type="button"
      onClick={onClick}
      title={collapsed ? collapsedTitle : navTitle}
      className={cn(
        'w-full flex items-center rounded-lg text-sm transition-all text-left',
        collapsed ? 'justify-center px-2 py-2.5' : 'gap-3 px-4 py-2.5',
        active
          ? 'bg-[var(--accent-soft)] text-[var(--accent)] font-semibold ring-1 ring-inset ring-[var(--border-accent)]'
          : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)]',
      )}
    >
      <span className="shrink-0 flex items-center justify-center [&>svg]:shrink-0">{icon}</span>
      {collapsed ? (
        <span className="sr-only">{collapsedTitle}</span>
      ) : subtitle ? (
        <span className="min-w-0 flex flex-col gap-0.5">
          <span className="truncate leading-tight">{label}</span>
          <span
            className={cn(
              'truncate text-[11px] font-normal leading-tight',
              active ? 'text-[var(--accent)]/65' : 'text-[var(--text-disabled)]',
            )}
          >
            {subtitle}
          </span>
        </span>
      ) : (
        <span className="truncate">{label}</span>
      )}
    </button>
  );
}

function StatCard({ icon, label, value, sub, trend, trendColor }: { icon: React.ReactNode; label: string; value: string; sub: string; trend?: string; trendColor?: string }) {
  return (
    <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-xl p-6 shadow-[var(--shadow-card)] hover:border-[var(--accent)]/45 hover:shadow-[var(--shadow-float)] transition-[box-shadow,border-color] duration-200 group">
      <div className="flex items-center justify-between mb-4">
        <div className="p-2 bg-[var(--surface-subtle)] rounded-lg border border-[var(--border)] group-hover:border-[var(--accent)]/30 transition-colors">
          {icon}
        </div>
        {trend && (
          <span className={cn("text-sm font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[var(--surface-subtle)] border border-[var(--border)]", trendColor)}>
            {trend}
          </span>
        )}
      </div>
      <div className="space-y-1">
        <p className="text-base uppercase tracking-widest text-[var(--text-secondary)] font-medium">{label}</p>
        <h4 className="text-3xl font-bold font-mono tracking-tight">{value}</h4>
        <p className="text-base text-[var(--text-secondary)]">{sub}</p>
      </div>
    </div>
  );
}
