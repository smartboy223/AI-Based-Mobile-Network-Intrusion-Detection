import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  deepseekAskWithEvidenceAndHistory,
  fetchAssistantGreetingFromApi,
  isDeepSeekConfigured,
  sanitizeAssistantPublicMarkdown,
  staticAssistantGreetingMarkdown,
  type ChatMessage,
} from '../lib/deepseek';
import type { TrafficLog, SystemStats } from '../types';
import {
  parseMnidsRowPatch,
  type ApplyTrafficRowPatchOpts,
  type TrafficRowAiPatch,
} from '../lib/assistantPatch';
import { buildAssistantEvidenceJson, EVIDENCE_ROW_LIMIT } from '../lib/assistantEvidence';
import type { VtDomainClientResult, VtIpClientResult } from '../lib/virusTotal';

/** Bump when greetings/prompts change or legacy wording must be purged from localStorage (e.g. "Passive IDS" in cached chat). */
const STORAGE_KEY = 'mnids-assistant-chat-v4';
const ARCHIVES_STORAGE_KEY = 'mnids-assistant-chat-archives-v4';
const MAX_ARCHIVES = 40;
/** Last flow pinned in assistant (any tab). */
export const MNIDS_LAST_PINNED_FLOW_KEY = 'mnids-last-pinned-flow-v1';


export type ChatEntry = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: number;
};

/** Saved snapshot of a conversation (browser localStorage). */
export type ChatArchive = {
  id: string;
  savedAt: number;
  title: string;
  messages: ChatEntry[];
};

function loadMessages(): ChatEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    const rows = parsed.filter(
      (m): m is ChatEntry =>
        m &&
        typeof m === 'object' &&
        (m as ChatEntry).role &&
        typeof (m as ChatEntry).content === 'string',
    );
    return rows.map((m) =>
      m.role === 'assistant' ? { ...m, content: sanitizeAssistantPublicMarkdown(m.content) } : m,
    );
  } catch {
    return [];
  }
}

function saveMessages(messages: ChatEntry[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(messages));
  } catch {
    /* ignore quota */
  }
}

function loadArchives(): ChatArchive[] {
  try {
    const raw = localStorage.getItem(ARCHIVES_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (a): a is ChatArchive =>
        a &&
        typeof a === 'object' &&
        typeof (a as ChatArchive).id === 'string' &&
        typeof (a as ChatArchive).savedAt === 'number' &&
        typeof (a as ChatArchive).title === 'string' &&
        Array.isArray((a as ChatArchive).messages),
    );
  } catch {
    return [];
  }
}

function saveArchivesToStorage(list: ChatArchive[]) {
  try {
    localStorage.setItem(ARCHIVES_STORAGE_KEY, JSON.stringify(list));
  } catch {
    /* ignore quota */
  }
}

function archiveTitleFromMessages(messages: ChatEntry[]): string {
  const firstUser = messages.find((m) => m.role === 'user');
  if (firstUser?.content?.trim()) {
    const t = firstUser.content.trim().replace(/\s+/g, ' ');
    return t.length > 72 ? `${t.slice(0, 72)}…` : t;
  }
  return `Chat ${new Date().toLocaleString()}`;
}

function conversationHasUserTurns(entries: ChatEntry[]): boolean {
  return entries.some((m) => m.role === 'user');
}

function regenerateMessageIds(entries: ChatEntry[], prefix: string): ChatEntry[] {
  return entries.map((m, i) => ({
    ...m,
    id: `${prefix}-${i}-${m.createdAt}`,
  }));
}

let greetingPromise: Promise<string> | null = null;

function getGreetingOnce(): Promise<string> {
  if (!greetingPromise) {
    greetingPromise = (async () => {
      if (isDeepSeekConfigured()) {
        try {
          return await fetchAssistantGreetingFromApi();
        } catch {
          return staticAssistantGreetingMarkdown();
        }
      }
      return staticAssistantGreetingMarkdown();
    })();
  }
  return greetingPromise;
}

export function resetAssistantGreetingCache() {
  greetingPromise = null;
}

function chatEntriesToPriorTurns(entries: ChatEntry[]): ChatMessage[] {
  const firstUser = entries.findIndex((m) => m.role === 'user');
  const slice = firstUser < 0 ? [] : entries.slice(firstUser);
  return slice
    .filter((m) => m.role === 'user' || m.role === 'assistant')
    .map((m) => ({ role: m.role, content: m.content }));
}

type Ctx = {
  messages: ChatEntry[];
  sendMessage: (text: string) => Promise<void>;
  stopAssistant: () => void;
  clearHistory: () => void;
  archives: ChatArchive[];
  saveChatToArchive: () => void;
  /** Saves current chat to Past tasks (if you sent any messages), then clears for a fresh task. */
  startNewTask: () => void;
  restoreArchive: (archiveId: string) => void;
  deleteArchive: (archiveId: string) => void;
  loading: boolean;
  error: string | null;
  evidenceJson: string;
  evidenceRowLabel: string;
  hasTrafficEvidence: boolean;
  pinnedTrafficRow: TrafficLog | null;
  setPinnedTrafficRow: (log: TrafficLog | null) => void;
  applyTrafficRowPatch:
    | ((flowId: string, patch: TrafficRowAiPatch, opts?: ApplyTrafficRowPatchOpts) => void)
    | null;
};

const AssistantChatContext = createContext<Ctx | null>(null);

type ProviderProps = {
  children: React.ReactNode;
  logs: TrafficLog[];
  stats: Pick<SystemStats, 'totalTraffic' | 'attacksDetected' | 'suspiciousFlagged'>;
  sessionSavedAt: number | null;
  /** Flow id from ?pin= when opening assistant in a new browser tab */
  deeplinkPinFlowId?: string | null;
  applyTrafficRowPatch?: (
    flowId: string,
    patch: TrafficRowAiPatch,
    opts?: ApplyTrafficRowPatchOpts,
  ) => void;
  /** Saved VirusTotal IPv4 results; included in assistant evidence as virusTotalByIp. */
  vtIpReputation?: Record<string, VtIpClientResult>;
  /** Saved VirusTotal domain results; included as virusTotalByDomain. */
  vtDomainReputation?: Record<string, VtDomainClientResult>;
  /**
   * True while the full Assistant tab or the floating AI drawer is open.
   * When this flips true → false, an in-progress or finished chat is archived and cleared so reopening does not look like an unfinished task.
   */
  assistantSurfaceActive?: boolean;
};

export function AssistantChatProvider({
  children,
  logs,
  stats,
  sessionSavedAt,
  deeplinkPinFlowId = null,
  applyTrafficRowPatch,
  vtIpReputation = {},
  vtDomainReputation = {},
  assistantSurfaceActive = false,
}: ProviderProps) {
  const [messages, setMessages] = useState<ChatEntry[]>(() => loadMessages());
  const [archives, setArchives] = useState<ChatArchive[]>(() => loadArchives());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pinnedTrafficRow, setPinnedTrafficRow] = useState<TrafficLog | null>(null);
  const chatAbortRef = useRef<AbortController | null>(null);
  const sendMessageRef = useRef<(text: string) => Promise<void>>(async () => {});
  const messagesRef = useRef<ChatEntry[]>([]);
  const loadingRef = useRef(false);
  const prevAssistantSurfaceRef = useRef<boolean | null>(null);

  messagesRef.current = messages;
  loadingRef.current = loading;

  useEffect(() => {
    if (!deeplinkPinFlowId) return;
    const hit = logs.find((l) => l.id === deeplinkPinFlowId);
    if (hit) {
      setPinnedTrafficRow(hit);
      return;
    }
    // Logs in this tab don't contain the flow yet. Try localStorage regardless
    // of `logs.length` — the source tab seeds MNIDS_LAST_PINNED_FLOW_KEY with
    // the clicked row before window.open, so it's the authoritative source
    // for the deeplink. Previously this fallback only ran when logs.length===0,
    // which missed the common case of "new tab loaded with a session snapshot
    // that doesn't include the freshly-clicked flow id".
    try {
      const lastSaved = localStorage.getItem(MNIDS_LAST_PINNED_FLOW_KEY);
      if (lastSaved) {
        const saved = JSON.parse(lastSaved) as TrafficLog;
        if (saved && saved.id === deeplinkPinFlowId) {
          setPinnedTrafficRow(saved);
        }
      }
    } catch {
      /* ignore parse errors */
    }
  }, [deeplinkPinFlowId, logs]);

  useEffect(() => {
    if (!pinnedTrafficRow) return;
    try {
      localStorage.setItem(MNIDS_LAST_PINNED_FLOW_KEY, JSON.stringify(pinnedTrafficRow));
    } catch {
      /* quota */
    }
  }, [pinnedTrafficRow]);

  const evidenceJson = useMemo(
    () =>
      buildAssistantEvidenceJson(
        logs,
        stats,
        sessionSavedAt,
        pinnedTrafficRow,
        vtIpReputation,
        vtDomainReputation,
      ),
    [logs, stats, sessionSavedAt, pinnedTrafficRow, vtIpReputation, vtDomainReputation],
  );
  const evidenceRowLabel =
    logs.length === 0 ? '0 rows' : `${Math.min(logs.length, EVIDENCE_ROW_LIMIT)} / ${logs.length}`;
  const hasTrafficEvidence = logs.length > 0;

  const sendMessage = useCallback(
    async (text: string) => {
      const trimmed = text.trim();
      if (!trimmed) return;
      if (!isDeepSeekConfigured()) {
        setError('Backend reports no DEEPSEEK_API_KEY. Add it to backend/.env and restart the server.');
        return;
      }

      chatAbortRef.current?.abort();
      const ac = new AbortController();
      chatAbortRef.current = ac;
      const signal = ac.signal;

      const priorTurns = chatEntriesToPriorTurns(messages);
      const pinAtSend = pinnedTrafficRow;
      const userMsg: ChatEntry = {
        id: `u-${Date.now()}`,
        role: 'user',
        content: trimmed,
        createdAt: Date.now(),
      };
      setMessages((m) => [...m, userMsg]);
      setLoading(true);
      setError(null);

      try {
        const expanded = pinnedTrafficRow != null;
        const reply = await deepseekAskWithEvidenceAndHistory(
          priorTurns,
          trimmed,
          evidenceJson,
          {
            maxTokens: expanded ? 2048 : 896,
            signal,
          },
        );
        const assistantMsg: ChatEntry = {
          id: `a-${Date.now()}`,
          role: 'assistant',
          content: reply,
          createdAt: Date.now(),
        };
        setMessages((m) => [...m, assistantMsg]);

        if (!signal.aborted && applyTrafficRowPatch && pinAtSend) {
          const parsed = parseMnidsRowPatch(reply);
          if (parsed && parsed.flowId === pinAtSend.id) {
            applyTrafficRowPatch(parsed.flowId, parsed.patch);
          }
        }
      } catch (e) {
        if (e instanceof DOMException && e.name === 'AbortError') {
          return;
        }
        if (e instanceof Error && e.name === 'AbortError') {
          return;
        }
        setError(e instanceof Error ? e.message : 'Request failed');
      } finally {
        setLoading(false);
        if (chatAbortRef.current === ac) chatAbortRef.current = null;
      }
    },
    [applyTrafficRowPatch, evidenceJson, messages, pinnedTrafficRow],
  );

  sendMessageRef.current = sendMessage;

  useEffect(() => {
    saveMessages(messages);
  }, [messages]);

  useEffect(() => {
    saveArchivesToStorage(archives);
  }, [archives]);

  useEffect(() => {
    if (messages.length > 0) return;
    let cancelled = false;
    getGreetingOnce().then((text) => {
      if (cancelled) return;
      setMessages((m) => {
        if (m.length > 0) return m;
        return [{ id: `g-${Date.now()}`, role: 'assistant', content: text, createdAt: Date.now() }];
      });
    });
    return () => {
      cancelled = true;
    };
  }, [messages.length]);

  const stopAssistant = useCallback(() => {
    chatAbortRef.current?.abort();
  }, []);

  const clearHistory = useCallback(() => {
    chatAbortRef.current?.abort();
    chatAbortRef.current = null;
    resetAssistantGreetingCache();
    localStorage.removeItem(STORAGE_KEY);
    setMessages([]);
    setError(null);
    setLoading(false);
  }, []);

  /** When the user leaves the Assistant tab or closes the AI drawer, archive any real conversation and reset to a fresh greeting. */
  useEffect(() => {
    const prev = prevAssistantSurfaceRef.current;
    prevAssistantSurfaceRef.current = assistantSurfaceActive;
    if (prev === null) return;
    if (prev !== true || assistantSurfaceActive !== false) return;

    chatAbortRef.current?.abort();
    const msgs = messagesRef.current;
    if (!conversationHasUserTurns(msgs)) return;

    const snapshot = msgs.map((m) => ({ ...m }));
    const busy = loadingRef.current;
    const baseTitle = archiveTitleFromMessages(snapshot);
    const entry: ChatArchive = {
      id: `arch-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      savedAt: Date.now(),
      title: busy ? `${baseTitle} (reply interrupted)` : baseTitle,
      messages: snapshot,
    };
    setArchives((a) => [entry, ...a].slice(0, MAX_ARCHIVES));
    clearHistory();
  }, [assistantSurfaceActive, clearHistory]);

  const saveChatToArchive = useCallback(() => {
    if (messages.length === 0) return;
    const snapshot = messages.map((m) => ({ ...m }));
    const entry: ChatArchive = {
      id: `arch-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      savedAt: Date.now(),
      title: archiveTitleFromMessages(snapshot),
      messages: snapshot,
    };
    setArchives((prev) => [entry, ...prev].slice(0, MAX_ARCHIVES));
  }, [messages]);

  const startNewTask = useCallback(() => {
    if (loading) return;
    if (conversationHasUserTurns(messages)) {
      const snapshot = messages.map((m) => ({ ...m }));
      const entry: ChatArchive = {
        id: `arch-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        savedAt: Date.now(),
        title: archiveTitleFromMessages(snapshot),
        messages: snapshot,
      };
      setArchives((prev) => [entry, ...prev].slice(0, MAX_ARCHIVES));
    }
    clearHistory();
  }, [messages, loading, clearHistory]);

  const restoreArchive = useCallback(
    (archiveId: string) => {
      const a = archives.find((x) => x.id === archiveId);
      if (!a) return;
      if (
        !confirm(
          'Open this past task? Unsaved messages in the current chat will be lost—use New task first to save them.',
        )
      ) {
        return;
      }
      chatAbortRef.current?.abort();
      chatAbortRef.current = null;
      setError(null);
      setLoading(false);
      setMessages(regenerateMessageIds(
        a.messages.map((m) =>
          m.role === 'assistant' ? { ...m, content: sanitizeAssistantPublicMarkdown(m.content) } : m,
        ),
        `r-${a.id}`,
      ));
    },
    [archives],
  );

  const deleteArchive = useCallback((archiveId: string) => {
    if (!confirm('Remove this past task from this browser?')) return;
    setArchives((prev) => prev.filter((x) => x.id !== archiveId));
  }, []);

  const value = useMemo(
    () => ({
      messages,
      sendMessage,
      stopAssistant,
      clearHistory,
      archives,
      saveChatToArchive,
      startNewTask,
      restoreArchive,
      deleteArchive,
      loading,
      error,
      evidenceJson,
      evidenceRowLabel,
      hasTrafficEvidence,
      pinnedTrafficRow,
      setPinnedTrafficRow,
      applyTrafficRowPatch: applyTrafficRowPatch ?? null,
    }),
    [
      messages,
      sendMessage,
      stopAssistant,
      clearHistory,
      archives,
      saveChatToArchive,
      startNewTask,
      restoreArchive,
      deleteArchive,
      loading,
      error,
      evidenceJson,
      evidenceRowLabel,
      hasTrafficEvidence,
      pinnedTrafficRow,
      applyTrafficRowPatch,
    ],
  );

  return <AssistantChatContext.Provider value={value}>{children}</AssistantChatContext.Provider>;
}

export function useAssistantChat() {
  const ctx = useContext(AssistantChatContext);
  if (!ctx) throw new Error('useAssistantChat must be used within AssistantChatProvider');
  return ctx;
}
