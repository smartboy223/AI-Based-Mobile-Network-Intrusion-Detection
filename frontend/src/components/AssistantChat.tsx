import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  Send,
  Loader2,
  AlertCircle,
  Trash2,
  Square,
  Archive,
  ChevronDown,
  ChevronUp,
  RotateCcw,
  ListRestart,
} from 'lucide-react';
import { cn } from '../lib/utils';
import { useAssistantChat } from '../context/AssistantChatContext';
import { AssistantMarkdown } from './AssistantMarkdown';
import { AssistantPatchActions } from './AssistantPatchActions';
import { isDeepSeekConfigured, refreshDeepSeekConfigured } from '../lib/deepseek';
import { trafficStatusLabel } from '../types';

const COMPOSER_STORAGE_KEY = 'mnids-assistant-composer-v1';

function loadStoredComposer(): { draft: string } {
  try {
    const raw = localStorage.getItem(COMPOSER_STORAGE_KEY);
    if (!raw) return { draft: '' };
    const p = JSON.parse(raw) as { draft?: unknown; focusIp?: unknown };
    return {
      draft: typeof p.draft === 'string' ? p.draft : '',
    };
  } catch {
    return { draft: '' };
  }
}

function storeComposer(draft: string) {
  try {
    localStorage.setItem(COMPOSER_STORAGE_KEY, JSON.stringify({ draft }));
  } catch {
    /* quota */
  }
}

type Props = {
  /** Side drawer (compact) vs full AI tab */
  variant?: 'drawer' | 'fullPage';
};

export function AssistantChat({ variant = 'drawer' }: Props) {
  const isFull = variant === 'fullPage';
  // Probe backend at mount so the "Add DEEPSEEK_API_KEY" banner reflects the
  // real server config (key lives in backend/.env, not the browser bundle).
  const [, setProbeTick] = useState(0);
  useEffect(() => {
    let cancelled = false;
    void refreshDeepSeekConfigured().then(() => {
      if (!cancelled) setProbeTick((n) => n + 1);
    });
    return () => {
      cancelled = true;
    };
  }, []);
  const {
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
    pinnedTrafficRow,
    setPinnedTrafficRow,
  } = useAssistantChat();
  const initialComposer = useMemo(() => loadStoredComposer(), []);
  const [draft, setDraft] = useState(initialComposer.draft);
  const [archivesOpen, setArchivesOpen] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const composerMinH = isFull ? 44 : 40;
  const composerMaxH = isFull ? 180 : 160;

  const adjustComposerHeight = useCallback(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    const sh = el.scrollHeight;
    const next = Math.min(composerMaxH, Math.max(composerMinH, sh));
    el.style.height = `${next}px`;
    el.style.overflowY = sh > composerMaxH ? 'auto' : 'hidden';
  }, [composerMinH, composerMaxH]);

  useLayoutEffect(() => {
    adjustComposerHeight();
  }, [draft, adjustComposerHeight, isFull]);

  useEffect(() => {
    const t = window.setTimeout(() => storeComposer(draft), 300);
    return () => window.clearTimeout(t);
  }, [draft]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft.trim() || loading) return;
    const t = draft;
    setDraft('');
    await sendMessage(t);
  };

  return (
    <div
      className={cn(
        'flex flex-col h-full min-h-0 select-text',
        isFull ? 'p-4 sm:p-5' : 'min-h-[320px]',
      )}
    >
      <div
        className={cn(
          'flex-1 overflow-y-auto space-y-3 pr-1 min-h-0',
          !isFull && 'max-h-[calc(100vh-200px)]',
        )}
      >
        {pinnedTrafficRow && (
          <div className="space-y-2 shrink-0">
            {pinnedTrafficRow && (
              <div className="rounded-lg border border-violet-200 bg-violet-50 px-3 py-2.5 text-base text-violet-950">
                <div className="flex items-start justify-between gap-2">
                  <span>
                    <strong className="text-violet-900">Pinned flow</strong>{' '}
                    <span className="font-mono text-violet-800">
                      {pinnedTrafficRow.sourceIP} → {pinnedTrafficRow.destIP}
                    </span>{' '}
                    <span className="text-[var(--text-secondary)]">({trafficStatusLabel(pinnedTrafficRow.status)})</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => setPinnedTrafficRow(null)}
                    className="shrink-0 text-sm uppercase tracking-wide text-violet-700 hover:text-violet-950"
                  >
                    Clear
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
        <div className="flex flex-wrap items-center justify-between gap-2 shrink-0">
          <div className="min-w-0">
            <span className="text-sm uppercase tracking-wider text-[var(--text-secondary)]">
              {isFull ? 'Current task' : 'Chat'}
            </span>
            <p className="text-[10px] text-[var(--text-disabled)] mt-0.5 max-w-xl leading-snug">
              <strong className="text-[var(--text-disabled)] font-medium">New task</strong> archives this chat and starts fresh.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 justify-end shrink-0">
            <button
              type="button"
              disabled={loading}
              title="Save chat to Past tasks (if you sent messages), then start a new task"
              onClick={() => {
                const hadUser = messages.some((m) => m.role === 'user');
                startNewTask();
                if (hadUser) setArchivesOpen(true);
              }}
              className="flex items-center gap-1.5 text-xs sm:text-sm font-semibold uppercase tracking-wide text-white bg-violet-600 hover:bg-violet-700 px-3 py-2 rounded-lg border border-violet-500 disabled:opacity-40"
            >
              <ListRestart size={16} aria-hidden />
              New task
            </button>
            <button
              type="button"
              disabled={loading}
              title="Discard this chat without saving to Past tasks"
              onClick={() => {
                if (messages.length === 0) return;
                if (
                  !confirm(
                    'Discard this chat without saving? Use New task if you want it kept under Past tasks.',
                  )
                ) {
                  return;
                }
                clearHistory();
              }}
              className="flex items-center gap-1.5 text-[11px] sm:text-xs uppercase text-red-700 hover:text-red-900 px-2.5 py-2 rounded-lg border border-red-500/25 hover:bg-red-500/10"
            >
              <Trash2 size={14} aria-hidden />
              Discard
            </button>
          </div>
        </div>

        {messages.map((m) => (
          <div
            key={m.id}
            className={cn(
              'rounded-xl border px-3 py-3',
              isFull && 'px-4 py-3.5',
              m.role === 'user'
                ? 'border-[var(--accent)]/25 bg-[var(--accent)]/5 ml-2 sm:ml-6'
                : 'border-[var(--border)] bg-[var(--surface-subtle)] mr-2 sm:mr-6',
            )}
          >
            <div className="text-sm uppercase tracking-wider mb-2 text-[var(--text-secondary)]">
              {m.role === 'user' ? 'You' : 'Assistant'}
              <span className="text-[var(--text-disabled)] font-mono normal-case ml-2 text-xs">
                {new Date(m.createdAt).toLocaleString()}
              </span>
            </div>
            {m.role === 'user' ? (
              <p
                className={cn(
                  'text-[var(--text-primary)] whitespace-pre-wrap leading-relaxed',
                  isFull ? 'text-lg' : 'text-base',
                )}
              >
                {m.content}
              </p>
            ) : (
              <>
                <AssistantMarkdown
                  content={m.content.trim() ? m.content : '_The assistant returned no visible text. Try again or check the API._'}
                  comfortable={isFull}
                />
                <AssistantPatchActions messageContent={m.content} />
              </>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex flex-wrap items-center justify-between gap-2 text-base text-[var(--text-secondary)] py-2">
            <div className="flex items-center gap-2 min-w-0">
              <Loader2 size={18} className="animate-spin text-[var(--accent)] shrink-0" />
              <span>Working… you can stop if it loops or hangs.</span>
            </div>
            <button
              type="button"
              onClick={stopAssistant}
              className="inline-flex items-center gap-2 shrink-0 rounded-lg border border-red-500/40 bg-red-500/15 px-3 py-2 text-sm font-semibold uppercase tracking-wide text-red-800 hover:bg-red-500/25"
            >
              <Square size={14} className="fill-current" aria-hidden />
              Stop
            </button>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {!isDeepSeekConfigured() && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-amber-500/25 bg-amber-500/5 p-3 text-sm text-amber-950 shrink-0">
          <AlertCircle size={18} className="shrink-0 mt-0.5 text-amber-800" />
          <span>
            Backend reports no <code className="bg-[var(--surface-subtle)] px-1.5 py-0.5 rounded text-sm">DEEPSEEK_API_KEY</code>.
            Set it in <code className="bg-[var(--surface-subtle)] px-1.5 py-0.5 rounded text-sm">backend/.env</code> and restart the server.
          </span>
        </div>
      )}

      {error && (
        <div className="mt-2 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-900 shrink-0">
          <AlertCircle size={16} className="shrink-0 text-red-700" />
          <span className="font-mono break-all">{error}</span>
        </div>
      )}

      {!isFull && (
        <p className="mt-2 text-xs text-[var(--text-disabled)] shrink-0 leading-snug">
          Each question includes fresh table evidence. <strong className="text-[var(--text-muted)]">New task</strong> → fresh chat.
        </p>
      )}

      <div
        className={cn(
          'mt-3 rounded-xl border border-[var(--border)] bg-[var(--surface-subtle)]/80 shrink-0 overflow-hidden',
          isFull && 'mt-4',
        )}
      >
        <button
          type="button"
          onClick={() => setArchivesOpen((o) => !o)}
          className="w-full flex items-center justify-between gap-2 px-3 py-2.5 text-left text-sm text-[var(--text-secondary)] hover:bg-[var(--bg-elevated)]/80 transition-colors"
          aria-expanded={archivesOpen}
        >
          <span className="uppercase tracking-wider font-mono text-xs">
            Past tasks
            <span className="text-[var(--text-disabled)] font-sans normal-case ml-2">({archives.length})</span>
          </span>
          {archivesOpen ? <ChevronUp size={18} className="shrink-0" /> : <ChevronDown size={18} className="shrink-0" />}
        </button>
        {archivesOpen && (
          <div className="border-t border-[var(--border)] max-h-48 overflow-y-auto">
            <div className="px-3 py-2 flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)]/60">
              <p className="text-[10px] text-[var(--text-disabled)] leading-snug">
                Saved automatically when you click <strong className="text-[var(--text-muted)]">New task</strong> after sending messages.
              </p>
              <button
                type="button"
                disabled={messages.length === 0 || loading}
                title="Add a copy of the current chat without starting a new task"
                onClick={() => {
                  saveChatToArchive();
                }}
                className="inline-flex items-center gap-1 text-[10px] uppercase text-[var(--text-secondary)] hover:text-[var(--text-primary)] px-2 py-1 rounded border border-[var(--border-strong)] hover:bg-[var(--surface-hover)] disabled:opacity-40"
              >
                <Archive size={12} aria-hidden />
                Save copy
              </button>
            </div>
            {archives.length === 0 ? (
              <p className="px-3 py-3 text-xs text-[var(--text-disabled)]">No past tasks yet. Send a message, then use New task to save here.</p>
            ) : (
              <ul className="divide-y divide-[var(--border)]/70">
                {archives.map((a) => (
                  <li key={a.id} className="px-3 py-2.5 flex flex-col sm:flex-row sm:items-center gap-2">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-[var(--text-primary)] leading-snug line-clamp-2" title={a.title}>
                        {a.title}
                      </p>
                      <p className="text-[10px] text-[var(--text-disabled)] mt-0.5 tabular-nums">
                        {new Date(a.savedAt).toLocaleString()} · {a.messages.length} messages
                      </p>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <button
                        type="button"
                        onClick={() => restoreArchive(a.id)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded-md border border-[var(--border-strong)] text-[11px] uppercase text-[var(--accent)] hover:bg-[var(--accent)]/10"
                      >
                        <RotateCcw size={12} aria-hidden />
                        Restore
                      </button>
                      <button
                        type="button"
                        onClick={() => deleteArchive(a.id)}
                        className="inline-flex items-center gap-1 p-1.5 rounded-md border border-red-500/25 text-red-400/90 hover:bg-red-500/10"
                        aria-label="Delete archive"
                      >
                        <Trash2 size={14} aria-hidden />
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      <form onSubmit={handleSubmit} className={cn('mt-3 flex flex-col gap-3 shrink-0', isFull && 'mt-4 gap-3')}>
        <div className={cn('flex gap-3 flex-wrap', !isFull && 'flex-col sm:flex-row')}>
          <label htmlFor="assistant-chat-input" className="sr-only">
            Message to AI assistant
          </label>
          <textarea
            ref={textareaRef}
            id="assistant-chat-input"
            name="mnids-assistant-message"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            disabled={loading || !isDeepSeekConfigured()}
            rows={1}
            autoComplete="off"
            spellCheck={true}
            placeholder={
              isDeepSeekConfigured()
                ? isFull
                  ? 'Type or paste… Enter = send, Shift+Enter = new line'
                  : 'Type or paste… Enter = send, Shift+Enter = new line'
                : 'Set API key in .env to chat…'
            }
            className={cn(
              'flex-1 rounded-xl border border-[var(--border)] bg-[var(--surface-subtle)] px-4 py-2.5 text-[var(--text-primary)] resize-none min-h-0 block w-full',
              'select-text cursor-text selection:bg-violet-500/35',
              isFull
                ? 'text-lg leading-relaxed placeholder:text-[var(--text-disabled)] focus:outline-none focus:border-violet-500/45'
                : 'text-base leading-relaxed px-3 py-2 rounded-lg',
              (!isDeepSeekConfigured() || loading) && 'opacity-60',
            )}
            style={{
              minHeight: composerMinH,
              maxHeight: composerMaxH,
              WebkitUserSelect: 'text',
              userSelect: 'text',
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                void handleSubmit(e);
              }
            }}
          />
          <div className={cn('flex flex-col gap-2 shrink-0', isFull ? 'self-end' : 'sm:self-end w-full sm:w-auto')}>
            <button
              type="submit"
              disabled={!draft.trim() || loading || !isDeepSeekConfigured()}
              title={isFull ? undefined : 'Send message'}
              className={cn(
                'rounded-xl flex items-center justify-center gap-2 font-semibold uppercase tracking-wide',
                isFull
                  ? 'px-6 py-3 text-sm bg-violet-600 text-white hover:bg-violet-500 disabled:bg-[var(--surface-hover)] disabled:text-[var(--text-secondary)]'
                  : 'w-full sm:w-auto px-5 py-3 text-sm bg-violet-600 text-white hover:bg-violet-500 disabled:bg-[var(--surface-hover)] disabled:text-[var(--text-secondary)]',
              )}
            >
              {loading ? <Loader2 size={20} className="animate-spin" /> : <Send size={20} />}
              {isFull ? <span>Send</span> : null}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
