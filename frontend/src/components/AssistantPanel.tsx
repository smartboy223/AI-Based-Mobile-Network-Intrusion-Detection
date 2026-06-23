import React from 'react';
import { Sparkles } from 'lucide-react';
import { AssistantChat } from './AssistantChat';

/**
 * Full-width, full-height AI tab: maximum space to read and type; no raw evidence panel.
 */
export function AssistantPanel() {
  return (
    <div className="flex flex-col flex-1 min-h-0 bg-[var(--surface-subtle)] border-t border-[var(--border)]">
      <header className="shrink-0 px-4 sm:px-6 py-3 border-b border-[var(--border)] bg-[var(--bg-elevated)]/90 flex items-center gap-3">
        <div className="p-2 rounded-lg bg-[var(--accent-soft)] text-[var(--accent)] border border-[var(--border-accent)]">
          <Sparkles size={20} />
        </div>
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-[var(--text-primary)] tracking-tight">AI Assistant</h2>
          <p className="text-xs text-[var(--text-muted)] mt-0.5 leading-snug">
            Supports a <strong className="text-[var(--text-soft)]">5G IDS</strong> workflow: interpret evidence, triage, draft
            ML/VT analyst summaries, and export narratives—<strong className="text-[var(--text-secondary)]">not</strong> inline blocking.
            Use <strong className="text-[var(--text-soft)]">New task</strong> for Past tasks + fresh chat.{' '}
            <strong className="text-[var(--text-soft)]">AI</strong> on a row pins that flow; patches need{' '}
            <code className="text-sky-800 text-[11px]">flowId</code> = pinned row.
          </p>
        </div>
      </header>
      <div className="flex-1 min-h-0 flex flex-col px-4 sm:px-6 py-4">
        <div className="flex-1 min-h-0 flex flex-col rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)] overflow-hidden shadow-[var(--shadow-card)] ring-1 ring-[var(--border)] select-text">
          <AssistantChat variant="fullPage" />
        </div>
      </div>
    </div>
  );
}
