import { useEffect, useRef } from 'react';
import { Terminal } from 'lucide-react';

type Props = {
  lines: string[];
  busy: boolean;
  inferenceStability: number | null;
};

export function FlowAnalysisFeed({ lines, busy, inferenceStability }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [lines.length, busy]);

  if (!busy && lines.length === 0) return null;

  return (
    <div className="bg-[var(--surface-subtle)] border border-[var(--border)] rounded-xl overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 border-b border-[var(--border)] bg-[var(--bg-elevated)]/80">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
          <Terminal size={14} className="text-[var(--accent)] shrink-0" aria-hidden />
          Analysis trace
        </div>
        {inferenceStability != null ? (
          <span className="text-[10px] sm:text-xs font-mono text-violet-800" title="Session calibration rises as more flows are scored (lab UI)">
            Inference stability {Math.round(inferenceStability * 100)}%
          </span>
        ) : null}
      </div>
      <pre
        className="max-h-[min(220px,32vh)] lg:max-h-[min(360px,42vh)] overflow-y-auto px-3 py-2 text-[11px] sm:text-xs font-mono text-[var(--text-soft)] leading-relaxed whitespace-pre-wrap break-words"
        aria-live="polite"
      >
        {lines.length === 0 && busy ? (
          <span className="text-[var(--text-disabled)]">
            Initializing hybrid pipeline · preparing RF + Isolation Forest scoring…
          </span>
        ) : (
          lines.map((line, i) => (
            <span key={i} className="block">
              {line}
            </span>
          ))
        )}
        <div ref={bottomRef} />
      </pre>
    </div>
  );
}
