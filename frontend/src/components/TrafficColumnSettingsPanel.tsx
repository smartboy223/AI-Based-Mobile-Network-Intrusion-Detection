import React, { useEffect, useRef, useState } from 'react';
import { Columns3, ChevronUp, ChevronDown, RotateCcw, X } from 'lucide-react';
import { cn } from '../lib/utils';
import {
  DEFAULT_TRAFFIC_COLUMN_ORDER,
  DEFAULT_TRAFFIC_COLUMN_VISIBLE,
  TRAFFIC_COLUMN_LABELS,
  type TrafficColumnPrefs,
  type TrafficDataColumnId,
} from '../lib/trafficTableColumnPrefs';

type Props = {
  prefs: TrafficColumnPrefs;
  onChange: (next: TrafficColumnPrefs) => void;
};

export function TrafficColumnSettingsPanel({ prefs, onChange }: Props) {
  const [open, setOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const move = (id: TrafficDataColumnId, dir: -1 | 1) => {
    const idx = prefs.order.indexOf(id);
    const n = idx + dir;
    if (idx < 0 || n < 0 || n >= prefs.order.length) return;
    const next = [...prefs.order];
    [next[idx], next[n]] = [next[n], next[idx]];
    onChange({ ...prefs, order: next });
  };

  const toggleVisible = (id: TrafficDataColumnId) => {
    onChange({
      ...prefs,
      visible: { ...prefs.visible, [id]: !prefs.visible[id] },
    });
  };

  const resetDefaults = () => {
    onChange({
      order: [...DEFAULT_TRAFFIC_COLUMN_ORDER],
      visible: { ...DEFAULT_TRAFFIC_COLUMN_VISIBLE },
    });
  };

  return (
    <div className="relative shrink-0" ref={panelRef}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={cn(
          'inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm font-semibold uppercase tracking-wide transition-colors',
          open
            ? 'border-[var(--accent)] bg-[var(--accent)]/10 text-[var(--accent)]'
            : 'border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]',
        )}
        aria-expanded={open}
        aria-haspopup="dialog"
      >
        <Columns3 size={14} aria-hidden />
        Columns
      </button>
      {open ? (
        <div
          className="absolute right-0 top-full z-50 mt-1 w-[min(100vw-2rem,22rem)] max-h-[min(70vh,28rem)] overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)] shadow-xl flex flex-col"
          role="dialog"
          aria-label="Traffic table columns"
        >
          <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-[var(--border)] bg-[var(--surface-subtle)]">
            <span className="text-sm font-semibold text-[var(--text-primary)]">Show & order</span>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={resetDefaults}
                className="p-1 rounded text-[var(--text-muted)] hover:text-[var(--accent)] hover:bg-[var(--accent)]/10"
                title="Reset defaults"
                aria-label="Reset column defaults"
              >
                <RotateCcw size={14} />
              </button>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                aria-label="Close"
              >
                <X size={14} />
              </button>
            </div>
          </div>
          <p className="text-xs text-[var(--text-muted)] px-3 py-2 border-b border-[var(--border)] leading-relaxed">
            Toggle visibility and order. VT / AI / Scan column stays on the right.
          </p>
          <ul className="overflow-y-auto p-2 space-y-0.5 flex-1 min-h-0">
            {prefs.order.map((id) => (
              <li
                key={id}
                className="flex items-center gap-1 rounded-lg px-1 py-0.5 hover:bg-[var(--surface-hover)]/80"
              >
                <label className="flex items-center gap-2 min-w-0 flex-1 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={prefs.visible[id] !== false}
                    onChange={() => toggleVisible(id)}
                    className="rounded border-[var(--border)] shrink-0"
                  />
                  <span className="text-sm text-[var(--text-soft)] truncate">{TRAFFIC_COLUMN_LABELS[id]}</span>
                </label>
                <div className="flex flex-col shrink-0">
                  <button
                    type="button"
                    className="p-0.5 text-[var(--text-disabled)] hover:text-[var(--text-primary)] disabled:opacity-30"
                    disabled={prefs.order.indexOf(id) <= 0}
                    onClick={() => move(id, -1)}
                    aria-label={`Move ${TRAFFIC_COLUMN_LABELS[id]} up`}
                  >
                    <ChevronUp size={14} />
                  </button>
                  <button
                    type="button"
                    className="p-0.5 text-[var(--text-disabled)] hover:text-[var(--text-primary)] disabled:opacity-30"
                    disabled={prefs.order.indexOf(id) >= prefs.order.length - 1}
                    onClick={() => move(id, 1)}
                    aria-label={`Move ${TRAFFIC_COLUMN_LABELS[id]} down`}
                  >
                    <ChevronDown size={14} />
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
