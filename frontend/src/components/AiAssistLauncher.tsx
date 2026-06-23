import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Sparkles, X } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '../lib/utils';
import { AssistantChat } from './AssistantChat';
import { ASSISTANT_BRANDING } from '../lib/deepseek';

const STORAGE_KEY = 'mnids-ai-fab-pos-v2';
const FAB_SIZE = 56;
const MARGIN = 8;
/** Movement past this (px) counts as drag; smaller gesture opens chat. */
const DRAG_THRESHOLD_PX = 10;
/** Default sits above typical table pagination bar (bottom-right). */
const DEFAULT_RIGHT = 24;
const DEFAULT_BOTTOM = 120;

type FabPos = { right: number; bottom: number };

function clamp(n: number, lo: number, hi: number) {
  return Math.min(hi, Math.max(lo, n));
}

function loadFabPos(): FabPos {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { right: DEFAULT_RIGHT, bottom: DEFAULT_BOTTOM };
    const j = JSON.parse(raw) as { right?: number; bottom?: number };
    if (typeof j.right === 'number' && typeof j.bottom === 'number') {
      return { right: j.right, bottom: j.bottom };
    }
  } catch {
    /* ignore */
  }
  return { right: DEFAULT_RIGHT, bottom: DEFAULT_BOTTOM };
}

function clampPosToViewport(right: number, bottom: number): FabPos {
  if (typeof window === 'undefined') return { right, bottom };
  const w = window.innerWidth;
  const h = window.innerHeight;
  return {
    right: clamp(right, MARGIN, w - FAB_SIZE - MARGIN),
    bottom: clamp(bottom, MARGIN, h - FAB_SIZE - MARGIN),
  };
}

type Props = {
  open: boolean;
  onOpen: () => void;
  onClose: () => void;
};

/**
 * Floating AI control — drag the icon to reposition (persisted).
 * Short tap / click opens chat; movement beyond threshold is drag only.
 */
export function AiAssistLauncher({ open, onOpen, onClose }: Props) {
  const [pos, setPos] = useState<FabPos>(() => {
    const p = loadFabPos();
    if (typeof window === 'undefined') return p;
    return clampPosToViewport(p.right, p.bottom);
  });

  const [isDragging, setIsDragging] = useState(false);

  const posRef = useRef(pos);
  posRef.current = pos;

  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    r0: number;
    b0: number;
    dragged: boolean;
  } | null>(null);

  useEffect(() => {
    const onResize = () => {
      setPos((p) => clampPosToViewport(p.right, p.bottom));
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  const persistPos = useCallback((p: FabPos) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(p));
    } catch {
      /* ignore */
    }
  }, []);

  const onFabPointerDown = (e: React.PointerEvent) => {
    e.currentTarget.setPointerCapture(e.pointerId);
    dragRef.current = {
      pointerId: e.pointerId,
      startX: e.clientX,
      startY: e.clientY,
      r0: posRef.current.right,
      b0: posRef.current.bottom,
      dragged: false,
    };
  };

  const onFabPointerMove = (e: React.PointerEvent) => {
    const d = dragRef.current;
    if (!d || e.pointerId !== d.pointerId) return;
    const deltaX = e.clientX - d.startX;
    const deltaY = e.clientY - d.startY;
    const dist = Math.hypot(deltaX, deltaY);
    if (dist > DRAG_THRESHOLD_PX) {
      if (!d.dragged) {
        d.dragged = true;
        setIsDragging(true);
      }
      const w = window.innerWidth;
      const h = window.innerHeight;
      const next = {
        right: clamp(d.r0 - deltaX, MARGIN, w - FAB_SIZE - MARGIN),
        bottom: clamp(d.b0 - deltaY, MARGIN, h - FAB_SIZE - MARGIN),
      };
      posRef.current = next;
      setPos(next);
    }
  };

  const onFabPointerUp = (e: React.PointerEvent) => {
    const d = dragRef.current;
    if (!d || e.pointerId !== d.pointerId) return;
    dragRef.current = null;
    setIsDragging(false);
    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
    if (d.dragged) {
      persistPos(posRef.current);
      return;
    }
    onOpen();
  };

  const onFabPointerCancel = (e: React.PointerEvent) => {
    const d = dragRef.current;
    if (!d || e.pointerId !== d.pointerId) return;
    dragRef.current = null;
    setIsDragging(false);
    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
    if (d.dragged) persistPos(posRef.current);
  };

  const onFabKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onOpen();
    }
  };

  return (
    <>
      <div
        className="fixed z-40 flex flex-col items-end gap-0 pointer-events-none"
        style={{ right: pos.right, bottom: pos.bottom }}
      >
        <div className="pointer-events-auto flex flex-col items-end gap-2">
          <div className="group flex flex-col items-end gap-2">
            <div
              className={cn(
                'rounded-lg border border-[var(--border)] bg-[var(--bg-elevated)]/95 backdrop-blur-sm px-3 py-2 shadow-xl max-w-[240px]',
                'opacity-0 translate-y-1 pointer-events-none group-hover:opacity-100 group-hover:translate-y-0 transition-all duration-200',
              )}
            >
              <p className="text-sm text-[var(--text-primary)] leading-snug">
                <span className="font-semibold text-violet-900">AI Assistance</span>
                <br />
                <span className="text-[var(--text-secondary)]">for </span>
                <span className="text-[var(--accent)] font-medium">{ASSISTANT_BRANDING.studentName}</span>
                <span className="text-[var(--text-secondary)]"> · </span>
                <span className="italic text-[var(--text-secondary)]">{ASSISTANT_BRANDING.institution}</span>
              </p>
              <p className="text-[10px] text-[var(--text-disabled)] mt-1">Analysis &amp; triage help—no blocking. Drag to move, tap to open.</p>
            </div>

            <button
              type="button"
              onPointerDown={onFabPointerDown}
              onPointerMove={onFabPointerMove}
              onPointerUp={onFabPointerUp}
              onPointerCancel={onFabPointerCancel}
              onKeyDown={onFabKeyDown}
              aria-label="AI Assistance — tap to open chat, drag to move"
              title="Tap to open · drag to move"
              className={cn(
                'relative flex h-14 w-14 items-center justify-center rounded-full touch-none',
                'bg-gradient-to-br from-violet-600 to-[var(--accent)] text-white shadow-lg shadow-violet-900/40',
                'ring-2 ring-violet-400/30 hover:ring-violet-300/50 transition-transform select-none',
                isDragging ? 'cursor-grabbing scale-95' : 'cursor-grab hover:scale-105 active:scale-95',
              )}
            >
              <Sparkles className="w-7 h-7 pointer-events-none" strokeWidth={1.75} />
              <span className="absolute -top-0.5 -right-0.5 flex h-3 w-3 pointer-events-none">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#4ade80] opacity-60" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-[#4ade80] border-2 border-[var(--bg-elevated)]" />
              </span>
            </button>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {open && (
          <>
            <motion.button
              type="button"
              aria-label="Close overlay"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[60] bg-[var(--overlay-scrim)] backdrop-blur-[2px]"
              onClick={onClose}
            />
            <motion.aside
              role="dialog"
              aria-modal="true"
              aria-labelledby="ai-drawer-title"
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 28, stiffness: 320 }}
              className={cn(
                'fixed top-0 right-0 z-[70] h-full w-full max-w-md',
                'border-l border-[var(--border)] bg-[var(--bg-elevated)] shadow-2xl flex flex-col',
              )}
            >
              <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)] shrink-0">
                <div>
                  <h2 id="ai-drawer-title" className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2">
                    <Sparkles size={16} className="text-violet-400" />
                    AI Assistance
                  </h2>
                  <p className="text-sm text-[var(--text-secondary)] mt-0.5">
                    {ASSISTANT_BRANDING.studentName} · {ASSISTANT_BRANDING.institution}
                  </p>
                  <p className="text-[10px] text-[var(--text-disabled)] mt-1 uppercase tracking-wide">
                    Analysis only
                  </p>
                </div>
                <button
                  type="button"
                  onClick={onClose}
                  className="p-2 rounded-lg hover:bg-[var(--surface-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                  aria-label="Close AI chat"
                >
                  <X size={20} />
                </button>
              </div>
              <div className="flex-1 overflow-hidden p-4 min-h-0 select-text">
                <AssistantChat variant="drawer" />
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
