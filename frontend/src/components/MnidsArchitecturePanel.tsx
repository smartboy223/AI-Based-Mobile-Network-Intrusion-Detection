import { X, ArrowRight } from 'lucide-react';
import {
  DETECTION_MECHANISMS,
  MNIDS_SCOPE_NOTE,
  PIPELINE_ONE_LINER,
  PIPELINE_STAGES,
  TRAFFIC_SUMMARY_LINE,
} from '../lib/mnidsArchitecture';
import { PROJECT_DISPLAY_NAME } from '../lib/appMeta';
import { cn } from '../lib/utils';

type Props = {
  open: boolean;
  onClose: () => void;
};

export function MnidsArchitecturePanel({ open, onClose }: Props) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-[var(--overlay-scrim)] backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="mnids-arch-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className={cn(
          'w-full max-w-lg max-h-[min(85vh,560px)] overflow-hidden flex flex-col',
          'rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)] shadow-2xl shadow-black/50',
        )}
      >
        <div className="flex items-start justify-between gap-3 px-4 py-3 border-b border-[var(--border)] shrink-0">
          <div className="min-w-0">
            <h2 id="mnids-arch-title" className="text-base font-semibold text-[var(--text-primary)]">
              Architecture
            </h2>
            <p className="text-[11px] text-[var(--text-disabled)] mt-0.5 truncate">{PROJECT_DISPLAY_NAME}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="shrink-0 p-2 rounded-lg border border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-hover)] transition-colors"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
          <p className="text-[11px] text-[var(--text-muted)] leading-snug">{PIPELINE_ONE_LINER}</p>

          <section aria-label="Pipeline">
            <h3 className="sr-only">Pipeline</h3>
            <div className="flex flex-wrap items-center gap-y-1 gap-x-0.5 justify-center sm:justify-start">
              {PIPELINE_STAGES.map((s, i) => (
                <div key={s.id} className="flex items-center gap-0.5">
                  {i > 0 ? (
                    <ArrowRight className="w-3 h-3 text-[var(--text-muted)] shrink-0 hidden sm:block" aria-hidden />
                  ) : null}
                  <div
                    className="rounded-md border border-[var(--border-strong)] bg-[var(--surface-subtle)] px-2 py-1 text-center"
                    title={`${s.title}: ${s.description}`}
                  >
                    <div className="text-[11px] font-medium text-[var(--text-primary)] leading-tight">{s.shortTitle}</div>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <p className="text-[11px] text-[var(--text-disabled)] leading-snug border-l-2 border-[var(--accent)]/40 pl-2.5">
            {TRAFFIC_SUMMARY_LINE}
          </p>

          <section aria-label="Detection">
            <h3 className="text-[10px] font-semibold uppercase tracking-widest text-[var(--text-disabled)] mb-1.5">
              Detection layers
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {DETECTION_MECHANISMS.map((d) => (
                <span
                  key={d.id}
                  className={cn(
                    'rounded-md border px-2 py-0.5 text-[11px]',
                    d.requiredIntegration
                      ? 'border-amber-400 bg-amber-100 text-amber-950'
                      : 'border-[var(--border)] bg-[var(--surface-subtle)] text-[var(--text-soft)]',
                  )}
                  title={d.role}
                >
                  {d.name}
                </span>
              ))}
            </div>
          </section>

          <p className="text-[10px] text-[var(--text-disabled)] text-center pt-1 border-t border-[var(--border)]">{MNIDS_SCOPE_NOTE}</p>
        </div>
      </div>
    </div>
  );
}
