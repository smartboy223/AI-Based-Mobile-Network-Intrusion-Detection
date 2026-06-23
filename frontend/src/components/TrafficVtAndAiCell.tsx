import React from 'react';
import { ExternalLink, Loader2, MessageSquareText, RefreshCw, Sparkles } from 'lucide-react';
import { cn } from '../lib/utils';
import type { TrafficLog } from '../types';
import type { VtIpClientResult } from '../lib/virusTotal';

export type TrafficTableToastInput = {
  title: string;
  body?: string;
  variant?: 'info' | 'success' | 'warning';
};

type Props = {
  log: TrafficLog;
  vtBusy: boolean;
  /** True while VirusTotal, Suspicious auto-triage, or bulk triage is running for this row */
  rowJobBusy: boolean;
  vtApiConfigured: boolean | null;
  onVtApiStart: () => void;
  onVtApiEnd: () => void;
  /** VirusTotal enrichment (skips API for cached + private IPs) */
  runVtEnrichForRow: (log: TrafficLog) => Promise<{ src: VtIpClientResult; dst: VtIpClientResult } | null>;
  onReanalyzeRow: () => void;
  /** VirusTotal + ML triage for Suspicious rows (opens review modal in parent) */
  onSuspiciousAutoTriage?: () => void;
  /** Dashboard toast (temporary banner); used instead of alerts for VT flow */
  onToast?: (t: TrafficTableToastInput) => void;
  /** Tighter buttons and padding for dense traffic table layout */
  compact?: boolean;
};

export function TrafficVtAndAiCell({
  log,
  vtBusy,
  rowJobBusy,
  vtApiConfigured,
  onVtApiStart,
  onVtApiEnd,
  runVtEnrichForRow,
  onReanalyzeRow,
  onSuspiciousAutoTriage,
  onToast,
  compact = false,
}: Props) {
  const runApiEnrich = async () => {
    if (vtApiConfigured === false) {
      onToast?.({
        title: 'VirusTotal',
        body: 'Add VIRUSTOTAL_API_KEY to the dev server .env to enable API lookups.',
        variant: 'warning',
      });
      return;
    }
    onToast?.({
      title: 'VirusTotal',
      body:
        'Resolving source and destination IPv4; then up to two public HTTP/DNS hostnames on this row when present (cached entries skip API; private IPs never hit VT).',
      variant: 'info',
    });
    onVtApiStart();
    try {
      const pair = await runVtEnrichForRow(log);
      if (pair == null) {
        onToast?.({
          title: 'VirusTotal',
          body: 'API key not available on the server.',
          variant: 'warning',
        });
        return;
      }
      const { src: rSrc, dst: rDst } = pair;
      const skipped = [rSrc, rDst].filter((x) => x.skipReason === 'private_ip').length;
      let body = `${log.sourceIP} ↔ ${log.destIP} — saved with this session (localStorage).`;
      if (skipped === 2) {
        body =
          'Both addresses are private or reserved — no VirusTotal API calls (no quota use).';
      } else if (skipped === 1) {
        body =
          'One private/reserved IP handled locally; public IP used cache or was queried. Vendor data saved where applicable.';
      } else {
        body +=
          ' Public IPs use existing cache when available; otherwise rate-limited API lookup.';
      }
      onToast?.({
        title: skipped === 2 ? 'VirusTotal — private only' : 'VirusTotal results saved',
        body,
        variant: skipped === 2 ? 'info' : 'success',
      });
    } finally {
      onVtApiEnd();
    }
  };

  const openAssistantForRowNewTab = () => {
    // Persist THIS row as the "last pinned flow" BEFORE opening the new tab.
    // Why: the new tab's AssistantChatProvider tries to look up `pin=<id>`
    // inside `logs`, but logs in a fresh tab haven't necessarily loaded yet
    // (or may load from a different session snapshot). The provider falls
    // back to `localStorage[MNIDS_LAST_PINNED_FLOW_KEY]` when logs are empty.
    // If we don't seed the storage here, the new tab opens to an empty
    // assistant with no pinned context — exactly the bug "AI just redirects
    // to an empty dashboard page".
    //
    // Key kept in sync with AssistantChatContext.tsx (const
    // MNIDS_LAST_PINNED_FLOW_KEY = 'mnids-last-pinned-flow-v1').
    try {
      window.localStorage.setItem(
        'mnids-last-pinned-flow-v1',
        JSON.stringify(log),
      );
    } catch {
      /* storage may be unavailable / over quota — fall back to URL-only pin */
    }

    // Navigate to /assistant explicitly (not the current path with ?assistant=1)
    // so the new tab definitely lands on the assistant view even if the
    // current tab is on /mllab or /analytics.
    const u = new URL(window.location.href);
    u.pathname = '/assistant';
    u.searchParams.set('assistant', '1');
    u.searchParams.set('pin', log.id);
    window.open(u.toString(), '_blank', 'noopener,noreferrer');
  };

  return (
    <td
      className={cn(
        'align-middle border-b border-[var(--border)]',
        compact ? 'px-1.5 py-2 w-[7.75rem] min-w-[7.75rem]' : 'px-2 py-3 min-w-[128px]',
      )}
    >
      <div className={cn('flex flex-col items-stretch', compact ? 'gap-1.5' : 'gap-2')}>
        <button
          type="button"
          onClick={() => void runApiEnrich()}
          disabled={rowJobBusy || vtApiConfigured === false}
          aria-label={`VirusTotal lookup for flow ${log.sourceIP} to ${log.destIP}`}
          title={
            vtApiConfigured === false
              ? 'Add VIRUSTOTAL_API_KEY on the dev server'
              : 'VirusTotal: cached & private IPs skip API (saves quota)'
          }
          className={cn(
            'inline-flex items-center justify-center rounded-lg border font-semibold uppercase tracking-wide transition-colors disabled:opacity-45 w-full',
            compact
              ? 'gap-1 px-1.5 py-1.5 text-xs'
              : 'gap-1.5 px-2 py-2 text-sm',
            log.status !== 'Benign'
              ? 'border-[#fbbf24]/55 text-[#fbbf24] hover:bg-[#fbbf24]/10'
              : 'border-[var(--border-strong)] text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]',
          )}
        >
          {vtBusy ? (
            <Loader2 className={cn('shrink-0 animate-spin', compact ? 'w-3 h-3' : 'w-3.5 h-3.5')} aria-hidden />
          ) : (
            <ExternalLink className={cn('shrink-0', compact ? 'w-3 h-3' : 'w-3.5 h-3.5')} aria-hidden />
          )}
          VT
        </button>
        {log.status === 'Suspicious' && onSuspiciousAutoTriage ? (
          <button
            type="button"
            onClick={() => void onSuspiciousAutoTriage()}
            disabled={rowJobBusy}
            aria-label={`Auto triage Suspicious flow ${log.sourceIP} to ${log.destIP}`}
            title="VirusTotal (when configured) + lab ML scores (RF / IF / AE); no external LLM required"
            className={cn(
              'inline-flex items-center justify-center rounded-lg border font-semibold uppercase tracking-wide transition-colors w-full',
              compact ? 'gap-1 px-1.5 py-1.5 text-xs' : 'gap-1.5 px-2 py-2 text-sm',
              rowJobBusy
                ? 'border-[var(--border)] text-[var(--text-disabled)] cursor-not-allowed'
                : 'border-cyan-500/45 text-cyan-800 hover:bg-cyan-500/10',
            )}
          >
            {rowJobBusy ? (
              <Loader2 className={cn('shrink-0 animate-spin', compact ? 'w-3 h-3' : 'w-3.5 h-3.5')} aria-hidden />
            ) : (
              <Sparkles className={cn('shrink-0', compact ? 'w-3 h-3' : 'w-3.5 h-3.5')} aria-hidden />
            )}
            Triage
          </button>
        ) : null}
        <button
          type="button"
          onClick={openAssistantForRowNewTab}
          aria-label={`Open AI assistant in new tab for flow ${log.id}`}
          title="New assistant tab: new conversation with this flow pinned for triage and patches"
          className={cn(
            'inline-flex items-center justify-center rounded-lg border border-violet-500/40 font-semibold uppercase tracking-wide text-violet-800 hover:bg-violet-500/15 w-full',
            compact ? 'gap-1 px-1.5 py-1.5 text-xs' : 'gap-1.5 px-2 py-2 text-sm',
          )}
        >
          <MessageSquareText className={cn('shrink-0', compact ? 'w-3 h-3' : 'w-3.5 h-3.5')} aria-hidden />
          AI
        </button>
        <button
          type="button"
          onClick={onReanalyzeRow}
          disabled={rowJobBusy}
          aria-label={`Refresh ML scoring for flow ${log.id}`}
          title="Re-run ML scoring for this row (RF/IF/AE)"
          className={cn(
            'inline-flex items-center justify-center rounded-lg border border-amber-500/45 font-semibold uppercase tracking-wide text-amber-900 hover:bg-amber-500/15 w-full disabled:opacity-45',
            compact ? 'gap-1 px-1.5 py-1.5 text-xs' : 'gap-1.5 px-2 py-2 text-sm',
          )}
        >
          <RefreshCw className={cn('shrink-0', compact ? 'w-3 h-3' : 'w-3.5 h-3.5')} aria-hidden />
          Refresh
        </button>
      </div>
    </td>
  );
}
