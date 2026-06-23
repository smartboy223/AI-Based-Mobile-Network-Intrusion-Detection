import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ChevronUp, ChevronDown } from 'lucide-react';
import { cn } from '../lib/utils';
import type { TrafficLog, TrafficStatus, TrafficTableSortKey } from '../types';
import { trafficStatusLabel } from '../types';
import { trafficPlaneLabel } from '../lib/telecom5gFields';
import {
  TRAFFIC_COLUMN_LABELS,
  TRAFFIC_COLUMN_SORT_KEY,
  type TrafficDataColumnId,
} from '../lib/trafficTableColumnPrefs';
import {
  trafficConfBarClass,
  trafficStatusDotClass,
  trafficStatusTextClass,
  trafficStatusRowClass,
} from '../lib/trafficStatusUi';
import {
  vtIpCellClass,
  vtIpFieldFooter,
  vtVerdictScoreLine,
  type VtIpClientResult,
} from '../lib/virusTotal';
import { TrafficVtAndAiCell, type TrafficTableToastInput } from './TrafficVtAndAiCell';

function SortableTh({
  children,
  colKey,
  sortKey,
  sortDir,
  onSort,
  className,
  alignCenter = false,
}: {
  children: React.ReactNode;
  colKey: TrafficTableSortKey;
  sortKey: TrafficTableSortKey;
  sortDir: 'asc' | 'desc';
  onSort: (k: TrafficTableSortKey) => void;
  className?: string;
  alignCenter?: boolean;
}) {
  const active = sortKey === colKey;
  return (
    <th
      className={cn(
        'px-2.5 py-2.5 font-medium border-b border-[var(--border)] text-[var(--text-secondary)] uppercase tracking-wider font-mono text-xs',
        alignCenter && 'text-center',
        className,
      )}
    >
      <button
        type="button"
        onClick={() => onSort(colKey)}
        className={cn(
          'inline-flex items-center gap-0.5 hover:text-[var(--text-primary)] transition-colors w-full',
          alignCenter ? 'justify-center' : 'text-left',
        )}
        title="Sort"
      >
        <span className="truncate">{children}</span>
        {active ? (
          sortDir === 'asc' ? (
            <ChevronUp className="w-3 h-3 shrink-0 text-[var(--accent)]" aria-hidden />
          ) : (
            <ChevronDown className="w-3 h-3 shrink-0 text-[var(--accent)]" aria-hidden />
          )
        ) : (
          <span className="inline-flex flex-col leading-none shrink-0 opacity-25" aria-hidden>
            <ChevronUp className="w-2 h-2 -mb-0.5" />
            <ChevronDown className="w-2 h-2" />
          </span>
        )}
      </button>
    </th>
  );
}

function IpCompactCell({
  ip,
  rep,
}: {
  ip: string;
  rep: VtIpClientResult | undefined;
}) {
  const footer = rep ? vtIpFieldFooter(rep) : null;
  const score = rep ? vtVerdictScoreLine(rep) : null;
  const subLine =
    footer == null
      ? null
      : footer.tag === 'Skipped'
        ? footer.line
        : score
          ? `${footer.tag} · ${score}`
          : `${footer.tag} · ${footer.line}`;
  const title = subLine ? `${ip}\n${subLine}` : ip;

  return (
    <td
      className="align-middle px-2 py-2 border-b border-[var(--border)] min-w-[7.5rem] max-w-[8.5rem] w-[8rem] overflow-hidden"
      title={title}
    >
      <div className="flex flex-col items-stretch gap-1 min-w-0">
        <span
          className={cn(
            'font-mono text-xs leading-snug text-center block w-full min-w-0 max-w-full whitespace-nowrap overflow-hidden text-ellipsis',
            rep ? vtIpCellClass(rep, 'compact') : 'text-[var(--text-primary)]',
          )}
        >
          {ip}
        </span>
        {subLine ? (
          <p className="text-xs leading-snug text-[var(--text-muted)] text-center truncate min-w-0" title={subLine}>
            {subLine}
          </p>
        ) : null}
      </div>
    </td>
  );
}

export type TrafficDataTableProps = {
  visibleColumns: TrafficDataColumnId[];
  sortKey: TrafficTableSortKey;
  sortDir: 'asc' | 'desc';
  onSort: (k: TrafficTableSortKey) => void;
  logs: TrafficLog[];
  vtIpForUi: Record<string, VtIpClientResult>;
  trafficRowJobBusyId: string | null;
  bulkBusyId: string;
  vtApiConfigured: boolean | null;
  onVtApiStart: (flowId: string) => void;
  onVtApiEnd: () => void;
  runVtEnrichForRow: (log: TrafficLog) => Promise<{ src: VtIpClientResult; dst: VtIpClientResult } | null>;
  onReanalyzeRow: (flowId: string) => void;
  onSuspiciousAutoTriage: (log: TrafficLog) => void;
  onToast: (t: TrafficTableToastInput) => void;
  updateTrafficRowStatus: (flowId: string, status: TrafficStatus) => void;
};

export function TrafficDataTable({
  visibleColumns,
  sortKey,
  sortDir,
  onSort,
  logs,
  vtIpForUi,
  trafficRowJobBusyId,
  bulkBusyId,
  vtApiConfigured,
  onVtApiStart,
  onVtApiEnd,
  runVtEnrichForRow,
  onReanalyzeRow,
  onSuspiciousAutoTriage,
  onToast,
  updateTrafficRowStatus,
}: TrafficDataTableProps) {
  const colCount = visibleColumns.length + 1;

  function renderHeadCell(id: TrafficDataColumnId) {
    const sk = TRAFFIC_COLUMN_SORT_KEY[id];
    const label = TRAFFIC_COLUMN_LABELS[id];
    if (!sk) return null;
    const narrow = [
      'timestamp',
      'protocol',
      'trafficPlane',
      'upfInterface',
      'packetSize',
      'packetCount',
      'confidence',
      'fiveQi',
      'mlIsolationAnomalyScore',
      'mlAutoencoderAnomalyScore',
    ].includes(id);
    return (
      <SortableTh
        key={id}
        colKey={sk}
        sortKey={sortKey}
        sortDir={sortDir}
        onSort={onSort}
        alignCenter
        className={cn(
          (id === 'sourceIP' || id === 'destIP') && 'min-w-[7.5rem] max-w-[8.5rem]',
          id === 'sessionBearerKey' && 'max-w-[120px]',
          id === 'operationalCategory' && 'max-w-[140px]',
          id === 'ngapNasHint' && 'max-w-[160px]',
          id === 'dnnSlice' && 'max-w-[120px]',
          id === 'analystNote' && 'max-w-[140px]',
          narrow && 'whitespace-nowrap',
        )}
      >
        {label}
      </SortableTh>
    );
  }

  function renderBodyCell(log: TrafficLog, id: TrafficDataColumnId) {
    const srcRep = vtIpForUi[log.sourceIP];
    const dstRep = vtIpForUi[log.destIP];
    const baseTd =
      'px-2.5 py-2 align-middle text-center border-b border-[var(--border)] text-sm min-w-0 overflow-hidden';

    switch (id) {
      case 'timestamp':
        return (
          <td key={id} className={cn(baseTd, 'text-[var(--text-secondary)] font-mono whitespace-nowrap w-0')}>
            {log.timestamp}
          </td>
        );
      case 'sourceIP':
        return <IpCompactCell key={id} ip={log.sourceIP} rep={srcRep} />;
      case 'destIP':
        return <IpCompactCell key={id} ip={log.destIP} rep={dstRep} />;
      case 'protocol':
        return (
          <td key={id} className={cn(baseTd, 'w-0')}>
            <span className="inline-block px-2 py-0.5 bg-[var(--surface-hover)] rounded text-sm">{log.protocol}</span>
          </td>
        );
      case 'trafficPlane':
        return (
          <td key={id} className={cn(baseTd, 'text-cyan-800 text-sm max-w-[5.5rem] truncate w-0')}>
            <span title={log.trafficPlane ? trafficPlaneLabel(log.trafficPlane) : ''}>
              {log.trafficPlane ? trafficPlaneLabel(log.trafficPlane) : '—'}
            </span>
          </td>
        );
      case 'upfInterface':
        return (
          <td key={id} className={cn(baseTd, 'font-mono text-sm w-0')} title={log.upfInterface}>
            {log.upfInterface ?? '—'}
          </td>
        );
      case 'sessionBearerKey':
        return (
          <td
            key={id}
            className={cn(baseTd, 'font-mono text-xs text-[var(--text-secondary)] max-w-[104px] truncate')}
            title={log.sessionBearerKey ?? undefined}
          >
            {log.sessionBearerKey ?? '—'}
          </td>
        );
      case 'radioAccess':
        return (
          <td
            key={id}
            className={cn(baseTd, 'text-violet-800 text-sm max-w-[100px] truncate')}
            title={log.radioAccess}
          >
            {log.radioAccess ?? '—'}
          </td>
        );
      case 'fiveQi':
        return (
          <td key={id} className={cn(baseTd, 'font-mono w-0')}>
            {log.fiveQi ?? '—'}
          </td>
        );
      case 'dnnSlice':
        return (
          <td
            key={id}
            className={cn(baseTd, 'text-sm max-w-[120px] truncate')}
            title={log.dnnSlice}
          >
            {log.dnnSlice ?? '—'}
          </td>
        );
      case 'ngapNasHint':
        return (
          <td key={id} className={cn(baseTd, 'text-[var(--text-secondary)] text-left max-w-[200px]')}>
            <p className="line-clamp-2 text-xs leading-snug text-center" title={log.ngapNasHint}>
              {log.ngapNasHint ?? '—'}
            </p>
          </td>
        );
      case 'operationalCategory':
        return (
          <td
            key={id}
            className={cn(baseTd, 'text-[var(--text-soft)] max-w-[140px]')}
            title={log.engineeringNote ?? undefined}
          >
            <p className="line-clamp-2 text-xs leading-snug">{log.operationalCategory ?? '—'}</p>
          </td>
        );
      case 'packetSize':
        return (
          <td key={id} className={cn(baseTd, 'font-mono tabular-nums w-0')}>
            {log.packetSize}
          </td>
        );
      case 'packetCount':
        return (
          <td key={id} className={cn(baseTd, 'font-mono tabular-nums w-0')}>
            {log.packetCount ?? '—'}
          </td>
        );
      case 'byteTotal':
        return (
          <td key={id} className={cn(baseTd, 'font-mono tabular-nums text-sm')}>
            {log.byteTotal != null ? log.byteTotal.toLocaleString() : '—'}
          </td>
        );
      case 'mlRandomForestStatus': {
        const st = log.mlRandomForestStatus;
        const conf = log.mlRandomForestConfidence;
        if (!st || conf == null) {
          return (
            <td
              key={id}
              className={cn(baseTd, 'text-[var(--text-disabled)] text-sm')}
              title="RF label appears when the lab inference service (port 8787) scores this flow"
            >
              —
            </td>
          );
        }
        return (
          <td key={id} className={cn(baseTd, 'max-w-[120px]')}>
            <div className="flex flex-col gap-0.5 items-center min-w-0">
              <div className="flex items-center gap-1 justify-center">
                <div className={cn('w-1.5 h-1.5 rounded-full shrink-0', trafficStatusDotClass(st))} />
                <span className={cn('text-sm font-medium', trafficStatusTextClass(st))}>
                  {trafficStatusLabel(st)}
                </span>
              </div>
              <span className="text-xs text-[var(--text-muted)] font-mono">{(conf * 100).toFixed(0)}%</span>
            </div>
          </td>
        );
      }
      case 'mlIsolationAnomalyScore': {
        const s = log.mlIsolationAnomalyScore;
        if (s == null) {
          return (
            <td
              key={id}
              className={cn(baseTd, 'text-[var(--text-disabled)]')}
              title="Isolation Forest anomaly score when lab inference is running"
            >
              —
            </td>
          );
        }
        return (
          <td key={id} className={cn(baseTd, 'w-0')} title="Isolation Forest anomaly score (0–100%)">
            <div className="flex items-center gap-1 min-w-[68px] max-w-[80px] mx-auto justify-center">
              <div className="flex-1 h-1 bg-[var(--surface-hover)] rounded-full overflow-hidden min-w-[32px]">
                <div
                  className="h-full rounded-full bg-amber-400/90"
                  style={{ width: `${Math.min(100, s * 100)}%` }}
                />
              </div>
              <span className="text-xs text-[var(--text-secondary)] font-mono tabular-nums shrink-0">
                {(s * 100).toFixed(0)}%
              </span>
            </div>
          </td>
        );
      }
      case 'mlAutoencoderAnomalyScore': {
        const s = log.mlAutoencoderAnomalyScore;
        if (s == null) {
          return (
            <td
              key={id}
              className={cn(baseTd, 'text-[var(--text-disabled)]')}
              title="Autoencoder anomaly score when Keras model is deployed"
            >
              —
            </td>
          );
        }
        return (
          <td key={id} className={cn(baseTd, 'w-0')} title="Autoencoder reconstruction anomaly (0–100%)">
            <div className="flex items-center gap-1 min-w-[68px] max-w-[80px] mx-auto justify-center">
              <div className="flex-1 h-1 bg-[var(--surface-hover)] rounded-full overflow-hidden min-w-[32px]">
                <div
                  className="h-full rounded-full bg-violet-400/90"
                  style={{ width: `${Math.min(100, s * 100)}%` }}
                />
              </div>
              <span className="text-xs text-[var(--text-secondary)] font-mono tabular-nums shrink-0">
                {(s * 100).toFixed(0)}%
              </span>
            </div>
          </td>
        );
      }
      case 'status':
        return (
          <td key={id} className={cn(baseTd, 'max-w-[150px]')}>
            <div className="flex flex-col gap-1 min-w-0 items-center">
              <div className="flex items-center gap-1.5 w-full justify-center">
                <div className={cn('w-1.5 h-1.5 rounded-full shrink-0', trafficStatusDotClass(log.status))} />
                <select
                  value={log.status}
                  onChange={(e) => updateTrafficRowStatus(log.id, e.target.value as TrafficStatus)}
                  aria-label={`Status for flow ${log.id}`}
                  className={cn(
                    'min-w-0 flex-1 max-w-[130px] rounded border border-[var(--border)] bg-[var(--surface-subtle)] text-sm py-1.5 px-2 font-medium text-center',
                    trafficStatusTextClass(log.status),
                  )}
                >
                  <option value="Benign">Clean</option>
                  <option value="Suspicious">Suspicious</option>
                  <option value="Malicious">Malicious</option>
                </select>
              </div>
              {log.status !== 'Benign' && log.attackType ? (
                <p className="text-xs text-[var(--text-secondary)] line-clamp-1 w-full text-center" title={log.attackType}>
                  {log.attackType}
                </p>
              ) : null}
            </div>
          </td>
        );
      case 'analystNote':
        return (
          <td key={id} className={cn(baseTd, 'text-left max-w-[160px]')}>
            {log.analystNote ? (
              <p className="text-xs text-[var(--text-secondary)] line-clamp-2 leading-snug" title={log.analystNote}>
                {log.analystNote}
              </p>
            ) : (
              <span className="text-[var(--text-disabled)]">—</span>
            )}
          </td>
        );
      case 'confidence':
        return (
          <td key={id} className={cn(baseTd, 'w-0')}>
            <div className="flex items-center gap-1 min-w-[72px] max-w-[88px] mx-auto justify-center">
              <div className="flex-1 h-1 bg-[var(--surface-hover)] rounded-full overflow-hidden min-w-[36px]">
                <div
                  className={cn('h-full rounded-full', trafficConfBarClass(log.status))}
                  style={{ width: `${log.confidence * 100}%` }}
                />
              </div>
              <span className="text-xs text-[var(--text-secondary)] font-mono tabular-nums shrink-0">
                {(log.confidence * 100).toFixed(0)}%
              </span>
            </div>
          </td>
        );
      default:
        return null;
    }
  }

  return (
    <div className="overflow-x-auto isolate">
      <table className="w-full text-base border-collapse table-auto min-w-[760px]">
        <thead>
          <tr className="bg-[var(--surface-subtle)]">
            {visibleColumns.map(renderHeadCell)}
            <th className="px-1.5 py-2.5 font-medium border-b border-[var(--border)] text-[var(--text-secondary)] uppercase tracking-wider font-mono text-xs text-center align-bottom min-w-[7.5rem] w-[7.75rem]">
              VT / Triage / Refresh
            </th>
          </tr>
        </thead>
        <tbody className="text-[var(--text-primary)]">
          <AnimatePresence initial={false}>
            {logs.map((log) => (
              <motion.tr
                key={log.id}
                initial={{ opacity: 0, y: -6 }}
                animate={{ opacity: 1, y: 0 }}
                className={cn('hover:bg-[var(--surface-subtle)]/80 transition-colors', trafficStatusRowClass(log.status))}
              >
                {visibleColumns.map((col) => renderBodyCell(log, col))}
                <TrafficVtAndAiCell
                  log={log}
                  vtBusy={trafficRowJobBusyId === log.id}
                  rowJobBusy={trafficRowJobBusyId === log.id || trafficRowJobBusyId === bulkBusyId}
                  vtApiConfigured={vtApiConfigured}
                  onVtApiStart={() => onVtApiStart(log.id)}
                  onVtApiEnd={onVtApiEnd}
                  runVtEnrichForRow={runVtEnrichForRow}
                  onReanalyzeRow={() => onReanalyzeRow(log.id)}
                  onSuspiciousAutoTriage={() => onSuspiciousAutoTriage(log)}
                  onToast={onToast}
                  compact
                />
              </motion.tr>
            ))}
          </AnimatePresence>
          {logs.length === 0 && (
            <tr>
              <td colSpan={colCount} className="px-6 py-12 text-center text-[var(--text-secondary)] max-w-prose mx-auto">
                <p className="font-medium text-[var(--text-soft)] mb-2">No flow records yet</p>
                <p className="text-sm leading-relaxed">
                  Ingest a PCAP from <strong className="text-[var(--text-primary)]">PCAP</strong> or the{' '}
                  <strong className="text-[var(--text-primary)]">ML lab</strong> tab — flows show here after parse.
                </p>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
