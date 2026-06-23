import React, { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Layers } from 'lucide-react';
import type { TrafficLog } from '../types';
import { trafficStatusLabel } from '../types';
import { trafficPlaneLabel } from '../lib/telecom5gFields';

type Props = {
  logs: TrafficLog[];
};

export function SessionBearerPanel({ logs }: Props) {
  const [openKey, setOpenKey] = useState<string | null>(null);

  const groups = useMemo(() => {
    const m = new Map<
      string,
      { key: string; rows: TrafficLog[]; planes: Set<string>; interfaces: Set<string> }
    >();
    for (const log of logs) {
      const key = log.sessionBearerKey ?? `flow-${log.id}`;
      let g = m.get(key);
      if (!g) {
        g = { key, rows: [], planes: new Set(), interfaces: new Set() };
        m.set(key, g);
      }
      g.rows.push(log);
      if (log.trafficPlane) g.planes.add(trafficPlaneLabel(log.trafficPlane));
      if (log.upfInterface) g.interfaces.add(log.upfInterface);
    }
    return [...m.values()].sort((a, b) => b.rows.length - a.rows.length || a.key.localeCompare(b.key));
  }, [logs]);

  if (logs.length === 0) return null;

  return (
    <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <div className="p-1.5 rounded-md bg-violet-500/15 text-violet-800">
          <Layers size={18} />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">Sessions / bearers</h3>
          <p className="text-xs text-[var(--text-disabled)]">
            Grouped by TEID, inner UE IPv4, or PDU + DNN — aligned with 5G UPF / SMF visibility.
          </p>
        </div>
      </div>
      <ul className="space-y-1 max-h-64 overflow-y-auto">
        {groups.map((g) => {
          const mal = g.rows.filter((r) => r.status === 'Malicious').length;
          const susp = g.rows.filter((r) => r.status === 'Suspicious').length;
          const open = openKey === g.key;
          return (
            <li key={g.key} className="border border-[var(--border)] rounded-lg bg-[var(--surface-subtle)]/60">
              <button
                type="button"
                onClick={() => setOpenKey(open ? null : g.key)}
                className="w-full flex items-start gap-2 px-3 py-2 text-left hover:bg-[var(--surface-hover)]/80 rounded-lg transition-colors"
              >
                {open ? (
                  <ChevronDown size={16} className="text-[var(--accent)] shrink-0 mt-0.5" />
                ) : (
                  <ChevronRight size={16} className="text-[var(--text-disabled)] shrink-0 mt-0.5" />
                )}
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-[var(--text-primary)] font-mono break-all leading-snug">{g.key}</p>
                  <p className="text-xs text-[var(--text-muted)] mt-0.5">
                    {g.rows.length} flow{g.rows.length === 1 ? '' : 's'}
                    {mal ? ` · ${mal} malicious` : ''}
                    {susp ? ` · ${susp} suspicious` : ''}
                    {g.planes.size ? ` · ${[...g.planes].join(', ')}` : ''}
                    {g.interfaces.size ? ` · IF ${[...g.interfaces].join('/')}` : ''}
                  </p>
                </div>
              </button>
              {open ? (
                <ul className="px-3 pb-2 pt-0 space-y-1 border-t border-[var(--border)]/80">
                  {g.rows.map((r) => (
                    <li
                      key={r.id}
                      className="text-xs font-mono text-[var(--text-secondary)] flex flex-wrap gap-x-2 gap-y-0.5 py-1 border-b border-[var(--border)]/40 last:border-0"
                    >
                      <span className="text-[var(--text-disabled)]">{r.timestamp}</span>
                      <span>
                        {r.sourceIP}→{r.destIP}
                      </span>
                      <span>{r.protocol}</span>
                      <span className="text-violet-800">{trafficStatusLabel(r.status)}</span>
                    </li>
                  ))}
                </ul>
              ) : null}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
