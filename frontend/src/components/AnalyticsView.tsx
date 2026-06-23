import React, { useMemo } from 'react';
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid,
  Area,
  AreaChart,
} from 'recharts';
import { BarChart3, Wifi } from 'lucide-react';
import type { TrafficLog, SystemStats } from '../types';

const DIST_COLORS = ['#4ade80', '#fbbf24', '#f72585'];

type ChartPoint = {
  time: string;
  traffic: number;
  attacks: number;
  suspicious: number;
};

type Props = {
  logs: TrafficLog[];
  totalTrafficCounter: number;
  chartData: ChartPoint[];
  stats: Pick<SystemStats, 'totalTraffic' | 'attacksDetected' | 'suspiciousFlagged'>;
  onOpenDashboard: () => void;
};

export function AnalyticsView({
  logs,
  totalTrafficCounter,
  chartData: chartDataProp,
  stats,
  onOpenDashboard,
}: Props) {
  const throughputSeries = useMemo(() => {
    /** When the traffic table has rows (e.g. after PCAP analyze), derive the series from flows — never show a stale saved chart from a prior session. */
    if (logs.length > 0) {
      const take = Math.min(48, logs.length);
      const slice = logs.slice(0, take).reverse();
      return slice.map((l) => ({
        time: l.timestamp,
        traffic: Math.max(1, Math.round(l.packetSize)),
        attacks: l.status === 'Malicious' ? 1 : 0,
        suspicious: l.status === 'Suspicious' ? 1 : 0,
      }));
    }
    if (chartDataProp.length > 0) return chartDataProp;
    return [];
  }, [chartDataProp, logs]);

  const cleanCount = Math.max(
    0,
    stats.totalTraffic - stats.attacksDetected - stats.suspiciousFlagged,
  );

  const pieData = useMemo(
    () => [
      { name: 'Clean', value: cleanCount },
      { name: 'Suspicious', value: stats.suspiciousFlagged },
      { name: 'Malicious', value: stats.attacksDetected },
    ],
    [cleanCount, stats.suspiciousFlagged, stats.attacksDetected],
  );

  const statusBars = useMemo(
    () => [
      { name: 'Clean', value: cleanCount, fill: '#4ade80' },
      { name: 'Suspicious', value: stats.suspiciousFlagged, fill: '#fbbf24' },
      { name: 'Malicious', value: stats.attacksDetected, fill: '#f72585' },
    ],
    [cleanCount, stats.suspiciousFlagged, stats.attacksDetected],
  );

  const protocolCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const l of logs) {
      m.set(l.protocol, (m.get(l.protocol) ?? 0) + 1);
    }
    return [...m.entries()]
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  }, [logs]);

  const avgPacketSize = useMemo(() => {
    if (!logs.length) return 0;
    return Math.round(logs.reduce((s, l) => s + l.packetSize, 0) / logs.length);
  }, [logs]);

  const threatPct =
    stats.totalTraffic > 0
      ? Math.round((stats.attacksDetected / stats.totalTraffic) * 100)
      : 0;

  const pctOfTotal = (n: number) =>
    stats.totalTraffic > 0 ? Math.round((n / stats.totalTraffic) * 100) : 0;
  const pctClean = pctOfTotal(cleanCount);
  const pctSuspiciousOnly = pctOfTotal(stats.suspiciousFlagged);
  const pctMalOnly = pctOfTotal(stats.attacksDetected);

  const timeSpanLabel = useMemo(() => {
    if (logs.length === 0) return null;
    const times = logs
      .map((l) => {
        const t = Date.parse(l.timestamp);
        return Number.isNaN(t) ? null : t;
      })
      .filter((t): t is number => t != null);
    if (times.length === 0) return `${logs.length} flows (timestamps unavailable)`;
    const lo = Math.min(...times);
    const hi = Math.max(...times);
    const fmt = (ms: number) =>
      new Date(ms).toLocaleString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        month: 'short',
        day: 'numeric',
      });
    return lo === hi ? `Sample time: ${fmt(lo)} · ${logs.length} flows` : `${fmt(lo)} → ${fmt(hi)} · ${logs.length} flows`;
  }, [logs]);

  const confidenceStats = useMemo(() => {
    if (logs.length === 0) return null;
    const vals = logs.map((l) => l.confidence);
    const sum = vals.reduce((a, b) => a + b, 0);
    return {
      mean: Math.round((sum / vals.length) * 100) / 100,
      min: Math.min(...vals),
      max: Math.max(...vals),
    };
  }, [logs]);

  const topEndpoints = useMemo(() => {
    if (logs.length === 0) return [];
    const m = new Map<string, number>();
    for (const l of logs) {
      m.set(l.sourceIP, (m.get(l.sourceIP) ?? 0) + 1);
      m.set(l.destIP, (m.get(l.destIP) ?? 0) + 1);
    }
    return [...m.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, value]) => ({ name, value }));
  }, [logs]);

  const tooltipStyle = {
    backgroundColor: '#f4f6fa',
    border: '1px solid #ccd6e6',
    color: '#0c1524',
    fontSize: '12px',
    borderRadius: '8px',
    boxShadow: '0 4px 12px rgba(15, 23, 42, 0.08)',
  };

  return (
    <div className="w-full max-w-7xl 2xl:max-w-[88rem] mx-auto space-y-5 pb-8 px-0">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-lg font-semibold text-[var(--text-primary)] flex items-center gap-2">
          <BarChart3 className="text-[var(--accent)]" size={22} aria-hidden />
          Analytics
        </h2>
        <button
          type="button"
          onClick={onOpenDashboard}
          className="text-xs uppercase px-3 py-2 rounded-lg border border-[var(--accent)]/40 text-[var(--accent)] hover:bg-[var(--accent)]/10 font-semibold"
        >
          Dashboard
        </button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-3">
          <p className="text-[10px] uppercase tracking-wide text-[var(--text-disabled)]">Flows</p>
          <p className="text-xl font-mono font-semibold text-[var(--text-primary)]">{logs.length}</p>
        </div>
        <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-3">
          <p className="text-[10px] uppercase tracking-wide text-[var(--text-disabled)]">Avg size</p>
          <p className="text-xl font-mono font-semibold text-[var(--accent)]">{avgPacketSize}</p>
        </div>
        <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-3">
          <p className="text-[10px] uppercase tracking-wide text-[var(--text-disabled)]">Suspicious</p>
          <p className="text-xl font-mono font-semibold text-[#fbbf24]">{stats.suspiciousFlagged}</p>
        </div>
        <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-3">
          <p className="text-[10px] uppercase tracking-wide text-[var(--text-disabled)]">Malicious</p>
          <p className="text-xl font-mono font-semibold text-[#f72585]">{stats.attacksDetected}</p>
        </div>
      </div>

      {timeSpanLabel ? (
        <p className="text-xs text-[var(--text-muted)] rounded-lg border border-[var(--border)] bg-[var(--surface-subtle)]/60 px-3 py-2">
          <span className="text-[var(--text-secondary)] font-medium">Observation window:</span> {timeSpanLabel}
        </p>
      ) : null}

      <div className="h-[200px] sm:h-[220px] lg:h-[280px] bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-3">
        <div className="mb-2">
          <p className="text-[11px] text-[var(--text-secondary)] flex items-center gap-1.5">
            <Wifi size={12} className="text-[var(--accent)]" aria-hidden />
            Throughput
          </p>
          <p className="text-[10px] text-[var(--text-disabled)] mt-0.5">
            Byte-volume proxy per flow (shown in ingestion order slice). Combine with Distribution to contrast volume vs
            labels.
          </p>
        </div>
        {throughputSeries.length === 0 ? (
          <div className="h-[calc(100%-1.5rem)] flex items-center justify-center text-xs text-[var(--text-disabled)]">
            Load a PCAP on the dashboard.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={throughputSeries} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="anT" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2563eb" stopOpacity={0.28} />
                  <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#ccd6e6" vertical={false} />
              <XAxis dataKey="time" stroke="#5c6d8a" fontSize={9} tickLine={false} interval="preserveStartEnd" />
              <YAxis stroke="#5c6d8a" fontSize={9} width={32} tickLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="traffic" stroke="#2563eb" fill="url(#anT)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 lg:gap-6">
        <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-3 min-h-[240px] lg:min-h-[280px] flex flex-col">
          <h4 className="text-xs font-medium text-[var(--text-secondary)] mb-2">!!!!Distribution</h4>
          <p className="text-[10px] text-[var(--text-disabled)] mb-2">
            Share of flows by label — cite green / amber / magenta story for presenters.
          </p>
          <div className="flex-1 min-h-[180px] lg:min-h-[220px]">
            {logs.length === 0 ? (
              <p className="text-xs text-[var(--text-disabled)]">No data.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius="45%"
                    outerRadius="70%"
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {pieData.map((_, i) => (
                      <Cell key={i} fill={DIST_COLORS[i % DIST_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
          <p className="text-center text-[10px] text-[var(--text-disabled)] mt-1">
            Threat share {threatPct}% · Counter {totalTrafficCounter} · Clean {pctClean}% · Suspicious {pctSuspiciousOnly}%
            · Malicious {pctMalOnly}%
          </p>
        </div>

        <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-3 min-h-[240px] lg:min-h-[280px] flex flex-col">
          <h3 className="text-xs font-medium text-[var(--text-secondary)] mb-2">Status</h3>
          <p className="text-[10px] text-[var(--text-disabled)] mb-2">Absolute flow counts matching the Dashboard status column.</p>
          <div className="flex-1 min-h-[180px] lg:min-h-[220px]">
            {logs.length === 0 ? (
              <p className="text-xs text-[var(--text-disabled)]">No data.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={statusBars} margin={{ top: 8, right: 8, left: 8, bottom: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ccd6e6" vertical={false} />
                  <XAxis dataKey="name" stroke="#5c6d8a" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="#5c6d8a" fontSize={10} allowDecimals={false} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={48}>
                    {statusBars.map((e, i) => (
                      <Cell key={i} fill={e.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {protocolCounts.length > 0 ? (
        <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-3">
          <h3 className="text-xs font-medium text-[var(--text-secondary)] mb-2">Protocols</h3>
          <p className="text-[10px] text-[var(--text-disabled)] mb-2">Frequency of synthesized protocol labels in this batch.</p>
          <div className="h-36 sm:h-40 lg:h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={protocolCounts} layout="vertical" margin={{ left: 4, right: 12 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ccd6e6" horizontal={false} />
                <XAxis type="number" stroke="#5c6d8a" fontSize={10} />
                <YAxis type="category" dataKey="name" width={72} stroke="#5c6d8a" fontSize={10} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} fill="#2563eb" fillOpacity={0.85} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      ) : null}

      {confidenceStats && logs.length > 0 ? (
        <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-3">
          <h3 className="text-xs font-medium text-[var(--text-secondary)] mb-1">Heuristic confidence</h3>
          <p className="text-[10px] text-[var(--text-disabled)] mb-2">
            Min / mean / max of parser or rules confidence on loaded flows — cite alongside ML RF/IF columns on Dashboard.
          </p>
          <p className="text-sm font-mono text-[var(--text-soft)]">
            min {confidenceStats.min.toFixed(2)} · mean {confidenceStats.mean.toFixed(2)} · max{' '}
            {confidenceStats.max.toFixed(2)}
          </p>
        </div>
      ) : null}

      {topEndpoints.length > 0 ? (
        <div className="bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-3">
          <h3 className="text-xs font-medium text-[var(--text-secondary)] mb-1">Busiest IPs (appearances)</h3>
          <p className="text-[10px] text-[var(--text-disabled)] mb-2">
            How often each IPv4 occurred as source or destination — highlights talkative endpoints.
          </p>
          <div className="h-40 sm:h-44 lg:h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topEndpoints} layout="vertical" margin={{ left: 4, right: 12 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ccd6e6" horizontal={false} />
                <XAxis type="number" stroke="#5c6d8a" fontSize={10} />
                <YAxis type="category" dataKey="name" width={120} stroke="#5c6d8a" fontSize={9} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} fill="#a855f7" fillOpacity={0.75} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      ) : null}
    </div>
  );
}
