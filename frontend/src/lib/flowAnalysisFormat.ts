import { type TrafficLog, trafficStatusLabel as statusEnumLabel } from '../types';

export function formatFlowDetectionLogLine(log: TrafficLog, idx: number, total: number): string {
  const t = new Date().toISOString().split('T')[1].replace('Z', '').slice(0, 12);
  const atk = log.attackType ? ` · ${log.attackType}` : '';
  return `[${t}] ${idx + 1}/${total}  ${log.sourceIP}→${log.destIP}  ${log.protocol}  ${statusEnumLabel(log.status)}${atk}`;
}

export function formatMlLogLine(log: TrafficLog, mlAttempted: boolean): string {
  if (!mlAttempted) {
    return `       └─ ML: no feature vector (skip)`;
  }
  if (
    log.mlRandomForestConfidence == null &&
    log.mlIsolationAnomalyScore == null &&
    log.mlRandomForestStatus == null &&
    log.mlAutoencoderAnomalyScore == null
  ) {
    return `       └─ ML: service offline or unavailable — enable npm run ml:serve`;
  }
  const rf =
    log.mlRandomForestStatus != null && log.mlRandomForestConfidence != null
      ? `${log.mlRandomForestStatus} ${(log.mlRandomForestConfidence * 100).toFixed(0)}%`
      : '—';
  const ifs =
    log.mlIsolationAnomalyScore != null ? `IF ${(log.mlIsolationAnomalyScore * 100).toFixed(0)}%` : 'IF —';
  const ae =
    log.mlAutoencoderAnomalyScore != null ? `AE ${(log.mlAutoencoderAnomalyScore * 100).toFixed(0)}%` : 'AE —';
  return `       └─ RF ${rf} · ${ifs} · ${ae}`;
}
