import type { TrafficLog, TrafficPlane, UpfInterface } from '../types';

export function trafficPlaneLabel(p: TrafficPlane): string {
  switch (p) {
    case 'USER_PLANE':
      return 'User plane';
    case 'CONTROL_PLANE':
      return 'Control plane';
    case 'BREAKOUT_AND_IP':
      return 'Breakout / IP';
    default:
      return p;
  }
}

export function inferTrafficPlane(
  protocol: TrafficLog['protocol'],
  upfInterface?: UpfInterface,
): TrafficPlane {
  if (protocol === 'GTP-U') return 'USER_PLANE';
  if (protocol === 'NGAP' || protocol === 'NAS-5G') return 'CONTROL_PLANE';
  if (protocol === 'SCTP') return 'CONTROL_PLANE';
  if (upfInterface === 'N6' || upfInterface === 'Non-3GPP') return 'BREAKOUT_AND_IP';
  if (protocol === 'TCP' || protocol === 'UDP' || protocol === 'HTTP/2' || protocol === 'QUIC') {
    return upfInterface === 'N3' || upfInterface === 'N9' ? 'USER_PLANE' : 'BREAKOUT_AND_IP';
  }
  return 'BREAKOUT_AND_IP';
}

function dnnShort(dnn?: string): string {
  if (!dnn) return 'default';
  if (dnn.includes('ims')) return 'IMS';
  if (dnn.includes('emb') || dnn.includes('slice')) return 'eMBB slice';
  return 'Internet DNN';
}

/** Stable grouping key: inner UE IPv4 when known, else TEID, else PDU + DNN. */
export function buildSessionBearerKey(log: Pick<TrafficLog, 'innerUeIpv4' | 'gtpuTeidHex' | 'pduSessionId' | 'dnnSlice'>): string {
  if (log.innerUeIpv4?.trim()) {
    const te = log.gtpuTeidHex?.trim();
    return te ? `UE ${log.innerUeIpv4} · ${te}` : `UE ${log.innerUeIpv4}`;
  }
  if (log.gtpuTeidHex?.trim()) return log.gtpuTeidHex.trim();
  const pdu = log.pduSessionId ?? 0;
  return `PDU ${pdu} · ${dnnShort(log.dnnSlice)}`;
}

export function deriveOperationalCategory(log: TrafficLog): string {
  const atkRaw = log.attackType ?? '';
  const atk = atkRaw.toLowerCase();
  const proto = log.protocol;
  if (atkRaw.startsWith('IOC:')) return 'Legacy correlation tag (imported label)';
  if (atk.includes('signal') || atk.includes('ngap') || atk.includes('nas')) {
    return 'Signaling load / control-plane anomaly';
  }
  if (atk.includes('gtp') || proto === 'GTP-U') {
    return 'User-plane tunnel / TEID behavior';
  }
  if (atk.includes('n6') || atk.includes('breakout') || log.upfInterface === 'N6') {
    return 'N6 breakout / data network path';
  }
  if (atk.includes('ssh') || atk.includes('brute')) {
    return 'Service-facing access attempt (N6 / exposed service)';
  }
  if (atk.includes('flood') || atk.includes('ddos') || atk.includes('volumetric')) {
    return 'Volumetric / flood pattern';
  }
  if (log.status === 'Suspicious') return 'Policy or baseline deviation (review)';
  if (log.status === 'Malicious') return 'High-confidence threat indicator';
  return 'Within expected operating profile';
}

export function deriveEngineeringNote(log: TrafficLog): string {
  const plane = inferTrafficPlane(log.protocol, log.upfInterface);
  if (plane === 'USER_PLANE' && log.status !== 'Benign') {
    return 'Correlate with UPF encapsulation policy, peer gNB N3 allow-list, and subscriber slice binding. Rule out mis-steered N6 leakage before treating as data exfiltration.';
  }
  if (plane === 'CONTROL_PLANE' && log.status !== 'Benign') {
    return 'Distinguish AMF / SMF overload from coordinated signaling abuse; check SCTP multihoming and SCTP PPID for NGAP.';
  }
  if (log.upfInterface === 'N6' && log.status !== 'Benign') {
    return 'Validate DNN / slice vs observed destination; misconfigured UPF breakout can resemble intentional exfiltration.';
  }
  if (log.protocol === 'GTP-U' && !log.innerUeIpv4) {
    return 'No inner IPv4 extracted on this GTP-U aggregate; confirm encapsulation format (T-PDU) and capture point (N3 vs internal).';
  }
  return 'No additional engineering note.';
}

export function ensureTelecomFields(log: TrafficLog): TrafficLog {
  const trafficPlane = inferTrafficPlane(log.protocol, log.upfInterface);
  const operationalCategory = deriveOperationalCategory(log);
  const engineeringNote = deriveEngineeringNote(log);
  const sessionBearerKey = buildSessionBearerKey(log);
  return {
    ...log,
    trafficPlane,
    operationalCategory,
    engineeringNote,
    sessionBearerKey,
  };
}
