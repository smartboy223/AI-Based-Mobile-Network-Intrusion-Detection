import ExcelJS from 'exceljs';
import { saveAs } from 'file-saver';
import type { TrafficLog } from '../types';
import { trafficPlaneLabel } from './telecom5gFields';
import { trafficStatusExportWord } from './trafficStatusUi';
import type { ExcelAiNarrative, ExcelAiRiskPosture } from './deepseek';

export type ExportLogsOptions = {
  /** When set, first worksheet is an AI-written intro + bullets (DeepSeek). */
  aiNarrative?: ExcelAiNarrative | null;
};

const NO_DNS = '— (no DNS QNAME parsed on this flow’s UDP/53 traffic)';
const NO_HTTP = '— (no cleartext HTTP Host on this flow’s TCP payload)';
const NO_JA3 = '— (no TLS ClientHello parsed)';
const NO_JA3S = '— (no TLS ServerHello parsed)';

// --- Brand palette ----------------------------------------------------------
// AARRGGBB for ExcelJS. Hand-picked so the workbook looks like a real briefing
// when opened in Excel / LibreOffice / Google Sheets.
const PALETTE = {
  ink: 'FF12121A',
  inkSoft: 'FF2D2D36',
  inkMuted: 'FF5C5C66',
  paper: 'FFFFFFFF',
  paperSoft: 'FFF6F7F9',
  accent: 'FF0E7490', // teal
  accentSoft: 'FFF0FDFA',
  accentInk: 'FFE1E1E6',
  cleanFill: 'FFD1FAE5',
  cleanInk: 'FF065F46',
  cleanChip: 'FF10B981',
  susFill: 'FFFEF3C7',
  susInk: 'FF92400E',
  susChip: 'FFF59E0B',
  malFill: 'FFFEE2E2',
  malInk: 'FF991B1B',
  malChip: 'FFEF4444',
} as const;

const RISK_COLORS: Record<ExcelAiRiskPosture, { fill: string; ink: string; label: string }> = {
  Critical: { fill: 'FF7F1D1D', ink: 'FFFFFFFF', label: 'CRITICAL RISK' },
  High:     { fill: 'FFB91C1C', ink: 'FFFFFFFF', label: 'HIGH RISK' },
  Medium:   { fill: 'FFD97706', ink: 'FFFFFFFF', label: 'MEDIUM RISK' },
  Low:      { fill: 'FF0E7490', ink: 'FFFFFFFF', label: 'LOW RISK' },
  Clean:    { fill: 'FF047857', ink: 'FFFFFFFF', label: 'CLEAN' },
};

function formatDns(log: TrafficLog): string {
  const d = log.dnsQueryNames ?? [];
  return d.length > 0 ? d.join('; ') : NO_DNS;
}

function formatHttpHost(log: TrafficLog): string {
  return log.httpHost?.trim() ? log.httpHost : NO_HTTP;
}

function formatJa3(log: TrafficLog): string {
  return log.ja3?.trim() ? log.ja3 : NO_JA3;
}

function formatJa3s(log: TrafficLog): string {
  return log.ja3s?.trim() ? log.ja3s : NO_JA3S;
}

function addFieldGuideSheet(workbook: ExcelJS.Workbook) {
  const ws = workbook.addWorksheet('Field guide');
  ws.columns = [
    { header: 'Column', key: 'c', width: 22 },
    { header: 'What it means', key: 'd', width: 78 },
  ];
  const h = ws.getRow(1);
  h.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  h.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.ink } };
  const rows = [
    ['DNS QNAMEs', 'DNS question names parsed from UDP/53 payloads aggregated into this 5-tuple flow.'],
    ['HTTP Host', 'Cleartext HTTP/1.x Host header from TCP payload (TLS inside 443 is opaque here).'],
    ['JA3 / JA3S', 'TLS fingerprint MD5 from ClientHello / ServerHello when present in cleartext TCP.'],
    ['Plane / session / operating profile', '5G dual lens: traffic plane, bearer grouping, telecom operating category, engineering note.'],
    ['Empty-looking cells', '“— (no …)” means the parser did not see that artefact on this flow — not an export bug.'],
    ['ML RF / IF / AE anomaly', 'Lab Random Forest + Isolation Forest + Autoencoder scores. Refresh from the dashboard row buttons.'],
    ['Status colours', 'Green = Clean, Amber = Suspicious, Red = Malicious. Confidence cells use a red data bar.'],
  ];
  for (const [a, b] of rows) {
    const r = ws.addRow({ c: a, d: b });
    r.getCell(1).font = { bold: true, color: { argb: PALETTE.accent } };
    r.getCell(2).alignment = { wrapText: true, vertical: 'top' };
  }
}

/** Render a row of three stat tiles (counts). Returns the next free row. */
function addCountsStrip(
  ws: ExcelJS.Worksheet,
  startRow: number,
  counts: { malicious: number; suspicious: number; clean: number; total: number },
): number {
  const tiles: Array<{ label: string; value: number; fill: string; ink: string }> = [
    { label: 'TOTAL FLOWS', value: counts.total, fill: PALETTE.ink, ink: PALETTE.accentInk },
    { label: 'MALICIOUS', value: counts.malicious, fill: PALETTE.malChip, ink: 'FFFFFFFF' },
    { label: 'SUSPICIOUS', value: counts.suspicious, fill: PALETTE.susChip, ink: 'FFFFFFFF' },
    { label: 'CLEAN', value: counts.clean, fill: PALETTE.cleanChip, ink: 'FFFFFFFF' },
  ];
  // Tiles laid out as 4 blocks, each spanning 2 columns of the 8-col sheet.
  // Row 1 of the tile: count (big), Row 2: label (small).
  const valueRow = ws.getRow(startRow);
  const labelRow = ws.getRow(startRow + 1);
  valueRow.height = 30;
  labelRow.height = 16;
  tiles.forEach((t, i) => {
    const col = i * 2 + 1; // 1,3,5,7
    const col2 = col + 1;
    ws.mergeCells(startRow, col, startRow, col2);
    ws.mergeCells(startRow + 1, col, startRow + 1, col2);
    const valCell = ws.getRow(startRow).getCell(col);
    valCell.value = t.value;
    valCell.font = { bold: true, size: 22, color: { argb: t.ink } };
    valCell.alignment = { vertical: 'middle', horizontal: 'center' };
    valCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: t.fill } };
    const labCell = ws.getRow(startRow + 1).getCell(col);
    labCell.value = t.label;
    labCell.font = { bold: true, size: 9, color: { argb: t.ink } };
    labCell.alignment = { vertical: 'middle', horizontal: 'center' };
    labCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: t.fill } };
  });
  return startRow + 2;
}

/** Render the tag chip strip starting at `startRow`. Returns next row. */
function addTagsRow(ws: ExcelJS.Worksheet, startRow: number, tags: string[]): number {
  if (!tags.length) return startRow;
  ws.mergeCells(startRow, 1, startRow, 8);
  const cell = ws.getRow(startRow).getCell(1);
  cell.value = tags.map((t) => `  ${t}  `).join('  •  ');
  cell.font = { bold: true, size: 10, color: { argb: PALETTE.accent } };
  cell.alignment = { vertical: 'middle', horizontal: 'left', wrapText: true };
  cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.accentSoft } };
  ws.getRow(startRow).height = 22;
  return startRow + 1;
}

/** Priority-IP table: ip | status chip | reason. */
function addPriorityIpsTable(
  ws: ExcelJS.Worksheet,
  startRow: number,
  rows: ExcelAiNarrative['priorityIps'],
): number {
  if (!rows.length) return startRow;
  // Section heading
  ws.mergeCells(startRow, 1, startRow, 8);
  const hdr = ws.getRow(startRow).getCell(1);
  hdr.value = 'Priority IPs — pivot on these first';
  hdr.font = { bold: true, size: 12, color: { argb: PALETTE.accent } };
  hdr.alignment = { vertical: 'middle' };
  startRow++;

  // Column headers
  const tblHead = ws.getRow(startRow);
  ws.mergeCells(startRow, 1, startRow, 2);
  ws.mergeCells(startRow, 3, startRow, 3);
  ws.mergeCells(startRow, 4, startRow, 8);
  tblHead.getCell(1).value = 'IPv4';
  tblHead.getCell(3).value = 'Status';
  tblHead.getCell(4).value = 'Why it matters';
  for (const col of [1, 3, 4]) {
    const c = tblHead.getCell(col);
    c.font = { bold: true, size: 10, color: { argb: 'FFFFFFFF' } };
    c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.ink } };
    c.alignment = { vertical: 'middle' };
  }
  startRow++;

  for (const r of rows) {
    const rowObj = ws.getRow(startRow);
    rowObj.height = 22;
    ws.mergeCells(startRow, 1, startRow, 2);
    ws.mergeCells(startRow, 3, startRow, 3);
    ws.mergeCells(startRow, 4, startRow, 8);
    const ipCell = rowObj.getCell(1);
    ipCell.value = r.ip;
    ipCell.font = { name: 'Consolas', size: 11, color: { argb: PALETTE.inkSoft } };
    ipCell.alignment = { vertical: 'middle' };
    const statusCell = rowObj.getCell(3);
    statusCell.value = r.status.toUpperCase();
    const chip =
      r.status === 'Malicious'
        ? { fill: PALETTE.malChip, ink: 'FFFFFFFF' }
        : r.status === 'Suspicious'
          ? { fill: PALETTE.susChip, ink: 'FFFFFFFF' }
          : { fill: PALETTE.cleanChip, ink: 'FFFFFFFF' };
    statusCell.font = { bold: true, size: 10, color: { argb: chip.ink } };
    statusCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: chip.fill } };
    statusCell.alignment = { vertical: 'middle', horizontal: 'center' };
    const reasonCell = rowObj.getCell(4);
    reasonCell.value = r.reason || '—';
    reasonCell.font = { size: 10, color: { argb: PALETTE.inkSoft } };
    reasonCell.alignment = { wrapText: true, vertical: 'middle' };
    startRow++;
  }
  return startRow;
}

function addNextStepsBlock(
  ws: ExcelJS.Worksheet,
  startRow: number,
  steps: string[],
): number {
  if (!steps.length) return startRow;
  ws.mergeCells(startRow, 1, startRow, 8);
  const hdr = ws.getRow(startRow).getCell(1);
  hdr.value = 'Recommended next steps';
  hdr.font = { bold: true, size: 12, color: { argb: PALETTE.accent } };
  startRow++;
  steps.forEach((s, i) => {
    ws.mergeCells(startRow, 1, startRow, 8);
    const c = ws.getRow(startRow).getCell(1);
    c.value = `  ${i + 1}.  ${s}`;
    c.font = { size: 10, color: { argb: PALETTE.inkSoft } };
    c.alignment = { wrapText: true, vertical: 'middle' };
    c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.paperSoft } };
    startRow++;
  });
  return startRow;
}

function addStyledAiSheet(
  workbook: ExcelJS.Workbook,
  n: ExcelAiNarrative,
  counts: { malicious: number; suspicious: number; clean: number; total: number },
) {
  const ai = workbook.addWorksheet('Executive briefing', {
    views: [{ showGridLines: false }],
  });

  // 8-column grid so we can lay out tiles and tables cleanly.
  for (let i = 1; i <= 8; i++) ai.getColumn(i).width = 14;

  // --- Title banner ---
  ai.mergeCells('A1:H1');
  const title = ai.getCell('A1');
  title.value = n.headline;
  title.font = { bold: true, size: 18, color: { argb: PALETTE.accentInk } };
  title.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.accent } };
  title.alignment = { vertical: 'middle', horizontal: 'center', wrapText: true };
  ai.getRow(1).height = 42;

  ai.mergeCells('A2:H2');
  const sub = ai.getCell('A2');
  sub.value = `MNIDS · AI-assisted workbook · ${new Date().toLocaleString()}`;
  sub.font = { italic: true, size: 10, color: { argb: 'FF8B8B96' } };
  sub.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.ink } };
  sub.alignment = { vertical: 'middle', horizontal: 'center' };
  ai.getRow(2).height = 20;

  // --- TL;DR banner with risk color ---
  const risk = RISK_COLORS[n.riskPosture];
  ai.mergeCells('A3:B3');
  const riskBadge = ai.getCell('A3');
  riskBadge.value = risk.label;
  riskBadge.font = { bold: true, size: 12, color: { argb: risk.ink } };
  riskBadge.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: risk.fill } };
  riskBadge.alignment = { vertical: 'middle', horizontal: 'center' };
  ai.mergeCells('C3:H3');
  const tldr = ai.getCell('C3');
  tldr.value = n.tldr;
  tldr.font = { bold: true, size: 11, color: { argb: PALETTE.inkSoft } };
  tldr.alignment = { vertical: 'middle', wrapText: true };
  tldr.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.paperSoft } };
  ai.getRow(3).height = 28;

  // Tiny rationale line under the badge
  ai.mergeCells('A4:H4');
  const rat = ai.getCell('A4');
  rat.value = `Why this rating: ${n.riskRationale}`;
  rat.font = { italic: true, size: 9, color: { argb: PALETTE.inkMuted } };
  rat.alignment = { vertical: 'middle', wrapText: true };

  let r = 6;

  // --- Counts strip ---
  r = addCountsStrip(ai, r, counts);
  r++;

  // --- Tag chips ---
  if (n.tags.length) {
    r = addTagsRow(ai, r, n.tags);
    r++;
  }

  // --- Executive overview ---
  ai.mergeCells(`A${r}:H${r}`);
  ai.getCell(`A${r}`).value = 'Executive overview';
  ai.getCell(`A${r}`).font = { bold: true, size: 12, color: { argb: PALETTE.accent } };
  r++;
  ai.mergeCells(`A${r}:H${r + 2}`);
  const introCell = ai.getCell(`A${r}`);
  introCell.value = n.intro;
  introCell.alignment = { wrapText: true, vertical: 'top' };
  introCell.font = { size: 11, color: { argb: PALETTE.inkSoft } };
  introCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.accentSoft } };
  r += 4;

  // --- Key points ---
  ai.mergeCells(`A${r}:H${r}`);
  ai.getCell(`A${r}`).value = 'Key points';
  ai.getCell(`A${r}`).font = { bold: true, size: 12, color: { argb: PALETTE.accent } };
  r++;
  for (const b of n.bullets) {
    ai.mergeCells(`A${r}:H${r}`);
    const c = ai.getCell(`A${r}`);
    c.value = `▸  ${b}`;
    c.alignment = { wrapText: true, vertical: 'top' };
    c.font = { size: 10, color: { argb: PALETTE.inkSoft } };
    c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.accentSoft } };
    r++;
  }
  r++;

  // --- Priority IPs ---
  r = addPriorityIpsTable(ai, r, n.priorityIps);
  r++;

  // --- Recommended next steps ---
  r = addNextStepsBlock(ai, r, n.nextSteps);
  r++;

  // --- Dataset signals ---
  if (n.signals.length > 0) {
    ai.mergeCells(`A${r}:H${r}`);
    ai.getCell(`A${r}`).value = 'Dataset signals (from export snapshot)';
    ai.getCell(`A${r}`).font = { bold: true, size: 11, color: { argb: PALETTE.accent } };
    r++;
    for (const s of n.signals) {
      ai.mergeCells(`A${r}:H${r}`);
      const c = ai.getCell(`A${r}`);
      c.value = `◆  ${s}`;
      c.font = { size: 10, color: { argb: PALETTE.inkMuted } };
      c.alignment = { wrapText: true, vertical: 'top' };
      r++;
    }
    r++;
  }

  // --- Closing ---
  ai.mergeCells(`A${r}:H${r + 1}`);
  const close = ai.getCell(`A${r}`);
  close.value = n.closing;
  close.font = { italic: true, size: 10, color: { argb: PALETTE.inkMuted } };
  close.alignment = { wrapText: true, vertical: 'top' };
}

export async function exportLogsToExcel(logs: TrafficLog[], options?: ExportLogsOptions) {
  const workbook = new ExcelJS.Workbook();

  const hasAi =
    options?.aiNarrative &&
    (options.aiNarrative.headline ||
      options.aiNarrative.intro ||
      options.aiNarrative.bullets.length > 0);

  const counts = {
    total: logs.length,
    malicious: logs.filter((l) => l.status === 'Malicious').length,
    suspicious: logs.filter((l) => l.status === 'Suspicious').length,
    clean: logs.filter((l) => l.status === 'Benign').length,
  };

  if (hasAi && options.aiNarrative) {
    addStyledAiSheet(workbook, options.aiNarrative, counts);
  }

  const worksheet = workbook.addWorksheet('Security Scan Results', {
    views: [{ state: 'frozen', ySplit: 1 }],
  });

  worksheet.columns = [
    { header: 'Timestamp', key: 'timestamp', width: 20 },
    { header: 'Source IP', key: 'sourceIP', width: 18 },
    { header: 'Dest IP', key: 'destIP', width: 18 },
    { header: 'Protocol', key: 'protocol', width: 12 },
    { header: 'DNS QNAMEs', key: 'dnsQueryNames', width: 36 },
    { header: 'HTTP Host', key: 'httpHost', width: 28 },
    { header: 'JA3', key: 'ja3', width: 36 },
    { header: 'JA3S', key: 'ja3s', width: 36 },
    { header: 'Plane', key: 'trafficPlane', width: 14 },
    { header: 'Session / bearer', key: 'sessionBearerKey', width: 28 },
    { header: 'Operating profile', key: 'operationalCategory', width: 28 },
    { header: 'Engineering note', key: 'engineeringNote', width: 44 },
    { header: 'GTP TEID', key: 'gtpuTeidHex', width: 14 },
    { header: 'Inner UE IPv4', key: 'innerUeIpv4', width: 16 },
    { header: 'Radio', key: 'radioAccess', width: 14 },
    { header: 'IF (N3/N6)', key: 'upfInterface', width: 12 },
    { header: 'DNN / slice', key: 'dnnSlice', width: 28 },
    { header: '5QI', key: 'fiveQi', width: 8 },
    { header: 'PDU', key: 'pduSessionId', width: 8 },
    { header: 'NGAP/NAS / GTP hint', key: 'ngapNasHint', width: 36 },
    { header: 'Raw sample', key: 'rawFrameSample', width: 18 },
    { header: 'Size (Bytes)', key: 'packetSize', width: 12 },
    { header: 'Packets', key: 'packetCount', width: 10 },
    { header: 'Bytes (flow)', key: 'byteTotal', width: 14 },
    { header: 'Duration (s)', key: 'duration', width: 12 },
    { header: 'Status', key: 'status', width: 12 },
    { header: 'Attack Type', key: 'attackType', width: 22 },
    { header: 'Analyst note', key: 'analystNote', width: 28 },
    { header: 'Confidence (%)', key: 'confidence', width: 14 },
    { header: 'ML RF class', key: 'mlRf', width: 14 },
    { header: 'ML RF conf. (%)', key: 'mlRfConf', width: 14 },
    { header: 'IF anomaly (0–1)', key: 'mlIf', width: 16 },
    { header: 'AE anomaly (0–1)', key: 'mlAe', width: 16 },
    { header: 'ML model', key: 'mlModel', width: 22 },
  ];

  const headerRow = worksheet.getRow(1);
  headerRow.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  headerRow.fill = {
    type: 'pattern',
    pattern: 'solid',
    fgColor: { argb: PALETTE.ink },
  };
  headerRow.height = 22;
  headerRow.alignment = { vertical: 'middle' };

  // Auto-filter dropdown on the header so the analyst can slice the sheet.
  worksheet.autoFilter = {
    from: { row: 1, column: 1 },
    to: { row: 1, column: worksheet.columns.length },
  };

  logs.forEach((log) => {
    const row = worksheet.addRow({
      timestamp: log.timestamp,
      sourceIP: log.sourceIP,
      destIP: log.destIP,
      protocol: log.protocol,
      dnsQueryNames: formatDns(log),
      httpHost: formatHttpHost(log),
      ja3: formatJa3(log),
      ja3s: formatJa3s(log),
      trafficPlane: log.trafficPlane ? trafficPlaneLabel(log.trafficPlane) : '—',
      sessionBearerKey: log.sessionBearerKey ?? '—',
      operationalCategory: log.operationalCategory ?? '—',
      engineeringNote: log.engineeringNote ?? '—',
      gtpuTeidHex: log.gtpuTeidHex ?? '—',
      innerUeIpv4: log.innerUeIpv4 ?? '—',
      radioAccess: log.radioAccess ?? '—',
      upfInterface: log.upfInterface ?? '—',
      dnnSlice: log.dnnSlice ?? '—',
      fiveQi: log.fiveQi ?? '—',
      pduSessionId: log.pduSessionId ?? '—',
      ngapNasHint: log.ngapNasHint ?? '—',
      rawFrameSample: log.rawFrameSample ?? '—',
      packetSize: log.packetSize,
      packetCount: log.packetCount ?? '—',
      byteTotal: log.byteTotal ?? '—',
      duration: log.duration,
      status: trafficStatusExportWord(log.status),
      attackType: log.attackType || 'N/A',
      analystNote: log.analystNote?.trim() ? log.analystNote : '— (none)',
      confidence: Number((log.confidence * 100).toFixed(1)),
      mlRf: log.mlRandomForestStatus ? trafficStatusExportWord(log.mlRandomForestStatus) : '—',
      mlRfConf:
        log.mlRandomForestConfidence != null
          ? Number((log.mlRandomForestConfidence * 100).toFixed(1))
          : '—',
      mlIf:
        log.mlIsolationAnomalyScore != null ? log.mlIsolationAnomalyScore.toFixed(4) : '—',
      mlAe:
        log.mlAutoencoderAnomalyScore != null ? log.mlAutoencoderAnomalyScore.toFixed(4) : '—',
      mlModel: log.mlModelVersion ?? '—',
    });

    if (log.status === 'Malicious') {
      row.eachCell((cell) => {
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.malFill } };
        cell.font = { color: { argb: PALETTE.malInk } };
      });
      const statusCell = row.getCell('status');
      statusCell.value = '● MALICIOUS';
      statusCell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
      statusCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.malChip } };
      statusCell.alignment = { horizontal: 'center' };
    } else if (log.status === 'Suspicious') {
      row.eachCell((cell) => {
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.susFill } };
        cell.font = { color: { argb: PALETTE.susInk } };
      });
      const statusCell = row.getCell('status');
      statusCell.value = '● SUSPICIOUS';
      statusCell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
      statusCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.susChip } };
      statusCell.alignment = { horizontal: 'center' };
    } else {
      const statusCell = row.getCell('status');
      statusCell.value = '● CLEAN';
      statusCell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
      statusCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.cleanChip } };
      statusCell.alignment = { horizontal: 'center' };
    }

    // Same chip treatment for the ML RF class column when we have a prediction.
    const mlCell = row.getCell('mlRf');
    const mlRaw = log.mlRandomForestStatus;
    if (mlRaw === 'Malicious') {
      mlCell.value = '● MALICIOUS';
      mlCell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
      mlCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.malChip } };
      mlCell.alignment = { horizontal: 'center' };
    } else if (mlRaw === 'Suspicious') {
      mlCell.value = '● SUSPICIOUS';
      mlCell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
      mlCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.susChip } };
      mlCell.alignment = { horizontal: 'center' };
    } else if (mlRaw === 'Benign') {
      mlCell.value = '● CLEAN';
      mlCell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
      mlCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: PALETTE.cleanChip } };
      mlCell.alignment = { horizontal: 'center' };
    }
  });

  // Confidence columns: 3-stop color scale (white -> amber -> red) so
  // high-confidence rows pop visually. ExcelJS exposes colorScale rules
  // with strongly-typed argb colors, unlike dataBar.
  if (logs.length > 0) {
    const lastRow = logs.length + 1;
    worksheet.addConditionalFormatting({
      ref: `AC2:AC${lastRow}`,
      rules: [
        {
          type: 'colorScale',
          priority: 1,
          cfvo: [
            { type: 'num', value: 0 },
            { type: 'num', value: 60 },
            { type: 'num', value: 100 },
          ],
          color: [
            { argb: 'FFFFFFFF' },
            { argb: PALETTE.susChip },
            { argb: PALETTE.malChip },
          ],
        },
      ],
    });
    worksheet.addConditionalFormatting({
      ref: `AE2:AE${lastRow}`,
      rules: [
        {
          type: 'colorScale',
          priority: 1,
          cfvo: [
            { type: 'num', value: 0 },
            { type: 'num', value: 60 },
            { type: 'num', value: 100 },
          ],
          color: [
            { argb: 'FFFFFFFF' },
            { argb: PALETTE.cleanChip },
            { argb: PALETTE.accent },
          ],
        },
      ],
    });
  }

  addFieldGuideSheet(workbook);

  const buffer = await workbook.xlsx.writeBuffer();
  const blob = new Blob([buffer], {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  saveAs(blob, `5G_IDS_Scan_${new Date().toISOString().split('T')[0]}.xlsx`);
}
