const path = require('path');
const fs = require('fs');
const PptxGenJS = require('pptxgenjs');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const OUT_DIR = path.join(REPO_ROOT, 'archive', 'presentation', 'final');
const OUT_FILE = path.join(OUT_DIR, 'MNIDS_Final_Presentation.pptx');
const SHOT_DIR = path.join(OUT_DIR, 'screenshots');

const FONT_TITLE = 'Calibri';
const FONT_BODY = 'Calibri';
const FONT_CODE = 'Consolas';
const HEADER_BAR_H = 0.74;

const C = {
  dark: '0a0a0e',
  headerBg: '0f172a',
  headerMuted: '94a3b8',
  panel: '12121a',
  line: 'cbd5e1',
  accent: '38bdf8',
  accent2: 'f472b6',
  warn: 'fbbf24',
  ok: '4ade80',
  white: 'FFFFFF',
  ink: '1e293b',
  muted: '64748b',
  lightBg: 'f8fafc',
  pageBg: 'eef2f6',
  card: 'e2e8f0',
  codeBg: '0c1222',
  gold: 'c9a227',
};

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function addProfessionalHeader(slide, pres, title, subtitle) {
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0,
    y: 0,
    w: 10,
    h: HEADER_BAR_H,
    fill: { color: C.headerBg },
    line: { width: 0 },
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0,
    y: 0,
    w: 0.14,
    h: HEADER_BAR_H,
    fill: { color: C.accent },
    line: { width: 0 },
  });
  slide.addText(title, {
    x: 0.3,
    y: 0.1,
    w: 9.55,
    h: subtitle ? 0.32 : 0.52,
    fontSize: 25,
    bold: true,
    color: C.white,
    fontFace: FONT_TITLE,
    valign: 'middle',
  });
  if (subtitle) {
    slide.addText(subtitle, {
      x: 0.3,
      y: 0.44,
      w: 9.55,
      h: 0.26,
      fontSize: 11,
      color: C.headerMuted,
      fontFace: FONT_BODY,
    });
  }
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0,
    y: HEADER_BAR_H - 0.035,
    w: 10,
    h: 0.035,
    fill: { color: C.gold },
    line: { width: 0 },
  });
}

function addContentFooter(slide, pres, darkBg) {
  const fg = darkBg ? '94a3b8' : '64748b';
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0.28,
    y: 5.31,
    w: 3.2,
    h: 0.038,
    fill: { color: C.gold },
    line: { width: 0 },
  });
  slide.addText(
    'MNIDS · Open-source mobile-network security lab · 5G IDS research demo',
    {
      x: 0.28,
      y: 5.34,
      w: 8.2,
      h: 0.22,
      fontSize: 7.5,
      color: fg,
      fontFace: FONT_BODY,
    },
  );
}

function addSlideNumberStd(slide) {
  slide.slideNumber = {
    x: 8.72,
    y: 5.14,
    w: 1.2,
    h: 0.28,
    fontSize: 9,
    color: '64748b',
    fontFace: FONT_BODY,
    align: 'right',
  };
}

function addContentSlide(pres, title, subtitle) {
  const slide = pres.addSlide();
  slide.background = { color: C.pageBg };
  addProfessionalHeader(slide, pres, title, subtitle);
  addContentFooter(slide, pres, false);
  addSlideNumberStd(slide);
  return slide;
}

function addSectionDivider(pres, title, subtitle) {
  const slide = pres.addSlide();
  slide.background = { color: C.dark };
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0,
    y: 2.05,
    w: 10,
    h: 0.07,
    fill: { color: C.accent },
    line: { width: 0 },
  });
  slide.addText(title, {
    x: 0.55,
    y: 1.25,
    w: 8.9,
    h: 0.85,
    fontSize: 34,
    bold: true,
    color: C.white,
    fontFace: FONT_TITLE,
  });
  slide.addText(subtitle, {
    x: 0.55,
    y: 2.35,
    w: 8.5,
    h: 0.55,
    fontSize: 15,
    color: C.headerMuted,
    fontFace: FONT_BODY,
  });
  slide.addShape(pres.shapes.OVAL, {
    x: 7.4,
    y: 0.4,
    w: 3.2,
    h: 3.2,
    fill: { color: C.accent, transparency: 92 },
    line: { width: 0 },
  });
  slide.addShape(pres.shapes.OVAL, {
    x: -0.8,
    y: 3.6,
    w: 2.6,
    h: 2.6,
    fill: { color: C.accent2, transparency: 93 },
    line: { width: 0 },
  });
  addContentFooter(slide, pres, true);
  slide.slideNumber = {
    x: 8.72,
    y: 5.14,
    w: 1.2,
    h: 0.28,
    fontSize: 9,
    color: '94a3b8',
    fontFace: FONT_BODY,
    align: 'right',
  };
  return slide;
}

function addWireframeDashboard(slide, pres, x0, y0, w, h) {
  const hdrH = h * 0.1;
  slide.addShape(pres.shapes.RECTANGLE, {
    x: x0,
    y: y0,
    w,
    h: hdrH,
    fill: { color: C.panel },
    line: { color: C.line, width: 1 },
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: x0 + w * 0.35,
    y: y0 + hdrH * 0.2,
    w: w * 0.3,
    h: hdrH * 0.6,
    fill: { color: C.card },
    line: { color: '94a3b8', width: 1 },
  });
  const cardW = (w - 0.25) / 4;
  const cy = y0 + hdrH + 0.12;
  const ch = h * 0.22;
  const colors = [C.accent, C.accent2, C.warn, C.ok];
  for (let i = 0; i < 4; i++) {
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: x0 + 0.05 + i * (cardW + 0.04),
      y: cy,
      w: cardW,
      h: ch,
      fill: { color: colors[i], transparency: 75 },
      line: { color: C.line, width: 1 },
      rectRadius: 0.06,
    });
  }
  const ty = cy + ch + 0.15;
  slide.addShape(pres.shapes.RECTANGLE, {
    x: x0,
    y: ty,
    w,
    h: y0 + h - ty,
    fill: { color: 'ffffff' },
    line: { color: C.line, width: 1 },
  });
  for (let r = 0; r < 5; r++) {
    slide.addShape(pres.shapes.RECTANGLE, {
      x: x0 + 0.08,
      y: ty + 0.12 + r * 0.28,
      w: w - 0.16,
      h: 0.22,
      fill: { color: r % 2 ? 'f8fafc' : 'ffffff' },
      line: { color: 'e2e8f0', width: 0.5 },
    });
  }
}

function addBarChartMock(slide, pres, x0, y0, w, h) {
  slide.addShape(pres.shapes.RECTANGLE, {
    x: x0,
    y: y0,
    w,
    h,
    fill: { color: 'ffffff' },
    line: { color: C.line, width: 1 },
  });
  const baseY = y0 + h - 0.35;
  const bw = 0.35;
  const gaps = [0.35, 0.55, 0.4, 0.65, 0.5];
  let cx = x0 + 0.4;
  gaps.forEach((gh, i) => {
    slide.addShape(pres.shapes.RECTANGLE, {
      x: cx,
      y: baseY - gh,
      w: bw,
      h: gh,
      fill: { color: i % 2 ? C.accent : '0d9488' },
      line: { color: '0f766e', width: 0.5 },
    });
    cx += bw + 0.25;
  });
  slide.addShape(pres.shapes.LINE, {
    x: x0 + 0.25,
    y: baseY,
    w: w - 0.5,
    h: 0,
    line: { color: C.ink, width: 1 },
  });
}

const LAB_ML_PIPELINE_ITEMS = [
  'PCAP → flow features (mlFeatures.ts)',
  'Random Forest — multiclass status + confidence',
  'Isolation Forest — anomaly score',
  'Autoencoder — reconstruction MSE',
  'FastAPI :8787 · joblib / Keras artefacts',
  'Heuristic labels if inference API offline',
];

/** Right-side diagram: lab ML stack (replaces legacy IOC rule mock). */
function addMlStackMock(slide, pres, x0, y0, w, h) {
  const split = w * 0.34;
  slide.addShape(pres.shapes.RECTANGLE, {
    x: x0,
    y: y0,
    w: split - 0.08,
    h,
    fill: { color: 'ffffff' },
    line: { color: C.line, width: 1 },
  });
  slide.addText('5G IDS — ML detection stack', {
    x: x0 + 0.1,
    y: y0 + 0.08,
    w: split - 0.2,
    h: 0.28,
    fontSize: 9,
    bold: true,
    color: C.muted,
    fontFace: FONT_BODY,
  });
  for (let i = 0; i < 6; i++) {
    slide.addShape(pres.shapes.RECTANGLE, {
      x: x0 + 0.08,
      y: y0 + 0.42 + i * 0.36,
      w: split - 0.24,
      h: 0.3,
      fill: { color: i === 1 ? 'e0f2fe' : 'f8fafc' },
      line: { color: i === 1 ? C.accent : 'e2e8f0', width: i === 1 ? 1.5 : 0.5 },
    });
    slide.addText(LAB_ML_PIPELINE_ITEMS[i] || `step_${i}`, {
      x: x0 + 0.14,
      y: y0 + 0.48 + i * 0.36,
      w: split - 0.32,
      h: 0.22,
      fontSize: 7.5,
      color: C.ink,
      fontFace: FONT_CODE,
    });
  }

  const codeX = x0 + split;
  const codeW = w - split;
  slide.addShape(pres.shapes.RECTANGLE, {
    x: codeX,
    y: y0,
    w: codeW,
    h,
    fill: { color: C.codeBg },
    line: { color: C.accent, width: 1 },
  });
  slide.addText('inference payload (conceptual)', {
    x: codeX + 0.12,
    y: y0 + 0.1,
    w: codeW - 0.24,
    h: 0.22,
    fontSize: 10,
    bold: true,
    color: C.accent,
    fontFace: FONT_CODE,
  });
  const snippet = [
    '// Flow row → numeric feature vector',
    'POST /api/ml/infer',
    '{ "features": [ ... 14 floats ... ] }',
    '// → rfStatus, rfConfidence,',
    '//   ifAnomalyScore, aeAnomalyScore',
  ].join('\n');
  slide.addText(snippet, {
    x: codeX + 0.1,
    y: y0 + 0.38,
    w: codeW - 0.2,
    h: h - 0.48,
    fontSize: 7.5,
    color: 'e2e8f0',
    fontFace: FONT_CODE,
    valign: 'top',
  });
}

function addChatMock(slide, pres, x0, y0, w, h) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: x0,
    y: y0,
    w,
    h,
    fill: { color: 'faf5ff' },
    line: { color: 'c4b5fd', width: 1 },
    rectRadius: 0.06,
  });
  slide.addText('AI Assistant — same contract as live UI', {
    x: x0 + 0.14,
    y: y0 + 0.08,
    w: w - 0.28,
    h: 0.22,
    fontSize: 9,
    bold: true,
    color: '6d28d9',
    fontFace: FONT_BODY,
  });

  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: x0 + 0.12,
    y: y0 + 0.34,
    w: w * 0.78,
    h: 0.58,
    fill: { color: 'c7d2fe' },
    line: { color: '4f46e5', width: 0.5 },
    rectRadius: 0.07,
  });
  slide.addText(
    'Analyst: Summarise this flow using only the Evidence JSON. How do RF / IF / AE scores support Suspicious vs Clean?',
    {
      x: x0 + 0.2,
      y: y0 + 0.4,
      w: w * 0.7,
      h: 0.48,
      fontSize: 9,
      color: '1e1b4b',
      fontFace: FONT_BODY,
    },
  );

  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: x0 + w * 0.18,
    y: y0 + 1.05,
    w: w * 0.78,
    h: 1.05,
    fill: { color: 'ffffff' },
    line: { color: '7c3aed', width: 0.5 },
    rectRadius: 0.07,
  });
  slide.addText(
    'Assistant (DeepSeek): Evidence shows RFC1918 endpoints, elevated IF/AE anomaly scores vs lab thresholds, RF suggests Suspicious pending VT on public IPs. I will not invent IPs — apply mnids-patch only if you confirm.',
    {
      x: x0 + w * 0.24,
      y: y0 + 1.12,
      w: w * 0.68,
      h: 0.92,
      fontSize: 9,
      color: '334155',
      fontFace: FONT_BODY,
    },
  );

  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: x0 + 0.12,
    y: y0 + 2.25,
    w: w * 0.72,
    h: 0.52,
    fill: { color: 'c7d2fe' },
    line: { color: '4f46e5', width: 0.5 },
    rectRadius: 0.07,
  });
  slide.addText(
    'Analyst: Suggest a mnids-patch to mark Clean if VT is clean and ML agrees — I will review before apply.',
    {
      x: x0 + 0.2,
      y: y0 + 0.05 + 2.25,
      w: w * 0.64,
      h: 0.42,
      fontSize: 9,
      color: '1e1b4b',
      fontFace: FONT_BODY,
    },
  );

  slide.addShape(pres.shapes.RECTANGLE, {
    x: x0 + 0.12,
    y: y0 + h - 0.38,
    w: w - 0.24,
    h: 0.3,
    fill: { color: 'fef3c7' },
    line: { color: 'd97706', width: 0.5 },
  });
  slide.addText('Human-in-the-loop: patches never apply without analyst confirmation.', {
    x: x0 + 0.18,
    y: y0 + h - 0.34,
    w: w - 0.36,
    h: 0.24,
    fontSize: 8,
    bold: true,
    color: '92400e',
    fontFace: FONT_BODY,
  });
}

function embedScreenshotSlide(pres, title, figNo, fileName, bulletPoints = []) {
  const full = path.join(SHOT_DIR, fileName);
  const slide = pres.addSlide();
  slide.background = { color: C.pageBg };
  addProfessionalHeader(slide, pres, title, `Figure ${figNo}`);

  const topY = HEADER_BAR_H + 0.08;
  const contentH = 4.58;
  const leftW = bulletPoints.length > 0 ? 3.22 : 0;
  const gap = 0.14;

  if (bulletPoints.length > 0) {
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 0.32,
      y: topY,
      w: leftW - 0.04,
      h: contentH,
      fill: { color: 'ffffff' },
      line: { color: C.line, width: 1 },
      rectRadius: 0.05,
    });
    slide.addShape(pres.shapes.RECTANGLE, {
      x: 0.32,
      y: topY,
      w: 0.08,
      h: contentH,
      fill: { color: C.accent },
      line: { width: 0 },
    });
    slide.addText('Highlights', {
      x: 0.48,
      y: topY + 0.12,
      w: leftW - 0.55,
      h: 0.26,
      fontSize: 11,
      bold: true,
      color: C.headerBg,
      fontFace: FONT_TITLE,
    });
    const blt = bulletPoints.map((t) => ({ text: t, options: { bullet: true, breakLine: true } }));
    slide.addText(blt, {
      x: 0.48,
      y: topY + 0.4,
      w: leftW - 0.58,
      h: contentH - 0.52,
      fontSize: 11,
      color: C.ink,
      fontFace: FONT_BODY,
    });
  }

  const imgX = bulletPoints.length > 0 ? 0.32 + leftW + gap : 0.32;
  const imgW = bulletPoints.length > 0 ? 9.36 - leftW - gap : 9.36;
  const imgH = contentH;

  if (fs.existsSync(full)) {
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: imgX - 0.03,
      y: topY - 0.03,
      w: imgW + 0.06,
      h: imgH + 0.06,
      fill: { color: 'ffffff' },
      line: { color: 'e2e8f0', width: 1 },
      rectRadius: 0.04,
    });
    slide.addImage({
      path: full,
      x: imgX,
      y: topY,
      w: imgW,
      h: imgH,
      sizing: { type: 'contain', w: imgW, h: imgH },
      altText: title,
    });
  } else {
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: imgX,
      y: topY,
      w: imgW,
      h: imgH,
      fill: { color: 'fee2e2' },
      line: { color: 'f87171', width: 1 },
      rectRadius: 0.04,
    });
    slide.addText(
      [
        `Missing screenshot: ${fileName}`,
        'Save PNGs under: archive/presentation/final/screenshots/',
        'Then run: npm run capture:screenshots  →  npm run gen:presentation',
      ].join('\n'),
      {
        x: imgX,
        y: topY + imgH * 0.35,
        w: imgW,
        h: 1.4,
        fontSize: 12,
        color: '991b1b',
        align: 'center',
        valign: 'middle',
        fontFace: FONT_BODY,
      },
    );
  }
  addContentFooter(slide, pres, false);
  addSlideNumberStd(slide);
}

function addProjectResourcesSlide(pres) {
  const top = HEADER_BAR_H + 0.1;
  const slide = addContentSlide(
    pres,
    'Project resources & technology stack',
    'Discuss during viva: what is required to run, demo, and extend MNIDS',
  );
  const cw = 4.48;
  const ch = 2.06;
  const y1 = top;
  const y2 = top + 2.2;
  const card = (x, y, title, lines, fill, stroke) => {
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x,
      y,
      w: cw,
      h: ch,
      fill: { color: fill },
      line: { color: stroke, width: 1 },
      rectRadius: 0.07,
    });
    slide.addText(title, {
      x: x + 0.12,
      y: y + 0.08,
      w: cw - 0.24,
      h: 0.28,
      fontSize: 11,
      bold: true,
      color: C.headerBg,
      fontFace: FONT_TITLE,
    });
    slide.addText(lines.join('\n'), {
      x: x + 0.12,
      y: y + 0.36,
      w: cw - 0.22,
      h: ch - 0.44,
      fontSize: 8,
      color: C.ink,
      fontFace: FONT_BODY,
      valign: 'top',
    });
  };
  card(
    0.32,
    y1,
    'Hardware & runtime',
    [
      '• Multi-core PC or laptop; 8 GB RAM minimum, 16 GB for larger PCAPs.',
      '• SSD recommended; Chromium-based or Firefox browser.',
      '• No dedicated server required for core SPA + optional local proxy.',
    ],
    'fff7ed',
    'ea580c',
  );
  card(
    4.92,
    y1,
    'Frontend (UI)',
    [
      '• React 19, TypeScript, Vite 6, Tailwind CSS 4.',
      '• Recharts, Lucide, Motion, React Markdown, ExcelJS, file-saver.',
      '• In-browser PCAP parsing; localStorage for session, rules, caches.',
    ],
    'e0f2fe',
    '0284c7',
  );
  card(
    0.32,
    y2,
    'Backend & tooling',
    [
      '• Vite dev server: custom plugins (PCAP library, VirusTotal proxy).',
      '• Proxy /api/deepseek → DeepSeek; dotenv for keys.',
      '• Playwright captures; PptxGenJS for this deck; Express in deps if extended.',
    ],
    'f0fdf4',
    '16a34a',
  );
  card(
    4.92,
    y2,
    'APIs, datasets & budget',
    [
      '• Optional VT key (quotas); DeepSeek-compatible key for assistant.',
      '• PCAP captures; public IDS datasets (e.g. CICIDS2018, 5G-NIDD per report).',
      '• Indicative total ~112 OMR (software-centric; see report Table 4.1).',
    ],
    'faf5ff',
    '7c3aed',
  );
}

function addSystemComponentsTable(slide, pres, y0) {
  const h = { bold: true, color: 'FFFFFF', fill: { color: '0f172a' }, fontFace: FONT_BODY };
  slide.addTable(
    [
      [{ text: 'Module', options: h }, { text: 'Role (per project report)', options: h }],
      ['PCAP input', 'Analyst-uploaded captures; primary data source for analysis.'],
      ['Parsing', 'Extracts IPs, ports, protocols, timestamps, packet sizes from raw traffic.'],
      ['Flow generation', 'Aggregates packets into flows for session-level behaviour inspection.'],
      ['ML inference (RF / IF / AE)', 'Trained models score each flow; heuristic fallback if API offline.'],
      ['VirusTotal', 'Optional reputation enrichment for IPs, domains, and related artefacts.'],
      ['AI assistant (DeepSeek)', 'Evidence-grounded explanations; supports but does not replace detection.'],
      ['Dashboard & export', 'Interactive visualization; structured Excel and JSON outputs.'],
    ],
    {
      x: 0.3,
      y: y0,
      w: 9.4,
      colW: [2.45, 6.95],
      fontSize: 9,
      border: { type: 'solid', color: 'cbd5e1', pt: 1 },
      fontFace: FONT_BODY,
    },
  );
}

function main() {
  ensureDir(OUT_DIR);
  const pres = new PptxGenJS();
  pres.layout = 'LAYOUT_16x9';
  pres.author = 'MNIDS Contributors';
  pres.title = 'AI-Based Mobile Network Intrusion Detection';
  pres.subject =
    'Final presentation: Mobile Network Intrusion Detection & Analysis System (MNIDS) — Bachelor project';

  const contentTop = HEADER_BAR_H + 0.1;

  let slide = pres.addSlide();
  slide.background = { color: C.dark };
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 6.8,
    y: -0.4,
    w: 4.5,
    h: 6.5,
    fill: { color: C.accent, transparency: 88 },
    line: { width: 0 },
    rotate: 18,
  });
  slide.addShape(pres.shapes.OVAL, {
    x: -0.6,
    y: 3.8,
    w: 2.8,
    h: 2.8,
    fill: { color: C.accent2, transparency: 90 },
    line: { width: 0 },
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0,
    y: 5.08,
    w: 10,
    h: 0.06,
    fill: { color: C.gold },
    line: { width: 0 },
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0,
    y: 5.15,
    w: 10,
    h: 0.45,
    fill: { color: C.accent },
    line: { width: 0 },
  });
  slide.addText('AI-Based Mobile Network\nIntrusion Detection', {
    x: 0.55,
    y: 1.05,
    w: 8.9,
    h: 1.55,
    fontSize: 40,
    bold: true,
    color: C.accent,
    fontFace: FONT_TITLE,
  });
  slide.addText('Mobile Network Intrusion Detection & Analysis System (MNIDS)', {
    x: 0.55,
    y: 2.45,
    w: 8.5,
    h: 0.45,
    fontSize: 14,
    color: C.gold,
    fontFace: FONT_TITLE,
    bold: true,
  });
  slide.addText('Browser-based 5G IDS workstation: PCAP to flows, ML detection, optional threat intel, and AI-assisted triage', {
    x: 0.55,
    y: 2.88,
    w: 8.5,
    h: 0.75,
    fontSize: 16,
    color: C.white,
    fontFace: FONT_BODY,
  });
  slide.addText(
    'MNIDS Contributors\nOpen-source mobile-network security lab',
    {
      x: 0.55,
      y: 3.52,
      w: 8.5,
      h: 1,
      fontSize: 14,
      color: C.headerMuted,
      fontFace: FONT_BODY,
    },
  );

  slide = addContentSlide(
    pres,
    'Executive summary',
    'Aligned with the public project architecture and validation workflow',
  );
  slide.addText(
    [
      {
        text: 'MNIDS processes PCAP into structured flows, extracts lab feature vectors, and runs **5G IDS** ML detection (Random Forest, Isolation Forest, autoencoder) with parser heuristics as fallback.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Threat intelligence (e.g. VirusTotal) and an AI-assisted layer provide contextual enrichment; this prototype focuses on detection and analysis in the browser, not inline blocking.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Deliverable: transparent, analyst-driven investigation — visualization, filtering, export — suitable for SOC-style triage and academic demonstration.',
        options: { bullet: true, breakLine: true },
      },
    ],
    { x: 0.38, y: contentTop, w: 9.25, h: 3.5, fontSize: 14, color: C.ink, fontFace: FONT_BODY },
  );

  slide = addContentSlide(pres, 'Presentation outline', 'Final defence and live demonstration');
  slide.addText(
    [
      { text: 'Context: 5G threats, national digital priorities, project scope', options: { bullet: true, breakLine: true } },
      { text: 'Aim, objectives, limitations, and V-Model methodology', options: { bullet: true, breakLine: true } },
      { text: 'Architecture and system modules (design chapter mapping)', options: { bullet: true, breakLine: true } },
      { text: 'Dashboard, Analytics, ML lab, Architecture, AI Assistant (screenshots)', options: { bullet: true, breakLine: true } },
      { text: 'Threat intelligence, exports, resources & technology stack, workflow, demo', options: { bullet: true, breakLine: true } },
      { text: 'Conclusions, key references, closing', options: { bullet: true } },
    ],
    { x: 0.4, y: contentTop, w: 5.45, h: 3.95, fontSize: 14, color: C.ink, fontFace: FONT_BODY },
  );
  addWireframeDashboard(slide, pres, 5.92, contentTop, 3.78, 3.95);
  slide.addText('Dashboard concept', {
    x: 5.92,
    y: contentTop + 4.05,
    w: 3.78,
    h: 0.32,
    fontSize: 10,
    color: C.muted,
    italic: true,
    align: 'center',
    fontFace: FONT_BODY,
  });

  slide = addContentSlide(pres, 'Context and motivation', 'Telecom security and project positioning');
  slide.addText(
    [
      {
        text: '5G core and user-plane traffic are complex: GTP-U, SCTP, and application fingerprints must be interpreted together.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Operators need analyst-grade visibility: flag suspicious flows, triage with context, export defensible evidence.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'This work delivers a credible in-browser demonstrator: PCAP → flow features → **ML-centric 5G IDS** (RF / IF / AE) → optional VirusTotal + AI triage — not an inline blocker.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Oman context: growth of digital services and 5G raises the priority of securing national communication infrastructures (aligned with Oman Vision 2040 themes for reliable connectivity).',
        options: { bullet: true, breakLine: true },
      },
    ],
    { x: 0.4, y: contentTop, w: 5.45, h: 3.15, fontSize: 13, color: C.ink, fontFace: FONT_BODY },
  );
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 6.05,
    y: contentTop,
    w: 3.45,
    h: 0.88,
    fill: { color: C.panel },
    line: { color: C.accent, width: 1 },
  });
  slide.addText('PCAP ingest', {
    x: 6.05,
    y: contentTop + 0.2,
    w: 3.45,
    h: 0.5,
    fontSize: 14,
    color: C.white,
    align: 'center',
    fontFace: FONT_BODY,
  });
  slide.addText('↓', {
    x: 6.05,
    y: contentTop + 0.95,
    w: 3.45,
    h: 0.32,
    fontSize: 20,
    color: C.accent,
    align: 'center',
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 6.05,
    y: contentTop + 1.32,
    w: 3.45,
    h: 0.88,
    fill: { color: '1e293b' },
    line: { color: C.accent, width: 1 },
  });
  slide.addText('Flow extraction + enrichments', {
    x: 6.05,
    y: contentTop + 1.48,
    w: 3.45,
    h: 0.55,
    fontSize: 13,
    color: C.white,
    align: 'center',
    fontFace: FONT_BODY,
  });
  slide.addText('↓', {
    x: 6.05,
    y: contentTop + 2.28,
    w: 3.45,
    h: 0.32,
    fontSize: 20,
    color: C.accent,
    align: 'center',
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 6.05,
    y: contentTop + 2.68,
    w: 3.45,
    h: 0.92,
    fill: { color: C.accent2 },
    line: { color: C.white, width: 1 },
    transparency: 35,
  });
  slide.addText('Detect · analyse · report', {
    x: 6.05,
    y: contentTop + 2.88,
    w: 3.45,
    h: 0.55,
    fontSize: 13,
    color: C.ink,
    align: 'center',
    bold: true,
    fontFace: FONT_BODY,
  });

  slide = addContentSlide(
    pres,
    'Project aim and objectives',
    'From the approved project planning report',
  );
  slide.addText(
    'Aim: design and develop MNIDS to analyse mobile and 5G-oriented traffic and identify suspicious or abnormal behaviour using traffic analysis and behavioural techniques.',
    {
      x: 0.38,
      y: contentTop,
      w: 9.2,
      h: 0.85,
      fontSize: 13,
      bold: true,
      color: C.ink,
      fontFace: FONT_BODY,
    },
  );
  slide.addText(
    [
      {
        text: 'Acquire and process 5G-oriented PCAP traffic into structured flow representations for telecom analysis.',
        options: { bullet: { type: 'number' }, breakLine: true },
      },
      {
        text: 'Detect and classify anomalies using **ML-centric** techniques (RF, IF, AE) aligned with engineered flow features and 5G-oriented parser context.',
        options: { bullet: { type: 'number' }, breakLine: true },
      },
      {
        text: 'Integrate threat intelligence and evidence-based tools for effective investigation of network events.',
        options: { bullet: { type: 'number' }, breakLine: true },
      },
      {
        text: 'Present results through an interactive dashboard and structured reporting for visibility of patterns and security insights.',
        options: { bullet: { type: 'number' }, breakLine: true },
      },
    ],
    { x: 0.38, y: contentTop + 0.92, w: 9.2, h: 3.35, fontSize: 13, color: C.ink, fontFace: FONT_BODY },
  );

  slide = addContentSlide(pres, 'Scope and limitations', 'Honest boundaries for a PCAP-first demonstrator');
  slide.addText(
    [
      {
        text: 'Offline PCAP-based analysis: not real-time inline prevention or live network enforcement.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Detection blends lab-trained models and parser fallbacks — trade-offs include false positives and reliance on synthetic/lab traffic for training.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Quality of results depends on capture fidelity and protocol parsing, especially in complex 5G environments.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'External services (VirusTotal, LLM APIs) depend on availability, quotas, keys, and acceptable use.',
        options: { bullet: true, breakLine: true },
      },
    ],
    { x: 0.38, y: contentTop, w: 9.2, h: 3.6, fontSize: 14, color: C.ink, fontFace: FONT_BODY },
  );

  slide = addContentSlide(
    pres,
    'Methodology',
    'Modified V-Model: specification, design, implementation, and mapped validation',
  );
  slide.addText(
    [
      {
        text: 'Requirements: PCAP ingest, flow generation, **ML inference** (RF / IF / AE), dashboard, exports, optional VT and AI.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Analysis: PCAP and simulated traffic (e.g. Wireshark); features include duration, ports, protocols, addresses, and session behaviour.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Design: modular browser platform — **interpretable flow features + model scores** anchor the detector; optional intel layers are adjunct.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Validation: unit, integration, system, and acceptance testing aligned with V-Model stages.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Literature gap addressed: many ML/DL IDS studies lack 5G-specific traffic and deployable transparency; MNIDS emphasises interpretable PCAP-first analysis.',
        options: { bullet: true, breakLine: true },
      },
    ],
    { x: 0.38, y: contentTop, w: 9.2, h: 3.95, fontSize: 12, color: C.ink, fontFace: FONT_BODY },
  );

  slide = addContentSlide(
    pres,
    'High-level architecture',
    'Single-page application — parsing and detection stay in the analyst browser',
  );
  slide.addText(
    [
      { text: 'React + TypeScript + Vite: PCAP parsed client-side; **ML inference** via FastAPI (:8787) for RF / IF / AE scores.', options: { bullet: true, breakLine: true } },
      { text: 'Feature extraction + trained models — **5G IDS** story: flows → `mlFeatures.ts` → ONNX/joblib artefacts.', options: { bullet: true, breakLine: true } },
      { text: 'Optional: VirusTotal proxy (rate-limited) + DeepSeek via OpenAI-compatible API.', options: { bullet: true, breakLine: true } },
      { text: 'Persistence: localStorage for session, VT cache, and chat transcripts.', options: { bullet: true, breakLine: true } },
    ],
    { x: 0.4, y: contentTop, w: 9.2, h: 2.35, fontSize: 14, color: C.ink, fontFace: FONT_BODY },
  );
  const pipeY = contentTop + 2.5;
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0.45,
    y: pipeY,
    w: 2.05,
    h: 0.72,
    fill: { color: C.accent },
    transparency: 25,
    line: { color: C.accent, width: 1 },
  });
  slide.addText('PCAP', { x: 0.45, y: pipeY + 0.18, w: 2.05, h: 0.4, fontSize: 13, align: 'center', fontFace: FONT_BODY });
  slide.addText('→', { x: 2.55, y: pipeY + 0.2, w: 0.45, h: 0.4, fontSize: 16, align: 'center' });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 3.05,
    y: pipeY,
    w: 2.25,
    h: 0.72,
    fill: { color: '0d9488' },
    transparency: 28,
    line: { color: '0f766e', width: 1 },
  });
  slide.addText('Parser / flows', {
    x: 3.05,
    y: pipeY + 0.18,
    w: 2.25,
    h: 0.4,
    fontSize: 12,
    align: 'center',
    color: C.white,
    fontFace: FONT_BODY,
  });
  slide.addText('→', { x: 5.35, y: pipeY + 0.2, w: 0.45, h: 0.4, fontSize: 16, align: 'center' });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 5.85,
    y: pipeY,
    w: 1.9,
    h: 0.72,
    fill: { color: C.warn },
    transparency: 32,
    line: { color: 'b45309', width: 1 },
  });
  slide.addText('ML infer', { x: 5.85, y: pipeY + 0.18, w: 1.9, h: 0.4, fontSize: 12, align: 'center', fontFace: FONT_BODY });
  slide.addText('→', { x: 7.8, y: pipeY + 0.2, w: 0.45, h: 0.4, fontSize: 16, align: 'center' });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 8.3,
    y: pipeY,
    w: 1.25,
    h: 0.72,
    fill: { color: C.accent2 },
    transparency: 38,
    line: { color: C.accent2, width: 1 },
  });
  slide.addText('UI + AI', { x: 8.3, y: pipeY + 0.18, w: 1.25, h: 0.4, fontSize: 11, align: 'center', fontFace: FONT_BODY });

  slide = addContentSlide(
    pres,
    'System component overview',
    'Functional mapping consistent with the report design and analysis chapter',
  );
  addSystemComponentsTable(slide, pres, contentTop);

  slide = addContentSlide(
    pres,
    'Live Dashboard',
    'Primary analyst surface after PCAP ingest',
  );
  slide.addText(
    [
      { text: 'PCAP library and upload; pipeline progress while packets are parsed in-browser.', options: { bullet: true, breakLine: true } },
      { text: 'KPI tiles: Malicious / Suspicious / Clean with **ML scores** (RF, IF, AE) on each row.', options: { bullet: true, breakLine: true } },
      { text: 'Each row: **Refresh** (ML), VirusTotal links where configured, **AI** pins the flow in the assistant.', options: { bullet: true, breakLine: true } },
      { text: 'Excel export and bulk triage helpers for Suspicious rows.', options: { bullet: true, breakLine: true } },
    ],
    { x: 0.4, y: contentTop, w: 4.45, h: 3.6, fontSize: 14, color: C.ink, fontFace: FONT_BODY },
  );
  addWireframeDashboard(slide, pres, 4.95, contentTop, 4.88, 4.42);

  embedScreenshotSlide(pres, 'Live Dashboard', '1', '01-live-dashboard.png', [
    'Top: PCAP strip and session KPIs (Malicious / Suspicious / Clean).',
    'Middle: sortable traffic table — each row shows **ML** columns when inference is online.',
    'Actions: Refresh (ML), VT, AI — AI opens with Evidence JSON for that row.',
  ]);

  embedScreenshotSlide(pres, 'Analytics view', '2', '02-analytics.png', [
    'Recharts views over the same session (no separate data source).',
    'Use for briefings: plane mix, volume, and bearer-oriented slices.',
    'Cross-reference a chart spike with a filtered table selection.',
  ]);

  slide = addContentSlide(pres, 'Analytics view', 'Quantitative context for the traffic table');
  slide.addText(
    [
      { text: 'Built from the current parse session — charts and table stay consistent.', options: { bullet: true, breakLine: true } },
      { text: 'Supports “storytelling” during demo: show a visual, then drill to the underlying flows.', options: { bullet: true, breakLine: true } },
      { text: 'Complements Excel export for management-style reporting.', options: { bullet: true, breakLine: true } },
    ],
    { x: 0.4, y: contentTop, w: 4.35, h: 2.4, fontSize: 14, color: C.ink, fontFace: FONT_BODY },
  );
  addBarChartMock(slide, pres, 4.85, contentTop, 4.95, 3.25);
  slide.addText('Illustrative layout — live charts follow session data', {
    x: 4.85,
    y: contentTop + 3.35,
    w: 4.95,
    h: 0.35,
    fontSize: 10,
    color: C.muted,
    italic: true,
    align: 'center',
    fontFace: FONT_BODY,
  });

  addSectionDivider(
    pres,
    'Machine Learning (RF / IF / AE)',
    'Lab models, ML Lab page, inference API health',
  );

  slide = addContentSlide(
    pres,
    'ML detection — Random Forest · Isolation Forest · Autoencoder',
    'Engineered flow features → trained artefacts under `cnn_model/`',
  );
  slide.addText(
    [
      {
        text: '**5G IDS** core path: PCAP bytes → aggregates → numeric vector → `/api/ml` → per-row RF status, IF and AE anomaly scores.',
        options: { bullet: true, breakLine: true },
      },
      { text: 'Retrain locally: `npm run ml:build` / **ML Lab** — metrics, confusion matrices, API health.', options: { bullet: true, breakLine: true } },
      {
        text: 'No embedded IOC rule database in this build; triage optionally fuses VirusTotal with **existing** model scores (no online weight updates from VT).',
        options: { bullet: true, breakLine: true },
      },
      { text: 'Heuristic/parser labels remain a **fallback** when FastAPI inference is unreachable.', options: { bullet: true, breakLine: true } },
    ],
    { x: 0.4, y: contentTop, w: 4.25, h: 2.85, fontSize: 13, color: C.ink, fontFace: FONT_BODY },
  );
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 0.38,
    y: contentTop + 2.95,
    w: 4.32,
    h: 1.38,
    fill: { color: 'e0f2fe' },
    line: { color: C.accent, width: 1 },
    rectRadius: 0.06,
  });
  slide.addText(
    [
      'Key terms',
      '• **RF** — supervised multiclass aligned with Clean / Suspicious / Malicious.',
      '• **IF / AE** — unsupervised anomaly signals for defence-in-depth.',
      '• **meta.json** — train rows, versions, thresholds (see ML Lab).',
    ].join('\n'),
    {
      x: 0.48,
      y: contentTop + 3.05,
      w: 4.12,
      h: 1.2,
      fontSize: 10,
      color: '0c4a6e',
      fontFace: FONT_BODY,
    },
  );
  addMlStackMock(slide, pres, 4.78, contentTop, 5.12, 4.38);

  embedScreenshotSlide(pres, 'ML Lab (application)', '3', '03-ml-lab.png', [
    'Metrics, retrain controls, and links to `cnn_model/` artefacts.',
    'Confusion matrix / loss plots when generated by the training pipeline.',
    'Use to show **model lifecycle** separate from dashboard PCAP analysis.',
  ]);

  addSectionDivider(
    pres,
    'AI-assisted analysis',
    'Evidence-grounded assistant — DeepSeek, OpenAI-compatible API',
  );

  slide = addContentSlide(
    pres,
    'AI assistant (DeepSeek)',
    'Answers must cite the pinned flow’s Evidence JSON — no fabricated observables',
  );
  slide.addText(
    [
      { text: 'System prompt constrains the model: RAG-style grounding on structured evidence only.', options: { bullet: true, breakLine: true } },
      { text: 'mnids-patch: suggested updates to classification / analyst note for the pinned flow (JSON block).', options: { bullet: true, breakLine: true } },
    ],
    { x: 0.4, y: contentTop, w: 4.35, h: 2.05, fontSize: 13, color: C.ink, fontFace: FONT_BODY },
  );
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0.38,
    y: contentTop + 2.12,
    w: 4.38,
    h: 2.35,
    fill: { color: 'ffffff' },
    line: { color: C.line, width: 1 },
  });
  slide.addText('Analyst workflow (4 steps)', {
    x: 0.45,
    y: contentTop + 2.2,
    w: 4.2,
    h: 0.28,
    fontSize: 11,
    bold: true,
    color: C.headerBg,
    fontFace: FONT_TITLE,
  });
  slide.addText(
    [
      { text: 'Pin a flow from the Dashboard (Evidence JSON attached automatically).', options: { bullet: { type: 'number' }, breakLine: true } },
      { text: 'Ask for summary, MITRE-style mapping, or remediation hints — grounded in JSON.', options: { bullet: { type: 'number' }, breakLine: true } },
      { text: 'If satisfied, copy or apply **mnids-patch** from the reply (no automatic row writes).', options: { bullet: { type: 'number' }, breakLine: true } },
      { text: 'Review every patch; the app never auto-applies assistant output without confirmation.', options: { bullet: { type: 'number' }, breakLine: true } },
    ],
    { x: 0.45, y: contentTop + 2.48, w: 4.22, h: 1.9, fontSize: 11, color: C.ink, fontFace: FONT_BODY },
  );
  addChatMock(slide, pres, 4.88, contentTop, 4.98, 4.45);

  embedScreenshotSlide(pres, 'AI Assistant (application)', '4', '04-ai-assistant.png', [
    'Pinned flow context: Evidence JSON is visible to the model via the prompt contract.',
    'Conversation shows analyst questions and structured assistant replies.',
    'Watch for **mnids-patch** blocks — copy/apply only after review.',
    'API key configured in settings; traffic goes to your chosen OpenAI-compatible endpoint.',
  ]);

  slide = addContentSlide(
    pres,
    'Threat intelligence & exports',
    'VirusTotal, spreadsheets, and quick AI drawer',
  );
  slide.addText(
    [
      { text: 'VirusTotal: optional API key via server proxy; responses cached in localStorage to respect quotas.', options: { bullet: true, breakLine: true } },
      { text: 'Excel: multi-sheet export with telecom-oriented columns and optional AI narrative sheet.', options: { bullet: true, breakLine: true } },
      { text: 'Floating AI drawer on Dashboard / Analytics for short, in-context questions.', options: { bullet: true, breakLine: true } },
    ],
    { x: 0.4, y: contentTop, w: 9.15, h: 2.45, fontSize: 14, color: C.ink, fontFace: FONT_BODY },
  );
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 0.42,
    y: contentTop + 2.58,
    w: 4.25,
    h: 1.42,
    fill: { color: 'dbeafe' },
    line: { color: '2563eb', width: 1 },
    rectRadius: 0.08,
  });
  slide.addText('VirusTotal\nReputation and enrichment for hashes / URLs when configured', {
    x: 0.42,
    y: contentTop + 2.85,
    w: 4.25,
    h: 1,
    fontSize: 14,
    bold: true,
    color: '1e3a8a',
    align: 'center',
    fontFace: FONT_BODY,
  });
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 5.05,
    y: contentTop + 2.58,
    w: 4.38,
    h: 1.42,
    fill: { color: 'ede9fe' },
    line: { color: '7c3aed', width: 1 },
    rectRadius: 0.08,
  });
  slide.addText('DeepSeek LLM\nEvidence JSON in · structured patches out', {
    x: 5.05,
    y: contentTop + 2.85,
    w: 4.38,
    h: 1,
    fontSize: 14,
    bold: true,
    color: '5b21b6',
    align: 'center',
    fontFace: FONT_BODY,
  });

  addProjectResourcesSlide(pres);

  slide = addContentSlide(
    pres,
    'End-to-end operational workflow',
    'Integrated flow consistent with the system flowchart in the project report',
  );
  slide.addText(
    [
      {
        text: 'Input: analyst uploads PCAP; system parses packets into structured flows (addresses, ports, protocols, timing).',
        options: { bullet: { type: 'number' }, breakLine: true },
      },
      {
        text: 'Detection: **ML models** score each flow from engineered features; parser heuristics provide behavioural cues when inference is unavailable.',
        options: { bullet: { type: 'number' }, breakLine: true },
      },
      {
        text: 'Enrichment: optional VirusTotal queries add reputation context where configured.',
        options: { bullet: { type: 'number' }, breakLine: true },
      },
      {
        text: 'Decision: flows classified with alerts and rationale visible to the analyst.',
        options: { bullet: { type: 'number' }, breakLine: true },
      },
      {
        text: 'AI support: DeepSeek assists with structured evidence; **detector** outputs come from RF/IF/AE + fallbacks.',
        options: { bullet: { type: 'number' }, breakLine: true },
      },
      {
        text: 'Output: interactive dashboard, statistics, and exports (e.g. Excel, JSON) for reporting.',
        options: { bullet: { type: 'number' }, breakLine: true },
      },
    ],
    { x: 0.38, y: contentTop, w: 9.2, h: 3.95, fontSize: 12, color: C.ink, fontFace: FONT_BODY },
  );

  slide = addContentSlide(pres, 'Demonstration script', 'Suggested order for the live viva demo');
  slide.addText(
    [
      { text: 'Project resources slide → state hardware, React/Vite UI stack, Node/Express proxy, keys, datasets, budget.', options: { bullet: { type: 'number' }, breakLine: true } },
      { text: 'Load a PCAP → show pipeline states → populated traffic table.', options: { bullet: { type: 'number' }, breakLine: true } },
      { text: 'Pick a Suspicious row → optional VT → explain RF / IF / AE scores.', options: { bullet: { type: 'number' }, breakLine: true } },
      { text: 'Analytics → tie one chart insight back to filtered rows.', options: { bullet: { type: 'number' }, breakLine: true } },
      { text: 'ML Lab → metrics / artefact paths → **`cnn_model/`**.', options: { bullet: { type: 'number' }, breakLine: true } },
      { text: 'AI Assistant → evidence-only summary → mnids-patch if applicable.', options: { bullet: { type: 'number' }, breakLine: true } },
    ],
    { x: 0.4, y: contentTop, w: 9.1, h: 3.85, fontSize: 13, color: C.ink, fontFace: FONT_BODY },
  );

  slide = addContentSlide(pres, 'Conclusions', 'Outcomes from the planning, design, and implementation trajectory');
  slide.addText(
    [
      {
        text: 'MNIDS provides a structured, PCAP-first path from raw captures to analyst-ready flows with interpretable detection.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: '**Feature + ML-centric** detection preserves inspectable scores; AI and VT add context without replacing the models.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'The interactive dashboard and exports support SOC-style triage, academic demonstration, and telecom-oriented reporting.',
        options: { bullet: true, breakLine: true },
      },
      {
        text: 'Future work may extend toward streaming capture, richer 5G protocol coverage, and tighter integration with operator workflows.',
        options: { bullet: true, breakLine: true },
      },
    ],
    { x: 0.38, y: contentTop, w: 9.2, h: 3.5, fontSize: 14, color: C.ink, fontFace: FONT_BODY },
  );

  slide = addContentSlide(pres, 'Key references', 'Representative sources cited in the project report');
  slide.addText(
    [
      'Ferrag et al. (2020). Deep learning for cyber security intrusion detection. Journal of Network and Computer Applications.',
      'Buczak & Guven (2016). Survey of data mining and ML methods for cyber security intrusion detection. IEEE Communications Surveys & Tutorials.',
      'Shone et al. (2022). Deep learning approach to network intrusion detection. IEEE Access.',
      'Hameed et al. (2023). 5G-NIDD: intrusion detection dataset for next-generation mobile networks. Future Internet.',
      'Chinnasamy et al. (2025). Deep learning-driven methods for network-based IDS. ICT Express.',
    ].join('\n\n'),
    {
      x: 0.38,
      y: contentTop,
      w: 9.2,
      h: 3.95,
      fontSize: 10,
      color: C.ink,
      fontFace: FONT_BODY,
    },
  );

  slide = pres.addSlide();
  slide.background = { color: C.dark };
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0,
    y: 5.02,
    w: 10,
    h: 0.06,
    fill: { color: C.gold },
    line: { width: 0 },
  });
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0,
    y: 5.1,
    w: 10,
    h: 0.42,
    fill: { color: C.accent },
    line: { width: 0 },
  });
  slide.addText('Thank you', {
    x: 0.5,
    y: 1.75,
    w: 9,
    h: 1,
    fontSize: 44,
    bold: true,
    color: C.accent,
    align: 'center',
    fontFace: FONT_TITLE,
  });
  slide.addText('Questions?', {
    x: 0.5,
    y: 2.78,
    w: 9,
    h: 0.6,
    fontSize: 22,
    color: C.white,
    align: 'center',
    fontFace: FONT_BODY,
  });
  slide.addText('AI-Based Mobile Network Intrusion Detection  ·  5G IDS research demo', {
    x: 0.5,
    y: 4.78,
    w: 9,
    h: 0.45,
    fontSize: 12,
    color: C.headerMuted,
    align: 'center',
    fontFace: FONT_BODY,
  });

  pres.writeFile({ fileName: OUT_FILE }).then(() => {
    console.log('Wrote', OUT_FILE);
  });
}

main();
