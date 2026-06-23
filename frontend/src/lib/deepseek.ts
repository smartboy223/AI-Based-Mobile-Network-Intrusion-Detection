/**
 * DeepSeek (OpenAI-compatible) chat client.
 *
 * Security: The API key NEVER leaves the backend. All requests go through the
 * Express proxy at `/api/deepseek/v1/chat/completions`, which adds Authorization
 * server-side from backend/.env. The browser bundle has no key inside it.
 *
 * Configuration is probed at runtime via `/api/deepseek/health` (cached).
 */

/** Strict system prompt for retrieval-grounded Q&A (minimal creativity). */
export const DEEPSEEK_SYSTEM_PROMPT_RAG = `You are a technical assistant for MNIDS: a **5G IDS** (intrusion detection and analysis) dashboard for 5G core / RAN-oriented traffic (PCAP-derived flows: GTP-U user plane, SCTP / signaling candidates, N3 / N6 / N9 interfaces). The tool **observes and classifies** traffic for analysts; it **does not** block packets, terminate sessions, push firewall or SMF/UPF policy changes, or perform active response—unless Evidence explicitly says otherwise (it will not). Never tell the user that MNIDS enforces or prevents traffic inline.

Rules (follow strictly):
0. If the user message is a simple greeting / small-talk / acknowledgment (e.g., "hi", "hello", "thanks", "ok"), reply in 1-2 short lines, friendly and concise. Do NOT auto-summarize Evidence unless the user asks for status, summary, analysis, findings, or similar.
1. Use ONLY the information inside the user message block labeled "Evidence:". Treat it as the single source of truth.
2. Do not invent IPs, ports, protocols, attack names, CVEs, vendors, or statistics that do not appear in Evidence.
3. If the question cannot be answered from Evidence AND it is not about editing pinnedTrafficRow, reply with exactly: "Not found in the provided evidence."
4. Never send an empty reply. Always include at least one short paragraph or bullet list.
5. Prefer short bullet points. When stating a fact, cite the matching id from Evidence (e.g. Flow id) in parentheses.
6. Format answers using Markdown when helpful: **bold** for critical terms, ## for section titles, and bullet lists.
7. Do not give long generic cybersecurity lectures unless the user explicitly asks.
8. When Evidence includes "pinnedTrafficRow", you may explain that flow using only its fields and suggest Malicious vs Suspicious vs Clean analyst outcomes.
9. Terminology: JSON and machine patches use the exact string "Benign" for non-threat traffic. In **all natural language to the user** (summaries, status lines, bullets), never say "Benign" — always say **Clean** instead (e.g. "Status: Clean (confidence 0.93)"). The evidence JSON may include statusUiLabel for the same meaning.
10. When the user asks to change classification, add a remark, or "mark" the pinned flow, you MUST: (a) explain the change in plain language using **Clean** not Benign in prose; (b) include the machine-readable patch as valid JSON shaped as: {"flowId":"<id from pinnedTrafficRow>","patch":{"status":"Benign"|"Suspicious"|"Malicious","attackType":"optional string","analystNote":"optional string","confidence":0.0-1.0}} — patch.status must remain the exact token Benign, Suspicious, or Malicious for the app. Put that JSON inside a fenced block labeled mnids-patch OR json, or as a single raw JSON object on its own line. Include only patch keys you intend to change. flowId must match pinnedTrafficRow.id exactly. The app auto-applies that JSON to the traffic table when flowId equals the pinned row at send time (no extra click required), then persists to localStorage.
11. Multi-turn chat: earlier user and assistant messages are conversation context only. The **current** dashboard state is always the Evidence JSON in the **latest** user message — use it as authoritative for facts; use history only for follow-up phrasing and pronouns.
12. If the user's request is missing required context (e.g. no pinned flow but they ask to edit a row), say what is missing and what they should attach.
13. Evidence includes structured fields: **summary** (table counts), **ipOccurrencesInFullTable** (per-IP asSource, asDestination, rowsTouchingIp across the full table), **topSourceIps**, **trafficRows** (first slice only), **virusTotalByIp** (optional saved IPv4 lookups: stats, verdictLine, or skipReason for private IPs), and **virusTotalByDomain** (optional saved domain lookups for httpHost / DNS names on flows). For VT-backed answers, quote only numbers present under virusTotalByIp or virusTotalByDomain. Traffic rows may include **trafficPlane**, **sessionBearerKey**, **operationalCategory**, **engineeringNote**, **gtpuTeidHex**, **innerUeIpv4**, **dnsQueryNames**, **httpHost**, and **ja3** / **ja3s** (TLS fingerprints). For questions about a specific IP, open with a **one-line numeric summary** using ipOccurrencesInFullTable (and trafficRows for detail). Do not invent counts—use only these objects. Prefer compact bullets and tables when listing multiple flows.
14. **5G IDS scope:** Describe the system as detection and analyst support (alerts, triage, reports). Do not claim real-time prevention, automated blocking, or network enforcement capabilities for this UI.
15. Product name: NEVER say "Passive IDS" or "passive intrusion detection"; always "**5G IDS**" when referring to MNIDS detector scope.`;

export type ChatMessage = { role: 'system' | 'user' | 'assistant'; content: string };

/** Branding shown in greetings and UI copy. */
export const ASSISTANT_BRANDING = {
  productName: 'MNIDS 5G IDS',
  institution: 'Open-source mobile-network security lab',
} as const;

/**
 * Normalize legacy / hallucinated phrasing end-users must never see (e.g. API greeting rewriting "5G IDS" as "Passive IDS").
 */
export function sanitizeAssistantPublicMarkdown(markdown: string): string {
  return markdown
    .replace(/\*\*Passive IDS\*\*/gi, '**5G IDS**')
    .replace(/\bpassive\s+intrusion\s+detection\b/gi, '5G IDS')
    .replace(/\bpassive\s+IDS\b/gi, '5G IDS')
    .replace(/\bpassive\s+ids\b/gi, '5G IDS')
    .replace(/\bPassive\s+ids\b/g, '5G IDS');
}

export function staticAssistantGreetingMarkdown(): string {
  const { productName, institution } = ASSISTANT_BRANDING;
  return `## MNIDS AI 👋

**${productName}** · *${institution}*

- 🔎 **5G IDS** — detect & analyze flows (no inline blocking)
- 📊 Pin a row (**AI** on a flow) for triage & patches
- 🧠 Explain RF / IF / AE; 📤 help with Excel export

What would you like to look at?`;
}

/**
 * Backend proxy base. All DeepSeek traffic goes through Express so the key
 * stays server-side. In SSR/build contexts where `window` is missing, fall
 * back to a relative path which the build step will never actually exercise.
 */
function getProxyBase(): string {
  if (typeof window !== 'undefined') {
    return `${window.location.origin}/api/deepseek`;
  }
  return '/api/deepseek';
}

function getModel(): string {
  // Allow optional override at build time, but never the API key.
  const m =
    typeof process !== 'undefined' && (process.env?.DEEPSEEK_MODEL as string | undefined);
  return (m && m.trim()) || 'deepseek-chat';
}

// Runtime configuration probe (cached). Replaces the old build-time key check.
let _configuredCache: { value: boolean; at: number } | null = null;
const CONFIG_CACHE_MS = 30_000;

export function isDeepSeekConfigured(): boolean {
  // Synchronous check used by render code — returns last known good value.
  // First call returns true optimistically; the async probe below corrects it.
  if (_configuredCache) return _configuredCache.value;
  void refreshDeepSeekConfigured();
  return true;
}

export async function refreshDeepSeekConfigured(): Promise<boolean> {
  if (_configuredCache && Date.now() - _configuredCache.at < CONFIG_CACHE_MS) {
    return _configuredCache.value;
  }
  try {
    const res = await fetch(`${getProxyBase()}/health`, { cache: 'no-store' });
    if (!res.ok) {
      _configuredCache = { value: false, at: Date.now() };
      return false;
    }
    const data = (await res.json()) as { configured?: boolean };
    const value = Boolean(data.configured);
    _configuredCache = { value, at: Date.now() };
    return value;
  } catch {
    _configuredCache = { value: false, at: Date.now() };
    return false;
  }
}

/**
 * Single-turn chat completion. Pass Evidence inside the user message.
 * Always proxied through the Express backend; the browser never sees the API key.
 */
export async function deepseekChat(
  messages: ChatMessage[],
  opts?: { temperature?: number; max_tokens?: number; signal?: AbortSignal },
): Promise<string> {
  const url = `${getProxyBase()}/v1/chat/completions`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: getModel(),
        messages,
        temperature: opts?.temperature ?? 0.1,
        max_tokens: opts?.max_tokens ?? 512,
        stream: false,
      }),
      signal: opts?.signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    if (e instanceof Error && e.name === 'AbortError') throw e;
    throw e;
  }

  if (!res.ok) {
    const errText = await res.text();
    // Surface a clear message for the most common server-side failure.
    if (res.status === 400 && /not configured/i.test(errText)) {
      _configuredCache = { value: false, at: Date.now() };
      throw new Error(
        'DEEPSEEK_API_KEY not configured on the backend. Set it in backend/.env and restart the server.',
      );
    }
    throw new Error(`DeepSeek proxy ${res.status}: ${errText.slice(0, 500)}`);
  }

  const data = (await res.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };
  const raw = data.choices?.[0]?.message?.content;
  const text = typeof raw === 'string' ? raw.trim() : '';
  if (!text) {
    throw new Error(
      'DeepSeek returned an empty response. Try again, shorten the question, or check quota / model settings.',
    );
  }
  return text;
}

/**
 * Convenience: one user question + JSON evidence string (your flows/alerts).
 */
export async function deepseekAskWithEvidence(
  userQuestion: string,
  evidenceJson: string,
  opts?: { maxTokens?: number; signal?: AbortSignal },
): Promise<string> {
  const reply = await deepseekChat(
    [
      { role: 'system', content: DEEPSEEK_SYSTEM_PROMPT_RAG },
      {
        role: 'user',
        content: `Evidence (JSON or text from the application only):\n${evidenceJson}\n\nQuestion:\n${userQuestion}`,
      },
    ],
    { temperature: 0.15, max_tokens: opts?.maxTokens ?? 768, signal: opts?.signal },
  );
  return sanitizeAssistantPublicMarkdown(reply);
}

const MAX_HISTORY_API_MESSAGES = 28;

/**
 * Multi-turn: prior user/assistant pairs (no system), then one user message with fresh evidence + question.
 */
export async function deepseekAskWithEvidenceAndHistory(
  priorTurns: ChatMessage[],
  userQuestion: string,
  evidenceJson: string,
  opts?: { maxTokens?: number; signal?: AbortSignal },
): Promise<string> {
  const capped = priorTurns.slice(-MAX_HISTORY_API_MESSAGES);
  const reply = await deepseekChat(
    [
      { role: 'system', content: DEEPSEEK_SYSTEM_PROMPT_RAG },
      ...capped,
      {
        role: 'user',
        content: `Evidence (JSON — current dashboard state; authoritative for this turn):\n${evidenceJson}\n\nQuestion:\n${userQuestion}`,
      },
    ],
    { temperature: 0.15, max_tokens: opts?.maxTokens ?? 896, signal: opts?.signal },
  );
  return sanitizeAssistantPublicMarkdown(reply);
}

const GREETING_SYSTEM = `You greet the user for MNIDS: a **5G IDS** dashboard (detection & analysis on PCAP/table evidence—**not** inline blocking or prevention) with an embedded AI assistant.

Reply in Markdown only. Start with a short ## title and one friendly emoji (e.g. 👋).

Keep the whole greeting brief (about 5–7 short lines total, not a wall of text). Cover in plain language:
- Who: **${ASSISTANT_BRANDING.studentName}** · *${ASSISTANT_BRANDING.institution}*
- **5G IDS** 🔎 — PCAP/table detection & analysis support; no dropping traffic or changing policy from this UI
- **Traffic** 📊 — re-assess / explain table evidence; pinned row + triage / patches when they use AI on a flow
- **ML triage** 🧠 — explain model outcomes and suggest analyst-ready row updates
- **Reports** 📤 — summaries and help with Excel export / executive narrative
- Tip: **New task** → fresh chat (previous saved under Past tasks); Shift+Enter for newline; composer supports copy/paste
- You support the analyst; you do not replace the IDS. End with one inviting question.

Hard constraints — **never** mention any of these (they are not part of this build): YARA-style rules, IOC databases, IOC DB, embedded reputation/IP blocklists, or “create/refine indicator rules”. Detection here is PCAP flows → engineered features → lab ML scores (RF / IF / AE), plus optional VirusTotal enrichment and this chat—not rule authoring.

**Forbidden product name:** NEVER write "Passive IDS", "passive IDS", or "passive intrusion detection". The ONLY correct branding is "**5G IDS**" (you may repeat it in bullets).

Use a few tasteful emojis; do not put an emoji on every single line. Do not invent IPs, alerts, or statistics.`;

/** One-shot greeting when the user first opens chat (API path). */
export async function fetchAssistantGreetingFromApi(): Promise<string> {
  const raw = await deepseekChat(
    [
      { role: 'system', content: GREETING_SYSTEM },
      {
        role: 'user',
        content:
          'The user just opened the AI assistant. Write your greeting now (Markdown only). Do NOT use the words Passive IDS or passive IDS — always say **5G IDS**. Follow the system bullets for scope.',
      },
    ],
    { temperature: 0.2, max_tokens: 320 },
  );
  return sanitizeAssistantPublicMarkdown(raw);
}

/** One-shot triage for Suspicious flows: VT-grounded when virusTotalByIp is populated in evidence. */
const SUSPICIOUS_TRIAGE_SYSTEM = `You are an analyst automation assistant for MNIDS **5G IDS**: detection and classification only—no blocking or enforcement.

Task: Triage ONE flow that is currently marked Suspicious. Evidence JSON includes pinnedTrafficRow (that flow) and may include virusTotalByIp for its source and destination IPv4 addresses after a rate-limited VirusTotal lookup. It may also include virusTotalByDomain for HTTP Host or DNS names on that flow if the analyst ran a lookup that queried domains.

Rules:
1. Use ONLY Evidence. Quote VT numbers only from virusTotalByIp / virusTotalByDomain when present. If an IP has skipReason private_ip or is missing from virusTotalByIp, state that VT was not used for it. If domain VT is missing, note that domains may not have been queried (quota-smart workflow).
2. **Resolve the queue:** patch.status must be exactly one of Benign, Suspicious, or Malicious (Benign = Clean in UI). **Do not leave the row Suspicious by default.** Use Suspicious only when evidence is genuinely conflicting or VT/engine data is missing for a public IP you would need to decide. If attackType or context indicates a **threat-intel “elevated scrutiny” public-IP** Suspicious tag and VirusTotal on the **public** address shows **0 malicious and 0 suspicious** with engines that ran, you **must** set patch.status to **Benign**. If VT shows malicious > 0, set **Malicious**. Prefer **Benign** over lingering Suspicious when VT is clean and there is no separate strong malware signal in Evidence.
3. Set analystNote to a short professional summary (1–4 sentences) for the SOC handoff.
4. Optionally set attackType if Malicious or Suspicious warrants a label; omit or shorten if Clean.
5. Set confidence between 0 and 1 reflecting certainty.
6. You MUST include a machine-readable patch JSON with the exact flowId from pinnedTrafficRow.id. Put it in a \`\`\`mnids-patch fenced block containing {"flowId":"...","patch":{...}}. patch.status must use Benign/Suspicious/Malicious tokens (not the word Clean).
7. Before the fence, write a brief Markdown summary for the analyst (use **Clean** in prose, never Benign in prose).`;

const SUSPICIOUS_TRIAGE_USER = `Run automated triage for the pinned Suspicious flow: summarize VirusTotal (if any), then choose a **final** status (avoid leaving Suspicious unless you must). End with the mnids-patch JSON block.`;

export async function deepseekSuspiciousTriage(
  evidenceJson: string,
  opts?: { signal?: AbortSignal },
): Promise<string> {
  return deepseekChat(
    [
      { role: 'system', content: SUSPICIOUS_TRIAGE_SYSTEM },
      {
        role: 'user',
        content: `Evidence (JSON — authoritative):\n${evidenceJson}\n\n${SUSPICIOUS_TRIAGE_USER}`,
      },
    ],
    { temperature: 0.1, max_tokens: 1200, signal: opts?.signal },
  );
}

const BULK_SUSPICIOUS_TRIAGE_NARRATIVE_SYSTEM = `You consolidate multiple Suspicious-flow triage results into one concise analyst narrative for MNIDS **5G IDS** (detection and triage support—no enforcement). Inputs are VirusTotal-assisted + ML-assisted triage excerpts from the dashboard—not YARA rules or IOC databases.

Rules:
1. Use ONLY IPv4 addresses, ports, protocols, or strings that appear in the JSON bundle (flow src/dst, notes, patches).
2. Output Markdown with short sections: "Summary", "Risk posture", and "Recommended next checks".
3. Do not invent IPs, domains, or indicators not present in the bundle. If the bundle is thin, clearly state limitations.`;

export async function deepseekBulkSuspiciousTriageNarrative(
  triageBundleJson: string,
  opts?: { signal?: AbortSignal },
): Promise<string> {
  return deepseekChat(
    [
      { role: 'system', content: BULK_SUSPICIOUS_TRIAGE_NARRATIVE_SYSTEM },
      {
        role: 'user',
        content: `Triage bundle (JSON from dashboard bulk run):\n${triageBundleJson}\n\nWrite the consolidated triage narrative in Markdown now.`,
      },
    ],
    { temperature: 0.14, max_tokens: 1400, signal: opts?.signal },
  );
}

const EXCEL_SUMMARY_SYSTEM = `You write an impressive, briefing-quality executive cover sheet for an exported spreadsheet from MNIDS (**5G IDS**: detection & analysis, not inline prevention; open-source mobile-network security lab context).

Output **only** valid JSON (no markdown fences). Shape exactly:
{
  "headline":"one punchy title line, max 12 words, professional",
  "tldr":"ONE sentence (≤ 30 words) — the elevator pitch for an exec who reads only this line",
  "riskPosture":"Critical | High | Medium | Low | Clean",
  "riskRationale":"one short sentence justifying the riskPosture choice from payload numbers",
  "intro":"2-3 sentences: what this workbook is, scope, and why it matters for review",
  "bullets":["5-8 concise bullets: mix of counts, risk posture, protocols, next-step suggestions"],
  "priorityIps":[
    {"ip":"<ipv4 from payload only>","status":"Malicious|Suspicious|Clean","reason":"≤14 words why this IP matters"}
  ],
  "tags":["3-7 short keyword tags, 1-3 words each, e.g. 'DNS tunneling', 'GTP-U N3', 'Bulk scan'"],
  "nextSteps":["3-5 short imperative checklist items for the analyst, max 12 words each"],
  "closing":"1-2 sentences: handoff tone (SOC / course submission)",
  "signals":["0-4 optional bullets naming only artefacts from payload e.g. DNS/HTTP/JA3 presence"]
}

Rules:
1. Use ONLY facts from the user JSON payload. Do not invent IPs, domains, CVEs, or vendor names not in the payload.
2. Say **Clean** instead of Benign in all prose strings, BUT in the "status" field of priorityIps use exactly "Clean", "Suspicious", or "Malicious".
3. riskPosture must be one of: Critical, High, Medium, Low, Clean. Use Critical only if malicious > 5 OR suspicious > 20. Use High if malicious >= 1. Use Medium if suspicious >= 1 and malicious = 0. Use Low for tiny counts. Use Clean only if both malicious and suspicious are 0.
4. priorityIps: 0-5 entries, ONLY IPv4 strings that appear in payload.topMaliciousIps / payload.topSuspiciousIps / payload.protocolsTop or sample fields. Empty array is OK if the payload doesn't expose IPs.
5. tags: short, specific, no full sentences. Examples: "5G N3", "Bulk SSH", "DNS QNAME", "TLS JA3 seen", "Empty captures".
6. nextSteps: imperative voice ("Pivot on…", "Verify VT on…", "Re-check ML triage…"). Avoid generic filler.
7. Tone: confident analyst briefing, not generic AI filler—use active voice, specific numbers from payload.
8. If payload says hasDnsOrHttp / hasJa3 false, you may say "Application-layer enrichments sparse in this extract" without inventing hosts.
9. Mention MNIDS export context when payload.source indicates dashboard export.`;

export type ExcelAiPriorityIp = {
  ip: string;
  status: 'Clean' | 'Suspicious' | 'Malicious';
  reason: string;
};

export type ExcelAiRiskPosture = 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';

export type ExcelAiNarrative = {
  headline: string;
  /** One-sentence elevator pitch for the cover banner. */
  tldr: string;
  /** Overall risk colour band shown as the banner gradient. */
  riskPosture: ExcelAiRiskPosture;
  /** Short justification displayed under the risk badge. */
  riskRationale: string;
  intro: string;
  bullets: string[];
  /** Up to 5 IPs the LLM thinks the analyst should pivot on first. */
  priorityIps: ExcelAiPriorityIp[];
  /** Short keyword chips (e.g. "DNS tunneling", "GTP-U N3"). */
  tags: string[];
  /** 3-5 imperative checklist items. */
  nextSteps: string[];
  closing: string;
  signals: string[];
};

function normalizeRiskPosture(raw: unknown): ExcelAiRiskPosture {
  const s = typeof raw === 'string' ? raw.trim() : '';
  switch (s) {
    case 'Critical':
    case 'High':
    case 'Medium':
    case 'Low':
    case 'Clean':
      return s;
    default:
      return 'Medium';
  }
}

function normalizePriorityIps(raw: unknown): ExcelAiPriorityIp[] {
  if (!Array.isArray(raw)) return [];
  const out: ExcelAiPriorityIp[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const r = item as { ip?: unknown; status?: unknown; reason?: unknown };
    const ip = typeof r.ip === 'string' ? r.ip.trim() : '';
    const reason = typeof r.reason === 'string' ? r.reason.trim() : '';
    if (!ip) continue;
    let status: ExcelAiPriorityIp['status'] = 'Clean';
    if (r.status === 'Malicious' || r.status === 'Suspicious') status = r.status;
    out.push({ ip, status, reason });
  }
  return out.slice(0, 5);
}

function normalizeStringArray(raw: unknown, max: number, maxLen: number): string[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((x): x is string => typeof x === 'string')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => (s.length > maxLen ? s.slice(0, maxLen - 1) + '…' : s))
    .slice(0, max);
}

function tryParseExcelNarrativeJson(text: string): ExcelAiNarrative | null {
  const t = text
    .trim()
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/```\s*$/i, '')
    .trim();
  try {
    const j = JSON.parse(t) as Record<string, unknown>;
    const headline = typeof j.headline === 'string' ? j.headline.trim() : '';
    const intro = typeof j.intro === 'string' ? j.intro.trim() : '';
    const bullets = normalizeStringArray(j.bullets, 12, 220);
    const closing = typeof j.closing === 'string' ? j.closing.trim() : '';
    const signals = normalizeStringArray(j.signals, 6, 180);
    const tldr = typeof j.tldr === 'string' ? j.tldr.trim() : '';
    const riskPosture = normalizeRiskPosture(j.riskPosture);
    const riskRationale =
      typeof j.riskRationale === 'string' ? j.riskRationale.trim() : '';
    const priorityIps = normalizePriorityIps(j.priorityIps);
    const tags = normalizeStringArray(j.tags, 8, 30);
    const nextSteps = normalizeStringArray(j.nextSteps, 6, 120);
    if (!intro && bullets.length === 0 && !headline) return null;
    return {
      headline: headline || 'Traffic intelligence export',
      tldr: tldr || 'MNIDS analyst workbook ready for review.',
      riskPosture,
      riskRationale: riskRationale || 'Posture inferred from row counts in this export.',
      intro: intro || 'MNIDS analyst workbook export.',
      bullets: bullets.length
        ? bullets
        : ['Review the Security Scan Results sheet for flow-level detail.'],
      priorityIps,
      tags: tags.length ? tags : ['MNIDS export'],
      nextSteps: nextSteps.length
        ? nextSteps
        : ['Skim the Security Scan Results sheet top to bottom.'],
      closing: closing || 'Generated for analyst review; verify against raw captures and VT where applicable.',
      signals,
    };
  } catch {
    return null;
  }
}

/**
 * One-shot narrative for the Excel "AI Executive summary" sheet (requires DEEPSEEK_API_KEY).
 */
export async function deepseekExcelExportNarrative(
  payloadJson: string,
  opts?: { signal?: AbortSignal },
): Promise<ExcelAiNarrative> {
  const raw = await deepseekChat(
    [
      { role: 'system', content: EXCEL_SUMMARY_SYSTEM },
      {
        role: 'user',
        content: `Export context (JSON):\n${payloadJson}`,
      },
    ],
    { temperature: 0.28, max_tokens: 1400, signal: opts?.signal },
  );
  const parsed = tryParseExcelNarrativeJson(raw);
  if (parsed) return parsed;
  return {
    headline: 'MNIDS export — narrative fallback',
    tldr: 'The LLM returned non-JSON; raw excerpt preserved below.',
    riskPosture: 'Medium',
    riskRationale: 'Risk posture not produced by the LLM on this attempt.',
    intro: 'The model returned non-JSON; excerpt preserved below.',
    bullets: [raw.slice(0, 500) + (raw.length > 500 ? '…' : '')],
    priorityIps: [],
    tags: ['LLM fallback'],
    nextSteps: ['Re-export with DeepSeek JSON mode if this sheet should be regenerated.'],
    closing: 'Re-export with DeepSeek JSON mode if this sheet should be regenerated.',
    signals: [],
  };
}
