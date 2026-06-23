import type { TrafficLog, TrafficStatus } from '../types';

/** Fields the assistant may propose updating on a traffic row (applied automatically when flowId matches pinned row, or via Apply button). */
export type TrafficRowAiPatch = {
  status?: TrafficStatus;
  attackType?: string;
  analystNote?: string;
  confidence?: number;
};

/** Optional flags when applying a patch from the AI assistant UI. */
export type ApplyTrafficRowPatchOpts = {
  /** Show success modal (used by “Apply to traffic table” button). */
  fromAssistantButton?: boolean;
  /** Skip per-row toast (e.g. bulk apply from summary dialog). */
  silentBulk?: boolean;
};

export type ParsedMnidsPatch = {
  flowId: string;
  patch: TrafficRowAiPatch;
};

const MNIDS_BLOCK_RE = /```mnids-patch\s*([\s\S]*?)```/i;
/** Any fenced code block (```json, ``` or ```text) — try parse as flowId+patch JSON. */
const ANY_FENCE_RE = /```(?:[a-z0-9_-]*)?\s*([\s\S]*?)```/gi;

function parseFirstPatchFromFencedBlocks(markdown: string): ParsedMnidsPatch | null {
  ANY_FENCE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ANY_FENCE_RE.exec(markdown)) !== null) {
    const j = tryParseJson(m[1].trim());
    const p = parsePatchPayload(j);
    if (p) return p;
  }
  return null;
}

function isTrafficStatus(s: unknown): s is TrafficStatus {
  return s === 'Benign' || s === 'Suspicious' || s === 'Malicious';
}

function buildPatchFromRecord(p: Record<string, unknown>): TrafficRowAiPatch | null {
  const patch: TrafficRowAiPatch = {};
  if (isTrafficStatus(p.status)) patch.status = p.status;
  if (typeof p.attackType === 'string') patch.attackType = p.attackType;
  if (typeof p.analystNote === 'string') patch.analystNote = p.analystNote;
  if (typeof p.confidence === 'number' && Number.isFinite(p.confidence)) {
    patch.confidence = Math.min(1, Math.max(0, p.confidence));
  }
  if (
    patch.status === undefined &&
    patch.attackType === undefined &&
    patch.analystNote === undefined &&
    patch.confidence === undefined
  ) {
    return null;
  }
  return patch;
}

function parsePatchPayload(j: unknown): ParsedMnidsPatch | null {
  if (!j || typeof j !== 'object') return null;
  const rec = j as Record<string, unknown>;
  const flowId = rec.flowId;
  if (typeof flowId !== 'string' || !flowId.trim()) return null;
  const rawPatch = rec.patch;
  if (!rawPatch || typeof rawPatch !== 'object') return null;
  const patch = buildPatchFromRecord(rawPatch as Record<string, unknown>);
  if (!patch) return null;
  return { flowId: flowId.trim(), patch };
}

function tryParseJson(s: string): unknown {
  try {
    return JSON.parse(s) as unknown;
  } catch {
    return null;
  }
}

/** Extract a JSON object starting at `start` with string-aware brace matching. */
function extractBalancedObject(text: string, start: number): string | null {
  if (start < 0 || start >= text.length || text[start] !== '{') return null;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (esc) {
      esc = false;
      continue;
    }
    if (inStr) {
      if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      continue;
    }
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}

/** Find raw JSON like {"flowId":"...","patch":{...}} anywhere in the assistant reply (no fence required). */
function findLoosePatchJson(text: string): string | null {
  const needle = '"flowId"';
  let from = 0;
  while (from < text.length) {
    const fi = text.indexOf(needle, from);
    if (fi < 0) break;
    let brace = text.lastIndexOf('{', fi);
    if (brace < 0) {
      from = fi + 1;
      continue;
    }
    const chunk = extractBalancedObject(text, brace);
    if (chunk) {
      const j = tryParseJson(chunk);
      const parsed = parsePatchPayload(j);
      if (parsed) return chunk;
    }
    from = fi + 1;
  }
  return null;
}

/**
 * Parse AI-proposed row patch from Markdown: fenced ```mnids-patch, fenced ```json, or loose JSON in the message.
 */
export function parseMnidsRowPatch(markdown: string): ParsedMnidsPatch | null {
  const mnids = markdown.match(MNIDS_BLOCK_RE);
  if (mnids) {
    const j = tryParseJson(mnids[1].trim());
    const p = parsePatchPayload(j);
    if (p) return p;
  }

  const fromFences = parseFirstPatchFromFencedBlocks(markdown);
  if (fromFences) return fromFences;

  const loose = findLoosePatchJson(markdown);
  if (loose) {
    const p = parsePatchPayload(tryParseJson(loose));
    if (p) return p;
  }

  return null;
}

export function applyPatchToTrafficLog(log: TrafficLog, patch: TrafficRowAiPatch): TrafficLog {
  let analystStatusLocked = log.analystStatusLocked ?? false;
  if (patch.status !== undefined) {
    analystStatusLocked = patch.status === 'Benign';
  }
  return {
    ...log,
    ...(patch.status !== undefined ? { status: patch.status } : {}),
    ...(patch.attackType !== undefined ? { attackType: patch.attackType } : {}),
    ...(patch.analystNote !== undefined ? { analystNote: patch.analystNote } : {}),
    ...(patch.confidence !== undefined ? { confidence: patch.confidence } : {}),
    analystStatusLocked,
  };
}
