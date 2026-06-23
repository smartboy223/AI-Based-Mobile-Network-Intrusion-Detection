import express from 'express';
import fs from 'fs';
import path from 'path';

const router = express.Router();
const DEEPSEEK_BASE_URL = 'https://api.deepseek.com/chat/completions';

/**
 * Read the API key at *request* time, not at module-load time.
 *
 * ES modules execute `import` statements before any statement in the file
 * that imports them. `backend/server.js` calls `dotenv.config()` AFTER
 * `import deepseekRouter from './deepseekRoutes.mjs'`, so if we captured
 * `process.env.DEEPSEEK_API_KEY` into a module-level constant here, it
 * would be `undefined` even when backend/.env has a valid key, and every
 * request would return "API key not configured".
 *
 * Reading from process.env on each request costs nothing and guarantees
 * we always see the latest value (including hot-reload edits to .env).
 */
function getDeepseekApiKey() {
  const raw = process.env.DEEPSEEK_API_KEY;
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  // Reject obvious placeholders so the UI shows "not configured" instead
  // of forwarding a junk Authorization header to api.deepseek.com.
  if (!trimmed || /^(your[_-]?api[_-]?key|placeholder|xxx+)$/i.test(trimmed)) {
    return '';
  }
  return trimmed;
}

/**
 * RAG: Search project files and return relevant context
 */
function searchProjectContext(query, projectRoot) {
  const searchDirs = [
    path.join(projectRoot, 'backend'),
    path.join(projectRoot, 'frontend', 'src'),
  ];

  let results = [];
  const keywords = query.toLowerCase().split(/\s+/);

  for (const dir of searchDirs) {
    if (!fs.existsSync(dir)) continue;

    const files = fs.readdirSync(dir, { recursive: true }).filter((f) =>
      /\.(js|py|ts|tsx|mjs)$/.test(f),
    );

    for (const file of files) {
      const filePath = path.join(dir, file);
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');

        let matchCount = 0;
        const matches = [];

        lines.forEach((line, idx) => {
          if (keywords.some((kw) => line.toLowerCase().includes(kw))) {
            matchCount++;
            matches.push({
              line: idx + 1,
              content: line.trim().substring(0, 150),
            });
          }
        });

        if (matchCount > 0) {
          results.push({
            file: file,
            path: filePath.replace(projectRoot, ''),
            matches: matches.slice(0, 3),
            matchCount: matchCount,
          });
        }
      } catch (e) {
        // Skip unreadable files
      }
    }
  }

  return results.slice(0, 5);
}

/**
 * Chat handler: supports two body shapes.
 *   A) { messages: [{role, content}, ...], model?, temperature?, max_tokens? }
 *      Full passthrough — preferred path used by frontend deepseek.ts.
 *   B) { message: string, includeRAG?, projectRoot? }
 *      Legacy single-message helper (kept for backward compatibility).
 */
async function handleChat(req, res) {
  const apiKey = getDeepseekApiKey();
  if (!apiKey) {
    return res
      .status(400)
      .json({ ok: false, error: 'Deepseek API key not configured on server' });
  }

  const {
    messages,
    model = 'deepseek-chat',
    temperature = 0.15,
    max_tokens = 768,
    message,
    includeRAG,
    projectRoot,
  } = req.body || {};

  let outboundMessages = Array.isArray(messages) ? messages : null;

  if (!outboundMessages) {
    if (!message) {
      return res
        .status(400)
        .json({ ok: false, error: 'messages[] or message required' });
    }
    let systemPrompt = `You are an AI assistant helping with a Mobile Network Intrusion Detection System project. Be concise and helpful.`;
    if (includeRAG && projectRoot) {
      const ragResults = searchProjectContext(message, projectRoot);
      if (ragResults.length > 0) {
        systemPrompt += `\n\nProject Context:\n`;
        ragResults.forEach((result) => {
          systemPrompt += `\nFile: ${result.path}\nMatches:\n`;
          result.matches.forEach((match) => {
            systemPrompt += `  Line ${match.line}: ${match.content}\n`;
          });
        });
      }
    }
    outboundMessages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: message },
    ];
  }

  try {
    const response = await fetch(DEEPSEEK_BASE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: outboundMessages,
        temperature,
        max_tokens,
        stream: false,
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error('Deepseek API error:', errText.slice(0, 400));
      return res.status(response.status).json({
        ok: false,
        error: `Deepseek API ${response.status}`,
        detail: errText.slice(0, 400),
      });
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ ok: false, error: error.message });
  }
}

// --- Routes -----------------------------------------------------------------

router.post('/chat', handleChat);
// OpenAI-compatible alias the current frontend uses.
router.post('/v1/chat/completions', handleChat);
// Older / legacy paths kept as aliases so a stale frontend bundle doesn't 404
// against a freshly-restarted server. All point to the same handler.
router.post('/v1/completions', handleChat);
router.post('/completions', handleChat);
router.post('/chat/completions', handleChat);

/** Health probe so the frontend can show "Assistant ready" without a build-time key. */
router.get('/health', (_req, res) => {
  res.json({ ok: true, configured: Boolean(getDeepseekApiKey()) });
});

/** Search project files (RAG) */
router.post('/search', (req, res) => {
  const { query, projectRoot } = req.body;
  if (!query) {
    return res.status(400).json({ error: 'Query required' });
  }
  const results = searchProjectContext(query, projectRoot);
  res.json({ ok: true, results });
});

/**
 * Catch-all fallback for /api/deepseek/* paths that don't match any of the
 * routes above. Returns JSON (not HTML) with a hint listing actual routes —
 * much friendlier than Express' default HTML 404, which is what users hit
 * when the server was started before a route was added (e.g. before the
 * /v1/chat/completions alias landed).
 */
router.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: `No route ${req.method} /api/deepseek${req.path}`,
    hint:
      'If you expect this endpoint to exist, restart the server (Ctrl+C then START.bat). ' +
      'The most likely cause is that backend code was edited after the server started.',
    available: [
      'POST /api/deepseek/chat',
      'POST /api/deepseek/v1/chat/completions',
      'POST /api/deepseek/v1/completions',
      'POST /api/deepseek/completions',
      'POST /api/deepseek/chat/completions',
      'POST /api/deepseek/search',
      'GET  /api/deepseek/health',
    ],
  });
});

export default router;
