// groq-proxy/server.js — Groq key rotation proxy for EHS app
const express = require('express');
const app = express();
app.use(express.json({ limit: '20mb' }));

// ── Key rotation ────────────────────────────────────────────────
// Replace KEY_1/KEY_2/KEY_3 with your actual Groq API keys
const GROQ_KEYS = [
  process.env.GROQ_KEY_1 || 'REPLACE_WITH_GROQ_KEY_1',
  process.env.GROQ_KEY_2 || 'REPLACE_WITH_GROQ_KEY_2',
  process.env.GROQ_KEY_3 || 'REPLACE_WITH_GROQ_KEY_3',
].filter(k => k && !k.startsWith('REPLACE'));

let keyIndex = 0;
function nextKey() {
  const key = GROQ_KEYS[keyIndex % GROQ_KEYS.length];
  keyIndex++;
  return key;
}

// ── Health check ────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', keys: GROQ_KEYS.length, version: '1.0.0' });
});

// ── Chat completions proxy ──────────────────────────────────────
app.post('/v1/chat/completions', async (req, res) => {
  if (GROQ_KEYS.length === 0) {
    return res.status(500).json({ error: 'No API keys configured' });
  }

  const MAX_RETRIES = GROQ_KEYS.length;
  let lastError = null;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    const key = nextKey();
    try {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
        body:    JSON.stringify(req.body),
      });

      if (response.status === 429 && attempt < MAX_RETRIES - 1) {
        // Rate limited — try next key
        lastError = { status: 429, message: 'Rate limited, rotating key' };
        await new Promise(r => setTimeout(r, 500));
        continue;
      }

      const data = await response.json();
      return res.status(response.status).json(data);
    } catch (err) {
      lastError = err;
    }
  }

  res.status(500).json({ error: 'All keys exhausted', detail: String(lastError) });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Groq proxy running on port ${PORT}`));
