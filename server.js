const express = require('express');
const app = express();
app.use(express.json({ limit: '20mb' }));

// ── CORS ─────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Key rotation ─────────────────────────────────────────────
const GROQ_KEYS = [
  process.env.GROQ_KEY_1,
  process.env.GROQ_KEY_2,
  process.env.GROQ_KEY_3,
].filter(Boolean);

let keyIndex = 0;
function nextKey() {
  const key = GROQ_KEYS[keyIndex % GROQ_KEYS.length];
  keyIndex++;
  return key;
}

// ── Health check ─────────────────────────────────────────────
app.get('/', (_req, res) => {
  res.json({ status: 'ok', keys: GROQ_KEYS.length, version: '1.1.0' });
});

// ── Proxy ─────────────────────────────────────────────────────
app.post('/v1/chat/completions', async (req, res) => {
  if (GROQ_KEYS.length === 0) {
    return res.status(500).json({ error: 'No GROQ_KEY_* env vars configured' });
  }

  let lastStatus = 500;
  let lastBody   = {};

  for (let attempt = 0; attempt < GROQ_KEYS.length; attempt++) {
    const key = nextKey();
    try {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${key}`,
        },
        body: JSON.stringify(req.body),
      });

      lastStatus = response.status;
      lastBody   = await response.json();

      if (response.status === 429 && attempt < GROQ_KEYS.length - 1) {
        await new Promise(r => setTimeout(r, 300));
        continue;
      }

      return res.status(lastStatus).json(lastBody);
    } catch (err) {
      console.error(`[proxy] attempt ${attempt + 1} error:`, err.message);
    }
  }

  res.status(lastStatus).json(lastBody);
});

// ── Start ─────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3000', 10);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Groq proxy v1.1.0 listening on 0.0.0.0:${PORT}`);
  console.log(`Keys loaded: ${GROQ_KEYS.length}`);
});
