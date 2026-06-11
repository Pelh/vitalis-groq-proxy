const express = require('express');
const crypto = require('crypto');
const stripeSecretKey = process.env.STRIPE_SECRET_KEY || '';
const stripe = stripeSecretKey ? require('stripe')(stripeSecretKey) : null;
const { createClient } = require('@supabase/supabase-js');

// Accepte les deux noms de variable courants pour la clé service-role
// (évite un crash au démarrage si elle est nommée SUPABASE_SERVICE_ROLE_KEY).
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY,
);

// Maps plan IDs (used in the app) to Stripe price env vars
const PRICE_MAP = {
  solo:       process.env.PRICE_SOLO,
  pme:        process.env.PRICE_PME,
  pro:        process.env.PRICE_PRO,
  enterprise: process.env.PRICE_ENTERPRISE,
};

// maxAuditors = collaborateurs EN PLUS de l'admin (sièges totaux = maxAuditors + 1).
const PLAN_META = {
  solo:       { legacyPlan: 'solo',       maxAuditors: 0 },
  pme:        { legacyPlan: 'pme',        maxAuditors: 2 },
  pro:        { legacyPlan: 'pme',        maxAuditors: 9 },
  enterprise: { legacyPlan: 'entreprise', maxAuditors: -1 },
};

function requireStripe(res) {
  if (stripe) return true;
  res.status(503).json({ error: 'Stripe is not configured' });
  return false;
}

function normalizePlanId(planId) {
  if (planId === 'entreprise') return 'enterprise';
  return PLAN_META[planId] ? planId : null;
}

function readBearerToken(req) {
  const header = req.headers.authorization || req.headers.Authorization || '';
  const match = String(header).match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

async function getAuthenticatedUser(req) {
  const token = readBearerToken(req);
  if (!token) return null;
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user;
}

function isDateInFuture(value) {
  if (!value) return false;
  const time = new Date(value).getTime();
  return Number.isFinite(time) && time > Date.now();
}

async function requireApprovedAppUser(req, res, next) {
  const authUser = await getAuthenticatedUser(req);
  if (!authUser) {
    return res.status(401).json({ error: 'Authenticated Supabase session required' });
  }

  const { data: profile, error } = await supabase
    .from('profiles')
    .select('id, role, org_id, is_blocked, approval_status, subscription_expires_at')
    .eq('id', authUser.id)
    .single();

  if (error || !profile) {
    return res.status(403).json({ error: 'User profile not found' });
  }

  if (profile.role !== 'admin') {
    if (profile.is_blocked || profile.approval_status !== 'approved') {
      return res.status(403).json({ error: 'Account must be approved before using backend features' });
    }

    if (!isDateInFuture(profile.subscription_expires_at)) {
      return res.status(402).json({ error: 'Active subscription required' });
    }
  }

  req.vitalisUser = {
    id: authUser.id,
    role: profile.role,
    orgId: profile.org_id || null,
  };
  next();
}

async function requireApprovedAiUser(req, res, next) {
  const authUser = await getAuthenticatedUser(req);
  if (!authUser) {
    return res.status(401).json({ error: 'Authenticated Supabase session required' });
  }

  const { data: profile, error } = await supabase
    .from('profiles')
    .select('id, role, org_id, is_blocked, approval_status, plan, subscription_plan, subscription_expires_at')
    .eq('id', authUser.id)
    .single();

  if (error || !profile) {
    return res.status(403).json({ error: 'User profile not found' });
  }

  if (profile.role !== 'admin') {
    if (profile.is_blocked || profile.approval_status !== 'approved') {
      return res.status(403).json({ error: 'Account must be approved before using AI features' });
    }

    if (!isDateInFuture(profile.subscription_expires_at)) {
      return res.status(402).json({ error: 'Active subscription required for AI features' });
    }
  }

  req.vitalisUser = {
    id: authUser.id,
    role: profile.role,
    orgId: profile.org_id || null,
  };
  next();
}

function resolvePlanFromSubscription(subscription) {
  const metaPlan = normalizePlanId(subscription?.metadata?.planId);
  if (metaPlan) return metaPlan;
  const priceId = subscription?.items?.data?.[0]?.price?.id;
  return Object.entries(PRICE_MAP).find(([, value]) => value === priceId)?.[0] || null;
}

function legacySafeValues(values) {
  const { plan, max_auditors, ...legacyValues } = values;
  return legacyValues;
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || ''));
}

function profileSeedValues(authUser) {
  const meta = authUser?.user_metadata || {};
  const fullName = String(meta.full_name || meta.name || authUser?.email || 'Utilisateur').trim() || 'Utilisateur';
  const orgId = isUuid(meta.org_id) ? meta.org_id : authUser.id;

  return {
    id: authUser.id,
    full_name: fullName,
    role: 'auditor',
    org_id: orgId,
    org_name: meta.org_name || null,
    company: meta.company || null,
    is_blocked: true,
    approval_status: 'pending',
    plan: null,
    max_auditors: 0,
    subscription_plan: 'none',
  };
}

async function ensureProfileForAuthUser(authUser) {
  const selectedColumns = 'id, role, org_id, is_blocked, approval_status';
  const existing = await supabase
    .from('profiles')
    .select(selectedColumns)
    .eq('id', authUser.id)
    .maybeSingle();

  if (existing.data) return { profile: existing.data, error: null };

  const values = profileSeedValues(authUser);
  let inserted = await supabase
    .from('profiles')
    .insert(values)
    .select(selectedColumns)
    .single();

  if (inserted.error) {
    const message = String(inserted.error.message || '');
    if (message.includes('plan') || message.includes('max_auditors') || message.includes('schema cache')) {
      inserted = await supabase
        .from('profiles')
        .insert(legacySafeValues(values))
        .select(selectedColumns)
        .single();
    }
  }

  if (!inserted.error && inserted.data) return { profile: inserted.data, error: null };

  // Race condition: the Supabase trigger may have inserted the row between
  // the initial read and our insert. Re-read before reporting a real failure.
  const reread = await supabase
    .from('profiles')
    .select(selectedColumns)
    .eq('id', authUser.id)
    .maybeSingle();

  if (reread.data) return { profile: reread.data, error: null };
  return { profile: null, error: inserted.error || reread.error || existing.error };
}

async function updateProfileById(userId, values) {
  const { error } = await supabase.from('profiles').update(values).eq('id', userId);
  if (!error) return null;

  const message = String(error.message || '');
  if (message.includes('plan') || message.includes('max_auditors') || message.includes('schema cache')) {
    const fallback = await supabase.from('profiles').update(legacySafeValues(values)).eq('id', userId);
    return fallback.error ?? null;
  }
  return error;
}

async function updateProfileByCustomer(customerId, values) {
  const { error } = await supabase.from('profiles').update(values).eq('stripe_customer_id', customerId);
  if (!error) return null;

  const message = String(error.message || '');
  if (message.includes('plan') || message.includes('max_auditors') || message.includes('schema cache')) {
    const fallback = await supabase.from('profiles').update(legacySafeValues(values)).eq('stripe_customer_id', customerId);
    return fallback.error ?? null;
  }
  return error;
}

async function getSubscriptionExpiresAt(session) {
  if (session.subscription && stripe) {
    try {
      const subscription = await stripe.subscriptions.retrieve(session.subscription);
      if (subscription.current_period_end) {
        return new Date(subscription.current_period_end * 1000).toISOString();
      }
    } catch (err) {
      console.error('[stripe] subscription period lookup error:', err.message);
    }
  }

  return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
}

// Public URL used in Stripe redirects. On Infomaniak, set PUBLIC_PROXY_BASE.
const publicProxyBase = process.env.PUBLIC_PROXY_BASE
  || process.env.APP_PUBLIC_BASE_URL
  || (process.env.RAILWAY_PUBLIC_DOMAIN
  ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
  : '');
const PROXY_BASE = (publicProxyBase || `http://localhost:${process.env.PORT || 3000}`).replace(/\/+$/, '');

const app = express();
const ALLOWED_ORIGINS = String(process.env.CORS_ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// Stripe webhook needs the raw body for signature verification;
// every other route gets normal JSON parsing.
app.use((req, _res, next) => {
  if (req.originalUrl === '/webhook') {
    express.raw({ type: 'application/json' })(req, _res, next);
  } else {
    express.json({ limit: '20mb' })(req, _res, next);
  }
});

// ── CORS ─────────────────────────────────────────────────────
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.length > 0 && origin && !ALLOWED_ORIGINS.includes(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  const allowedOrigin = ALLOWED_ORIGINS.length === 0 ? '*' : (origin || ALLOWED_ORIGINS[0]);
  res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Vitalis-Client');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Key rotation ─────────────────────────────────────────────
const AI_PROVIDER_NAME = process.env.AI_PROVIDER_NAME || 'groq';
const AI_PROVIDER_BASE_URL = (process.env.AI_PROVIDER_BASE_URL || 'https://api.groq.com/openai/v1').replace(/\/+$/, '');
const AI_CHAT_ENDPOINT = process.env.AI_CHAT_ENDPOINT || '/chat/completions';
const AI_AUDIO_ENDPOINT = process.env.AI_AUDIO_ENDPOINT || '/audio/transcriptions';
const EXPO_PUSH_URL = process.env.EXPO_PUSH_URL || 'https://exp.host/--/api/v2/push/send';
const AI_KEYS = [
  process.env.AI_API_KEY,
  process.env.AI_KEY_1,
  process.env.AI_KEY_2,
  process.env.AI_KEY_3,
  process.env.GROQ_KEY_1,
  process.env.GROQ_KEY_2,
  process.env.GROQ_KEY_3,
].filter(Boolean);

let keyIndex = 0;
function nextKey() {
  const key = AI_KEYS[keyIndex % AI_KEYS.length];
  keyIndex++;
  return key;
}

function providerUrl(path) {
  return `${AI_PROVIDER_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
}

const AI_CACHE_TTL_MS = parseInt(process.env.AI_CACHE_TTL_MS || '300000', 10);
const AI_CACHE_MAX_ITEMS = parseInt(process.env.AI_CACHE_MAX_ITEMS || '200', 10);
const aiResponseCache = new Map();

function stableStringify(value) {
  if (value == null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

function aiCacheKey(req, route) {
  const scope = req.vitalisUser?.orgId || req.vitalisUser?.id || 'anonymous';
  return crypto.createHash('sha256')
    .update(`${route}:${scope}:${stableStringify(req.body)}`)
    .digest('hex');
}

function readAiCache(key) {
  if (AI_CACHE_TTL_MS <= 0) return null;
  const hit = aiResponseCache.get(key);
  if (!hit) return null;
  if (hit.expiresAt <= Date.now()) {
    aiResponseCache.delete(key);
    return null;
  }
  return hit.value;
}

function writeAiCache(key, value) {
  if (AI_CACHE_TTL_MS <= 0) return;
  aiResponseCache.set(key, { value, expiresAt: Date.now() + AI_CACHE_TTL_MS });
  if (aiResponseCache.size > AI_CACHE_MAX_ITEMS) {
    const firstKey = aiResponseCache.keys().next().value;
    if (firstKey) aiResponseCache.delete(firstKey);
  }
}

function publicAiError(status) {
  if (status === 401 || status === 403) return 'AI provider authentication failed';
  if (status === 429) return 'AI provider rate limit exceeded';
  if (status >= 500) return 'AI provider temporarily unavailable';
  return 'AI request failed';
}

async function readProviderJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return {
      error: publicAiError(response.status),
      provider_status: response.status,
      provider_body_preview: text.slice(0, 300),
    };
  }
}

async function logAiUsage(req, route, status, startedAt, responseBody, errorMessage, cacheHit = false) {
  try {
    const usage = cacheHit ? {} : (responseBody?.usage || {});
    await supabase.from('ai_usage_events').insert({
      user_id: req.vitalisUser?.id || null,
      org_id: req.vitalisUser?.orgId || null,
      provider: AI_PROVIDER_NAME,
      route,
      model: responseBody?.model || req.body?.model || null,
      prompt_tokens: Number(usage.prompt_tokens || 0),
      completion_tokens: Number(usage.completion_tokens || 0),
      total_tokens: Number(usage.total_tokens || 0),
      status,
      duration_ms: Date.now() - startedAt,
      error_message: errorMessage ? String(errorMessage).slice(0, 500) : null,
      cache_hit: cacheHit,
    });
  } catch {}
}

const AI_RATE_WINDOW_MS = parseInt(process.env.AI_RATE_WINDOW_MS || '60000', 10);
const AI_RATE_MAX = parseInt(process.env.AI_RATE_MAX_PER_WINDOW || '60', 10);
const aiRateBuckets = new Map();

function rateLimitKey(req) {
  return req.vitalisUser?.id || req.ip || req.headers['x-forwarded-for'] || 'anonymous';
}

function rateLimitAi(req, res, next) {
  const key = String(rateLimitKey(req));
  const now = Date.now();
  const current = aiRateBuckets.get(key);

  if (!current || current.resetAt <= now) {
    aiRateBuckets.set(key, { count: 1, resetAt: now + AI_RATE_WINDOW_MS });
    return next();
  }

  current.count += 1;
  if (current.count > AI_RATE_MAX) {
    const retryAfter = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
    res.setHeader('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'AI rate limit exceeded', retryAfter });
  }

  next();
}

// ── Health check ─────────────────────────────────────────────
app.get('/', (_req, res) => {
  res.json({
    status:  'ok',
    keys:    AI_KEYS.length,
    version: '1.5.0',
    stripe:  !!stripe,
    stripeWebhook: !!process.env.STRIPE_WEBHOOK_SECRET,
    aiAuth:  true,
    pushProxy: true,
    corsRestricted: ALLOWED_ORIGINS.length > 0,
    aiProvider: {
      name: AI_PROVIDER_NAME,
      baseConfigured: !!AI_PROVIDER_BASE_URL,
      chatEndpoint: AI_CHAT_ENDPOINT,
      audioEndpoint: AI_AUDIO_ENDPOINT,
    },
    aiCache: {
      ttlMs: AI_CACHE_TTL_MS,
      maxItems: AI_CACHE_MAX_ITEMS,
      size: aiResponseCache.size,
    },
    aiRateLimit: { windowMs: AI_RATE_WINDOW_MS, max: AI_RATE_MAX },
    stripePrices: Object.fromEntries(
      Object.entries(PRICE_MAP).map(([plan, price]) => [plan, !!price]),
    ),
  });
});

// ── Stripe checkout result pages ─────────────────────────────
app.get('/subscription-success', (_req, res) => {
  res.send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Paiement réussi</title>
<style>body{font-family:sans-serif;text-align:center;padding:60px 20px;background:#0a0a0a;color:#fff}
h2{color:#00e5ff}p{color:#aaa;margin-top:16px}</style></head>
<body><h2>✅ Paiement réussi !</h2>
<p>Votre abonnement est activé.<br>Retournez à l'application Vitalis Sécurité.</p>
</body></html>`);
});

app.get('/subscription-cancel', (_req, res) => {
  res.send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Paiement annulé</title>
<style>body{font-family:sans-serif;text-align:center;padding:60px 20px;background:#0a0a0a;color:#fff}
h2{color:#ff6b35}p{color:#aaa;margin-top:16px}</style></head>
<body><h2>Paiement annulé</h2>
<p>Aucun montant n'a été débité.<br>Retournez à l'application pour réessayer.</p>
</body></html>`);
});

// ── Create Stripe Checkout session ───────────────────────────
app.post('/create-checkout-session', async (req, res) => {
  if (!requireStripe(res)) return;

  const { planId } = req.body ?? {};
  if (!planId) {
    return res.status(400).json({ error: 'planId is required' });
  }

  const authUser = await getAuthenticatedUser(req);
  if (!authUser) {
    return res.status(401).json({ error: 'Authenticated Supabase session required' });
  }

  const normalizedPlanId = normalizePlanId(planId);
  if (!normalizedPlanId) {
    return res.status(400).json({ error: `Unknown plan: ${planId}` });
  }

  const priceId = PRICE_MAP[normalizedPlanId];
  if (!priceId) {
    return res.status(500).json({ error: `Stripe price not configured for plan: ${normalizedPlanId}` });
  }

  try {
    const { profile, error: profileError } = await ensureProfileForAuthUser(authUser);

    if (profileError || !profile) {
      console.error('[stripe] profile ensure error:', profileError?.message || profileError);
      return res.status(500).json({ error: 'Unable to prepare user profile for payment' });
    }
    const rejected = profile.approval_status === 'rejected';
    const suspendedApprovedAccount = profile.approval_status === 'approved' && profile.is_blocked === true;
    if (profile.role !== 'admin' && (rejected || suspendedApprovedAccount)) {
      return res.status(403).json({ error: 'Account cannot start payment because it is rejected or suspended' });
    }

    const session = await stripe.checkout.sessions.create({
      mode:                 'subscription',
      payment_method_types: ['card'],
      customer_email:       authUser.email || undefined,
      line_items:           [{ price: priceId, quantity: 1 }],
      metadata:             { planId: normalizedPlanId, userId: authUser.id, orgId: profile.org_id || '' },
      subscription_data:    { metadata: { planId: normalizedPlanId, userId: authUser.id, orgId: profile.org_id || '' } },
      client_reference_id:  authUser.id,
      success_url:          `${PROXY_BASE}/subscription-success`,
      cancel_url:           `${PROXY_BASE}/subscription-cancel`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('[stripe] create-checkout-session error:', err.message);
    res.status(500).json({ error: 'Stripe checkout unavailable' });
  }
});

// ── Stripe portal ─────────────────────────────────────────────
app.post('/create-portal-session', async (req, res) => {
  if (!requireStripe(res)) return;

  const authUser = await getAuthenticatedUser(req);
  if (!authUser) {
    return res.status(401).json({ error: 'Authenticated Supabase session required' });
  }

  try {
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('id, stripe_customer_id')
      .eq('id', authUser.id)
      .single();

    if (error || !profile) {
      return res.status(403).json({ error: 'User profile not found' });
    }
    if (!profile.stripe_customer_id) {
      return res.status(400).json({ error: 'No Stripe customer linked to this profile' });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: profile.stripe_customer_id,
      return_url: `${PROXY_BASE}/subscription-success`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('[stripe] create-portal-session error:', err.message);
    res.status(500).json({ error: 'Stripe portal unavailable' });
  }
});

app.post('/send-push', requireApprovedAppUser, async (req, res) => {
  const userId = String(req.body?.userId || '').trim();
  const title = String(req.body?.title || '').trim().slice(0, 120);
  const body = String(req.body?.body || '').trim().slice(0, 500);
  const extraData = req.body?.data && typeof req.body.data === 'object' ? req.body.data : {};

  if (!userId || !title || !body) {
    return res.status(400).json({ error: 'userId, title and body are required' });
  }

  try {
    const { data: target, error } = await supabase
      .from('profiles')
      .select('id, org_id, push_token')
      .eq('id', userId)
      .single();

    if (error || !target) {
      return res.status(404).json({ sent: false, reason: 'target_not_found' });
    }

    const requesterOrg = req.vitalisUser?.orgId || null;
    if (!target.org_id || !requesterOrg || target.org_id !== requesterOrg) {
      return res.status(403).json({ error: 'Target user is outside your organization' });
    }

    if (!target.push_token) {
      return res.json({ sent: false, reason: 'no_push_token' });
    }

    const expoResponse = await fetch(EXPO_PUSH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        to: target.push_token,
        title,
        body,
        data: extraData,
        sound: 'default',
        priority: 'high',
      }),
    });

    const text = await expoResponse.text();
    let payload = null;
    try { payload = JSON.parse(text); } catch {}

    if (!expoResponse.ok) {
      console.error('[push] expo send failed:', expoResponse.status, text.slice(0, 300));
      return res.status(502).json({ sent: false, reason: 'push_provider_unavailable' });
    }

    res.json({ sent: true, providerStatus: payload?.data?.status || 'sent' });
  } catch (err) {
    console.error('[push] send error:', err.message);
    res.status(500).json({ sent: false, reason: 'push_send_failed' });
  }
});

app.post('/webhook', async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(503).send('Stripe webhook is not configured');
  }

  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET,
    );
  } catch (err) {
    console.error('[webhook] signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session  = event.data.object;
      const userId   = session.client_reference_id;
      const planId   = normalizePlanId(session.metadata?.planId ?? 'solo') ?? 'solo';
      const planMeta = PLAN_META[planId];
      const expires  = await getSubscriptionExpiresAt(session);

      if (!userId) {
        console.error('[webhook] checkout completed without user id');
        return res.json({ received: true });
      }

      const error = await updateProfileById(userId, {
        plan:                    planId,
        max_auditors:            planMeta.maxAuditors,
        subscription_plan:       planMeta.legacyPlan,
        subscription_expires_at: expires,
        stripe_customer_id:      session.customer,
        is_blocked:              false,
        approval_status:         'approved',
        approved_at:             new Date().toISOString(),
      });

      if (error) console.error('[webhook] supabase update error:', error.message);
      else console.log(`[webhook] activated plan=${planId} for user=${userId}`);
    }

    if (event.type === 'customer.subscription.updated') {
      const subscription = event.data.object;
      const customerId = subscription.customer;
      const planId = normalizePlanId(resolvePlanFromSubscription(subscription) ?? 'solo') ?? 'solo';
      const planMeta = PLAN_META[planId];
      const isActive = ['active', 'trialing'].includes(subscription.status);
      const expires = isActive && subscription.current_period_end
        ? new Date(subscription.current_period_end * 1000).toISOString()
        : null;

      const error = await updateProfileByCustomer(customerId, {
        plan:                    isActive ? planId : 'solo',
        max_auditors:            isActive ? planMeta.maxAuditors : 0,
        subscription_plan:       isActive ? planMeta.legacyPlan : 'none',
        subscription_expires_at: expires,
        ...(isActive ? {
          is_blocked:      false,
          approval_status: 'approved',
          approved_at:     new Date().toISOString(),
        } : {}),
      });

      if (error) console.error('[webhook] subscription update error:', error.message);
      else console.log(`[webhook] subscription ${subscription.status} for customer=${customerId}`);
    }

    if (event.type === 'invoice.paid') {
      const invoice = event.data.object;
      const subscriptionId = typeof invoice.subscription === 'string'
        ? invoice.subscription
        : invoice.subscription?.id;
      if (subscriptionId) {
        const subscription = await stripe.subscriptions.retrieve(subscriptionId);
        const planId = normalizePlanId(resolvePlanFromSubscription(subscription) ?? 'solo') ?? 'solo';
        const planMeta = PLAN_META[planId];
        const expires = subscription.current_period_end
          ? new Date(subscription.current_period_end * 1000).toISOString()
          : null;

        const error = await updateProfileByCustomer(subscription.customer, {
          plan:                    planId,
          max_auditors:            planMeta.maxAuditors,
          subscription_plan:       planMeta.legacyPlan,
          subscription_expires_at: expires,
          is_blocked:              false,
          approval_status:         'approved',
          approved_at:             new Date().toISOString(),
        });

        if (error) console.error('[webhook] invoice paid update error:', error.message);
        else console.log(`[webhook] invoice paid for customer=${subscription.customer}`);
      }
    }

    if (event.type === 'invoice.payment_failed') {
      const invoice = event.data.object;
      const customerId = invoice.customer;
      if (customerId) {
        const error = await updateProfileByCustomer(customerId, {
          plan:                    'solo',
          max_auditors:            0,
          subscription_plan:       'none',
          subscription_expires_at: null,
        });

        if (error) console.error('[webhook] invoice failed update error:', error.message);
        else console.log(`[webhook] invoice payment failed for customer=${customerId}`);
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      const customerId = event.data.object.customer;
      if (!customerId) {
        console.error('[webhook] cancellation received without customer id');
        return res.json({ received: true });
      }

      const error = await updateProfileByCustomer(customerId, {
        plan:                    'solo',
        max_auditors:            0,
        subscription_plan:       'none',
        subscription_expires_at: null,
      });

      if (error) console.error('[webhook] supabase cancel error:', error.message);
      else console.log(`[webhook] cancelled subscription for customer=${customerId}`);
    }
  } catch (err) {
    console.error('[webhook] handler error:', err.message);
  }

  res.json({ received: true });
});

// ── AI provider proxy ─────────────────────────────────────────
app.post('/v1/chat/completions', requireApprovedAiUser, rateLimitAi, async (req, res) => {
  if (AI_KEYS.length === 0) {
    return res.status(500).json({ error: 'No AI provider key configured' });
  }

  const startedAt = Date.now();
  const canCache = !req.body?.stream;
  const cacheKey = canCache ? aiCacheKey(req, 'chat') : null;
  if (cacheKey) {
    const cached = readAiCache(cacheKey);
    if (cached) {
      await logAiUsage(req, 'chat', cached.status, startedAt, cached.body, null, true);
      return res.status(cached.status).json(cached.body);
    }
  }

  let lastStatus = 500;
  let lastBody   = {};

  for (let attempt = 0; attempt < AI_KEYS.length; attempt++) {
    const key = nextKey();
    try {
      const response = await fetch(providerUrl(AI_CHAT_ENDPOINT), {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${key}`,
        },
        body: JSON.stringify(req.body),
      });

      lastStatus = response.status;
      lastBody   = await readProviderJson(response);

      if (response.status === 429 && attempt < AI_KEYS.length - 1) {
        await new Promise(r => setTimeout(r, 300));
        continue;
      }

      if (response.ok && cacheKey) {
        writeAiCache(cacheKey, { status: lastStatus, body: lastBody });
      }
      await logAiUsage(req, 'chat', lastStatus, startedAt, lastBody, response.ok ? null : publicAiError(response.status));
      return res.status(lastStatus).json(lastBody);
    } catch (err) {
      console.error(`[proxy] attempt ${attempt + 1} error:`, err.message);
      await logAiUsage(req, 'chat', 500, startedAt, null, err.message);
    }
  }

  res.status(lastStatus).json(lastBody);
});

// ── Start ─────────────────────────────────────────────────────
app.post('/v1/audio/transcriptions', requireApprovedAiUser, rateLimitAi, express.raw({ type: '*/*', limit: '50mb' }), async (req, res) => {
  if (AI_KEYS.length === 0) {
    return res.status(500).json({ error: 'No AI provider key configured' });
  }

  const contentType = req.headers['content-type'];
  if (!contentType) {
    return res.status(400).json({ error: 'Missing multipart content type' });
  }

  const startedAt = Date.now();
  let lastStatus = 500;
  let lastBody = '';
  let lastType = 'application/json';

  for (let attempt = 0; attempt < AI_KEYS.length; attempt++) {
    const key = nextKey();
    try {
      const response = await fetch(providerUrl(AI_AUDIO_ENDPOINT), {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${key}`,
          'Content-Type': contentType,
        },
        body: req.body,
      });

      lastStatus = response.status;
      lastType = response.headers.get('content-type') || lastType;
      lastBody = await response.text();

      if (response.status === 429 && attempt < AI_KEYS.length - 1) {
        await new Promise(r => setTimeout(r, 300));
        continue;
      }

      let parsedBody = null;
      try { parsedBody = JSON.parse(lastBody); } catch {}
      await logAiUsage(req, 'audio', lastStatus, startedAt, parsedBody, response.ok ? null : publicAiError(response.status));
      return res.status(lastStatus).type(lastType).send(lastBody);
    } catch (err) {
      console.error(`[proxy:audio] attempt ${attempt + 1} error:`, err.message);
      await logAiUsage(req, 'audio', 500, startedAt, null, err.message);
    }
  }

  res.status(lastStatus).type(lastType).send(lastBody || JSON.stringify({ error: 'Audio transcription failed' }));
});
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'groq-proxy',
    version: '1.5.0',
    timestamp: new Date().toISOString()
  });
});
const PORT = parseInt(process.env.PORT || '3000', 10);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Vitalis AI proxy v1.5.0 listening on 0.0.0.0:${PORT}`);
  console.log(`AI provider: ${AI_PROVIDER_NAME} (${AI_PROVIDER_BASE_URL})`);
  console.log(`AI keys loaded: ${AI_KEYS.length}`);
  console.log(`Stripe: ${stripe ? 'configured' : 'NOT configured'}`);
});
