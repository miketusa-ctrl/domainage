/**
 * RapidAPI marketplace routes /rapidapi/v1/* (shared pattern: UAParse v0.5.1, CertGuard, PlainGrade v0.5.0). RapidAPI's proxy
 * adds X-RapidAPI-Proxy-Secret (must equal Worker secret RAPIDAPI_PROXY_SECRET) and X-RapidAPI-User. Constant-time compare
 * (SHA-256 digests + XOR). Wrong/missing secret -> uniform 401; secret unset -> 503 rapidapi_unavailable. Tier from
 * X-RapidAPI-Subscription, read only AFTER the gate (missing/unknown -> BASIC). Per-minute limit per RapidAPI user on
 * RAPIDAPI_BASIC_LIMITER 10/min and RAPIDAPI_PRO_LIMITER 120/min, key "rapidapi-<tier>:<16-hex hash of X-RapidAPI-User>". Every
 * RapidAPI lookup counts (cache hits too); RapidAPI traffic never touches the free per-IP limiter. Monthly quotas are enforced by
 * RapidAPI.
 */
export const RAPIDAPI_PREFIX = '/rapidapi';
export const RAPIDAPI_TIERS = ['BASIC', 'PRO'];
export const RAPIDAPI_PER_MIN = { BASIC: 10, PRO: 120 };
/** Monthly hard quotas / prices set in Studio. */
export const RAPIDAPI_PER_MONTH = { BASIC: 100, PRO: 30_000 };
export const RAPIDAPI_PRICE_USD = { BASIC: 0, PRO: 9.99 };
export const RAPIDAPI_BINDING = { BASIC: 'RAPIDAPI_BASIC_LIMITER', PRO: 'RAPIDAPI_PRO_LIMITER' };

export function rapidTier(request) {
  const t = String(request.headers.get('x-rapidapi-subscription') || '').trim().toUpperCase();
  return RAPIDAPI_TIERS.includes(t) ? t : 'BASIC';
}
export const isRapidApiPath = (path) => path === RAPIDAPI_PREFIX || path.startsWith(`${RAPIDAPI_PREFIX}/`);

async function digest(s) { return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)))); }
export async function safeEqual(a, b) {
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let d = 0; for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}
export async function rapidUserKey(request, fallback) {
  const u = String(request.headers.get('x-rapidapi-user') || '').trim().slice(0, 128);
  return [...(await digest(u ? `u:${u}` : `ip:${fallback}`))].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
}
export async function rapidGate(request, env) {
  const secret = typeof env.RAPIDAPI_PROXY_SECRET === 'string' ? env.RAPIDAPI_PROXY_SECRET : '';
  // No RapidAPI-path error text points callers to the free /v1 API (proxied callers must never see that).
  if (!secret) return { status: 503, code: 'rapidapi_unavailable', message: 'The RapidAPI route is temporarily unavailable. Please retry later.', headers: { 'retry-after': '60' } };
  const presented = request.headers.get('x-rapidapi-proxy-secret');
  if (!presented || !(await safeEqual(presented, secret))) return { status: 401, code: 'unauthorized', message: 'Missing or invalid RapidAPI proxy secret. Call this API through RapidAPI.' };
  return null;
}

/** h = { json(status,obj,extra), err(status,code,msg,extra), readPostDomain(req) -> {raw}|{error}, runCheck, ipBucket, version, ctx, deps } */
export async function handleRapidApi(request, env, path, h) {
  const g = await rapidGate(request, env);
  if (g) return h.err(g.status, g.code, g.message, g.headers);
  const method = request.method.toUpperCase();
  const tier = rapidTier(request);
  const perMin = RAPIDAPI_PER_MIN[tier];
  const plan = { 'x-api-plan': `rapidapi-${tier.toLowerCase()}` };
  if (path === '/rapidapi/v1/health') {
    if (method !== 'GET') return h.err(405, 'method_not_allowed', 'Use GET /rapidapi/v1/health.', { allow: 'GET, HEAD' });
    return h.json(200, { ok: true, service: 'domainage', version: h.version, plan: 'rapidapi', tier }, plan);
  }
  let raw;
  if (path.startsWith('/rapidapi/v1/domain/') && method === 'GET') { try { raw = decodeURIComponent(path.slice(20)); } catch { raw = ''; } }
  else if (path === '/rapidapi/v1/domain' && method === 'POST') { const b = await h.readPostDomain(request); if (b.error) return b.error; raw = b.raw; }
  else if (path === '/rapidapi/v1/domain' || path.startsWith('/rapidapi/v1/domain/')) return h.err(405, 'method_not_allowed', 'Use GET /rapidapi/v1/domain/{name} or POST /rapidapi/v1/domain.', { allow: 'GET, HEAD, POST' });
  else return h.err(404, 'not_found', 'Unknown RapidAPI endpoint. Use GET /rapidapi/v1/domain/{name}, POST /rapidapi/v1/domain or GET /rapidapi/v1/health.');
  const limiter = env[RAPIDAPI_BINDING[tier]];
  // Fail closed. A missing binding (e.g. a wrangler 3 deploy that dropped it) must not mean "unlimited".
  if (!limiter || typeof limiter.limit !== 'function') return h.err(503, 'rapidapi_unavailable', 'The RapidAPI route is temporarily unavailable. Please retry later.', { 'retry-after': '60', ...plan });
  {
    const { success } = await limiter.limit({ key: `rapidapi-${tier.toLowerCase()}:${await rapidUserKey(request, h.ipBucket)}` });
    if (!success) return h.err(429, 'rate_limited', `Too many requests for your RapidAPI ${tier} plan (about ${perMin} per minute). Please wait a minute.`, { 'retry-after': '60', ...plan });
  }
  const r = await h.runCheck({ input: raw, auth: { ok: true, tier: `rapidapi-${tier.toLowerCase()}` }, env, ctx: h.ctx, ip: h.ip, deps: h.deps, skipIpLimit: true });
  if (!r.ok) return h.err(r.status, r.code, r.message, { ...r.headers, ...plan });
  return h.json(200, r.body, { ...r.headers, ...plan, 'cache-control': 'no-store' });
}
