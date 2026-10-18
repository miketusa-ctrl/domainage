import { RDAP, BOOTSTRAP_DATE } from './bootstrap.js';
import { PSL } from './psl.js';
import { VERSION } from './version.js';
import { handleMcp, MCP_CORS } from './lib/mcp.js';
import { isRapidApiPath, handleRapidApi } from './lib/rapidapi.js';
import { llmsTxt, openApiSpec, serverCard, limitsFor, mcpClientConfig, glamaJson } from './lib/agentdocs.js';
export { VERSION };
const MAX_UPSTREAM = 262144;   // registry response cap (bytes)
const MAX_LIST = 20;
const MAX_BODY = 4096;          // POST body cap (bytes)
const CACHE_TTL = 86400;        // 24h for successful lookups
const NEG_TTL = 3600;           // 1h for 404/not-found
const BACKOFF_MIN = 30, BACKOFF_MAX = 600, BACKOFF_DEFAULT = 60; // registry 429 / 503+Retry-After backoff (seconds)
const UA = `DomainAge/${VERSION} (+https://domainage.mike-tusa.workers.dev; digitalpromohub.support@gmail.com)`;
const DOMAIN_RE = /^(?=.{1,253}$)((?!-)[a-z0-9-]{1,63}(?<!-)\.)+(?!-)(?![0-9]+$)[a-z0-9-]{2,63}(?<!-)$/;
const SECURITY = { 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()' };
const JSON_CSP = "default-src 'none'; frame-ancestors 'none'";

function hdrs(env, extra = {}) {
  const h = { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*', 'content-security-policy': JSON_CSP, ...SECURITY, ...extra };
  if (env.PUBLIC_LAUNCH !== 'true') h['x-robots-tag'] = 'noindex, nofollow';
  return h;
}
const json = (env, obj, status = 200, extra) => new Response(JSON.stringify(obj, null, 2), { status, headers: hdrs(env, extra) });
const err = (env, status, code, message, extra) => json(env, { error: { code, message } }, status, extra);

export function normalizeDomain(input) {
  if (typeof input !== 'string') return null;
  let d = input.trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, '').split(/[\/?#]/)[0].replace(/:\d+$/, '').replace(/\.$/, '');
  if (d.startsWith('www.')) d = d.slice(4);
  try { d = new URL('http://' + d).hostname; } catch { return null; } // punycode IDNs
  if (/^\[|^[0-9.]+$|^0x/i.test(d)) return null;
  return DOMAIN_RE.test(d) ? d : null;
}
// Registrable domain (eTLD+1) via bundled PSL ICANN rules. confident=false when only the implicit "*" rule matched.
export function registrable(host) {
  const labels = host.split('.');
  let sufLen = 0, confident = false;
  for (let i = 0; i < labels.length; i++) {
    const cand = labels.slice(i).join('.'), rest = labels.slice(i + 1).join('.');
    if (PSL.has('!' + cand)) { sufLen = labels.length - i - 1; confident = true; break; }
    if (PSL.has(cand) || (rest && PSL.has('*.' + rest))) { sufLen = labels.length - i; confident = true; break; }
  }
  if (!confident) sufLen = 1;
  if (labels.length <= sufLen) return null; // input is itself a public suffix
  return { domain: labels.slice(-(sufLen + 1)).join('.'), confident };
}
export function rdapBase(domain) { return RDAP[domain.slice(domain.lastIndexOf('.') + 1)] || null; }

const evDate = (events, action) => { const e = (events || []).find(x => x.eventAction === action); return e ? e.eventDate : null; };
export function summarize(domain, r, now = Date.now()) {
  const created = evDate(r.events, 'registration');
  const age = created ? Math.floor((now - Date.parse(created)) / 86400000) : null;
  const reg = (r.entities || []).find(e => (e.roles || []).includes('registrar'));
  let registrar = null;
  if (reg) { const fn = (reg.vcardArray?.[1] || []).find(v => v[0] === 'fn'); registrar = { name: fn ? fn[3] : null, iana_id: (reg.publicIds || []).find(p => /iana/i.test(p.type))?.identifier || null }; }
  return {
    domain, registered: true,
    created, updated: evDate(r.events, 'last changed'), expires: evDate(r.events, 'expiration'),
    age_days: age, age_years: age == null ? null : Math.round(age / 36.525) / 10,
    registrar, status: (r.status || []).slice(0, MAX_LIST),
    nameservers: (r.nameservers || []).slice(0, MAX_LIST).map(n => String(n.ldhName || '').toLowerCase().replace(/\.$/, '')).filter(Boolean),
    dnssec: r.secureDNS ? !!r.secureDNS.delegationSigned : null,
  };
}

// Registry Retry-After (delta-seconds or HTTP-date) -> seconds, clamped 30-600, default 60.
export function retryAfterSeconds(v, now = Date.now()) {
  const t = String(v ?? '').trim();
  let n = /^\d+$/.test(t) ? Number(t) : (t && !Number.isNaN(Date.parse(t)) ? Math.ceil((Date.parse(t) - now) / 1000) : NaN);
  if (!Number.isFinite(n)) n = BACKOFF_DEFAULT;
  return Math.min(BACKOFF_MAX, Math.max(BACKOFF_MIN, n));
}
const rateLimited = (secs, hit) => ({ status: 503, body: { error: { code: 'upstream_rate_limited', message: 'The registry RDAP server is rate-limiting lookups right now. Please retry later.' } }, headers: { 'retry-after': String(secs), 'x-cache': hit ? 'HIT' : 'MISS' } });
// Per-registry-host backoff ("negative cache"): Cache API (per colo) plus an isolate-local map. Only rate-limit answers are stored.
const backoffMem = new Map();
const backoffKey = (env, host) => new Request(`https://cache.domainage.internal/${env?.DEPLOY_ENV || 'dev'}/backoff/${host}`);
async function backoffLeft(cache, env, host, now) {
  let until = backoffMem.get(host) || 0;
  if (until <= now && cache) { const hit = await cache.match(backoffKey(env, host)); if (hit) { try { until = Number((await hit.json()).until) || 0; } catch { until = 0; } } }
  return until > now ? Math.max(1, Math.ceil((until - now) / 1000)) : 0;
}
async function setBackoff(cache, env, host, secs, now, ctx) {
  const until = now + secs * 1000; if (backoffMem.size > 500) backoffMem.clear(); backoffMem.set(host, until);
  if (cache) { const p = cache.put(backoffKey(env, host), new Response(JSON.stringify({ until }), { headers: { 'cache-control': `max-age=${secs}` } })); ctx?.waitUntil ? ctx.waitUntil(p) : await p; }
}
export function _resetBackoff() { backoffMem.clear(); } // tests

// One outbound fetch per uncached lookup; result cached in the Cache API (per colo) for 24h.
export async function lookup(domain, ctx, deps = {}, opts = {}) {
  const base = rdapBase(domain);
  if (!base) return { status: 422, body: { error: { code: 'unsupported_tld', message: 'This TLD has no RDAP service in the IANA bootstrap.' } } };
  const cache = deps.cache ?? (typeof caches !== 'undefined' ? caches.default : null);
  const key = new Request(`https://cache.domainage.internal/${opts.env?.DEPLOY_ENV || 'dev'}/${VERSION}/${domain}`); // env in key
  if (cache) { const hit = await cache.match(key); if (hit) return { ...(await hit.json()), cached: true }; }
  const host = new URL(base).host, now = deps.now ? deps.now() : Date.now();
  const left = await backoffLeft(cache, opts.env, host, now); // registry backoff: no upstream fetch, no limiter charge
  if (left) return rateLimited(left, true);
  if (opts.beforeFetch) { const stop = await opts.beforeFetch(); if (stop) return stop; } // limiter only on cache MISS
  const f = deps.fetch ?? fetch;
  let res;
  try { res = await f(base + 'domain/' + domain, { headers: { accept: 'application/rdap+json', 'user-agent': UA }, redirect: 'manual', signal: AbortSignal.timeout(8000) }); }
  catch { return { status: 504, body: { error: { code: 'upstream_timeout', message: 'Registry RDAP server did not answer.' } } }; }
  let out;
  if (res.status === 429 || (res.status === 503 && res.headers.get('retry-after'))) {
    const secs = retryAfterSeconds(res.headers.get('retry-after'), now);
    await setBackoff(cache, opts.env, host, secs, now, ctx);
    return rateLimited(secs, false);
  }
  if (res.status >= 300 && res.status < 400) return { status: 502, body: { error: { code: 'upstream_redirect', message: 'Registry RDAP answered with a redirect.' } } };
  if (res.status === 404) out = { status: 200, body: { domain, registered: false }, ttl: NEG_TTL };
  else if (!res.ok) return { status: 502, body: { error: { code: 'upstream_error', message: `Registry RDAP returned HTTP ${res.status}.` } } };
  else { const txt = await readCapped(res, MAX_UPSTREAM);
    if (txt === null) return { status: 502, body: { error: { code: 'upstream_too_large', message: 'Registry RDAP response too large.' } } };
    let r; try { r = JSON.parse(txt); } catch { return { status: 502, body: { error: { code: 'upstream_bad_json', message: 'Registry returned invalid RDAP.' } } }; }
    out = { status: 200, body: { ...summarize(domain, r), rdap_server: host }, ttl: CACHE_TTL }; }
  if (cache) { const p = cache.put(key, new Response(JSON.stringify(out), { headers: { 'cache-control': `max-age=${out.ttl}` } })); ctx?.waitUntil ? ctx.waitUntil(p) : await p; }
  return { ...out, cached: false };
}

// shared gate for REST and MCP
export function ipBucket(ip) { // IPv4 as is; IPv6 -> its /64
  const s = String(ip || 'unknown').trim().toLowerCase();
  if (!s.includes(':')) return s;
  if (s.includes('.')) return s.slice(s.lastIndexOf(':') + 1);
  const [h, t] = s.split('::'), head = h ? h.split(':') : [], tail = t ? t.split(':') : [];
  const parts = t === undefined ? head : [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
  return parts.slice(0, 4).map((x) => x.replace(/^0+(?=.)/, '') || '0').join(':') + '::/64';
}
// DomainAge has no API keys yet: every caller is anonymous; Authorization / X-Api-Key are ignored (never echoed).
export async function authenticate(_request, _env) { return { ok: true, tier: 'anonymous' }; }
// { ok:true, body, headers, cached } | { ok:false, status, code, message, headers }
export async function runCheck({ input, auth, env, ctx, ip, deps, skipIpLimit = false }) {
  const host = normalizeDomain(input);
  const reg = host && registrable(host);
  if (!reg) return { ok: false, status: 400, code: 'invalid_domain', message: 'Give a domain name like example.com.', headers: {} };
  const domain = reg.domain;
  const L = limitsFor(env);
  const beforeFetch = async () => {
    if (skipIpLimit || !env.LOOKUP_LIMITER) return null; // RapidAPI path is limited per RapidAPI user instead
    const { success } = await env.LOOKUP_LIMITER.limit({ key: ipBucket(ip) });
    return success ? null : { status: 429, body: { error: { code: 'rate_limited', message: `About ${L.anonPerMin} uncached lookups/min per IP.` } }, headers: { 'retry-after': '60' } };
  };
  const r = await lookup(domain, ctx, deps, { env, beforeFetch });
  if (r.body.error) return { ok: false, status: r.status, code: r.body.error.code, message: r.body.error.message, headers: r.headers || {} };
  const echo = typeof input === 'string' && input.trim().toLowerCase() !== domain ? { input: String(input).slice(0, 253) } : {};
  return { ok: true, body: { ...r.body, ...echo, cached: r.cached }, cached: r.cached, headers: { 'x-cache': r.cached ? 'HIT' : 'MISS' } };
}
const memLimits = new Map();
export function memLimit(key, limit, periodMs, now = Date.now()) {
  const e = memLimits.get(key);
  if (!e || now - e.start >= periodMs) { if (memLimits.size > 5000) memLimits.clear(); memLimits.set(key, { start: now, n: 1 }); return true; }
  return ++e.n <= limit;
}
const REG_AUTH_RE = /^v=MCPv1; k=(ed25519|ecdsap384); p=[A-Za-z0-9+/=]{20,120}$/;
const FAVICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#1f4e79"/><text x="32" y="42" font-family="Arial,sans-serif" font-size="28" font-weight="700" fill="#fff" text-anchor="middle">DA</text></svg>';

const APP_JS = `document.getElementById('mcp-config').textContent=JSON.stringify({mcpServers:{domainage:{type:'http',url:location.origin+'/mcp'}}},null,2);f.onsubmit=async e=>{e.preventDefault();o.hidden=false;o.textContent='...';const r=await fetch('/v1/domain/'+encodeURIComponent(d.value.trim()));o.textContent=JSON.stringify(await r.json(),null,2)}`;
const PAGE_CSP = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const EXT = (href, text) => `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`;
const PRIVACY_PAGE = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DomainAge privacy</title><link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>body{font:16px system-ui;max-width:680px;margin:40px auto;padding:0 16px}</style>
<h1>DomainAge privacy</h1>
<p>We don't store your IP or the domains you look up beyond a 24h result cache; your IP is used only for rate limiting; registries see Cloudflare's IP, not yours. Registrant contact data is not returned.</p>
<h2 id="rapidapi">RapidAPI</h2>
<p>DomainAge is also offered on the ${EXT('https://rapidapi.com', 'RapidAPI')} marketplace. If you use it there, RapidAPI handles your account, API key, subscription, billing and usage metering under ${EXT('https://rapidapi.com/privacy', 'its own privacy policy')}, and your requests pass through RapidAPI's servers before they reach ours. On our side the RapidAPI route works like the free API: the same 24h result cache, nothing else stored. We keep only a short-lived per-minute rate-limit counter keyed by a one-way hash of your RapidAPI username.</p>
<p>Contact: digitalpromohub.support@gmail.com · <a href="/">Back to DomainAge</a></p></html>`;
const PAGE = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DomainAge: free domain age &amp; RDAP lookup</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="alternate" type="text/plain" href="/llms.txt" title="llms.txt"><link rel="service-desc" type="application/json" href="/openapi.json" title="OpenAPI 3.1">
<style>body{font:16px system-ui;max-width:680px;margin:40px auto;padding:0 16px}input{font:inherit;padding:8px;width:60%}button{font:inherit;padding:8px 14px}pre{background:#f4f4f4;padding:12px;overflow:auto}.small{font-size:14px}@media (max-width:560px){#mcp-config{white-space:pre-wrap;word-break:break-all}}</style>
<h1>DomainAge</h1><p>Free domain age and RDAP (WHOIS successor) lookup. Registration date, age, expiry, registrar, status and nameservers.</p>
<form id=f><input id=d placeholder="example.com" required maxlength=253> <button>Look up</button></form><pre id=o hidden></pre>
<h2>API</h2><pre>GET  /v1/domain/{name}
POST /v1/domain   {"domain":"example.com"}   (body max 4 KB)
GET  /v1/meta</pre><p>Free, about 10 uncached lookups/min per IP (cached results don't count). Registrant contact data is not returned. <code>expires</code> is null when the registry doesn't publish it. Results cached up to 24h. Subdomains are reduced to the registered domain.</p><p id="privacy"><a href="/privacy">Privacy</a>: we don't store your IP or the domains you look up beyond a 24h result cache; your IP is used only for rate limiting; registries see Cloudflare's IP, not yours.</p>
<section id="agents"><h2>For AI agents (MCP)</h2>
<p>DomainAge is also a remote <a href="https://modelcontextprotocol.io/" target="_blank" rel="noopener noreferrer">Model Context Protocol</a> (MCP) server. Most MCP clients accept this config; some use a different format (for example, VS Code uses a <code>servers</code> key). Clients with a settings screen just need the URL <code>https://domainage.mike-tusa.workers.dev/mcp</code>.</p>
<pre><code id="mcp-config">{ "mcpServers": { "domainage": { "type": "http", "url": "https://domainage.mike-tusa.workers.dev/mcp" } } }</code></pre>
<p class="small">Machine-readable docs: <a href="/llms.txt">llms.txt</a> · <a href="/openapi.json">OpenAPI 3.1 spec</a></p></section>
<script src="/app.js"></script></html>`;

export default {
  // HEAD mirrors GET on every GET route: same status + headers, no body.
  async fetch(request, env, ctx, deps) {
    if (request.method === 'HEAD') {
      const r = await handle(new Request(request.url, { method: 'GET', headers: request.headers }), env, ctx, deps);
      return new Response(null, { status: r.status, headers: r.headers });
    }
    return handle(request, env, ctx, deps);
  },
};
async function handle(request, env, ctx, deps) {
  {
    const url = new URL(request.url); const p = url.pathname;
    const noidx = env.PUBLIC_LAUNCH === 'true' ? {} : { 'x-robots-tag': 'noindex, nofollow' };
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (p === '/mcp') return handleMcp(request, env, ctx, { authenticate, runCheck, ip, ipBucket: ipBucket(ip), origin: url.origin, memLimit, security: { ...SECURITY, ...noidx }, cors: MCP_CORS, allowedOrigins: env.MCP_ALLOWED_ORIGINS, anonPerMin: limitsFor(env).anonPerMin, lookupDeps: deps });
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...SECURITY, ...noidx, 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'content-type' } });
    if (p === '/' && request.method === 'GET') return new Response(PAGE, { headers: { ...hdrs(env), 'content-type': 'text/html; charset=utf-8', 'content-security-policy': PAGE_CSP } });
    if (p === '/privacy' && request.method === 'GET') return new Response(PRIVACY_PAGE, { headers: { ...hdrs(env), 'content-type': 'text/html; charset=utf-8', 'content-security-policy': PAGE_CSP } });
    if (p === '/app.js' && request.method === 'GET') return new Response(APP_JS, { headers: { ...hdrs(env), 'content-type': 'text/javascript; charset=utf-8' } });
    if (p === '/robots.txt') return new Response(env.PUBLIC_LAUNCH === 'true' ? 'User-agent: *\nAllow: /\nDisallow: /v1/\nDisallow: /rapidapi/\n' : 'User-agent: *\nDisallow: /\n', { headers: { 'content-type': 'text/plain', ...SECURITY, ...noidx } });
    const doc = (body, type) => (request.method === 'GET' ? new Response(body, { headers: { ...hdrs(env), 'content-type': type, 'cache-control': 'public, max-age=3600' } }) : err(env, 405, 'method_not_allowed', 'GET, HEAD or OPTIONS only.', { allow: 'GET, HEAD, OPTIONS' }));
    if (p === '/llms.txt') return doc(llmsTxt(url.origin, limitsFor(env)), 'text/plain; charset=utf-8');
    if (p === '/openapi.json') return doc(JSON.stringify(openApiSpec(url.origin, limitsFor(env)), null, 2), 'application/json; charset=utf-8');
    if (p === '/.well-known/mcp/server-card.json') return doc(JSON.stringify(serverCard(url.origin), null, 2), 'application/json; charset=utf-8');
    if (p === '/.well-known/glama.json') { const g = glamaJson(env); return g ? doc(g, 'application/json; charset=utf-8') : err(env, 404, 'not_found', 'See / for docs.'); }
    if (p === '/favicon.svg') return doc(FAVICON, 'image/svg+xml');
    if (p === '/.well-known/mcp-registry-auth') {
      const v = String(env.MCP_REGISTRY_AUTH || '');
      if (request.method !== 'GET' || !REG_AUTH_RE.test(v)) return err(env, 404, 'not_found', 'See / for docs.');
      return new Response(v, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...SECURITY, ...noidx } });
    }
    if (p === '/v1/meta') return json(env, { name: 'DomainAge', version: VERSION, build: env.BUILD_SHA || 'dev', bootstrap: BOOTSTRAP_DATE, tlds: Object.keys(RDAP).length });
    let raw = null;
    if (isRapidApiPath(p)) return handleRapidApi(request, env, p, { json: (st, o, x) => json(env, o, st, x), err: (st, c, m, x) => err(env, st, c, m, x), readPostDomain: (r) => readPostDomain(r, env), runCheck, ipBucket: ipBucket(ip), ip, version: VERSION, ctx, deps });
    if (p.startsWith('/v1/domain/') && request.method === 'GET') { try { raw = decodeURIComponent(p.slice(11)); } catch { raw = ''; } }
    else if (p === '/v1/domain' && request.method === 'POST') {
      const b = await readPostDomain(request, env); if (b.error) return b.error; raw = b.raw;
    } else if (p === '/v1/domain' || p.startsWith('/v1/domain/')) return err(env, 405, 'method_not_allowed', 'Use GET /v1/domain/{name} or POST /v1/domain.');
    else return err(env, 404, 'not_found', 'See / for docs.');
    const auth = await authenticate(request, env);
    const r = await runCheck({ input: raw, auth, env, ctx, ip, deps });
    if (!r.ok) return err(env, r.status, r.code, r.message, r.headers);
    return json(env, r.body, 200, { 'cache-control': 'public, max-age=300', ...r.headers });
  }
}

async function readPostDomain(request, env) {
  const len = Number(request.headers.get('content-length') || 0);
  if (len > MAX_BODY) return { error: err(env, 413, 'body_too_large', `Body must be <= ${MAX_BODY} bytes.`) };
  const buf = await readCapped(request, MAX_BODY);
  if (buf === null) return { error: err(env, 413, 'body_too_large', `Body must be <= ${MAX_BODY} bytes.`) };
  try { return { raw: JSON.parse(buf).domain }; } catch { return { error: err(env, 400, 'bad_json', 'Send {"domain":"example.com"}.') }; }
}
async function readCapped(request, max) {
  if (!request.body) return '';
  const reader = request.body.getReader(); const chunks = []; let n = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; n += value.byteLength; if (n > max) { reader.cancel(); return null; } chunks.push(value); }
  const all = new Uint8Array(n); let o = 0; for (const c of chunks) { all.set(c, o); o += c.byteLength; }
  return new TextDecoder().decode(all);
}
