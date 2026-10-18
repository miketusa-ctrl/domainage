// llms.txt, OpenAPI 3.1 and MCP server card, generated from code constants.
import { TOOLS, SUPPORTED_VERSIONS, DISCOVERY_PER_MIN, MAX_BODY_BYTES, MAX_BATCH, SERVER_INFO } from './mcp.js';
import { VERSION } from '../version.js';

export const MAX_POST_BODY = 4096;
export const CACHE_HOURS = 24;
export const limitsFor = (env = {}) => ({ anonPerMin: Number(env.ANON_LOOKUPS_PER_MIN) || 10, cacheHours: CACHE_HOURS, maxBody: MAX_POST_BODY });
export const mcpClientConfig = (origin) => ({ mcpServers: { domainage: { type: 'http', url: `${origin}/mcp` } } });

export const llmsTxt = (origin, L) => `# DomainAge

> Domain age and RDAP (WHOIS successor) registration lookup: registration date, age in days, expiry, registrar, status flags and nameservers for any domain whose registry runs RDAP. For fraud/signup-risk checks, lead enrichment and domain research. Public JSON API plus a remote MCP server for AI agents.

## For AI agents

- [MCP server](${origin}/mcp): remote MCP over Streamable HTTP (POST only, stateless, JSON responses). Protocol versions: ${SUPPORTED_VERSIONS.join(', ')}. Tool \`${TOOLS[0].name}\` (domain). Read-only. Client config (most MCP clients accept this; some use a different format, for example VS Code uses a \`servers\` key): \`${JSON.stringify(mcpClientConfig(origin))}\`
- [OpenAPI 3.1 spec](${origin}/openapi.json): machine-readable description of the JSON API

## JSON API

- \`GET ${origin}/v1/domain/{name}\` or \`POST ${origin}/v1/domain\` with \`{"domain":"example.com"}\` (body max ${L.maxBody} bytes). URLs and subdomains are reduced to the registered domain (mail.google.com -> google.com; \`input\` echoes what you sent). Returns domain, registered, created, updated, expires, age_days, age_years, registrar {name, iana_id}, status[], nameservers[], dnssec, rdap_server, cached. registered:false when the registry has no record. Errors: { "error": { "code", "message" } } with 400 invalid_domain / bad_json, 405 method_not_allowed, 413 body_too_large, 422 unsupported_tld, 429 rate_limited, 502 upstream_error / upstream_redirect / upstream_too_large / upstream_bad_json, 503 upstream_rate_limited (the registry is rate-limiting us; honour Retry-After), 504 upstream_timeout.
- \`GET ${origin}/v1/meta\`: version, build, IANA bootstrap date, TLD count.

## Limits, keys and pricing

- Anonymous only (no API keys yet): about ${L.anonPerMin} uncached lookups per minute per IP; results are cached up to ${L.cacheHours} hours and cache hits don't count. The MCP endpoint uses the same counters: each \`tools/call\` is one lookup. Non-lookup MCP messages don't count as lookups, but are capped at about ${DISCOVERY_PER_MIN}/min per IP (HTTP 429 + Retry-After). Registrant contact data is not returned. Some ccTLDs have no RDAP service (422 unsupported_tld).

## Optional

- [Privacy](${origin}/privacy)
- Contact: digitalpromohub.support@gmail.com
`;

const errSchema = { type: 'object', properties: { error: { type: 'object', properties: { code: { type: 'string' }, message: { type: 'string' } }, required: ['code', 'message'] } }, required: ['error'] };
const resp = (d, extra = {}) => ({ description: d, content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } }, ...extra });
const retryHdr = { 'Retry-After': { schema: { type: 'integer' }, description: 'Seconds to wait' } };
const lookupResponses = {
  200: { description: 'Lookup result', headers: { 'X-Cache': { schema: { type: 'string', enum: ['HIT', 'MISS'] } } }, content: { 'application/json': { schema: { $ref: '#/components/schemas/Lookup' } } } },
  400: resp('invalid_domain or bad_json'), 422: resp('unsupported_tld: TLD has no RDAP service'),
  429: resp('rate_limited', { headers: retryHdr }), 502: resp('upstream_error, upstream_redirect, upstream_too_large or upstream_bad_json'),
  503: resp('upstream_rate_limited: the registry RDAP server is rate-limiting lookups; retry after Retry-After seconds', { headers: retryHdr }), 504: resp('upstream_timeout'),
};
export function openApiSpec(origin, L) {
  const tool = TOOLS[0];
  return {
    openapi: '3.1.0',
    info: { title: 'DomainAge API', version: VERSION, description: `Domain age and RDAP registration lookup. Anonymous, about ${L.anonPerMin} uncached lookups/min per IP; cached up to ${L.cacheHours}h.`, contact: { email: 'digitalpromohub.support@gmail.com' } },
    servers: [{ url: origin }],
    paths: {
      '/v1/domain/{name}': { get: { operationId: 'lookupDomain', summary: 'Look up a domain', parameters: [{ name: 'name', in: 'path', required: true, schema: { type: 'string', maxLength: 300 }, description: 'Domain, URL or subdomain' }], responses: { ...lookupResponses, 405: resp('method_not_allowed') } } },
      '/v1/domain': { post: { operationId: 'lookupDomainPost', summary: 'Look up a domain (JSON body)', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { domain: { type: 'string', maxLength: 300 } }, required: ['domain'] } } } }, responses: { ...lookupResponses, 413: resp(`body_too_large (max ${L.maxBody} bytes)`), 405: resp('method_not_allowed') } } },
      '/v1/meta': { get: { operationId: 'meta', summary: 'Version and bootstrap info', responses: { 200: { description: 'Meta', content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, version: { type: 'string' }, build: { type: 'string' }, bootstrap: { type: 'string' }, tlds: { type: 'integer' } } } } } } } } },
      '/mcp': {
        post: { operationId: 'mcp', summary: `MCP JSON-RPC 2.0 (Streamable HTTP, stateless). Tool ${tool.name}. Max ${MAX_BODY_BYTES} bytes, batch max ${MAX_BATCH}, one tools/call per request.`,
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object' } } } },
          responses: Object.fromEntries([[200, 'JSON-RPC response'], [202, 'Notification accepted (no body)'], [400, 'Parse error, invalid request or protocol version'], [401, 'Unauthorized (not used: no keys)'], [403, 'Origin not allowed'], [404, 'Method not found (2026-07-28)'], [413, 'Body too large'], [429, 'Too many requests'], [500, 'Internal error'], [503, 'Unavailable']].map(([c, d]) => [c, { description: d, ...(c === 429 ? { headers: retryHdr } : {}), ...(c === 202 ? {} : { content: { 'application/json': { schema: { type: 'object' } } } }) }])) },
        get: { operationId: 'mcpGet', summary: 'Not supported (no SSE stream)', responses: { 405: { description: 'Method not allowed', headers: { Allow: { schema: { type: 'string', const: 'POST, OPTIONS' } } } } } },
        delete: { operationId: 'mcpDelete', summary: 'Not supported (no sessions)', responses: { 405: { description: 'Method not allowed', headers: { Allow: { schema: { type: 'string', const: 'POST, OPTIONS' } } } } } },
      },
    },
    components: { schemas: { Error: errSchema, Lookup: tool.outputSchema } },
  };
}
export const serverCard = (origin) => ({ serverInfo: { name: SERVER_INFO.name, title: SERVER_INFO.title, version: VERSION }, transport: { type: 'streamable-http', url: `${origin}/mcp` }, authentication: { required: false }, tools: TOOLS, resources: [], prompts: [] });
// Glama connector ownership claim, served at /.well-known/glama.json. Replace the placeholder with your own claim token from glama.ai.
export const GLAMA_CLAIM_RE = /^glama_claim_[A-Za-z0-9_-]{8,128}$/;
export const glamaJson = (env = {}) => { const c = typeof env.GLAMA_CLAIM === 'string' ? env.GLAMA_CLAIM.trim() : ''; return GLAMA_CLAIM_RE.test(c) ? JSON.stringify({ $schema: 'https://glama.ai/mcp/schemas/connector.json', claim: c }) : null; };
