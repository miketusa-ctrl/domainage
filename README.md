# DomainAge

Domain age and RDAP lookup: registration date, age, expiry, registrar, status and nameservers.

## Live service

- Web app and API: https://domainage.mike-tusa.workers.dev/
- Pricing: https://rapidapi.com/miketusa/api/domainage-domain-age-and-rdap-lookup-api
- Support: digitalpromohub.support@gmail.com

## Use it from an AI assistant (MCP)

DomainAge is a remote MCP server (Streamable HTTP) at `https://domainage.mike-tusa.workers.dev/mcp`. Tools: `lookup_domain`.

Cursor, Cline and Windsurf accept this config:

```json
{
  "mcpServers": {
    "domainage": {
      "type": "http",
      "url": "https://domainage.mike-tusa.workers.dev/mcp"
    }
  }
}
```

Claude Desktop: open Settings > Connectors, choose "Add custom connector" and paste `https://domainage.mike-tusa.workers.dev/mcp`. Or, for clients that only support local (stdio) servers, use the mcp-remote bridge: `npx mcp-remote https://domainage.mike-tusa.workers.dev/mcp`.

VS Code uses a `servers` key instead of `mcpServers`.

The `server.json` file is the [MCP Registry](https://registry.modelcontextprotocol.io) manifest for this server.

## Run your own copy

Requires Node.js 22+ and a Cloudflare account.

```bash
npm install
npx wrangler@4 dev      # local dev server
```

`wrangler.toml` is a template: create your own KV namespaces / D1 databases / rate-limit namespaces and replace the `<PLACEHOLDER>` values before `npx wrangler@4 deploy`. Any secrets the Worker reads go in `wrangler secret put` (or `.dev.vars` locally), never in the repo.

## Third-party data

`src/psl.js` is generated from the [Public Suffix List](https://publicsuffix.org/) (MPL-2.0); `src/bootstrap.js` from the IANA RDAP bootstrap file (dns.json).

## License

MIT (c) Digital Promo Hub. See [LICENSE](LICENSE).
