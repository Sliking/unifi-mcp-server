# UniFi MCP Server

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Sliking/unifi-mcp-server)
[![CI](https://github.com/Sliking/unifi-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/Sliking/unifi-mcp-server/actions/workflows/ci.yml)

A secure, **read-only** remote [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for UniFi networks, running on **Cloudflare Workers**.

Connect it to any MCP-capable assistant (Claude, ChatGPT, Perplexity, Cursor, VS Code, …) and ask things like:

- *"Audit my current firewall policies and identify security issues"*
- *"Show me all VLANs and which ones can communicate"*
- *"Which devices are generating the most traffic?"*
- *"Is my IoT network properly isolated?"*

```
 ┌──────────────┐  OAuth 2.1 + Streamable HTTP   ┌─────────────────────────┐   Workers VPC    ┌─────────────┐   LAN    ┌──────────────┐
 │ Chat assistant├──────────────────────────────►│ Cloudflare Worker (MCP) ├─────────────────►│ cloudflared ├─────────►│ UniFi console │
 │ (MCP client)  │  Bearer token (audience-bound)│  read-only UniFi client │  (private, no    │  (tunnel)   │  HTTPS   │ UDM / UCG / … │
 └──────────────┘                                └─────────────────────────┘   public host)   └─────────────┘          └──────────────┘
                                                          │ sign-in
                                                          ▼
                                                     GitHub OAuth (allow-listed users only)
```

## Features

| Tool | What it does |
| --- | --- |
| `unifi_audit_security` | Prioritised findings (critical → info) with remediation: Internet-exposed rules/port forwards, any-any allows, shadowed and dangling rules, inter-VLAN segmentation gaps, IoT/guest leakage, Wi-Fi encryption (WEP/open/WPA2-only/PMF), UPnP, IPS, device SSH, firmware. |
| `unifi_vlan_connectivity` | Who-can-talk-to-whom matrix for every routed VLAN pair, the rule/policy that decides it, and any port-level exceptions. Supports both the **zone-based firewall** (Network 9+) and **legacy** LAN_IN/GUEST_IN rules. |
| `unifi_check_iot_isolation` | Pass/warn/fail checks for each IoT network, plus IoT-looking devices (by vendor/hostname) that are sitting on trusted networks. |
| `unifi_top_talkers` | Clients ranked by session traffic or by current throughput. |
| `unifi_network_overview` | Health of WAN/LAN/WLAN/VPN, device and client counts, networks. |
| `unifi_list_networks`, `unifi_list_firewall`, `unifi_list_clients`, `unifi_list_devices`, `unifi_list_wifi`, `unifi_list_sites` | Inventory, with all secrets redacted. |

It also ships MCP **prompts** for the four example questions above.

### Two ways to connect

- **Local mode** (recommended): Workers VPC + Cloudflare Tunnel with a View-Only local API key. Full feature set.
- **Cloud mode**: through Ubiquiti's Site Manager connector (`api.ui.com`) with no tunnel or extra hardware. Port-forward, UPnP and IPS checks and per-client traffic are not available because Ubiquiti's public API does not expose them. See the [comparison](docs/DEPLOYMENT.md).

## Security model

This server touches home network equipment, so it is built to be safe by default:

- **Read-only by construction.** The UniFi client can only issue `GET` requests to an explicit allow-list of endpoints. There is no code path that can change your network.
- **Standards-based authentication.** OAuth 2.1 authorization server with PKCE S256 ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)), Authorization Server Metadata ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)), Dynamic Client Registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)), Protected Resource Metadata ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)), Resource Indicators / audience-bound tokens ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)), `iss` in authorization responses ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)) and Bearer tokens ([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)), as required by the [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization).
- **Deny by default.** Users sign in with GitHub, and only logins listed in `ALLOWED_GITHUB_USERS` are authorised. The allow-list is re-checked on every MCP request, so removing a user revokes access immediately. The GitHub token is revoked right after sign-in and never stored.
- **No inbound ports on your network.** In local mode, the Worker reaches your console through [Workers VPC](https://developers.cloudflare.com/workers-vpc/) and an outbound-only Cloudflare Tunnel. The VPC service is pinned to a single host and port, which prevents SSRF. A Cloudflare Access service-token mode is also supported. In cloud mode, it goes through Ubiquiti's own cloud connector over HTTPS, using an allow-list of read-only Integration API paths.
- **Secrets never leave the Worker.** Wi-Fi passphrases, RADIUS secrets, VPN keys and SSH passwords are redacted from every response before it reaches the LLM.
- **Defence in depth.** Short-lived access tokens (1 h) with refresh-token rotation, per-user rate limiting, DNS-rebinding (Host) protection, CSRF-protected consent screen, `__Host-` cookies, strict security headers, request timeouts and response-size limits, and a structured audit log of every tool call in Workers Observability.

See [SECURITY.md](SECURITY.md) for the threat model and how to report vulnerabilities.

## Requirements

- A UniFi OS console (UDM, UDM Pro/SE, UCG Ultra/Max, UDR, UX, Cloud Key Gen2+, or UniFi OS Server) running UniFi Network 8.x or newer. Zone-based firewall analysis requires Network 9.0+.
- A Cloudflare account (the Workers Free plan is enough).
- A machine on your LAN that can run `cloudflared` (Raspberry Pi, NAS, Docker host, …).
- A GitHub account for sign-in.

## Quick start (one-click, cloud mode, about 10 minutes)

You need a Cloudflare account (the Free plan is fine), a GitHub account, and a UniFi console on UniFi OS 5.0.3+ that you can see at [unifi.ui.com](https://unifi.ui.com).

1. **Find your Worker URL.** In the Cloudflare dashboard, go to **Workers & Pages** and note your `*.workers.dev` subdomain. Your server will be at `https://unifi-mcp-server.<subdomain>.workers.dev`.
2. **Create a GitHub OAuth app** at <https://github.com/settings/applications/new>:
   - Homepage URL: `https://unifi-mcp-server.<subdomain>.workers.dev`
   - Redirect URI: `https://unifi-mcp-server.<subdomain>.workers.dev/callback`
   - Leave wildcard matching and device flow unchecked. Generate a client secret.
3. **Create a UniFi API key** at [unifi.ui.com](https://unifi.ui.com) → **API** → **Create API Key**.
4. **Click _Deploy to Cloudflare_** above and fill in the prompts:
   - `UNIFI_API_KEY`: the key from step 3
   - `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`: from step 2
   - `COOKIE_ENCRYPTION_KEY`: the output of `openssl rand -hex 32`
5. **Authorise yourself.** In the dashboard, go to **Workers & Pages → unifi-mcp-server → Settings → Variables and Secrets**. Set `ALLOWED_GITHUB_USERS` to your GitHub login. It is empty by default, so nobody can sign in until you set it. If you own more than one UniFi console, also set `UNIFI_CONSOLE_ID`, the long ID in the `unifi.ui.com/consoles/<ID>/…` URL.
6. **Connect your assistant** to `https://unifi-mcp-server.<subdomain>.workers.dev/mcp` (see below) and sign in with GitHub.

If you deploy under a different Worker name, use that name in the URLs above.

For the full feature set (port forwards, UPnP/IPS checks, per-client traffic), use **local mode** with Cloudflare Tunnel and a View-Only local API key. See **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

### Manual deploy (CLI)

```bash
git clone https://github.com/Sliking/unifi-mcp-server.git && cd unifi-mcp-server
npm install
npx wrangler login
# edit "vars" in wrangler.jsonc (ALLOWED_GITHUB_USERS, UNIFI_MODE, UNIFI_CONSOLE_ID)
npx wrangler secret put UNIFI_API_KEY
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
openssl rand -hex 32 | npx wrangler secret put COOKIE_ENCRYPTION_KEY
npm run deploy                     # the OAuth KV namespace is created automatically
```

## Connecting clients

| Client | How |
| --- | --- |
| **Claude** (web/desktop) | Settings → Connectors → *Add custom connector* → URL `https://…/mcp`. |
| **ChatGPT** | Settings → Apps & Connectors → *Advanced* → enable Developer mode → *Create* connector → URL `https://…/mcp`, authentication *OAuth*. |
| **Perplexity** | Settings → Connectors → *Add connector* → Remote MCP → URL `https://…/mcp`. |
| **Claude Code** | `claude mcp add --transport http unifi https://…/mcp` |
| **Cursor / VS Code** | Add `{"url": "https://…/mcp"}` to the MCP server config. |
| **MCP Inspector** | `npx @modelcontextprotocol/inspector` → Streamable HTTP → `https://…/mcp`. |

The first connection opens a browser window: approve the client, sign in with GitHub, done.

## Development

```bash
npm install
cp .dev.vars.example .dev.vars   # fill in values
npm run dev                      # http://localhost:8788/mcp
npm run check                    # type-check + unit tests
```

Analysis logic (`src/analysis/`) is pure TypeScript and fully unit-tested with fixtures in `test/fixtures.ts`, so you can contribute new checks without UniFi hardware.

## Project layout

```
src/
  index.ts                OAuth provider + MCP endpoint wiring, allow-list, rate limiting
  auth/                   GitHub sign-in, consent screen, CSRF/state helpers
  mcp/server.ts           MCP tools and prompts
  unifi/client.ts         Read-only, allow-listed UniFi API client
  unifi/redact.ts         Secret redaction
  analysis/               Connectivity engine, security audit, IoT checks, traffic ranking
test/                     Vitest unit and protocol tests
docs/                     Deployment and architecture docs
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md). Good first contributions: new audit checks, support for more UniFi endpoints, and real-world (anonymised) fixtures from different UniFi Network versions.

## Disclaimer

Not affiliated with or endorsed by Ubiquiti Inc. "UniFi" is a trademark of Ubiquiti Inc. The analysis is heuristic and based on configuration only; always verify findings before acting on them.

## License

[MIT](LICENSE)
