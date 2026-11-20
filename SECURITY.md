# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately through [GitHub Security Advisories](https://github.com/Sliking/unifi-mcp-server/security/advisories/new). You should get a response within 7 days.

## Threat model

| Asset | Threat | Mitigation |
| --- | --- | --- |
| UniFi configuration | An attacker or a prompt-injected LLM changes firewall, Wi-Fi or VLAN settings | The client only issues `GET` requests to an allow-listed set of paths (`src/unifi/client.ts`). A View-Only UniFi admin is recommended as a second layer. |
| UniFi console | The console is exposed to the Internet | Workers VPC + an outbound-only Cloudflare Tunnel. No inbound ports, no public hostname. The VPC service is pinned to one host and port (no SSRF). |
| MCP endpoint | Unauthorised use | OAuth 2.1 with PKCE (S256 only), audience-bound tokens (RFC 8707/9728), 1-hour access tokens, a GitHub allow-list that is re-checked on every request, and per-user rate limiting. |
| Secrets in UniFi responses | Wi-Fi PSKs, RADIUS/VPN secrets or SSH passwords leak into LLM context | Recursive redaction of `x_*` and secret-like keys on every tool response (`src/unifi/redact.ts`), covered by tests. |
| Consent flow | CSRF, state injection, open redirect | CSRF tokens, KV-backed single-use state bound to a `__Host-` cookie, and redirect URI re-validation against the registered client. |
| DNS rebinding | A browser on the LAN is tricked into calling the endpoint | `Host` header allow-list derived from `MCP_RESOURCE`. Origin validation is done by the MCP handler. |
| Upstream credentials | Leakage of the GitHub token | The token is used once to identify the user, then revoked. It is never stored in token props. |
| Data exfiltration via the LLM | Tool output contains client names, IPs and MACs | This is inherent to the use case. Only connect assistants you trust with this data. |

## Out of scope

- Vulnerabilities in UniFi OS, `cloudflared` or MCP clients themselves.
- Risks from granting the UniFi API key more than View-Only permissions.
