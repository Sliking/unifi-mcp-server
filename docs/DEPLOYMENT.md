# Deployment guide

This guide deploys the server to your own Cloudflare account and connects it privately to your UniFi console.

## 1. UniFi: create a read-only API key

The server never writes, but it is good practice to give it a credential that *cannot* write either.

1. In UniFi OS, go to **Admins & Users → Create New**.
2. Create a **local-only** admin (for example `mcp-readonly`), with **Restrict to local access only** enabled and the **Network** application role set to **View Only**. Give it no access to Protect, Access, or other apps.
3. Sign in to the console as `mcp-readonly`.
4. Go to **Settings → Control Plane → Integrations → Create API Key**. Name it `unifi-mcp-server` and copy the key. It is only shown once.

Check the key from a machine on your LAN:

```bash
curl -sk -H "X-API-KEY: <key>" https://192.168.1.1/proxy/network/api/self/sites
```

## 2. Cloudflare Tunnel (outbound-only connectivity)

1. In the Cloudflare dashboard, go to **Networking → Tunnels → Create a tunnel** (type *Cloudflared*). Name it `home`.
2. Install and run the connector on an always-on machine in your LAN that can reach the console. For example, with Docker:

   ```bash
   docker run -d --restart unless-stopped --name cloudflared \
     cloudflare/cloudflared:latest tunnel --no-autoupdate run --token <TUNNEL_TOKEN>
   ```

3. **Do not** add a public hostname. Workers VPC does not need one, so the console is never exposed to the Internet.
4. Note the **Tunnel ID**.

## 3. Cloudflare: Worker resources

```bash
git clone https://github.com/Sliking/unifi-mcp-server.git && cd unifi-mcp-server
npm install
npx wrangler login

# Private, host-pinned route to the console through the tunnel
npx wrangler vpc service create unifi-console \
  --type http --https-port 443 --ipv4 192.168.1.1 \
  --tunnel-id <TUNNEL_ID> --cert-verification-mode disabled

# Storage for OAuth clients, grants and tokens (encrypted by the OAuth library)
npx wrangler kv namespace create OAUTH_KV
```

> **TLS note:** UniFi consoles use a self-signed certificate. Traffic between the Worker and `cloudflared` is always encrypted by the tunnel. `disabled` only skips certificate verification on the last LAN hop. For stricter verification, export the console certificate, upload it with `npx wrangler cert upload certificate-authority --ca-cert unifi.pem --name unifi`, then use `--certificate-authority <ID> --cert-verification-mode verify_ca`.

Edit `wrangler.jsonc`:

```jsonc
"vars": {
  "MCP_RESOURCE": "https://unifi-mcp-server.<your-subdomain>.workers.dev/mcp",
  "ALLOWED_GITHUB_USERS": "your-github-login",
  "UNIFI_BASE_URL": "https://192.168.1.1",
  "UNIFI_SITE": "default"
},
"kv_namespaces": [{ "binding": "OAUTH_KV", "id": "<KV_ID>" }],
"vpc_services": [{ "binding": "UNIFI_VPC", "service_id": "<VPC_SERVICE_ID>", "remote": true }]
```

`MCP_RESOURCE` must be the exact public URL clients use. Access tokens are bound to it.

> **Tip:** to keep your personal IDs out of git, copy `wrangler.jsonc` to `wrangler.local.jsonc` (git-ignored), fill it in there, and use `npm run deploy:local` (add `-c wrangler.local.jsonc` to `wrangler secret put`).

## 4. GitHub OAuth app (sign-in)

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**.
2. Set **Homepage URL** to `https://unifi-mcp-server.<your-subdomain>.workers.dev`.
3. Set **Authorization callback URL** to `https://unifi-mcp-server.<your-subdomain>.workers.dev/callback`.
4. Generate a client secret.

For local development, create a second OAuth app with `http://localhost:8788` and `http://localhost:8788/callback`.

## 5. Secrets and deploy

```bash
npx wrangler secret put UNIFI_API_KEY
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
openssl rand -hex 32 | npx wrangler secret put COOKIE_ENCRYPTION_KEY
npm run deploy
```

Verify:

```bash
curl -i https://unifi-mcp-server.<sub>.workers.dev/mcp                       # 401 + WWW-Authenticate
curl https://unifi-mcp-server.<sub>.workers.dev/.well-known/oauth-protected-resource/mcp
npx @modelcontextprotocol/inspector                                          # connect + sign in
```

## Alternative: public hostname + Cloudflare Access

If you cannot use Workers VPC, publish the console on a tunnel public hostname (for example `unifi-api.example.com` → `https://192.168.1.1`, with *No TLS Verify*). Then protect it with a **Cloudflare Access** application that has a single **Service Auth** policy for a dedicated service token:

```bash
npx wrangler secret put CF_ACCESS_CLIENT_ID
npx wrangler secret put CF_ACCESS_CLIENT_SECRET
```

Set `UNIFI_BASE_URL` to `https://unifi-api.example.com` and remove the `vpc_services` block. Requests without a valid service token are rejected at Cloudflare's edge before they reach your network.

## Optional hardening

- **Custom domain:** serve the Worker on your own domain, and update `MCP_RESOURCE` and the GitHub callback URL to match.
- **Rate limit:** adjust `ratelimits[0].simple` in `wrangler.jsonc`. The default is 60 MCP requests per user per minute.
- **Logs:** every tool call is logged as `{"event":"tool_call","tool":…,"user":…}` in Workers Observability. Logins are logged as `login_ok` or `login_denied`.
- **Revoke everything:** to invalidate all issued tokens, rotate `COOKIE_ENCRYPTION_KEY` and delete the keys in the `OAUTH_KV` namespace.
