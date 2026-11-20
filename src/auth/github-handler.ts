import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { isAllowed, type Props } from "./props";
import {
	addApprovedClient,
	bindStateToSession,
	createOAuthState,
	generateCSRFProtection,
	isClientApproved,
	OAuthError,
	renderApprovalDialog,
	validateCSRFToken,
	validateOAuthState,
} from "./workers-oauth-utils";

type Bindings = Env & { OAUTH_PROVIDER: OAuthHelpers };

const app = new Hono<{ Bindings: Bindings }>();

const SECURITY_HEADERS: Record<string, string> = {
	"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy": "no-referrer",
	"X-Frame-Options": "DENY",
};

app.use("*", async (c, next) => {
	await next();
	for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
		if (!c.res.headers.has(k)) c.res.headers.set(k, v);
	}
});

app.get("/", (c) =>
	c.text("UniFi MCP server. Connect your MCP client to /mcp. Source: https://github.com/Sliking/unifi-mcp-server\n"),
);

app.get("/health", (c) => c.json({ status: "ok" }));

app.get("/authorize", async (c) => {
	const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
	const { clientId } = oauthReqInfo;
	if (!clientId) return c.text("Invalid request", 400);

	if (await isClientApproved(c.req.raw, clientId, c.env.COOKIE_ENCRYPTION_KEY)) {
		const { stateToken } = await createOAuthState(oauthReqInfo, c.env.OAUTH_KV);
		const { setCookie } = await bindStateToSession(stateToken);
		return redirectToGithub(c.req.raw, c.env, stateToken, { "Set-Cookie": setCookie });
	}

	const { token: csrfToken, setCookie } = generateCSRFProtection();
	return renderApprovalDialog(c.req.raw, {
		client: await c.env.OAUTH_PROVIDER.lookupClient(clientId),
		csrfToken,
		server: {
			name: "UniFi MCP Server",
			description:
				"Grants read-only access to your UniFi network configuration and statistics. You will sign in with GitHub; only allow-listed accounts are authorised.",
		},
		setCookie,
		state: { oauthReqInfo },
	});
});

app.post("/authorize", async (c) => {
	try {
		const formData = await c.req.raw.formData();
		validateCSRFToken(formData, c.req.raw);

		const encodedState = formData.get("state");
		if (!encodedState || typeof encodedState !== "string") return c.text("Missing state", 400);

		let state: { oauthReqInfo?: AuthRequest };
		try {
			state = JSON.parse(atob(encodedState));
		} catch {
			return c.text("Invalid state", 400);
		}
		if (!state.oauthReqInfo?.clientId) return c.text("Invalid request", 400);

		// Never trust the client-supplied copy of the auth request: re-validate the client and redirect URI.
		const client = await c.env.OAUTH_PROVIDER.lookupClient(state.oauthReqInfo.clientId);
		if (!client || !client.redirectUris.includes(state.oauthReqInfo.redirectUri)) {
			return c.text("Invalid client or redirect URI", 400);
		}

		const approvedCookie = await addApprovedClient(c.req.raw, state.oauthReqInfo.clientId, c.env.COOKIE_ENCRYPTION_KEY);
		const { stateToken } = await createOAuthState(state.oauthReqInfo, c.env.OAUTH_KV);
		const { setCookie: sessionCookie } = await bindStateToSession(stateToken);

		const headers = new Headers();
		headers.append("Set-Cookie", approvedCookie);
		headers.append("Set-Cookie", sessionCookie);
		return redirectToGithub(c.req.raw, c.env, stateToken, headers);
	} catch (error) {
		if (error instanceof OAuthError) return error.toResponse();
		console.error("POST /authorize error", error);
		return c.text("Internal server error", 500);
	}
});

function redirectToGithub(request: Request, env: Env, stateToken: string, headers: HeadersInit = {}) {
	const url = new URL("https://github.com/login/oauth/authorize");
	url.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
	url.searchParams.set("redirect_uri", new URL("/callback", request.url).href);
	url.searchParams.set("scope", "read:user");
	url.searchParams.set("state", stateToken);
	url.searchParams.set("allow_signup", "false");
	const h = new Headers(headers);
	h.set("Location", url.href);
	return new Response(null, { status: 302, headers: h });
}

app.get("/callback", async (c) => {
	let oauthReqInfo: AuthRequest;
	let clearCookie: string;
	try {
		const result = await validateOAuthState(c.req.raw, c.env.OAUTH_KV);
		oauthReqInfo = result.oauthReqInfo;
		clearCookie = result.clearCookie;
	} catch (error) {
		if (error instanceof OAuthError) return error.toResponse();
		return c.text("Internal server error", 500);
	}
	if (!oauthReqInfo.clientId) return c.text("Invalid OAuth request", 400);

	const code = c.req.query("code");
	if (!code) return c.text("Missing code", 400);

	const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
		body: new URLSearchParams({
			client_id: c.env.GITHUB_CLIENT_ID,
			client_secret: c.env.GITHUB_CLIENT_SECRET,
			code,
			redirect_uri: new URL("/callback", c.req.url).href,
		}),
	});
	const tokenBody = (await tokenRes.json().catch(() => ({}))) as { access_token?: string };
	if (!tokenRes.ok || !tokenBody.access_token) return c.text("GitHub sign-in failed", 502);

	const userRes = await fetch("https://api.github.com/user", {
		headers: { Authorization: `Bearer ${tokenBody.access_token}`, Accept: "application/vnd.github+json", "User-Agent": "unifi-mcp-server" },
	});
	if (!userRes.ok) return c.text("Could not read GitHub profile", 502);
	const user = (await userRes.json()) as { login: string; id: number; name: string | null };

	// Best effort: revoke the GitHub token immediately, it is not needed after identification.
	c.executionCtx.waitUntil(
		fetch(`https://api.github.com/applications/${c.env.GITHUB_CLIENT_ID}/token`, {
			method: "DELETE",
			headers: {
				Authorization: `Basic ${btoa(`${c.env.GITHUB_CLIENT_ID}:${c.env.GITHUB_CLIENT_SECRET}`)}`,
				Accept: "application/vnd.github+json",
				"User-Agent": "unifi-mcp-server",
			},
			body: JSON.stringify({ access_token: tokenBody.access_token }),
		}).catch(() => undefined),
	);

	if (!isAllowed(c.env, user.login)) {
		console.log(JSON.stringify({ event: "login_denied", login: user.login }));
		return c.text(`GitHub user "${user.login}" is not authorised to use this server.`, 403);
	}

	const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
		request: oauthReqInfo,
		userId: String(user.id),
		metadata: { label: user.login },
		scope: oauthReqInfo.scope,
		props: { login: user.login, id: user.id, name: user.name } satisfies Props,
	});
	console.log(JSON.stringify({ event: "login_ok", login: user.login, client: oauthReqInfo.clientId }));

	const headers = new Headers({ Location: redirectTo });
	if (clearCookie) headers.set("Set-Cookie", clearCookie);
	return new Response(null, { status: 302, headers });
});

export { app as GitHubHandler };
