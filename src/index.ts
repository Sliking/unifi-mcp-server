import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp/server";
import { GitHubHandler } from "./auth/github-handler";
import { isAllowed, type Props } from "./auth/props";
import { createServer } from "./mcp/server";

const ACCESS_TOKEN_TTL = 60 * 60; // 1 hour
const REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60; // 30 days

const apiHandler = {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const props = (ctx as ExecutionContext & { props?: Props }).props;

		// Re-check the allowlist on every request so removing a user revokes access immediately.
		if (!props || !isAllowed(env, props.login)) {
			return Response.json({ error: "forbidden", error_description: "User is not authorised" }, { status: 403 });
		}

		if (env.RATE_LIMITER) {
			const { success } = await env.RATE_LIMITER.limit({ key: `user:${props.id}` });
			if (!success) {
				return Response.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": "60" } });
			}
		}

		const handler = createMcpHandler(() => createServer({ env, props }), {
			route: "/mcp",
			// DNS-rebinding protection: only accept requests addressed to our own public hostname.
			allowedHostnames: [new URL(resourceUrl(env, request)).hostname],
		});
		return handler(request, env, ctx);
	},
} satisfies ExportedHandler<Env>;

/** Public MCP endpoint. Uses MCP_RESOURCE when set, otherwise the hostname Cloudflare routed the request to. */
function resourceUrl(env: Env, request: Request): string {
	return env.MCP_RESOURCE || `${new URL(request.url).origin}/mcp`;
}

const providers = new Map<string, OAuthProvider<Env>>();

function providerFor(resource: string): OAuthProvider<Env> {
	let provider = providers.get(resource);
	if (!provider) {
		provider = new OAuthProvider<Env>({
			apiRoute: "/mcp",
			apiHandler,
			defaultHandler: GitHubHandler as unknown as ExportedHandler<Env>,
			authorizeEndpoint: "/authorize",
			tokenEndpoint: "/token",
			clientRegistrationEndpoint: "/register",
			accessTokenTTL: ACCESS_TOKEN_TTL,
			refreshTokenTTL: REFRESH_TOKEN_TTL,
			// RFC 9728: tokens are audience-bound to this resource (RFC 8707).
			resourceMetadata: { resource },
		});
		providers.set(resource, provider);
	}
	return provider;
}

export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext) {
		return providerFor(resourceUrl(env, request)).fetch(request, env, ctx);
	},
} satisfies ExportedHandler<Env>;
