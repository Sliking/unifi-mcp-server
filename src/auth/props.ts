/**
 * Identity attached to every MCP access token issued by this server.
 * Encrypted at rest by workers-oauth-provider and exposed to the API handler.
 * The upstream GitHub token is intentionally NOT stored: it is only used once
 * to identify the user during login.
 */
export type Props = {
	login: string;
	id: number;
	name: string | null;
};

export function parseAllowlist(value: string | undefined): Set<string> {
	return new Set(
		(value ?? "")
			.split(",")
			.map((s) => s.trim().toLowerCase())
			.filter(Boolean),
	);
}

/** Deny by default: an empty allowlist authorises nobody. */
export function isAllowed(env: Pick<Env, "ALLOWED_GITHUB_USERS">, login: string | undefined): boolean {
	if (!login) return false;
	return parseAllowlist(env.ALLOWED_GITHUB_USERS).has(login.toLowerCase());
}
