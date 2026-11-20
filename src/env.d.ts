// Optional bindings and secrets that are not declared as required in wrangler.jsonc.
interface Env {
	/** Cloudflare Access service token (only when the console is published on a public hostname). */
	CF_ACCESS_CLIENT_ID?: string;
	CF_ACCESS_CLIENT_SECRET?: string;
	/** Workers VPC service binding to the UniFi console through Cloudflare Tunnel. */
	UNIFI_VPC?: Fetcher;
}
