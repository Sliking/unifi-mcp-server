import type { DeviceUplink, SourceCapabilities, UnifiSource } from "./source";
import type {
	UnifiClient as UnifiStation,
	UnifiDevice,
	UnifiFirewallGroup,
	UnifiFirewallPolicy,
	UnifiFirewallRule,
	UnifiHealth,
	UnifiNetworkConf,
	UnifiPortForward,
	UnifiSetting,
	UnifiSite,
	UnifiWlan,
	UnifiZone,
} from "./types";

export interface UnifiConfig {
	/** Base URL of the UniFi OS console, e.g. https://192.168.1.1 or https://unifi.example.com */
	baseUrl: string;
	/** UniFi OS API key (Settings → Control Plane → Integrations). */
	apiKey: string;
	/** Workers VPC service binding. When present, requests are routed through Cloudflare Tunnel privately. */
	vpc?: Fetcher;
	/** Cloudflare Access service token, used when the console is published on a public hostname. */
	accessClientId?: string;
	accessClientSecret?: string;
	timeoutMs?: number;
	maxResponseBytes?: number;
}

export class UnifiError extends Error {
	constructor(
		message: string,
		public readonly status?: number,
	) {
		super(message);
		this.name = "UnifiError";
	}
}

const SITE_NAME = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * Every upstream path this server is permitted to call. The client only ever
 * issues GET requests and refuses anything that is not on this list, so a
 * compromised or confused tool cannot change network configuration.
 */
const ALLOWED_PATHS: RegExp[] = [
	/^\/proxy\/network\/api\/self\/sites$/,
	/^\/proxy\/network\/api\/s\/[A-Za-z0-9_-]+\/(rest\/(networkconf|firewallrule|firewallgroup|portforward|wlanconf)|stat\/(sta|device|health)|get\/setting)$/,
	/^\/proxy\/network\/v2\/api\/site\/[A-Za-z0-9_-]+\/(firewall-policies|firewall\/zone|trafficrules)$/,
];

export function assertAllowedPath(path: string): void {
	if (!ALLOWED_PATHS.some((re) => re.test(path))) {
		throw new UnifiError(`Path not permitted: ${path}`);
	}
}

export function assertSiteName(site: string): void {
	if (!SITE_NAME.test(site)) throw new UnifiError("Invalid site name");
}

/** Read-only UniFi Network API client with per-instance memoisation. */
export class UnifiApi implements UnifiSource {
	readonly mode = "local" as const;
	readonly capabilities: SourceCapabilities = { clientTraffic: true, portForwards: true, gatewaySettings: true, legacyFirewall: true, health: true };
	private readonly cache = new Map<string, Promise<unknown>>();
	private readonly base: URL;

	constructor(private readonly config: UnifiConfig) {
		if (!config.apiKey) throw new UnifiError("UNIFI_API_KEY is not configured");
		let base: URL;
		try {
			base = new URL(config.baseUrl);
		} catch {
			throw new UnifiError("UNIFI_BASE_URL is not a valid URL");
		}
		// The API key must never travel in clear text over the public Internet.
		// Plain HTTP is only tolerated inside a Workers VPC tunnel, which is encrypted end to end.
		if (base.protocol !== "https:" && !config.vpc) {
			throw new UnifiError("UNIFI_BASE_URL must use https:// unless a Workers VPC binding is used");
		}
		this.base = base;
	}

	private async get<T>(path: string): Promise<T> {
		assertAllowedPath(path);
		const cached = this.cache.get(path);
		if (cached) return cached as Promise<T>;
		const promise = this.request<T>(path);
		this.cache.set(path, promise);
		promise.catch(() => this.cache.delete(path));
		return promise;
	}

	private async request<T>(path: string): Promise<T> {
		const url = new URL(path, this.base);
		const headers = new Headers({
			Accept: "application/json",
			"X-API-KEY": this.config.apiKey,
			"User-Agent": "unifi-mcp-server",
		});
		if (this.config.accessClientId && this.config.accessClientSecret) {
			headers.set("CF-Access-Client-Id", this.config.accessClientId);
			headers.set("CF-Access-Client-Secret", this.config.accessClientSecret);
		}
		const init: RequestInit = {
			method: "GET",
			headers,
			redirect: "manual",
			signal: AbortSignal.timeout(this.config.timeoutMs ?? 15_000),
		};

		let res: Response;
		try {
			res = this.config.vpc ? await this.config.vpc.fetch(url.toString(), init) : await fetch(url.toString(), init);
		} catch (err) {
			const reason = err instanceof Error && err.name === "TimeoutError" ? "timed out" : "failed";
			throw new UnifiError(`Request to UniFi console ${reason}`);
		}

		if (res.status >= 300 && res.status < 400) {
			// Typically a Cloudflare Access login redirect: the service token is missing or not allowed.
			throw new UnifiError("UniFi console redirected the request (check Cloudflare Access service token policy)", res.status);
		}
		if (res.status === 401 || res.status === 403) {
			throw new UnifiError("UniFi console rejected the credentials (check UNIFI_API_KEY)", res.status);
		}
		if (res.status === 404) {
			throw new UnifiError("Endpoint not available on this UniFi Network version", 404);
		}
		if (!res.ok) {
			throw new UnifiError(`UniFi console returned HTTP ${res.status}`, res.status);
		}

		const max = this.config.maxResponseBytes ?? 8 * 1024 * 1024;
		const declared = Number(res.headers.get("content-length") ?? "0");
		if (declared > max) throw new UnifiError("UniFi response too large");
		const text = await res.text();
		if (text.length > max) throw new UnifiError("UniFi response too large");

		let body: unknown;
		try {
			body = JSON.parse(text);
		} catch {
			throw new UnifiError("UniFi console returned a non-JSON response");
		}
		return unwrap<T>(body);
	}

	/** Like get() but resolves to `fallback` when the endpoint does not exist on this controller version. */
	private async optional<T>(path: string, fallback: T): Promise<T> {
		try {
			return await this.get<T>(path);
		} catch (err) {
			if (err instanceof UnifiError && (err.status === 404 || err.status === 400)) return fallback;
			throw err;
		}
	}

	private legacy(site: string, resource: string): string {
		assertSiteName(site);
		return `/proxy/network/api/s/${site}/${resource}`;
	}

	private v2(site: string, resource: string): string {
		assertSiteName(site);
		return `/proxy/network/v2/api/site/${site}/${resource}`;
	}

	async sites() {
		return this.get<UnifiSite[]>("/proxy/network/api/self/sites");
	}
	async networks(site: string) {
		return this.get<UnifiNetworkConf[]>(this.legacy(site, "rest/networkconf"));
	}
	async firewallRules(site: string) {
		return this.optional<UnifiFirewallRule[]>(this.legacy(site, "rest/firewallrule"), []);
	}
	async firewallGroups(site: string) {
		return this.optional<UnifiFirewallGroup[]>(this.legacy(site, "rest/firewallgroup"), []);
	}
	async portForwards(site: string) {
		return this.optional<UnifiPortForward[]>(this.legacy(site, "rest/portforward"), []);
	}
	async wlans(site: string) {
		return this.optional<UnifiWlan[]>(this.legacy(site, "rest/wlanconf"), []);
	}
	async clients(site: string) {
		return this.get<UnifiStation[]>(this.legacy(site, "stat/sta"));
	}
	async devices(site: string) {
		return this.get<UnifiDevice[]>(this.legacy(site, "stat/device"));
	}
	async health(site: string) {
		return this.optional<UnifiHealth[]>(this.legacy(site, "stat/health"), []);
	}
	async settings(site: string) {
		return this.optional<UnifiSetting[]>(this.legacy(site, "get/setting"), []);
	}
	async zones(site: string) {
		return this.optional<UnifiZone[]>(this.v2(site, "firewall/zone"), []);
	}
	async firewallPolicies(site: string) {
		return this.optional<UnifiFirewallPolicy[]>(this.v2(site, "firewall-policies"), []);
	}
	async trafficRules(site: string) {
		return this.optional<Record<string, unknown>[]>(this.v2(site, "trafficrules"), []);
	}
	async deviceUplinks(_site: string): Promise<DeviceUplink[]> {
		return [];
	}
}

/** Legacy endpoints wrap results in `{ meta: { rc }, data: [...] }`; v2 endpoints return bare JSON. */
function unwrap<T>(body: unknown): T {
	if (body && typeof body === "object" && !Array.isArray(body) && "data" in body) {
		const meta = (body as { meta?: { rc?: string; msg?: string } }).meta;
		if (meta?.rc && meta.rc !== "ok") {
			throw new UnifiError(`UniFi API error: ${meta.msg ?? meta.rc}`);
		}
		return (body as { data: T }).data;
	}
	return body as T;
}
