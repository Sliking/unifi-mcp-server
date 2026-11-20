import { cidrRange, parseCidr, parseIpv4 } from "../analysis/ipv4";
import { UnifiError } from "./client";
import type { DeviceUplink, SourceCapabilities, UnifiSource } from "./source";
import type {
	UnifiClient,
	UnifiDevice,
	UnifiFirewallPolicy,
	UnifiNetworkConf,
	UnifiPolicyEndpoint,
	UnifiSite,
	UnifiWlan,
	UnifiZone,
} from "./types";

/**
 * Reaches the console through Ubiquiti's Site Manager cloud connector
 * (https://api.ui.com/v1/connector/consoles/{hostId}/proxy/network/integration/...),
 * using the official UniFi Network Integration API. No tunnel or inbound port is needed.
 *
 * Responses are mapped field by field into the internal model, so credentials returned by
 * the API (e.g. Wi-Fi passphrases in broadcast details) are never copied in the first place.
 */

export interface CloudConfig {
	/** Site Manager API key from unifi.ui.com → API. */
	apiKey: string;
	/** Console (host) ID. Optional when the account owns exactly one console. */
	consoleId?: string;
	baseUrl?: string;
	timeoutMs?: number;
	maxResponseBytes?: number;
	/** Injected for tests. */
	fetcher?: typeof fetch;
}

const UUID = "[0-9a-fA-F-]{36}";
const CONSOLE_ID = /^[A-Za-z0-9:]{8,200}$/;
const INTEGRATION_PREFIX = "/proxy/network/integration/v1";

/** Integration API paths this client may read (relative to the connector prefix). */
const ALLOWED_INTEGRATION_PATHS: RegExp[] = [
	/^\/v1\/sites$/,
	new RegExp(`^/v1/sites/${UUID}/(networks|firewall/policies|firewall/zones|wifi/broadcasts|clients|devices)$`),
	new RegExp(`^/v1/sites/${UUID}/(networks|wifi/broadcasts)/${UUID}$`),
	new RegExp(`^/v1/sites/${UUID}/devices/${UUID}/statistics/latest$`),
];

export function assertAllowedCloudPath(path: string): void {
	if (!ALLOWED_INTEGRATION_PATHS.some((re) => re.test(path))) throw new UnifiError(`Path not permitted: ${path}`);
}

interface Page<T> {
	data: T[];
	totalCount?: number;
	count?: number;
	offset?: number;
	limit?: number;
}

/* --------------------------------------------------- integration API shapes */

interface IntSite {
	id: string;
	internalReference?: string;
	name?: string;
}
interface IntNetwork {
	id: string;
	name?: string;
	enabled?: boolean;
	default?: boolean;
	management?: string; // GATEWAY | SWITCH | UNMANAGED
	vlanId?: number;
	zoneId?: string;
	isolationEnabled?: boolean;
	internetAccessEnabled?: boolean;
	mdnsForwardingEnabled?: boolean;
	ipv4Configuration?: { hostIpAddress?: string; prefixLength?: number };
}
interface IntZone {
	id: string;
	name?: string;
	networkIds?: string[];
	metadata?: { origin?: string };
}
interface IntIpMatch {
	type?: string;
	value?: string;
	start?: string;
	stop?: string;
}
interface IntPortMatch {
	type?: string;
	value?: number;
	start?: number;
	stop?: number;
}
interface IntPortFilter {
	type?: string;
	matchOpposite?: boolean;
	items?: IntPortMatch[];
}
interface IntTrafficFilter {
	type?: string;
	networkFilter?: { networkIds?: string[]; matchOpposite?: boolean };
	ipAddressFilter?: { type?: string; matchOpposite?: boolean; items?: IntIpMatch[] };
	macAddressFilter?: unknown;
	portFilter?: IntPortFilter;
}
interface IntPolicy {
	id: string;
	name?: string;
	enabled?: boolean;
	index?: number;
	action?: { type?: string };
	loggingEnabled?: boolean;
	connectionStateFilter?: string[];
	ipProtocolScope?: { ipVersion?: string; protocolFilter?: { type?: string } };
	schedule?: { mode?: string };
	metadata?: { origin?: string };
	source?: { zoneId?: string; trafficFilter?: IntTrafficFilter };
	destination?: { zoneId?: string; trafficFilter?: IntTrafficFilter };
}
interface IntWifi {
	id: string;
	name?: string;
	enabled?: boolean;
	network?: { type?: string; networkId?: string };
	securityConfiguration?: { type?: string; pmfMode?: string; encryption?: string };
	clientIsolationEnabled?: boolean;
	hideName?: boolean;
}
interface IntClient {
	id: string;
	name?: string;
	type?: string; // WIRED | WIRELESS | VPN | TELEPORT
	ipAddress?: string;
	macAddress?: string;
	connectedAt?: string;
}
interface IntDevice {
	id: string;
	name?: string;
	model?: string;
	macAddress?: string;
	ipAddress?: string;
	state?: string;
	firmwareVersion?: string;
	firmwareUpdatable?: boolean;
	features?: string[];
}
interface IntDeviceStats {
	uptimeSec?: number;
	uplink?: { rxRateBps?: number; txRateBps?: number };
}
interface Host {
	id: string;
	type?: string;
	reportedState?: { name?: string; hostname?: string } | null;
}

/* ------------------------------------------------------------------ mapping */

const SYSTEM_ZONE_KEYS: Record<string, string> = {
	internal: "internal",
	external: "external",
	gateway: "gateway",
	vpn: "vpn",
	hotspot: "hotspot",
	dmz: "dmz",
};

export function mapZone(z: IntZone): UnifiZone {
	const key = z.metadata?.origin === "SYSTEM_DEFINED" ? SYSTEM_ZONE_KEYS[(z.name ?? "").toLowerCase()] : undefined;
	return { _id: z.id, name: z.name, zone_key: key, network_ids: z.networkIds ?? [] };
}

export function mapNetwork(n: IntNetwork, hotspotZoneIds: Set<string>): UnifiNetworkConf {
	const ip = n.ipv4Configuration;
	const isGateway = (n.management ?? "GATEWAY") === "GATEWAY";
	const purpose = !isGateway ? "vlan-only" : n.zoneId && hotspotZoneIds.has(n.zoneId) ? "guest" : "corporate";
	return {
		_id: n.id,
		name: n.name,
		purpose,
		enabled: n.enabled !== false,
		vlan_enabled: (n.vlanId ?? 1) !== 1,
		vlan: n.vlanId,
		ip_subnet: ip?.hostIpAddress && ip.prefixLength ? `${ip.hostIpAddress}/${ip.prefixLength}` : undefined,
		network_isolation_enabled: n.isolationEnabled === true,
		internet_access_enabled: n.internetAccessEnabled !== false,
		mdns_enabled: n.mdnsForwardingEnabled === true,
		firewall_zone_id: n.zoneId,
	};
}

function ipMatchToString(m: IntIpMatch): string | null {
	if ((m.type === "IP_ADDRESS" || m.type === "SUBNET") && m.value) return m.value;
	if (m.type === "IP_ADDRESS_RANGE" && m.start && m.stop) return `${m.start}-${m.stop}`;
	return null;
}

function portsToString(f: IntPortFilter | undefined): string | undefined {
	if (!f) return undefined;
	if (f.type !== "PORTS") return "(traffic matching list)";
	return (f.items ?? [])
		.map((p) => (p.type === "PORT_NUMBER_RANGE" ? `${p.start}-${p.stop}` : String(p.value)))
		.join(",");
}

function mapEndpoint(side: { zoneId?: string; trafficFilter?: IntTrafficFilter } | undefined): UnifiPolicyEndpoint {
	const f = side?.trafficFilter;
	const ep: UnifiPolicyEndpoint = { zone_id: side?.zoneId, matching_target: "ANY" };
	if (f?.portFilter) {
		ep.port_matching_type = f.portFilter.matchOpposite ? "SPECIFIC_INVERTED" : "SPECIFIC";
		ep.port = portsToString(f.portFilter);
	}
	switch (f?.type) {
		case undefined:
		case "PORT":
			break;
		case "NETWORK":
			ep.matching_target = "NETWORK";
			ep.network_ids = f.networkFilter?.networkIds ?? [];
			ep.match_opposite_networks = f.networkFilter?.matchOpposite === true;
			break;
		case "IP_ADDRESS": {
			const ips = (f.ipAddressFilter?.items ?? []).map(ipMatchToString).filter((x): x is string => Boolean(x));
			if (f.ipAddressFilter?.type === "IP_ADDRESSES" && ips.length) {
				ep.matching_target = "IP";
				ep.ips = ips;
				ep.match_opposite_ips = f.ipAddressFilter.matchOpposite === true;
			} else {
				ep.matching_target = "IP_LIST";
			}
			break;
		}
		default:
			ep.matching_target = f?.type ?? "ANY"; // MAC_ADDRESS, REGION, DOMAIN, APPLICATION, VPN_SERVER, ...
	}
	return ep;
}

export function mapPolicy(p: IntPolicy): UnifiFirewallPolicy {
	const ipVersion = p.ipProtocolScope?.ipVersion ?? "IPV4_AND_IPV6";
	return {
		_id: p.id,
		name: p.name,
		enabled: p.enabled !== false,
		action: p.action?.type ?? "UNKNOWN",
		index: p.index,
		predefined: (p.metadata?.origin ?? "USER_DEFINED") !== "USER_DEFINED",
		protocol: p.ipProtocolScope?.protocolFilter ? "specific" : "all",
		ip_version: ipVersion === "IPV4_AND_IPV6" ? "BOTH" : ipVersion,
		connection_state_type: p.connectionStateFilter?.length ? "CUSTOM" : "ALL",
		connection_states: p.connectionStateFilter,
		logging: p.loggingEnabled === true,
		schedule: p.schedule?.mode ? { mode: p.schedule.mode } : undefined,
		source: mapEndpoint(p.source),
		destination: mapEndpoint(p.destination),
	};
}

export function mapWifi(w: IntWifi, defaultNetworkId: string | undefined, guestNetworkIds: Set<string>): UnifiWlan {
	const type = w.securityConfiguration?.type ?? "";
	const networkId = w.network?.type === "SPECIFIC" ? w.network.networkId : defaultNetworkId;
	let security = "wpapsk";
	if (type === "OPEN") security = w.securityConfiguration?.encryption ? "owe" : "open";
	else if (type.endsWith("ENTERPRISE")) security = "wpaeap";
	return {
		_id: w.id,
		name: w.name,
		enabled: w.enabled !== false,
		security,
		wpa_mode: type.startsWith("WPA2") ? "wpa2" : undefined,
		wpa3_support: type.includes("WPA3"),
		wpa3_transition: type.startsWith("WPA2_WPA3"),
		pmf_mode: w.securityConfiguration?.pmfMode?.toLowerCase(),
		is_guest: networkId ? guestNetworkIds.has(networkId) : false,
		hide_ssid: w.hideName === true,
		networkconf_id: networkId,
		l2_isolation: w.clientIsolationEnabled,
	};
}

export function mapClient(c: IntClient, networkForIp: (ip?: string) => { id: string; name?: string } | undefined, now = Date.now()): UnifiClient {
	const net = networkForIp(c.ipAddress);
	const connected = c.connectedAt ? Date.parse(c.connectedAt) : NaN;
	return {
		mac: c.macAddress,
		name: c.name,
		hostname: c.name,
		ip: c.ipAddress,
		network: net?.name,
		network_id: net?.id,
		is_wired: c.type === "WIRED",
		uptime: Number.isFinite(connected) ? Math.max(0, Math.floor((now - connected) / 1000)) : undefined,
	};
}

export function mapDevice(d: IntDevice): UnifiDevice {
	const features = d.features ?? [];
	return {
		_id: d.id,
		mac: d.macAddress,
		name: d.name,
		model: d.model,
		type: features.includes("gateway") ? "gateway" : features.includes("accessPoint") ? "uap" : features.includes("switching") ? "usw" : undefined,
		version: d.firmwareVersion,
		upgradable: d.firmwareUpdatable === true,
		state: d.state === "ONLINE" ? 1 : d.state === "OFFLINE" ? 0 : 2,
		ip: d.ipAddress,
	};
}

/* ------------------------------------------------------------------- client */

export class UnifiCloudApi implements UnifiSource {
	readonly mode = "cloud" as const;
	readonly capabilities: SourceCapabilities = { clientTraffic: false, portForwards: false, gatewaySettings: false, legacyFirewall: false, health: false };

	private readonly cache = new Map<string, Promise<unknown>>();
	private readonly base: string;
	private readonly fetcher: typeof fetch;
	private consoleIdPromise?: Promise<string>;

	constructor(private readonly config: CloudConfig) {
		if (!config.apiKey) throw new UnifiError("UNIFI_API_KEY is not configured");
		if (config.consoleId && !CONSOLE_ID.test(config.consoleId)) throw new UnifiError("UNIFI_CONSOLE_ID is not a valid console ID");
		this.base = (config.baseUrl ?? "https://api.ui.com").replace(/\/$/, "");
		if (!this.base.startsWith("https://")) throw new UnifiError("Site Manager base URL must use https://");
		this.fetcher = config.fetcher ?? fetch.bind(globalThis);
	}

	private async raw<T>(url: string): Promise<T> {
		let res: Response;
		try {
			res = await this.fetcher(url, {
				method: "GET",
				headers: { Accept: "application/json", "X-API-Key": this.config.apiKey, "User-Agent": "unifi-mcp-server" },
				redirect: "manual",
				signal: AbortSignal.timeout(this.config.timeoutMs ?? 28_000),
			});
		} catch (err) {
			const reason = err instanceof Error && err.name === "TimeoutError" ? "timed out" : "failed";
			throw new UnifiError(`Request to UniFi Site Manager ${reason}`);
		}
		if (res.status === 401 || res.status === 403) {
			throw new UnifiError("UniFi Site Manager rejected the request (check the API key and that it owns this console)", res.status);
		}
		if (res.status === 404) throw new UnifiError("Endpoint not available (console offline, or Network version too old for this API)", 404);
		if (res.status === 429) throw new UnifiError("UniFi Site Manager rate limit reached (100 requests/minute per console); try again shortly", 429);
		if (!res.ok) throw new UnifiError(`UniFi Site Manager returned HTTP ${res.status}`, res.status);

		const max = this.config.maxResponseBytes ?? 10 * 1024 * 1024;
		const text = await res.text();
		if (text.length > max) throw new UnifiError("UniFi response too large");
		try {
			return JSON.parse(text) as T;
		} catch {
			throw new UnifiError("UniFi Site Manager returned a non-JSON response");
		}
	}

	private consoleId(): Promise<string> {
		if (this.config.consoleId) return Promise.resolve(this.config.consoleId);
		this.consoleIdPromise ??= this.raw<{ data?: Host[] }>(`${this.base}/v1/hosts`).then((body) => {
			const hosts = body.data ?? [];
			if (hosts.length === 1) return hosts[0].id;
			const names = hosts.map((h) => `${h.reportedState?.name ?? h.reportedState?.hostname ?? h.type} (${h.id})`).join("; ");
			throw new UnifiError(
				hosts.length ? `Several consoles found; set UNIFI_CONSOLE_ID to one of: ${names}` : "No consoles found for this API key",
			);
		});
		return this.consoleIdPromise;
	}

	private get<T>(path: string): Promise<T> {
		assertAllowedCloudPath(path.split("?")[0]);
		const cached = this.cache.get(path);
		if (cached) return cached as Promise<T>;
		const promise = this.consoleId().then((id) =>
			this.raw<T>(`${this.base}/v1/connector/consoles/${id}${INTEGRATION_PREFIX}${path.slice(3)}`),
		);
		this.cache.set(path, promise);
		promise.catch(() => this.cache.delete(path));
		return promise;
	}

	/** Reads every page of a paginated list (bounded, to respect the connector rate limit). */
	private async list<T>(path: string, maxPages = 10): Promise<T[]> {
		const limit = 200;
		const out: T[] = [];
		for (let page = 0; page < maxPages; page++) {
			const body = await this.get<Page<T>>(`${path}?offset=${page * limit}&limit=${limit}`);
			out.push(...(body.data ?? []));
			const total = body.totalCount ?? out.length;
			if (out.length >= total || !(body.data ?? []).length) break;
		}
		return out;
	}

	private async siteId(site: string): Promise<string> {
		if (new RegExp(`^${UUID}$`).test(site)) return site;
		const sites = await this.list<IntSite>("/v1/sites");
		const match = sites.find((s) => s.internalReference === site || s.name?.toLowerCase() === site.toLowerCase());
		if (!match) throw new UnifiError(`Unknown site "${site}"`);
		return match.id;
	}

	private async rawZones(site: string): Promise<IntZone[]> {
		const id = await this.siteId(site);
		return this.list<IntZone>(`/v1/sites/${id}/firewall/zones`);
	}

	private async rawNetworks(site: string): Promise<IntNetwork[]> {
		const id = await this.siteId(site);
		const overview = await this.list<IntNetwork>(`/v1/sites/${id}/networks`);
		// Subnet, isolation and zone are only in the detail view.
		return Promise.all(
			overview.slice(0, 64).map((n) => this.get<IntNetwork>(`/v1/sites/${id}/networks/${n.id}`).catch(() => n)),
		);
	}

	async sites(): Promise<UnifiSite[]> {
		const sites = await this.list<IntSite>("/v1/sites");
		return sites.map((s) => ({ _id: s.id, name: s.internalReference ?? s.id, desc: s.name }));
	}

	async zones(site: string): Promise<UnifiZone[]> {
		return (await this.rawZones(site)).map(mapZone);
	}

	async networks(site: string): Promise<UnifiNetworkConf[]> {
		const [nets, zones] = await Promise.all([this.rawNetworks(site), this.zones(site)]);
		const hotspot = new Set(zones.filter((z) => z.zone_key === "hotspot").map((z) => z._id));
		return nets.map((n) => mapNetwork(n, hotspot));
	}

	async firewallPolicies(site: string): Promise<UnifiFirewallPolicy[]> {
		const id = await this.siteId(site);
		return (await this.list<IntPolicy>(`/v1/sites/${id}/firewall/policies`)).map(mapPolicy);
	}

	async wlans(site: string): Promise<UnifiWlan[]> {
		const id = await this.siteId(site);
		const [overview, rawNets, networks] = await Promise.all([this.list<IntWifi>(`/v1/sites/${id}/wifi/broadcasts`), this.rawNetworks(site), this.networks(site)]);
		const details = await Promise.all(
			overview.slice(0, 32).map((w) => this.get<IntWifi>(`/v1/sites/${id}/wifi/broadcasts/${w.id}`).catch(() => w)),
		);
		const defaultNet = rawNets.find((n) => n.default)?.id;
		const guest = new Set(networks.filter((n) => n.purpose === "guest").map((n) => n._id));
		return details.map((w) => mapWifi(w, defaultNet, guest));
	}

	async clients(site: string): Promise<UnifiClient[]> {
		const id = await this.siteId(site);
		const [raw, networks] = await Promise.all([this.list<IntClient>(`/v1/sites/${id}/clients`), this.networks(site)]);
		const ranges = networks
			.map((n) => ({ id: n._id, name: n.name, cidr: parseCidr(n.ip_subnet) }))
			.filter((n) => n.cidr)
			.map((n) => ({ ...n, range: cidrRange(n.cidr!) }));
		const lookup = (ip?: string) => {
			const v = ip ? parseIpv4(ip) : null;
			if (v === null) return undefined;
			return ranges.find((r) => v >= r.range[0] && v <= r.range[1]);
		};
		return raw.map((c) => mapClient(c, lookup));
	}

	async devices(site: string): Promise<UnifiDevice[]> {
		const id = await this.siteId(site);
		return (await this.list<IntDevice>(`/v1/sites/${id}/devices`)).map(mapDevice);
	}

	async deviceUplinks(site: string): Promise<DeviceUplink[]> {
		const id = await this.siteId(site);
		const devices = (await this.list<IntDevice>(`/v1/sites/${id}/devices`)).filter((d) => d.state === "ONLINE").slice(0, 30);
		const stats = await Promise.all(
			devices.map((d) => this.get<IntDeviceStats>(`/v1/sites/${id}/devices/${d.id}/statistics/latest`).catch(() => null)),
		);
		return devices.map((d, i) => ({
			name: d.name ?? d.macAddress ?? d.id,
			mac: d.macAddress,
			model: d.model,
			rxRateBps: stats[i]?.uplink?.rxRateBps ?? 0,
			txRateBps: stats[i]?.uplink?.txRateBps ?? 0,
		}));
	}

	// Not exposed by the public Integration API.
	async firewallRules() {
		return [];
	}
	async firewallGroups() {
		return [];
	}
	async portForwards() {
		return [];
	}
	async health() {
		return [];
	}
	async settings() {
		return [];
	}
	async trafficRules() {
		return [];
	}
}
