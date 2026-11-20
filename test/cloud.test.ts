import { createMcpHandler } from "agents/mcp/server";
import { describe, expect, it } from "vitest";
import { zoneConnectivity } from "../src/analysis/connectivity";
import { normaliseNetworks } from "../src/analysis/networks";
import { createServer } from "../src/mcp/server";
import { assertAllowedCloudPath, UnifiCloudApi } from "../src/unifi/cloud";

const SITE = "11111111-1111-1111-1111-111111111111";
const Z = { int: "a0000000-0000-0000-0000-000000000001", iot: "a0000000-0000-0000-0000-000000000002", hot: "a0000000-0000-0000-0000-000000000003", ext: "a0000000-0000-0000-0000-000000000004" };
const N = { lan: "b0000000-0000-0000-0000-000000000001", iot: "b0000000-0000-0000-0000-000000000002", guest: "b0000000-0000-0000-0000-000000000003" };
const prefix = `/v1/connector/consoles/HOST1:123/proxy/network/integration/v1/sites`;

const networks = {
	[N.lan]: { id: N.lan, name: "Default", default: true, enabled: true, management: "GATEWAY", vlanId: 1, zoneId: Z.int, isolationEnabled: false, internetAccessEnabled: true, mdnsForwardingEnabled: false, ipv4Configuration: { hostIpAddress: "192.168.1.1", prefixLength: 24 } },
	[N.iot]: { id: N.iot, name: "IoT", enabled: true, management: "GATEWAY", vlanId: 20, zoneId: Z.iot, isolationEnabled: false, internetAccessEnabled: true, mdnsForwardingEnabled: true, ipv4Configuration: { hostIpAddress: "192.168.20.1", prefixLength: 24 } },
	[N.guest]: { id: N.guest, name: "Guest", enabled: true, management: "GATEWAY", vlanId: 40, zoneId: Z.hot, isolationEnabled: false, internetAccessEnabled: true, mdnsForwardingEnabled: false, ipv4Configuration: { hostIpAddress: "192.168.40.1", prefixLength: 24 } },
};

const routes: Record<string, unknown> = {
	"/v1/hosts": { data: [{ id: "HOST1:123", type: "udr", reportedState: { name: "UDR7" }, userData: { email: "me@example.com" } }] },
	[`${prefix}`]: { offset: 0, limit: 200, count: 1, totalCount: 1, data: [{ id: SITE, internalReference: "default", name: "Default" }] },
	[`${prefix}/${SITE}/networks`]: { totalCount: 3, data: Object.values(networks).map(({ id, name }) => ({ id, name })) },
	...Object.fromEntries(Object.entries(networks).map(([id, n]) => [`${prefix}/${SITE}/networks/${id}`, n])),
	[`${prefix}/${SITE}/firewall/zones`]: {
		totalCount: 4,
		data: [
			{ id: Z.int, name: "Internal", networkIds: [N.lan], metadata: { origin: "SYSTEM_DEFINED" } },
			{ id: Z.iot, name: "IoT", networkIds: [N.iot], metadata: { origin: "USER_DEFINED" } },
			{ id: Z.hot, name: "Hotspot", networkIds: [N.guest], metadata: { origin: "SYSTEM_DEFINED" } },
			{ id: Z.ext, name: "External", networkIds: [], metadata: { origin: "SYSTEM_DEFINED" } },
		],
	},
	[`${prefix}/${SITE}/firewall/policies`]: {
		totalCount: 4,
		data: [
			{ id: "p0", name: "LAN to IoT", enabled: true, index: 9999, action: { type: "ALLOW" }, loggingEnabled: false, ipProtocolScope: { ipVersion: "IPV4" }, metadata: { origin: "USER_DEFINED" }, source: { zoneId: Z.int }, destination: { zoneId: Z.iot } },
			{ id: "p1", name: "IoT to HA", enabled: true, index: 10000, action: { type: "ALLOW" }, loggingEnabled: false, ipProtocolScope: { ipVersion: "IPV4", protocolFilter: { type: "PRESET" } }, metadata: { origin: "USER_DEFINED" }, source: { zoneId: Z.iot }, destination: { zoneId: Z.int, trafficFilter: { type: "IP_ADDRESS", ipAddressFilter: { type: "IP_ADDRESSES", matchOpposite: false, items: [{ type: "IP_ADDRESS", value: "192.168.1.10" }] }, portFilter: { type: "PORTS", matchOpposite: false, items: [{ type: "PORT_NUMBER", value: 8123 }] } } } },
			{ id: "p2", name: "Expose NAS", enabled: true, index: 10001, action: { type: "ALLOW", allowReturnTraffic: true }, loggingEnabled: false, ipProtocolScope: { ipVersion: "IPV4" }, metadata: { origin: "USER_DEFINED" }, source: { zoneId: Z.ext }, destination: { zoneId: Z.int, trafficFilter: { type: "NETWORK", networkFilter: { networkIds: [N.lan], matchOpposite: false } } } },
			{ id: "p3", name: "Block IoT to Internal", enabled: true, index: 30000, action: { type: "BLOCK" }, loggingEnabled: false, ipProtocolScope: { ipVersion: "IPV4_AND_IPV6" }, metadata: { origin: "SYSTEM_DEFINED" }, source: { zoneId: Z.iot }, destination: { zoneId: Z.int } },
		],
	},
	[`${prefix}/${SITE}/wifi/broadcasts`]: { totalCount: 1, data: [{ id: "c0000000-0000-0000-0000-000000000001", name: "Home" }] },
	[`${prefix}/${SITE}/wifi/broadcasts/c0000000-0000-0000-0000-000000000001`]: { id: "c0000000-0000-0000-0000-000000000001", name: "Home", enabled: true, network: { type: "NATIVE" }, securityConfiguration: { type: "WPA2_PERSONAL", passphrase: "supersecret", pmfMode: "OPTIONAL" }, clientIsolationEnabled: false, hideName: false },
	[`${prefix}/${SITE}/clients`]: { totalCount: 2, data: [
		{ id: "x1", name: "esp-1234", type: "WIRELESS", ipAddress: "192.168.1.77", macAddress: "aa:bb", connectedAt: "2026-11-20T10:00:00Z" },
		{ id: "x2", name: "desktop", type: "WIRED", ipAddress: "192.168.1.5", macAddress: "cc:dd" },
	] },
	[`${prefix}/${SITE}/devices`]: { totalCount: 1, data: [{ id: "d0000000-0000-0000-0000-000000000001", name: "UDR7", model: "UDR7", macAddress: "ee:ff", ipAddress: "192.168.1.1", state: "ONLINE", firmwareVersion: "5.0.3", firmwareUpdatable: true, features: ["gateway", "accessPoint"] }] },
	[`${prefix}/${SITE}/devices/d0000000-0000-0000-0000-000000000001/statistics/latest`]: { uptimeSec: 100, uplink: { rxRateBps: 80_000_000, txRateBps: 8_000_000 } },
};

function makeFetch() {
	const calls: Request[] = [];
	const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const req = new Request(input, init);
		calls.push(req);
		const path = new URL(req.url).pathname;
		return path in routes ? Response.json(routes[path]) : new Response("{}", { status: 404 });
	}) as typeof fetch;
	return { fetcher, calls };
}

describe("UnifiCloudApi", () => {
	it("discovers the console, resolves the site and sends read-only authenticated requests", async () => {
		const { fetcher, calls } = makeFetch();
		const api = new UnifiCloudApi({ apiKey: "smkey", fetcher });
		const nets = await api.networks("default");
		expect(nets.map((n) => [n.name, n.purpose, n.ip_subnet, n.firewall_zone_id])).toEqual([
			["Default", "corporate", "192.168.1.1/24", Z.int],
			["IoT", "corporate", "192.168.20.1/24", Z.iot],
			["Guest", "guest", "192.168.40.1/24", Z.hot],
		]);
		for (const c of calls) {
			expect(c.method).toBe("GET");
			expect(new URL(c.url).host).toBe("api.ui.com");
			expect(c.headers.get("X-API-Key")).toBe("smkey");
		}
	});

	it("requires UNIFI_CONSOLE_ID when the key owns several consoles", async () => {
		const fetcher = (async () => Response.json({ data: [{ id: "A:1", reportedState: { name: "UK" } }, { id: "B:2", reportedState: { name: "Lisbon" } }] })) as typeof fetch;
		const api = new UnifiCloudApi({ apiKey: "k", fetcher });
		await expect(api.sites()).rejects.toThrow(/UNIFI_CONSOLE_ID.*UK \(A:1\).*Lisbon \(B:2\)/);
	});

	it("maps Wi-Fi without ever copying the passphrase", async () => {
		const { fetcher } = makeFetch();
		const wlans = await new UnifiCloudApi({ apiKey: "k", consoleId: "HOST1:123", fetcher }).wlans("default");
		expect(wlans[0]).toMatchObject({ name: "Home", security: "wpapsk", wpa_mode: "wpa2", wpa3_support: false, pmf_mode: "optional", networkconf_id: N.lan });
		expect(JSON.stringify(wlans)).not.toContain("supersecret");
	});

	it("assigns clients to networks by IP", async () => {
		const { fetcher } = makeFetch();
		const clients = await new UnifiCloudApi({ apiKey: "k", consoleId: "HOST1:123", fetcher }).clients("default");
		expect(clients.map((c) => [c.name, c.network, c.is_wired])).toEqual([["esp-1234", "Default", false], ["desktop", "Default", true]]);
	});

	it("feeds the zone connectivity engine", async () => {
		const { fetcher } = makeFetch();
		const api = new UnifiCloudApi({ apiKey: "k", consoleId: "HOST1:123", fetcher });
		const [raw, zones, policies] = await Promise.all([api.networks("default"), api.zones("default"), api.firewallPolicies("default")]);
		const report = zoneConnectivity(normaliseNetworks(raw, zones), zones, policies);
		const v = (a: string, b: string) => report.pairs.find((p) => p.from === a && p.to === b)?.verdict;
		expect(v("IoT", "Default")).toBe("blocked_with_exceptions");
		expect(v("Guest", "Default")).toBe("blocked");
		expect(v("Default", "IoT")).toBe("allowed");
	});

	it("only allows integration read paths", () => {
		expect(() => assertAllowedCloudPath(`/v1/sites/${SITE}/clients`)).not.toThrow();
		expect(() => assertAllowedCloudPath(`/v1/sites/${SITE}/devices/${SITE}/actions`)).toThrow();
		expect(() => assertAllowedCloudPath("/v1/sites/default/clients")).toThrow();
		expect(() => assertAllowedCloudPath("/../../api/auth")).toThrow();
	});

	it("rejects an invalid console ID", () => {
		expect(() => new UnifiCloudApi({ apiKey: "k", consoleId: "../x" })).toThrow();
	});
});

describe("MCP over cloud mode", () => {
	const { fetcher } = makeFetch();
	const api = new UnifiCloudApi({ apiKey: "k", consoleId: "HOST1:123", fetcher });
	const env = { UNIFI_SITE: "default" } as Env;
	const handler = createMcpHandler(() => createServer({ env, api }), { route: "/mcp" });
	let id = 0;
	const call = async (name: string, args: Record<string, unknown> = {}) => {
		const res = await handler(
			new Request("http://localhost/mcp", {
				method: "POST",
				headers: { host: "localhost", "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18" },
				body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method: "tools/call", params: { name, arguments: args } }),
			}),
			env,
			{ waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext,
		);
		const text = await res.text();
		const payload = text.startsWith("{") ? text : text.split("\n").find((l) => l.startsWith("data:"))!.slice(5);
		return JSON.parse(payload).result;
	};

	it("audits and explains checks that cloud mode cannot perform", async () => {
		const result = await call("unifi_audit_security");
		const body = JSON.parse(result.content[0].text);
		expect(body.findings.map((f: { id: string }) => f.id)).toEqual(expect.arrayContaining(["ZFW-EXTERNAL-ALLOW", "DEV-FIRMWARE", "WIFI-NO-WPA3"]));
		expect(body.notes.join(" ")).toMatch(/Port forwards are not exposed/);
		expect(result.content[0].text).not.toContain("supersecret");
	});

	it("falls back to device uplink throughput for top talkers", async () => {
		const body = JSON.parse((await call("unifi_top_talkers")).content[0].text);
		expect(body.scope).toBe("devices");
		expect(body.devices[0]).toMatchObject({ name: "UDR7", download: "80.0 Mbps" });
	});

	it("checks IoT isolation and spots stray IoT devices", async () => {
		const body = JSON.parse((await call("unifi_check_iot_isolation")).content[0].text);
		expect(body.possibleIotDevicesOnTrustedNetworks.map((d: { name: string }) => d.name)).toEqual(["esp-1234"]);
	});
});
