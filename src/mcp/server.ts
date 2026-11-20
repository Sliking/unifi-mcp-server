import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { runAudit } from "../analysis/audit";
import { type ConnectivityReport, legacyConnectivity, zoneConnectivity } from "../analysis/connectivity";
import { checkIotIsolation } from "../analysis/iot";
import { normaliseNetworks } from "../analysis/networks";
import { formatBytes, formatDuration, formatRate, toTalker, topTalkers } from "../analysis/traffic";
import type { Props } from "../auth/props";
import { UnifiApi, UnifiError } from "../unifi/client";
import { UnifiCloudApi } from "../unifi/cloud";
import type { UnifiSource } from "../unifi/source";
import { redact } from "../unifi/redact";

export const SERVER_NAME = "unifi-mcp-server";
export const SERVER_VERSION = "0.1.0";

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;

const siteArg = z
	.string()
	.regex(/^[A-Za-z0-9_-]{1,64}$/)
	.optional()
	.describe('UniFi site name (the short id, e.g. "default"). Defaults to the configured site.');

const iotArg = z
	.array(z.string().max(64))
	.max(32)
	.optional()
	.describe("Exact names of networks to treat as IoT. If omitted, IoT networks are inferred from names such as 'IoT', 'Smart Home', 'Cameras'.");

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

function ok(data: unknown): ToolResult {
	return { content: [{ type: "text", text: JSON.stringify(redact(data), null, 2) }] };
}

function fail(err: unknown): ToolResult {
	const message = err instanceof UnifiError ? err.message : "Unexpected error while talking to the UniFi console";
	if (!(err instanceof UnifiError)) console.error("tool error", err);
	return { content: [{ type: "text", text: `Error: ${message}` }], isError: true };
}

export function unifiFromEnv(env: Env): UnifiSource {
	if ((env.UNIFI_MODE ?? "local") === "cloud") {
		return new UnifiCloudApi({ apiKey: env.UNIFI_API_KEY, consoleId: env.UNIFI_CONSOLE_ID || undefined });
	}
	return new UnifiApi({
		baseUrl: env.UNIFI_BASE_URL,
		apiKey: env.UNIFI_API_KEY,
		vpc: env.UNIFI_VPC,
		accessClientId: env.CF_ACCESS_CLIENT_ID,
		accessClientSecret: env.CF_ACCESS_CLIENT_SECRET,
	});
}

async function loadConnectivity(api: UnifiSource, site: string, iotNames?: string[]) {
	const [rawNetworks, zones] = await Promise.all([api.networks(site), api.zones(site)]);
	const networks = normaliseNetworks(rawNetworks, zones, iotNames);
	let connectivity: ConnectivityReport;
	let rules: Awaited<ReturnType<UnifiSource["firewallRules"]>> = [];
	let groups: Awaited<ReturnType<UnifiSource["firewallGroups"]>> = [];
	let policies: Awaited<ReturnType<UnifiSource["firewallPolicies"]>> = [];
	if (zones.length) {
		policies = await api.firewallPolicies(site);
		connectivity = zoneConnectivity(networks, zones, policies);
	} else if (!api.capabilities.legacyFirewall) {
		throw new UnifiError("Cloud mode requires the zone-based firewall (UniFi Network 9+). Upgrade or migrate the firewall, or use local mode.");
	} else {
		[rules, groups] = await Promise.all([api.firewallRules(site), api.firewallGroups(site)]);
		connectivity = legacyConnectivity(networks, rules, groups);
	}
	return { networks, zones, rules, groups, policies, connectivity };
}

export interface ServerDeps {
	env: Env;
	props?: Props;
	api?: UnifiSource;
}

export function createServer({ env, props, api: injected }: ServerDeps): McpServer {
	const server = new McpServer(
		{ name: SERVER_NAME, version: SERVER_VERSION },
		{
			instructions:
				"Read-only access to a UniFi network (UniFi OS console). Use unifi_audit_security for a security review, unifi_vlan_connectivity for inter-VLAN reachability, unifi_check_iot_isolation for IoT segmentation and unifi_top_talkers for bandwidth usage. Secrets such as Wi-Fi passphrases are always redacted. This server cannot change configuration.",
		},
	);
	const defaultSite = env.UNIFI_SITE || "default";
	const getApi = () => injected ?? unifiFromEnv(env);

	const tool = <S extends z.ZodObject>(
		name: string,
		title: string,
		description: string,
		inputSchema: S,
		handler: (args: z.infer<S>, api: UnifiSource) => Promise<unknown>,
	) => {
		server.registerTool(name, { title, description, inputSchema, annotations: { title, ...READ_ONLY } }, (async (args: z.infer<S>) => {
			const started = Date.now();
			try {
				const result = await handler(args, getApi());
				console.log(JSON.stringify({ event: "tool_call", tool: name, user: props?.login, ok: true, ms: Date.now() - started }));
				return ok(result);
			} catch (err) {
				console.log(JSON.stringify({ event: "tool_call", tool: name, user: props?.login, ok: false, ms: Date.now() - started, error: err instanceof Error ? err.message : "unknown" }));
				return fail(err);
			}
		}) as never);
	};

	tool("unifi_list_sites", "List UniFi sites", "List the sites managed by the UniFi console.", z.object({}), async (_args, api) => {
		const sites = await api.sites();
		return sites.map((s) => ({ name: s.name, description: s.desc, role: s.role }));
	});

	tool(
		"unifi_network_overview",
		"Network overview",
		"High-level health and inventory of a site: subsystem health (WAN/LAN/WLAN/VPN), device and client counts, networks and firewall mode.",
		z.object({ site: siteArg }),
		async ({ site = defaultSite }, api) => {
			const [health, devices, clients, rawNetworks, zones] = await Promise.all([api.health(site), api.devices(site), api.clients(site), api.networks(site), api.zones(site)]);
			const networks = normaliseNetworks(rawNetworks, zones);
			return {
				site,
				connection: api.mode,
				firewallMode: zones.length ? "zone-based" : "legacy",
				health: health.map((h) => ({ subsystem: h.subsystem, status: h.status, wan_ip: h.wan_ip, isp: h.isp_name, latency_ms: h.latency, num_user: h.num_user, num_guest: h.num_guest })),
				devices: { total: devices.length, online: devices.filter((d) => d.state === 1).length, updatesAvailable: devices.filter((d) => d.upgradable).length },
				clients: { total: clients.length, wired: clients.filter((c) => c.is_wired).length, wireless: clients.filter((c) => !c.is_wired).length, guests: clients.filter((c) => c.is_guest).length },
				networks: networks.map((n) => ({ name: n.name, vlan: n.vlan, subnet: n.subnet, purpose: n.purpose, role: n.role })),
			};
		},
	);

	tool(
		"unifi_list_networks",
		"List networks / VLANs",
		"List all networks (VLANs) with VLAN ID, subnet, purpose, inferred role (trusted/IoT/guest/management), isolation, Internet access and mDNS settings, plus firewall zone membership.",
		z.object({ site: siteArg, iot_network_names: iotArg }),
		async ({ site = defaultSite, iot_network_names }, api) => {
			const [raw, zones] = await Promise.all([api.networks(site), api.zones(site)]);
			const zoneName = new Map(zones.map((z) => [z._id, z.name]));
			return normaliseNetworks(raw, zones, iot_network_names).map(({ cidr: _c, zoneId, ...n }) => ({ ...n, zone: zoneId ? (zoneName.get(zoneId) ?? zoneId) : null }));
		},
	);

	tool(
		"unifi_list_firewall",
		"List firewall configuration",
		"Return the firewall configuration: zone-based policies and zones (UniFi Network 9+), or legacy rules and groups, plus port forwards and traffic rules. Built-in policies are omitted unless include_predefined is true.",
		z.object({ site: siteArg, include_predefined: z.boolean().optional().describe("Include UniFi built-in (predefined) zone policies.") }),
		async ({ site = defaultSite, include_predefined }, api) => {
			const [zones, portForwards, trafficRules] = await Promise.all([api.zones(site), api.portForwards(site), api.trafficRules(site)]);
			if (zones.length) {
				const policies = await api.firewallPolicies(site);
				const zoneName = new Map(zones.map((z) => [z._id, z.name]));
				return {
					mode: "zone-based",
					zones: zones.map((z) => ({ id: z._id, name: z.name, key: z.zone_key, networks: z.network_ids?.length ?? 0 })),
					policies: policies
						.filter((p) => include_predefined || !p.predefined)
						.sort((a, b) => (a.index ?? 0) - (b.index ?? 0))
						.map((p) => ({ ...p, source: { ...p.source, zone: zoneName.get(p.source?.zone_id ?? "") }, destination: { ...p.destination, zone: zoneName.get(p.destination?.zone_id ?? "") } })),
					portForwards,
					trafficRules,
					...(api.capabilities.portForwards ? {} : { notes: ["Port forwards and traffic rules are not exposed by the UniFi cloud API; they are omitted in cloud mode."] }),
				};
			}
			const [rules, groups] = await Promise.all([api.firewallRules(site), api.firewallGroups(site)]);
			return {
				mode: "legacy",
				rules: [...rules].sort((a, b) => String(a.ruleset).localeCompare(String(b.ruleset)) || Number(a.rule_index) - Number(b.rule_index)),
				groups,
				portForwards,
				trafficRules,
			};
		},
	);

	tool(
		"unifi_audit_security",
		"Audit firewall & security",
		"Audit the site's firewall policies and security posture. Returns prioritised findings (critical → info) covering exposed ports, any-any rules, shadowed/redundant rules, inter-VLAN segmentation gaps, IoT/guest isolation, Wi-Fi encryption, UPnP, IPS and firmware, each with a recommendation.",
		z.object({ site: siteArg, iot_network_names: iotArg, min_severity: z.enum(["critical", "high", "medium", "low", "info"]).optional().describe("Only return findings at or above this severity.") }),
		async ({ site = defaultSite, iot_network_names, min_severity }, api) => {
			const [ctx, portForwards, wlans, settings, devices, clients] = await Promise.all([
				loadConnectivity(api, site, iot_network_names),
				api.portForwards(site),
				api.wlans(site),
				api.settings(site),
				api.devices(site),
				api.clients(site),
			]);
			const report = runAudit({ ...ctx, portForwards, wlans, settings, devices, clients });
			const caps = api.capabilities;
			if (!caps.portForwards) report.notes.push("Port forwards are not exposed by the UniFi cloud API, so Internet-exposed port forwards were NOT checked. Review Settings → Routing → Port Forwarding manually.");
			if (!caps.gatewaySettings) report.notes.push("Gateway settings (UPnP, IPS/IDS, device SSH) are not exposed by the UniFi cloud API and were NOT checked.");
			if (min_severity) {
				const order = ["critical", "high", "medium", "low", "info"];
				report.findings = report.findings.filter((f) => order.indexOf(f.severity) <= order.indexOf(min_severity));
			}
			return { site, ...report };
		},
	);

	tool(
		"unifi_vlan_connectivity",
		"VLAN connectivity matrix",
		"Show every routed network/VLAN and, for each ordered pair, whether hosts in the source can open new connections to the destination, which rule or default decides it, and any exceptions.",
		z.object({ site: siteArg, iot_network_names: iotArg }),
		async ({ site = defaultSite, iot_network_names }, api) => {
			const { connectivity } = await loadConnectivity(api, site, iot_network_names);
			const matrix: Record<string, Record<string, string>> = {};
			for (const p of connectivity.pairs) (matrix[p.from] ??= {})[p.to] = p.verdict;
			return { site, ...connectivity, matrix };
		},
	);

	tool(
		"unifi_check_iot_isolation",
		"Check IoT isolation",
		"Check whether IoT networks are properly isolated: can they reach trusted networks, is network isolation / mDNS enabled, and are any IoT-looking devices sitting on trusted networks.",
		z.object({ site: siteArg, iot_network_names: iotArg }),
		async ({ site = defaultSite, iot_network_names }, api) => {
			const [{ networks, connectivity }, clients] = await Promise.all([loadConnectivity(api, site, iot_network_names), api.clients(site)]);
			return { site, firewallMode: connectivity.mode, ...checkIotIsolation(networks, connectivity, clients) };
		},
	);

	tool(
		"unifi_top_talkers",
		"Top traffic clients",
		"Rank connected clients by traffic: cumulative bytes for the current session (sort_by=total) or current throughput (sort_by=current_rate).",
		z.object({
			site: siteArg,
			limit: z.number().int().min(1).max(100).default(10),
			sort_by: z.enum(["total", "current_rate"]).default("total"),
			network: z.string().max(64).optional().describe("Only include clients on this network name."),
		}),
		async ({ site = defaultSite, limit, sort_by, network }, api) => {
			if (!api.capabilities.clientTraffic) {
				const uplinks = (await api.deviceUplinks(site)).map((d) => ({ ...d, totalBps: d.rxRateBps + d.txRateBps }));
				uplinks.sort((a, b) => b.totalBps - a.totalBps);
				return {
					site,
					scope: "devices",
					devices: uplinks.slice(0, limit).map((d) => ({ name: d.name, model: d.model, mac: d.mac, download: formatRate(d.rxRateBps / 8), upload: formatRate(d.txRateBps / 8), total: formatRate(d.totalBps / 8) })),
					notes: [
						"The UniFi cloud API does not expose per-client traffic counters, so this ranks UniFi devices (gateway, switches, access points) by current uplink throughput instead.",
						"For per-client top talkers, use local mode (Cloudflare Tunnel) or check Insights → Clients in the UniFi app.",
					],
				};
			}
			const clients = await api.clients(site);
			return { site, scope: "clients", ...topTalkers(clients, { limit, sortBy: sort_by, network }) };
		},
	);

	tool(
		"unifi_list_clients",
		"List clients",
		"List currently connected clients with name, IP, MAC, network, vendor, connection type and traffic.",
		z.object({
			site: siteArg,
			network: z.string().max(64).optional().describe("Filter by network name."),
			search: z.string().max(64).optional().describe("Case-insensitive match on name, hostname, IP, MAC or vendor."),
			limit: z.number().int().min(1).max(500).default(100),
		}),
		async ({ site = defaultSite, network, search, limit }, api) => {
			const clients = await api.clients(site);
			const needle = search?.toLowerCase();
			const filtered = clients.filter((c) => {
				if (network && (c.network ?? "").toLowerCase() !== network.toLowerCase()) return false;
				if (needle) return [c.name, c.hostname, c.ip, c.mac, c.oui].some((v) => (v ?? "").toLowerCase().includes(needle));
				return true;
			});
			return { site, count: filtered.length, clients: filtered.slice(0, limit).map(toTalker) };
		},
	);

	tool(
		"unifi_list_devices",
		"List UniFi devices",
		"List adopted UniFi devices (gateways, switches, access points) with model, firmware, update availability, state and uptime.",
		z.object({ site: siteArg }),
		async ({ site = defaultSite }, api) => {
			const devices = await api.devices(site);
			return devices.map((d) => ({
				name: d.name,
				mac: d.mac,
				model: d.model,
				type: d.type,
				ip: d.ip,
				firmware: d.version,
				updateAvailable: d.upgradable === true ? (d.upgrade_to_firmware ?? true) : false,
				state: d.state === 1 ? "online" : d.state === 0 ? "offline" : `state ${d.state}`,
				uptime: formatDuration(d.uptime),
				clients: d.num_sta,
				traffic: formatBytes((d.tx_bytes ?? 0) + (d.rx_bytes ?? 0)),
			}));
		},
	);

	tool(
		"unifi_list_wifi",
		"List Wi-Fi networks",
		"List SSIDs with security mode, WPA3/PMF settings, guest/hidden flags and the network they bridge to. Passphrases are never returned.",
		z.object({ site: siteArg }),
		async ({ site = defaultSite }, api) => {
			const [wlans, networks] = await Promise.all([api.wlans(site), api.networks(site)]);
			const netName = new Map(networks.map((n) => [n._id, n.name]));
			return wlans.map((w) => ({
				name: w.name,
				enabled: w.enabled !== false,
				security: w.security,
				wpaMode: w.wpa_mode,
				wpa3: w.wpa3_support === true,
				wpa3Transition: w.wpa3_transition === true,
				pmf: w.pmf_mode,
				guest: w.is_guest === true,
				hidden: w.hide_ssid === true,
				clientIsolation: w.l2_isolation === true,
				network: w.networkconf_id ? netName.get(w.networkconf_id) : undefined,
				bands: w.wlan_bands,
			}));
		},
	);

	const prompt = (name: string, title: string, text: string) =>
		server.registerPrompt(name, { title, description: title }, () => ({ messages: [{ role: "user" as const, content: { type: "text" as const, text } }] }));

	prompt("audit_firewall", "Audit my firewall policies", "Audit my current UniFi firewall policies and identify security issues. Use unifi_audit_security, group the findings by severity, explain the risk of each in plain language and give concrete remediation steps.");
	prompt("vlan_overview", "Show VLANs and who can talk to whom", "Show me all my VLANs and which ones can communicate with each other. Use unifi_list_networks and unifi_vlan_connectivity and present the result as a matrix table, then call out anything surprising.");
	prompt("top_talkers", "Which devices use the most traffic", "Which devices on my network are generating the most traffic? Use unifi_top_talkers (both sort_by=total and sort_by=current_rate) and summarise.");
	prompt("iot_isolation", "Is my IoT network isolated?", "Is my IoT network properly isolated? Use unifi_check_iot_isolation and explain each check, then list the exact firewall changes needed to fix any failures.");

	return server;
}
