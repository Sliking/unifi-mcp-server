import type {
	UnifiClient,
	UnifiDevice,
	UnifiFirewallGroup,
	UnifiFirewallPolicy,
	UnifiFirewallRule,
	UnifiPortForward,
	UnifiSetting,
	UnifiWlan,
	UnifiZone,
} from "../unifi/types";
import type { ConnectivityReport, PairResult } from "./connectivity";
import type { Network } from "./networks";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
	id: string;
	severity: Severity;
	category: "firewall" | "segmentation" | "port-forwarding" | "wifi" | "gateway" | "devices";
	title: string;
	detail: string;
	resource?: { type: string; id?: string; name?: string };
	recommendation: string;
}

export interface AuditInput {
	networks: Network[];
	connectivity: ConnectivityReport;
	rules: UnifiFirewallRule[];
	groups: UnifiFirewallGroup[];
	zones: UnifiZone[];
	policies: UnifiFirewallPolicy[];
	portForwards: UnifiPortForward[];
	wlans: UnifiWlan[];
	settings: UnifiSetting[];
	devices: UnifiDevice[];
	clients: UnifiClient[];
}

export interface AuditReport {
	summary: Record<Severity, number> & { total: number; score: number };
	firewallMode: ConnectivityReport["mode"];
	findings: Finding[];
	notes: string[];
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };

/** Ports that should essentially never be reachable from the Internet without a VPN. */
const SENSITIVE_PORTS: Record<number, string> = {
	21: "FTP",
	22: "SSH",
	23: "Telnet",
	25: "SMTP",
	53: "DNS",
	135: "MS-RPC",
	137: "NetBIOS",
	139: "NetBIOS",
	161: "SNMP",
	445: "SMB",
	1433: "MSSQL",
	1883: "MQTT",
	2375: "Docker API",
	3306: "MySQL",
	3389: "RDP",
	5000: "NAS/UPnP admin",
	5432: "PostgreSQL",
	5900: "VNC",
	6379: "Redis",
	8080: "HTTP admin",
	8123: "Home Assistant",
	8443: "HTTPS admin",
	9000: "Admin UI",
	27017: "MongoDB",
};

export function expandPorts(spec: string | undefined): { ports: number[]; count: number } {
	if (!spec) return { ports: [], count: 65535 };
	const ports: number[] = [];
	let count = 0;
	for (const part of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
		const [a, b] = part.split(/[-:]/).map(Number);
		if (!Number.isFinite(a)) continue;
		const end = Number.isFinite(b) ? b : a;
		count += end - a + 1;
		if (end - a < 2048) for (let p = a; p <= end; p++) ports.push(p);
		else for (const p of Object.keys(SENSITIVE_PORTS).map(Number)) if (p >= a && p <= end) ports.push(p);
	}
	return { ports, count };
}

function isAnySource(value: string | undefined): boolean {
	return !value || value === "any" || value === "0.0.0.0/0";
}

function isAccept(action: string | undefined) {
	const a = (action ?? "").toLowerCase();
	return a === "accept" || a === "allow";
}

function isBlock(action: string | undefined) {
	const a = (action ?? "").toLowerCase();
	return a === "drop" || a === "reject" || a === "block";
}

function setting(settings: UnifiSetting[], key: string): UnifiSetting | undefined {
	return settings.find((s) => s.key === key);
}

function legacyRuleIsAnyAny(r: UnifiFirewallRule): boolean {
	const noSrc = !r.src_networkconf_id && !r.src_address && !(r.src_firewallgroup_ids ?? []).length && !r.src_mac_address;
	const noDst = !r.dst_networkconf_id && !r.dst_address && !(r.dst_firewallgroup_ids ?? []).length && !r.dst_port;
	return noSrc && noDst && (r.protocol ?? "all") === "all";
}

function ruleSignature(r: UnifiFirewallRule): string {
	return JSON.stringify([
		r.ruleset,
		r.protocol ?? "all",
		r.src_networkconf_id ?? "",
		r.src_address ?? "",
		[...(r.src_firewallgroup_ids ?? [])].sort(),
		r.src_mac_address ?? "",
		r.dst_networkconf_id ?? "",
		r.dst_address ?? "",
		[...(r.dst_firewallgroup_ids ?? [])].sort(),
		r.dst_port ?? "",
		Boolean(r.state_new),
		Boolean(r.state_established),
		Boolean(r.state_related),
		Boolean(r.state_invalid),
	]);
}

function auditLegacyRules(input: AuditInput, out: Finding[]) {
	const groupIds = new Set(input.groups.map((g) => g._id));
	const networkIds = new Set(input.networks.map((n) => n.id));
	const usedGroups = new Set<string>();
	const seen = new Map<string, UnifiFirewallRule>();
	const unloggedDrops: UnifiFirewallRule[] = [];
	const sorted = [...input.rules].sort((a, b) => Number(a.rule_index ?? 0) - Number(b.rule_index ?? 0));

	for (const r of sorted) {
		const name = r.name ?? r._id;
		const resource = { type: "firewall_rule", id: r._id, name };
		for (const id of [...(r.src_firewallgroup_ids ?? []), ...(r.dst_firewallgroup_ids ?? [])]) {
			usedGroups.add(id);
			if (!groupIds.has(id)) {
				out.push({ id: "FW-DANGLING-GROUP", severity: "medium", category: "firewall", title: "Rule references a missing firewall group", detail: `Rule "${name}" references group ${id}, which no longer exists. The rule may not match what you expect.`, resource, recommendation: "Edit or delete the rule so it only references existing groups." });
			}
		}
		for (const id of [r.src_networkconf_id, r.dst_networkconf_id]) {
			if (id && !networkIds.has(id)) {
				out.push({ id: "FW-DANGLING-NETWORK", severity: "medium", category: "firewall", title: "Rule references a missing network", detail: `Rule "${name}" references network ${id}, which no longer exists.`, resource, recommendation: "Edit or delete the rule." });
			}
		}

		if (r.enabled === false) {
			out.push({ id: "FW-DISABLED", severity: "info", category: "firewall", title: "Disabled firewall rule", detail: `Rule "${name}" (${r.ruleset}) is disabled.`, resource, recommendation: "Delete rules you no longer need so the policy stays easy to reason about." });
			continue;
		}

		const ruleset = r.ruleset ?? "";
		const newAllowed = r.state_new || ![r.state_established, r.state_related, r.state_invalid].some(Boolean);
		if ((ruleset === "WAN_IN" || ruleset === "WAN_LOCAL") && isAccept(r.action) && newAllowed) {
			const anySrc = !r.src_address && !(r.src_firewallgroup_ids ?? []).length && !r.src_networkconf_id;
			const { count } = expandPorts(r.dst_port);
			const severity: Severity = anySrc && count > 100 ? "critical" : anySrc ? "high" : "medium";
			out.push({
				id: "FW-WAN-ACCEPT",
				severity,
				category: "firewall",
				title: ruleset === "WAN_LOCAL" ? "Internet traffic allowed to the gateway itself" : "Inbound Internet traffic allowed",
				detail: `Rule "${name}" in ${ruleset} accepts new connections from ${anySrc ? "any Internet source" : "a restricted source"} to ${r.dst_port ? `port(s) ${r.dst_port}` : "all ports"} (${r.protocol ?? "all"}).`,
				resource,
				recommendation: "Remove the rule or restrict it to known source IPs. Prefer a VPN (WireGuard/Teleport) or Cloudflare Tunnel instead of opening inbound ports.",
			});
		}

		if ((ruleset === "LAN_IN" || ruleset === "GUEST_IN") && isAccept(r.action) && legacyRuleIsAnyAny(r) && newAllowed) {
			out.push({ id: "FW-ANY-ANY-ACCEPT", severity: "high", category: "firewall", title: "Any-to-any allow rule", detail: `Rule "${name}" (${ruleset} #${r.rule_index}) accepts all traffic from any source to any destination. Every rule after it in ${ruleset} is effectively bypassed.`, resource, recommendation: "Replace it with narrowly scoped allow rules (specific source network, destination and port)." });
		}

		const sig = ruleSignature(r);
		const earlier = seen.get(sig);
		if (earlier) {
			out.push({ id: "FW-SHADOWED", severity: "low", category: "firewall", title: "Redundant or shadowed rule", detail: `Rule "${name}" matches exactly the same traffic as earlier rule "${earlier.name ?? earlier._id}" in ${ruleset}; it will never be hit${earlier.action !== r.action ? ` and its action (${r.action}) is overridden by ${earlier.action}` : ""}.`, resource, recommendation: "Delete the redundant rule or merge the two." });
		} else {
			seen.set(sig, r);
		}

		if (isBlock(r.action) && !r.logging) unloggedDrops.push(r);
	}

	if (unloggedDrops.length) {
		out.push({ id: "FW-NO-LOGGING", severity: "low", category: "firewall", title: "Block rules without logging", detail: `${unloggedDrops.length} block rule(s) do not log matches: ${unloggedDrops.slice(0, 10).map((r) => `"${r.name ?? r._id}"`).join(", ")}${unloggedDrops.length > 10 ? ", …" : ""}.`, recommendation: "Enable logging on block rules that protect sensitive segments so blocked attempts are visible in syslog/SIEM." });
	}

	for (const g of input.groups) {
		if (!usedGroups.has(g._id)) {
			out.push({ id: "FW-UNUSED-GROUP", severity: "info", category: "firewall", title: "Unused firewall group", detail: `Group "${g.name ?? g._id}" (${g.group_type}) is not referenced by any rule.`, resource: { type: "firewall_group", id: g._id, name: g.name }, recommendation: "Delete unused groups to reduce clutter." });
		}
	}
}

function auditZonePolicies(input: AuditInput, out: Finding[]) {
	const zoneById = new Map(input.zones.map((z) => [z._id, z]));
	const unloggedBlocks: UnifiFirewallPolicy[] = [];
	for (const p of input.policies) {
		if (p.predefined) continue;
		const name = p.name ?? p._id;
		const resource = { type: "firewall_policy", id: p._id, name };
		if (p.enabled === false) {
			out.push({ id: "ZFW-DISABLED", severity: "info", category: "firewall", title: "Disabled firewall policy", detail: `Policy "${name}" is disabled.`, resource, recommendation: "Delete policies you no longer need." });
			continue;
		}
		const srcZone = zoneById.get(p.source?.zone_id ?? "");
		const dstZone = zoneById.get(p.destination?.zone_id ?? "");
		const allow = isAccept(p.action);
		const respondOnly = (p.connection_state_type ?? "ALL").toUpperCase() === "RESPOND_ONLY";
		const srcAny = (p.source?.matching_target ?? "ANY").toUpperCase() === "ANY";
		const dstAnyPort = (p.destination?.port_matching_type ?? "ANY").toUpperCase() === "ANY";

		if (allow && !respondOnly && srcZone?.zone_key === "external" && dstZone && ["internal", "gateway", "dmz", "vpn"].includes(dstZone.zone_key ?? "")) {
			out.push({
				id: "ZFW-EXTERNAL-ALLOW",
				severity: srcAny && dstAnyPort ? "critical" : srcAny ? "high" : "medium",
				category: "firewall",
				title: `Internet traffic allowed into ${dstZone.name ?? dstZone.zone_key} zone`,
				detail: `Policy "${name}" allows new connections from ${srcAny ? "any Internet source" : "a restricted Internet source"} to the ${dstZone.name} zone${dstAnyPort ? " on all ports" : ` on port(s) ${p.destination?.port ?? "(object)"}`}.`,
				resource,
				recommendation: "Restrict the source to known IPs or remove the policy and use a VPN / Cloudflare Tunnel for remote access.",
			});
		}

		if (allow && !respondOnly && srcAny && (p.destination?.matching_target ?? "ANY").toUpperCase() === "ANY" && dstAnyPort && (p.protocol ?? "all") === "all" && srcZone && dstZone && srcZone._id !== dstZone._id && srcZone.zone_key !== "external") {
			out.push({ id: "ZFW-ZONE-ANY-ALLOW", severity: srcZone.zone_key === "hotspot" || srcZone.zone_key === "dmz" ? "high" : "medium", category: "firewall", title: "Broad zone-to-zone allow policy", detail: `Policy "${name}" allows all traffic from zone ${srcZone.name} to zone ${dstZone.name}, removing the separation between them.`, resource, recommendation: "Narrow the policy to the specific destinations and ports that are actually needed." });
		}

		if (isBlock(p.action) && !p.logging) unloggedBlocks.push(p);
	}
	if (unloggedBlocks.length) {
		out.push({ id: "ZFW-NO-LOGGING", severity: "low", category: "firewall", title: "Block policies without logging", detail: `${unloggedBlocks.length} custom block polic(ies) do not log matches: ${unloggedBlocks.slice(0, 10).map((p) => `"${p.name ?? p._id}"`).join(", ")}.`, recommendation: "Enable syslog logging on block policies protecting sensitive zones." });
	}
}

function auditPortForwards(input: AuditInput, out: Finding[]) {
	for (const pf of input.portForwards) {
		if (pf.enabled === false) continue;
		const name = pf.name ?? pf._id;
		const anySrc = isAnySource(pf.src);
		const { ports, count } = expandPorts(pf.dst_port);
		const sensitive = ports.filter((p) => SENSITIVE_PORTS[p]).map((p) => `${p}/${SENSITIVE_PORTS[p]}`);
		let severity: Severity = anySrc ? "medium" : "low";
		if (anySrc && sensitive.length) severity = "high";
		if (anySrc && count > 1000) severity = "critical";
		out.push({
			id: "PF-EXPOSED",
			severity,
			category: "port-forwarding",
			title: sensitive.length ? `Sensitive service exposed to the Internet (${sensitive.join(", ")})` : "Port forward exposes an internal host",
			detail: `Port forward "${name}" sends ${pf.proto ?? "tcp_udp"} port(s) ${pf.dst_port ?? "?"} from ${anySrc ? "any source" : pf.src} to ${pf.fwd}:${pf.fwd_port ?? pf.dst_port}.${pf.log ? "" : " Logging is disabled."}`,
			resource: { type: "port_forward", id: pf._id, name },
			recommendation: anySrc
				? "Limit the source to known IPs, or remove the forward and publish the service through Cloudflare Tunnel / a VPN with authentication."
				: "Confirm the forward is still required and enable logging.",
		});
	}
}

function auditSegmentation(input: AuditInput, out: Finding[]) {
	const roleOf = new Map(input.networks.map((n) => [n.id, n.role]));
	const reach = (p: PairResult) => p.verdict === "allowed" || p.verdict === "allowed_with_exceptions";
	const partial = (p: PairResult) => p.verdict === "blocked_with_exceptions";
	const trustedLike = new Set(["trusted", "management"]);

	for (const p of input.connectivity.pairs) {
		const from = roleOf.get(p.fromId);
		const to = roleOf.get(p.toId);
		if (!to || !trustedLike.has(to)) continue;
		if (from === "iot" || from === "guest") {
			if (reach(p)) {
				out.push({ id: from === "iot" ? "SEG-IOT-TO-TRUSTED" : "SEG-GUEST-TO-TRUSTED", severity: from === "guest" ? "high" : "high", category: "segmentation", title: `${from === "iot" ? "IoT" : "Guest"} network can initiate connections to ${to} network`, detail: `"${p.from}" → "${p.to}" is ${p.verdict.replace(/_/g, " ")}: ${p.reason}.`, resource: { type: "network", id: p.fromId, name: p.from }, recommendation: `Add a block rule/policy from "${p.from}" to "${p.to}" (allow only established/related return traffic), or enable network isolation on "${p.from}".` });
			} else if (partial(p)) {
				out.push({ id: "SEG-PARTIAL", severity: "low", category: "segmentation", title: "Segmentation has explicit exceptions", detail: `"${p.from}" → "${p.to}" is blocked, but these rules allow some traffic: ${p.exceptions.map((e) => `"${e.name}"`).join(", ")}.`, resource: { type: "network", id: p.fromId, name: p.from }, recommendation: "Verify each exception is limited to the specific hosts and ports required." });
			}
		}
	}

	const routed = input.connectivity.networks;
	if (routed.length >= 2) {
		const allOpen = input.connectivity.pairs.every(reach);
		if (allOpen) {
			out.push({ id: "SEG-FLAT", severity: "medium", category: "segmentation", title: "No segmentation between VLANs", detail: `All ${routed.length} routed networks can reach each other. VLANs separate broadcast domains but provide no security boundary unless the firewall restricts inter-VLAN traffic.`, recommendation: "Block traffic from less-trusted networks (IoT, guest, lab) into trusted networks and allow only what is needed." });
		}
	}

	for (const n of input.networks) {
		if (n.role === "iot" && n.mdns) {
			out.push({ id: "SEG-IOT-MDNS", severity: "info", category: "segmentation", title: "mDNS reflection enabled on IoT network", detail: `mDNS is enabled on "${n.name}". This is often needed for casting/AirPlay but exposes service discovery across VLANs.`, resource: { type: "network", id: n.id, name: n.name }, recommendation: "Keep mDNS only on networks that need it and restrict it to the specific services required." });
		}
	}
}

function auditWifi(input: AuditInput, out: Finding[]) {
	const netName = new Map(input.networks.map((n) => [n.id, n]));
	for (const w of input.wlans) {
		if (w.enabled === false) continue;
		const name = w.name ?? w._id;
		const resource = { type: "wlan", id: w._id, name };
		const security = (w.security ?? "").toLowerCase();
		const net = w.networkconf_id ? netName.get(w.networkconf_id) : undefined;
		if (security === "wep") {
			out.push({ id: "WIFI-WEP", severity: "critical", category: "wifi", title: "WEP encryption in use", detail: `SSID "${name}" uses WEP, which can be cracked in minutes.`, resource, recommendation: "Switch to WPA2/WPA3." });
		} else if (security === "open") {
			const guestish = w.is_guest || net?.role === "guest";
			out.push({ id: "WIFI-OPEN", severity: guestish ? "low" : "high", category: "wifi", title: "Open (unencrypted) SSID", detail: `SSID "${name}" has no encryption${guestish ? " (guest network)" : ` and is bridged to "${net?.name ?? "a non-guest network"}"`}.`, resource, recommendation: guestish ? "Consider WPA3 OWE (Enhanced Open) or a simple shared passphrase for guests." : "Enable WPA2/WPA3 immediately or move the SSID to an isolated guest network." });
		} else if (security === "wpapsk") {
			if (w.wpa_mode === "wpa1") {
				out.push({ id: "WIFI-WPA1", severity: "high", category: "wifi", title: "Legacy WPA (TKIP) in use", detail: `SSID "${name}" uses WPA1.`, resource, recommendation: "Use WPA2 or WPA3." });
			} else if (!w.wpa3_support && !w.wpa3_transition) {
				out.push({ id: "WIFI-NO-WPA3", severity: "low", category: "wifi", title: "WPA3 not enabled", detail: `SSID "${name}" is WPA2-only.`, resource, recommendation: "Enable WPA2/WPA3 transition mode if your clients support it." });
			}
			if ((w.pmf_mode ?? "").toLowerCase() === "disabled") {
				out.push({ id: "WIFI-NO-PMF", severity: "low", category: "wifi", title: "Protected Management Frames disabled", detail: `SSID "${name}" has PMF disabled, allowing deauthentication attacks.`, resource, recommendation: "Set PMF to Optional (or Required with WPA3)." });
			}
		}
		if ((w.is_guest || net?.role === "guest") && w.l2_isolation === false) {
			out.push({ id: "WIFI-GUEST-NO-CLIENT-ISOLATION", severity: "low", category: "wifi", title: "Guest SSID without client isolation", detail: `Clients on guest SSID "${name}" can talk to each other.`, resource, recommendation: "Enable Client Device Isolation on guest SSIDs." });
		}
	}
}

function auditGateway(input: AuditInput, out: Finding[]) {
	const usg = setting(input.settings, "usg");
	if (usg?.upnp_enabled === true) {
		out.push({ id: "GW-UPNP", severity: "medium", category: "gateway", title: "UPnP is enabled", detail: "Any device on the LAN (including compromised IoT devices) can open inbound ports on your gateway without your approval.", resource: { type: "setting", name: "usg.upnp_enabled" }, recommendation: "Disable UPnP, or restrict it to a single trusted network (e.g. gaming consoles) if your UniFi version supports it." });
	}
	const ips = setting(input.settings, "ips");
	const ipsMode = typeof ips?.ips_mode === "string" ? ips.ips_mode : undefined;
	if (ips && (!ipsMode || ipsMode === "disabled")) {
		out.push({ id: "GW-IPS-OFF", severity: "medium", category: "gateway", title: "Intrusion Prevention (IPS/IDS) is disabled", detail: "CyberSecure / Threat Management is not inspecting traffic.", resource: { type: "setting", name: "ips.ips_mode" }, recommendation: "Enable IPS (or at least IDS) on WAN and on IoT/guest networks if your gateway has the throughput headroom." });
	} else if (ipsMode === "ids") {
		out.push({ id: "GW-IDS-ONLY", severity: "low", category: "gateway", title: "Threat management is detect-only (IDS)", detail: "Threats are logged but not blocked.", resource: { type: "setting", name: "ips.ips_mode" }, recommendation: "Switch to IPS mode to block detected threats." });
	}
	const mgmt = setting(input.settings, "mgmt");
	if (mgmt?.x_ssh_enabled === true || mgmt?.ssh_enabled === true) {
		out.push({ id: "GW-DEVICE-SSH", severity: "low", category: "gateway", title: "SSH enabled on adopted devices", detail: "Device SSH is enabled for all adopted UniFi devices.", resource: { type: "setting", name: "mgmt.ssh" }, recommendation: "Disable device SSH when not troubleshooting, or use key-based authentication with a strong, unique password." });
	}
}

function auditDevices(input: AuditInput, out: Finding[]) {
	const upgradable = input.devices.filter((d) => d.upgradable);
	if (upgradable.length) {
		out.push({ id: "DEV-FIRMWARE", severity: "medium", category: "devices", title: "Firmware updates available", detail: `${upgradable.length} device(s) have pending firmware updates: ${upgradable.map((d) => `${d.name ?? d.mac} (${d.version} → ${d.upgrade_to_firmware ?? "newer"})`).join(", ")}.`, recommendation: "Review the release notes and update, especially for security fixes." });
	}
	const offline = input.devices.filter((d) => d.state === 0);
	if (offline.length) {
		out.push({ id: "DEV-OFFLINE", severity: "info", category: "devices", title: "Devices offline", detail: `${offline.map((d) => d.name ?? d.mac).join(", ")} are disconnected from the controller.`, recommendation: "Check power/uplink, or forget devices that have been decommissioned." });
	}
}

export function runAudit(input: AuditInput): AuditReport {
	const findings: Finding[] = [];
	if (input.connectivity.mode === "zone") auditZonePolicies(input, findings);
	else auditLegacyRules(input, findings);
	auditPortForwards(input, findings);
	auditSegmentation(input, findings);
	auditWifi(input, findings);
	auditGateway(input, findings);
	auditDevices(input, findings);

	findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
	const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length])) as Record<Severity, number>;
	const penalty = findings.reduce((acc, f) => acc + SEVERITY_WEIGHT[f.severity], 0);
	return {
		summary: { ...counts, total: findings.length, score: Math.max(0, 100 - penalty) },
		firewallMode: input.connectivity.mode,
		findings,
		notes: [
			"Score is a heuristic (100 = no findings); weight critical=25, high=10, medium=4, low=1.",
			"Network roles (trusted/IoT/guest) are inferred from network names and purpose. Pass iot_network_names to override.",
			"This audit is read-only and based on the controller configuration; it does not perform active scanning.",
		],
	};
}
