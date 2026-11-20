import type { UnifiFirewallGroup, UnifiFirewallPolicy, UnifiFirewallRule, UnifiPolicyEndpoint, UnifiZone } from "../unifi/types";
import { type Coverage, combineCoverage, coverage } from "./ipv4";
import { type Network, routedNetworks } from "./networks";

export type FirewallMode = "zone" | "legacy";
export type Verdict = "allowed" | "blocked" | "allowed_with_exceptions" | "blocked_with_exceptions";
export type Confidence = "high" | "medium" | "low";

export interface RuleRef {
	id: string;
	name: string;
	action: string;
	origin: "user" | "predefined" | "default";
	detail?: string;
}

export interface PairResult {
	from: string;
	fromId: string;
	to: string;
	toId: string;
	verdict: Verdict;
	reason: string;
	decidedBy?: RuleRef;
	exceptions: RuleRef[];
	confidence: Confidence;
}

export interface ConnectivityReport {
	mode: FirewallMode;
	networks: { id: string; name: string; vlan: number | null; subnet: string | null; role: string; isolated: boolean; zone: string | null }[];
	pairs: PairResult[];
	notes: string[];
}

type Decision = "accept" | "drop";

function isBlock(action: string | undefined): boolean {
	const a = (action ?? "").toLowerCase();
	return a === "drop" || a === "reject" || a === "block";
}

function and(...values: Coverage[]): Coverage {
	if (values.includes("none")) return "none";
	if (values.every((v) => v === "full")) return "full";
	return "partial";
}

function invert(value: Coverage): Coverage {
	if (value === "full") return "none";
	if (value === "none") return "full";
	return "partial";
}

function finalVerdict(decision: Decision, exceptions: RuleRef[]): Verdict {
	if (decision === "accept") return exceptions.length ? "allowed_with_exceptions" : "allowed";
	return exceptions.length ? "blocked_with_exceptions" : "blocked";
}

/* ------------------------------------------------------------------ legacy */

function legacyEndpointCoverage(
	rule: UnifiFirewallRule,
	side: "src" | "dst",
	net: Network,
	groups: Map<string, UnifiFirewallGroup>,
): { address: Coverage; portRestricted: boolean } {
	const networkId = rule[`${side}_networkconf_id`];
	const networkType = rule[`${side}_networkconf_type`];
	const groupIds = rule[`${side}_firewallgroup_ids`] ?? [];
	const address = rule[`${side}_address`];
	const mac = side === "src" ? rule.src_mac_address : undefined;
	const port = rule[`${side}_port`];
	let portRestricted = Boolean(port);

	if (networkId) {
		// ADDRv4 targets the gateway's own address on that network, not the subnet.
		if (networkType === "ADDRv4") return { address: "none", portRestricted };
		return { address: networkId === net.id ? "full" : "none", portRestricted };
	}

	const addressGroups: UnifiFirewallGroup[] = [];
	for (const id of groupIds) {
		const g = groups.get(id);
		if (!g) continue;
		if (g.group_type === "port-group") portRestricted = true;
		else if (g.group_type === "address-group") addressGroups.push(g);
	}
	if (addressGroups.length && net.cidr) {
		const members = addressGroups.flatMap((g) => g.group_members ?? []);
		return { address: combineCoverage(members.map((m) => coverage(m, net.cidr!))), portRestricted };
	}
	if (address && net.cidr) return { address: coverage(address, net.cidr), portRestricted };
	if (mac) return { address: "partial", portRestricted };
	return { address: "full", portRestricted };
}

export function legacyRuleCoverage(
	rule: UnifiFirewallRule,
	src: Network,
	dst: Network,
	groups: Map<string, UnifiFirewallGroup>,
): Coverage {
	const states = [rule.state_new, rule.state_established, rule.state_related, rule.state_invalid];
	const anyStateSelected = states.some(Boolean);
	if (anyStateSelected && !rule.state_new) return "none";

	const s = legacyEndpointCoverage(rule, "src", src, groups);
	const d = legacyEndpointCoverage(rule, "dst", dst, groups);
	const proto = (rule.protocol ?? "all").toLowerCase();
	const protoCoverage: Coverage = proto === "all" && !rule.protocol_match_excepted ? "full" : "partial";
	const portCoverage: Coverage = s.portRestricted || d.portRestricted ? "partial" : "full";
	return and(s.address, d.address, protoCoverage, portCoverage);
}

function evaluateLegacyChain(
	rules: UnifiFirewallRule[],
	src: Network,
	dst: Network,
	groups: Map<string, UnifiFirewallGroup>,
	exceptions: RuleRef[],
): { decision: Decision; rule: UnifiFirewallRule } | null {
	const pendingPartials: RuleRef[] = [];
	for (const rule of rules) {
		const cov = legacyRuleCoverage(rule, src, dst, groups);
		if (cov === "none") continue;
		const ref: RuleRef = {
			id: rule._id,
			name: rule.name ?? rule._id,
			action: rule.action ?? "unknown",
			origin: "user",
			detail: `${rule.ruleset} #${rule.rule_index}`,
		};
		if (cov === "partial") {
			pendingPartials.push(ref);
			continue;
		}
		const decision: Decision = isBlock(rule.action) ? "drop" : "accept";
		for (const p of pendingPartials) {
			if ((decision === "drop") !== isBlock(p.action)) exceptions.push(p);
		}
		return { decision, rule };
	}
	exceptions.push(...pendingPartials);
	return null;
}

export function legacyConnectivity(
	networks: Network[],
	rules: UnifiFirewallRule[],
	groupsList: UnifiFirewallGroup[],
): ConnectivityReport {
	const groups = new Map(groupsList.map((g) => [g._id, g]));
	const active = rules
		.filter((r) => r.enabled !== false)
		.sort((a, b) => Number(a.rule_index ?? 0) - Number(b.rule_index ?? 0));
	const byRuleset = (name: string) => active.filter((r) => r.ruleset === name);
	const routed = routedNetworks(networks);
	const pairs: PairResult[] = [];

	for (const src of routed) {
		for (const dst of routed) {
			if (src.id === dst.id) continue;
			const srcGuest = src.purpose === "guest";
			const dstGuest = dst.purpose === "guest";
			const chains = [srcGuest ? "GUEST_IN" : "LAN_IN", dstGuest ? "GUEST_OUT" : "LAN_OUT"];
			const exceptions: RuleRef[] = [];
			let explicitAccept: UnifiFirewallRule | null = null;
			let blocked: UnifiFirewallRule | null = null;

			for (const chain of chains) {
				const result = evaluateLegacyChain(byRuleset(chain), src, dst, groups, exceptions);
				if (!result) continue;
				if (result.decision === "drop") {
					blocked = result.rule;
					break;
				}
				explicitAccept ??= result.rule;
			}

			const base = { from: src.name, fromId: src.id, to: dst.name, toId: dst.id };
			const relevantExceptions = (decision: Decision) =>
				exceptions.filter((e) => (decision === "drop") !== isBlock(e.action));

			if (blocked) {
				const ex = relevantExceptions("drop");
				pairs.push({
					...base,
					verdict: finalVerdict("drop", ex),
					reason: `Blocked by firewall rule "${blocked.name ?? blocked._id}" (${blocked.ruleset})`,
					decidedBy: { id: blocked._id, name: blocked.name ?? blocked._id, action: blocked.action ?? "drop", origin: "user" },
					exceptions: ex,
					confidence: "high",
				});
				continue;
			}
			if (explicitAccept) {
				const ex = relevantExceptions("accept");
				pairs.push({
					...base,
					verdict: finalVerdict("accept", ex),
					reason: `Allowed by firewall rule "${explicitAccept.name ?? explicitAccept._id}" (${explicitAccept.ruleset})`,
					decidedBy: { id: explicitAccept._id, name: explicitAccept.name ?? explicitAccept._id, action: explicitAccept.action ?? "accept", origin: "user" },
					exceptions: ex,
					confidence: "high",
				});
				continue;
			}

			let decision: Decision = "accept";
			let reason = "No user rule matches; UniFi allows inter-VLAN routing between corporate networks by default";
			let confidence: Confidence = "high";
			if (srcGuest) {
				decision = "drop";
				reason = "Guest network: UniFi blocks guest-to-LAN traffic by default";
			} else if (src.isolated || dst.isolated) {
				decision = "drop";
				reason = `Network isolation is enabled on "${src.isolated ? src.name : dst.name}"`;
			} else if (dstGuest) {
				reason = "No user rule matches; new connections into a guest network are not blocked by a default rule";
				confidence = "medium";
			}
			const ex = relevantExceptions(decision);
			pairs.push({
				...base,
				verdict: finalVerdict(decision, ex),
				reason,
				decidedBy: { id: "default", name: "UniFi default behaviour", action: decision, origin: "default" },
				exceptions: ex,
				confidence,
			});
		}
	}

	return {
		mode: "legacy",
		networks: routed.map((n) => ({ id: n.id, name: n.name, vlan: n.vlan, subnet: n.subnet, role: n.role, isolated: n.isolated, zone: null })),
		pairs,
		notes: [
			"Evaluates new IPv4 connections between routed networks using LAN_IN/LAN_OUT/GUEST_IN/GUEST_OUT rules in rule_index order (first match wins).",
			"Rules restricted to specific ports, protocols, MAC addresses or partial address ranges are reported as exceptions rather than deciding the verdict.",
			"Traffic to the gateway itself (LAN_LOCAL: DNS, DHCP, management UI) and Layer-2 traffic within a VLAN are not covered.",
		],
	};
}

/* -------------------------------------------------------------- zone-based */

const DEFAULT_ZONE_MATRIX: Record<string, Record<string, Decision>> = {
	internal: { internal: "accept", external: "accept", gateway: "accept", vpn: "accept", hotspot: "accept", dmz: "accept" },
	vpn: { internal: "accept", external: "accept", gateway: "accept", vpn: "accept", hotspot: "accept", dmz: "accept" },
	gateway: { internal: "accept", external: "accept", gateway: "accept", vpn: "accept", hotspot: "accept", dmz: "accept" },
	external: { internal: "drop", external: "drop", gateway: "drop", vpn: "drop", hotspot: "drop", dmz: "drop" },
	hotspot: { internal: "drop", external: "accept", gateway: "drop", vpn: "drop", hotspot: "accept", dmz: "drop" },
	dmz: { internal: "drop", external: "accept", gateway: "drop", vpn: "drop", hotspot: "drop", dmz: "accept" },
};

function zoneEndpointCoverage(ep: UnifiPolicyEndpoint | undefined, net: Network): Coverage {
	if (!ep) return "full";
	if (ep.zone_id && ep.zone_id !== net.zoneId) return "none";
	const target = (ep.matching_target ?? "ANY").toUpperCase();
	if (target === "ANY") return "full";
	if (target === "NETWORK") {
		const hit: Coverage = (ep.network_ids ?? []).includes(net.id) ? "full" : "none";
		return ep.match_opposite_networks ? invert(hit) : hit;
	}
	if (target === "IP" && net.cidr) {
		const hit = combineCoverage((ep.ips ?? []).map((ip) => coverage(ip, net.cidr!)));
		return ep.match_opposite_ips ? invert(hit) : hit;
	}
	// CLIENT, MAC, DEVICE, REGION, APP, DOMAIN...: matches only some hosts or flows.
	return "partial";
}

export function zonePolicyCoverage(policy: UnifiFirewallPolicy, src: Network, dst: Network): Coverage {
	if ((policy.ip_version ?? "BOTH").toUpperCase() === "IPV6") return "none";
	const stateType = (policy.connection_state_type ?? "ALL").toUpperCase();
	if (stateType === "RESPOND_ONLY") return "none";
	if (stateType === "CUSTOM" && !(policy.connection_states ?? []).map((s) => s.toUpperCase()).includes("NEW")) return "none";

	const s = zoneEndpointCoverage(policy.source, src);
	const d = zoneEndpointCoverage(policy.destination, dst);
	const proto = (policy.protocol ?? "all").toLowerCase();
	const protoCov: Coverage = proto === "all" ? "full" : "partial";
	const ports = [policy.source?.port_matching_type, policy.destination?.port_matching_type].map((p) => (p ?? "ANY").toUpperCase());
	const portCov: Coverage = ports.every((p) => p === "ANY") ? "full" : "partial";
	const scheduleMode = (policy.schedule?.mode ?? "ALWAYS").toUpperCase();
	const schedCov: Coverage = scheduleMode === "ALWAYS" ? "full" : "partial";
	return and(s, d, protoCov, portCov, schedCov);
}

export function zoneConnectivity(networks: Network[], zones: UnifiZone[], policies: UnifiFirewallPolicy[]): ConnectivityReport {
	const zoneById = new Map(zones.map((z) => [z._id, z]));
	const active = policies.filter((p) => p.enabled !== false).sort((a, b) => (a.index ?? 0) - (b.index ?? 0));
	const user = active.filter((p) => !p.predefined);
	const predefined = active.filter((p) => p.predefined);
	const routed = routedNetworks(networks);
	const pairs: PairResult[] = [];

	const ref = (p: UnifiFirewallPolicy): RuleRef => ({
		id: p._id,
		name: p.name ?? p._id,
		action: p.action ?? "unknown",
		origin: p.predefined ? "predefined" : "user",
	});

	const firstFull = (list: UnifiFirewallPolicy[], src: Network, dst: Network, partials: RuleRef[]) => {
		for (const p of list) {
			const cov = zonePolicyCoverage(p, src, dst);
			if (cov === "full") return p;
			if (cov === "partial") partials.push(ref(p));
		}
		return null;
	};

	for (const src of routed) {
		for (const dst of routed) {
			if (src.id === dst.id) continue;
			const base = { from: src.name, fromId: src.id, to: dst.name, toId: dst.id };
			const partials: RuleRef[] = [];
			const opposite = (decision: Decision) => partials.filter((p) => (decision === "drop") !== isBlock(p.action));

			const userHit = firstFull(user, src, dst, partials);
			if (userHit) {
				const decision: Decision = isBlock(userHit.action) ? "drop" : "accept";
				const ex = opposite(decision);
				pairs.push({ ...base, verdict: finalVerdict(decision, ex), reason: `${decision === "drop" ? "Blocked" : "Allowed"} by policy "${userHit.name}"`, decidedBy: ref(userHit), exceptions: ex, confidence: "high" });
				continue;
			}
			if (src.isolated || dst.isolated) {
				const ex = opposite("drop");
				pairs.push({ ...base, verdict: finalVerdict("drop", ex), reason: `Network isolation is enabled on "${src.isolated ? src.name : dst.name}"`, decidedBy: { id: "isolation", name: "Network isolation", action: "BLOCK", origin: "predefined" }, exceptions: ex, confidence: "high" });
				continue;
			}
			const sysHit = firstFull(predefined, src, dst, partials);
			if (sysHit) {
				const decision: Decision = isBlock(sysHit.action) ? "drop" : "accept";
				const ex = opposite(decision);
				pairs.push({ ...base, verdict: finalVerdict(decision, ex), reason: `${decision === "drop" ? "Blocked" : "Allowed"} by built-in policy "${sysHit.name}"`, decidedBy: ref(sysHit), exceptions: ex, confidence: "high" });
				continue;
			}

			const srcKey = src.zoneId ? zoneById.get(src.zoneId)?.zone_key : undefined;
			const dstKey = dst.zoneId ? zoneById.get(dst.zoneId)?.zone_key : undefined;
			let decision: Decision;
			let confidence: Confidence = "medium";
			if (src.zoneId && src.zoneId === dst.zoneId) {
				decision = "accept";
			} else if (srcKey && dstKey && DEFAULT_ZONE_MATRIX[srcKey]?.[dstKey]) {
				decision = DEFAULT_ZONE_MATRIX[srcKey][dstKey];
			} else {
				decision = "drop";
				confidence = "low";
			}
			const ex = opposite(decision);
			const srcZone = src.zoneId ? zoneById.get(src.zoneId)?.name : "unknown";
			const dstZone = dst.zoneId ? zoneById.get(dst.zoneId)?.name : "unknown";
			pairs.push({
				...base,
				verdict: finalVerdict(decision, ex),
				reason: `Default zone behaviour ${srcZone} → ${dstZone}`,
				decidedBy: { id: "default", name: "Zone default", action: decision === "drop" ? "BLOCK" : "ALLOW", origin: "default" },
				exceptions: ex,
				confidence,
			});
		}
	}

	return {
		mode: "zone",
		networks: routed.map((n) => ({ id: n.id, name: n.name, vlan: n.vlan, subnet: n.subnet, role: n.role, isolated: n.isolated, zone: n.zoneId ? (zoneById.get(n.zoneId)?.name ?? n.zoneId) : null })),
		pairs,
		notes: [
			"Evaluates new IPv4 connections between routed networks using zone-based firewall policies: user policies first (by index), then network isolation, then built-in policies, then zone defaults.",
			"Policies restricted to specific ports, protocols, clients, schedules or partial address ranges are reported as exceptions rather than deciding the verdict.",
			"Traffic to the gateway itself and Layer-2 traffic within a VLAN are not covered.",
		],
	};
}
