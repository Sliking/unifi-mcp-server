import type { UnifiNetworkConf, UnifiZone } from "../unifi/types";
import { type Cidr, formatCidr, parseCidr } from "./ipv4";

export type NetworkRole = "trusted" | "iot" | "guest" | "management" | "other";

export interface Network {
	id: string;
	name: string;
	purpose: string;
	enabled: boolean;
	vlan: number | null;
	subnet: string | null;
	cidr: Cidr | null;
	isolated: boolean;
	internetAccess: boolean;
	mdns: boolean;
	zoneId: string | null;
	role: NetworkRole;
}

const IOT_NAME = /\b(iot|smart|things|cams?|cameras?|cctv|nvr|security|media|tv|automation|home ?assistant|zigbee|matter|thread|appliances?)\b/i;
const GUEST_NAME = /\b(guest|visitor|hotspot|public)\b/i;
const MGMT_NAME = /\b(mgmt|management|infra|admin|network devices)\b/i;

/** Network purposes that represent routed LAN segments the gateway forwards between. */
export const ROUTED_PURPOSES = new Set(["corporate", "guest"]);

export function classifyNetwork(net: UnifiNetworkConf, iotNames: string[] = []): NetworkRole {
	const name = net.name ?? "";
	const explicitIot = iotNames.some((n) => n.toLowerCase() === name.toLowerCase());
	if (explicitIot) return "iot";
	if (net.purpose === "guest" || GUEST_NAME.test(name)) return "guest";
	if (IOT_NAME.test(name)) return "iot";
	if (MGMT_NAME.test(name)) return "management";
	if (net.purpose === "corporate") return "trusted";
	return "other";
}

export function normaliseNetworks(
	raw: UnifiNetworkConf[],
	zones: UnifiZone[] = [],
	iotNames: string[] = [],
): Network[] {
	const zoneByNetwork = new Map<string, string>();
	for (const zone of zones) {
		for (const id of zone.network_ids ?? []) zoneByNetwork.set(id, zone._id);
	}
	return raw
		.filter((n) => n.purpose !== "wan")
		.map((n) => {
			const cidr = parseCidr(n.ip_subnet);
			const vlanNum = n.vlan_enabled ? Number(n.vlan) : NaN;
			return {
				id: n._id,
				name: n.name ?? n._id,
				purpose: n.purpose ?? "unknown",
				enabled: n.enabled !== false,
				vlan: Number.isFinite(vlanNum) && vlanNum > 0 ? vlanNum : n.purpose === "corporate" || n.purpose === "guest" ? 1 : null,
				subnet: cidr ? formatCidr(cidr) : null,
				cidr,
				isolated: n.network_isolation_enabled === true,
				internetAccess: n.internet_access_enabled !== false,
				mdns: n.mdns_enabled === true,
				zoneId: n.firewall_zone_id ?? zoneByNetwork.get(n._id) ?? null,
				role: classifyNetwork(n, iotNames),
			};
		});
}

export function routedNetworks(networks: Network[]): Network[] {
	return networks.filter((n) => n.enabled && ROUTED_PURPOSES.has(n.purpose) && n.cidr);
}
