import type { UnifiClient } from "../unifi/types";
import type { ConnectivityReport, PairResult } from "./connectivity";
import type { Network } from "./networks";

const IOT_VENDOR = /(espressif|tuya|shelly|sonoff|itead|ring|nest|ecobee|signify|philips lighting|wyze|roku|chromecast|sonos|xiaomi|yeelight|tp-?link|kasa|tapo|meross|broadlink|ezviz|hikvision|dahua|reolink|eufy|anker|arlo|lifx|govee|wiz|amazon technologies|ecovacs|irobot|withings|netatmo|tado|aqara|lumi united|switchbot|blink|ubiquiti camera|azurewave|murata|seeed|raspberry)/i;
const IOT_HOSTNAME = /^(esp[-_]|shelly|tasmota|wled|sonoff|tuya|ring|nest|ecobee|wyze|roku|chromecast|google-home|googlehome|echo|alexa|amazon-|sonos|hue|lifx|govee|tapo|kasa|hs1\d\d|kp\d\d\d|camera|cam[-_]|ipcam|nvr|doorbell|thermostat|vacuum|roomba|printer|tv|lg-?webos|samsung-?tv|bravia|firetv|appletv)/i;

export interface IotCheck {
	name: string;
	status: "pass" | "warn" | "fail";
	detail: string;
}

export interface IotNetworkReport {
	network: { id: string; name: string; vlan: number | null; subnet: string | null };
	isolated: boolean;
	internetAccess: boolean;
	checks: IotCheck[];
	reachableNetworks: { name: string; verdict: string; reason: string }[];
}

export interface IotReport {
	verdict: "isolated" | "partially_isolated" | "not_isolated" | "no_iot_network";
	iotNetworks: IotNetworkReport[];
	possibleIotDevicesOnTrustedNetworks: { name: string; mac?: string; ip?: string; network?: string; vendor?: string }[];
	recommendations: string[];
}

export function looksLikeIot(c: UnifiClient): boolean {
	return IOT_VENDOR.test(c.oui ?? "") || IOT_HOSTNAME.test(c.hostname ?? c.name ?? "");
}

export function checkIotIsolation(networks: Network[], connectivity: ConnectivityReport, clients: UnifiClient[]): IotReport {
	const iot = networks.filter((n) => n.role === "iot" && n.enabled);
	const trustedIds = new Set(networks.filter((n) => n.role === "trusted" || n.role === "management").map((n) => n.id));
	const recommendations = new Set<string>();

	const strayDevices = clients
		.filter((c) => c.network_id && trustedIds.has(c.network_id) && looksLikeIot(c))
		.map((c) => ({ name: c.name ?? c.hostname ?? c.mac ?? "unknown", mac: c.mac, ip: c.ip, network: c.network, vendor: c.oui }));

	if (!iot.length) {
		recommendations.add("Create a dedicated IoT VLAN, move smart-home devices to it, and block IoT → trusted traffic (allow only established/related return traffic).");
		if (strayDevices.length) recommendations.add(`Move the ${strayDevices.length} IoT-looking device(s) currently on trusted networks to the new IoT VLAN.`);
		return { verdict: "no_iot_network", iotNetworks: [], possibleIotDevicesOnTrustedNetworks: strayDevices, recommendations: [...recommendations] };
	}

	const reports: IotNetworkReport[] = iot.map((net) => {
		const outbound = connectivity.pairs.filter((p) => p.fromId === net.id);
		const toTrusted = outbound.filter((p) => trustedIds.has(p.toId));
		const reachable = (p: PairResult) => p.verdict === "allowed" || p.verdict === "allowed_with_exceptions";
		const checks: IotCheck[] = [];

		const openToTrusted = toTrusted.filter(reachable);
		const holes = toTrusted.filter((p) => p.verdict === "blocked_with_exceptions");
		if (!toTrusted.length) {
			checks.push({ name: "IoT → trusted networks", status: "warn", detail: "No trusted networks identified to evaluate against." });
		} else if (openToTrusted.length) {
			checks.push({ name: "IoT → trusted networks", status: "fail", detail: `Can initiate connections to: ${openToTrusted.map((p) => `${p.to} (${p.reason})`).join("; ")}.` });
			recommendations.add(`Block new connections from "${net.name}" to ${openToTrusted.map((p) => `"${p.to}"`).join(", ")}, or enable network isolation on "${net.name}".`);
		} else if (holes.length) {
			checks.push({ name: "IoT → trusted networks", status: "warn", detail: `Blocked, with exceptions: ${holes.map((p) => `${p.to} via ${p.exceptions.map((e) => `"${e.name}"`).join(", ")}`).join("; ")}.` });
			recommendations.add("Review the exceptions that allow IoT traffic into trusted networks and scope them to specific hosts/ports.");
		} else {
			checks.push({ name: "IoT → trusted networks", status: "pass", detail: "New connections to all trusted networks are blocked." });
		}

		const otherOpen = outbound.filter((p) => !trustedIds.has(p.toId) && reachable(p));
		checks.push(
			otherOpen.length
				? { name: "IoT → other networks", status: "warn", detail: `Can reach: ${otherOpen.map((p) => p.to).join(", ")}.` }
				: { name: "IoT → other networks", status: "pass", detail: "No other routed networks are reachable." },
		);

		const wildcardHit = connectivity.pairs.some((p) => p.fromId === net.id && p.decidedBy?.origin === "user" && reachable(p));
		if (wildcardHit) {
			checks.push({ name: "Explicit allow rules", status: "warn", detail: "At least one user-defined rule explicitly allows traffic out of this IoT network to another LAN." });
		}

		checks.push(
			net.isolated
				? { name: "Network isolation", status: "pass", detail: "UniFi network isolation is enabled." }
				: { name: "Network isolation", status: "warn", detail: "UniFi network isolation is not enabled; separation relies on firewall rules only." },
		);

		checks.push(
			net.mdns
				? { name: "mDNS", status: "warn", detail: "mDNS reflection is enabled; service discovery crosses VLANs." }
				: { name: "mDNS", status: "pass", detail: "mDNS reflection is disabled." },
		);

		const reachableNetworks = outbound.map((p) => ({ name: p.to, verdict: p.verdict, reason: p.reason }));
		return { network: { id: net.id, name: net.name, vlan: net.vlan, subnet: net.subnet }, isolated: net.isolated, internetAccess: net.internetAccess, checks, reachableNetworks };
	});

	if (strayDevices.length) {
		recommendations.add(`${strayDevices.length} device(s) on trusted networks look like IoT devices (by vendor/hostname); consider moving them to the IoT VLAN.`);
	}
	recommendations.add("Allow IoT devices to reach only the gateway services they need (DHCP, DNS, NTP) and block access to the gateway management UI from the IoT network.");

	const failures = reports.flatMap((r) => r.checks).filter((c) => c.name === "IoT → trusted networks");
	const verdict = failures.every((c) => c.status === "pass")
		? strayDevices.length
			? "partially_isolated"
			: "isolated"
		: failures.some((c) => c.status === "fail")
			? "not_isolated"
			: "partially_isolated";

	return { verdict, iotNetworks: reports, possibleIotDevicesOnTrustedNetworks: strayDevices, recommendations: [...recommendations] };
}
