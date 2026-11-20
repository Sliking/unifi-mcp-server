import { describe, expect, it } from "vitest";
import { expandPorts, runAudit } from "../src/analysis/audit";
import { legacyConnectivity, zoneConnectivity } from "../src/analysis/connectivity";
import { checkIotIsolation } from "../src/analysis/iot";
import { coverage, parseCidr } from "../src/analysis/ipv4";
import { normaliseNetworks } from "../src/analysis/networks";
import { topTalkers } from "../src/analysis/traffic";
import { REDACTED, redact } from "../src/unifi/redact";
import * as f from "./fixtures";

const verdict = (pairs: { from: string; to: string; verdict: string }[], from: string, to: string) =>
	pairs.find((p) => p.from === from && p.to === to)?.verdict;

describe("ipv4", () => {
	it("normalises host bits", () => {
		expect(parseCidr("192.168.1.1/24")).toEqual({ network: 0xc0a80100, prefix: 24 });
	});
	it("computes coverage", () => {
		const net = parseCidr("192.168.20.0/24")!;
		expect(coverage("192.168.0.0/16", net)).toBe("full");
		expect(coverage("192.168.20.10", net)).toBe("partial");
		expect(coverage("10.0.0.0/8", net)).toBe("none");
		expect(coverage("192.168.20.0-192.168.20.255", net)).toBe("full");
	});
});

describe("redact", () => {
	it("removes UniFi secrets recursively", () => {
		const out = redact({ name: "Home", x_passphrase: "p", nested: [{ radius_secret: "s", key: "usg" }] });
		expect(out).toEqual({ name: "Home", x_passphrase: REDACTED, nested: [{ radius_secret: REDACTED, key: "usg" }] });
	});
});

describe("network classification", () => {
	it("infers roles and VLANs", () => {
		const nets = normaliseNetworks(f.networks);
		const byName = Object.fromEntries(nets.map((n) => [n.name, n]));
		expect(byName.Default).toMatchObject({ role: "trusted", vlan: 1, subnet: "192.168.1.0/24" });
		expect(byName.IoT).toMatchObject({ role: "iot", vlan: 20 });
		expect(byName.Cameras).toMatchObject({ role: "iot", isolated: true });
		expect(byName.Guest).toMatchObject({ role: "guest" });
		expect(byName["Internet 1"]).toBeUndefined();
	});
	it("honours explicit IoT names", () => {
		const nets = normaliseNetworks([{ _id: "x", name: "Lab", purpose: "corporate", ip_subnet: "10.9.0.1/24" }], [], ["lab"]);
		expect(nets[0].role).toBe("iot");
	});
});

describe("legacy connectivity", () => {
	const nets = normaliseNetworks(f.networks);
	const report = legacyConnectivity(nets, f.legacyRules, f.groups);

	it("blocks IoT → LAN with a documented exception", () => {
		expect(verdict(report.pairs, "IoT", "Default")).toBe("blocked_with_exceptions");
		const pair = report.pairs.find((p) => p.from === "IoT" && p.to === "Default")!;
		expect(pair.decidedBy?.name).toBe("Block IoT to LAN");
		expect(pair.exceptions.map((e) => e.name)).toContain("Allow IoT to Home Assistant");
	});
	it("allows LAN → IoT by default", () => {
		expect(verdict(report.pairs, "Default", "IoT")).toBe("allowed");
	});
	it("ignores established-only rules for new connections", () => {
		const pair = report.pairs.find((p) => p.from === "Default" && p.to === "IoT")!;
		expect(pair.decidedBy?.origin).toBe("default");
	});
	it("applies guest and isolation defaults", () => {
		expect(verdict(report.pairs, "Guest", "Default")).toBe("blocked");
		expect(verdict(report.pairs, "Default", "Cameras")).toBe("blocked");
		expect(verdict(report.pairs, "Cameras", "Default")).toBe("blocked");
	});
});

describe("zone connectivity", () => {
	const nets = normaliseNetworks(f.networks, f.zones);
	const report = zoneConnectivity(nets, f.zones, f.zonePolicies);

	it("uses user policies before built-in ones", () => {
		expect(verdict(report.pairs, "Default", "IoT")).toBe("allowed");
		expect(verdict(report.pairs, "IoT", "Default")).toBe("blocked_with_exceptions");
	});
	it("falls back to zone defaults", () => {
		expect(verdict(report.pairs, "Guest", "Default")).toBe("blocked");
		expect(verdict(report.pairs, "Default", "Guest")).toBe("allowed");
	});
	it("applies network isolation", () => {
		expect(verdict(report.pairs, "Default", "Cameras")).toBe("blocked");
	});
});

describe("audit", () => {
	const nets = normaliseNetworks(f.networks);
	const connectivity = legacyConnectivity(nets, f.legacyRules, f.groups);
	const report = runAudit({ networks: nets, connectivity, rules: f.legacyRules, groups: f.groups, zones: [], policies: [], portForwards: f.portForwards, wlans: f.wlans, settings: f.settings, devices: f.devices, clients: f.clients });
	const ids = report.findings.map((x) => x.id);

	it("flags exposed services and risky gateway settings", () => {
		expect(report.findings.find((x) => x.id === "PF-EXPOSED" && x.resource?.name === "RDP")?.severity).toBe("high");
		expect(ids).toEqual(expect.arrayContaining(["FW-WAN-ACCEPT", "GW-UPNP", "GW-IPS-OFF", "GW-DEVICE-SSH", "DEV-FIRMWARE", "DEV-OFFLINE"]));
	});
	it("flags rule hygiene problems", () => {
		expect(ids).toEqual(expect.arrayContaining(["FW-SHADOWED", "FW-DISABLED", "FW-UNUSED-GROUP", "FW-NO-LOGGING"]));
	});
	it("flags Wi-Fi weaknesses", () => {
		expect(ids).toEqual(expect.arrayContaining(["WIFI-OPEN", "WIFI-NO-WPA3", "WIFI-NO-PMF", "WIFI-GUEST-NO-CLIENT-ISOLATION"]));
	});
	it("sorts by severity and scores", () => {
		expect(report.findings[0].severity).not.toBe("info");
		expect(report.summary.total).toBe(report.findings.length);
		expect(report.summary.score).toBeLessThan(100);
	});
	it("flags zone policies exposing internal hosts", () => {
		const zNets = normaliseNetworks(f.networks, f.zones);
		const zr = runAudit({ networks: zNets, connectivity: zoneConnectivity(zNets, f.zones, f.zonePolicies), rules: [], groups: [], zones: f.zones, policies: f.zonePolicies, portForwards: [], wlans: [], settings: [], devices: [], clients: [] });
		expect(zr.findings.find((x) => x.id === "ZFW-EXTERNAL-ALLOW")?.severity).toBe("high");
	});
	it("expands port ranges", () => {
		expect(expandPorts("20-22,3389").ports).toEqual([20, 21, 22, 3389]);
		expect(expandPorts("1-65535").count).toBe(65535);
	});
});

describe("IoT isolation", () => {
	it("reports isolation status and stray devices", () => {
		const nets = normaliseNetworks(f.networks);
		const report = checkIotIsolation(nets, legacyConnectivity(nets, f.legacyRules, f.groups), f.clients);
		expect(report.verdict).toBe("partially_isolated");
		expect(report.possibleIotDevicesOnTrustedNetworks.map((d) => d.name)).toEqual(["esp-12345"]);
		const iot = report.iotNetworks.find((n) => n.network.name === "IoT")!;
		expect(iot.checks.find((c) => c.name === "IoT → trusted networks")?.status).toBe("warn");
	});
	it("fails when IoT can reach trusted networks", () => {
		const nets = normaliseNetworks(f.networks);
		const report = checkIotIsolation(nets, legacyConnectivity(nets, [], []), []);
		expect(report.verdict).toBe("not_isolated");
	});
});

describe("top talkers", () => {
	it("ranks by total and by current rate", () => {
		expect(topTalkers(f.clients, { limit: 2, sortBy: "total" }).talkers.map((t) => t.name)).toEqual(["tv", "desktop"]);
		expect(topTalkers(f.clients, { limit: 1, sortBy: "current_rate" }).talkers[0].name).toBe("tv");
		expect(topTalkers(f.clients, { limit: 5, sortBy: "total", network: "default" }).clientCount).toBe(2);
	});
});
