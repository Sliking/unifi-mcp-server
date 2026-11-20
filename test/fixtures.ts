import type {
	UnifiClient,
	UnifiDevice,
	UnifiFirewallGroup,
	UnifiFirewallPolicy,
	UnifiFirewallRule,
	UnifiNetworkConf,
	UnifiPortForward,
	UnifiSetting,
	UnifiWlan,
	UnifiZone,
} from "../src/unifi/types";

export const networks: UnifiNetworkConf[] = [
	{ _id: "wan", name: "Internet 1", purpose: "wan" },
	{ _id: "lan", name: "Default", purpose: "corporate", ip_subnet: "192.168.1.1/24", vlan_enabled: false },
	{ _id: "iot", name: "IoT", purpose: "corporate", ip_subnet: "192.168.20.1/24", vlan_enabled: true, vlan: 20, mdns_enabled: true },
	{ _id: "cams", name: "Cameras", purpose: "corporate", ip_subnet: "192.168.30.1/24", vlan_enabled: true, vlan: 30, network_isolation_enabled: true },
	{ _id: "guest", name: "Guest", purpose: "guest", ip_subnet: "192.168.40.1/24", vlan_enabled: true, vlan: 40 },
];

export const groups: UnifiFirewallGroup[] = [
	{ _id: "g-rfc1918", name: "RFC1918", group_type: "address-group", group_members: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] },
	{ _id: "g-unused", name: "Old servers", group_type: "address-group", group_members: ["192.168.1.50"] },
	{ _id: "g-hass", name: "Home Assistant port", group_type: "port-group", group_members: ["8123"] },
];

export const legacyRules: UnifiFirewallRule[] = [
	{ _id: "r1", name: "Allow established", ruleset: "LAN_IN", rule_index: 2000, action: "accept", enabled: true, protocol: "all", state_established: true, state_related: true },
	{ _id: "r2", name: "Allow IoT to Home Assistant", ruleset: "LAN_IN", rule_index: 2001, action: "accept", enabled: true, protocol: "tcp", src_networkconf_id: "iot", src_networkconf_type: "NETv4", dst_address: "192.168.1.10", dst_port: "8123" },
	{ _id: "r3", name: "Block IoT to LAN", ruleset: "LAN_IN", rule_index: 2002, action: "drop", enabled: true, protocol: "all", src_networkconf_id: "iot", src_networkconf_type: "NETv4", dst_firewallgroup_ids: ["g-rfc1918"] },
	{ _id: "r4", name: "Block IoT to LAN (dup)", ruleset: "LAN_IN", rule_index: 2003, action: "drop", enabled: true, protocol: "all", src_networkconf_id: "iot", src_networkconf_type: "NETv4", dst_firewallgroup_ids: ["g-rfc1918"] },
	{ _id: "r5", name: "Plex", ruleset: "WAN_IN", rule_index: 2000, action: "accept", enabled: true, protocol: "tcp", dst_address: "192.168.1.20", dst_port: "32400" },
	{ _id: "r6", name: "Old rule", ruleset: "LAN_IN", rule_index: 2010, action: "accept", enabled: false, protocol: "all" },
];

export const zones: UnifiZone[] = [
	{ _id: "z-int", name: "Internal", zone_key: "internal", network_ids: ["lan"] },
	{ _id: "z-iot", name: "IoT", network_ids: ["iot"] },
	{ _id: "z-ext", name: "External", zone_key: "external", network_ids: ["wan"] },
	{ _id: "z-hot", name: "Hotspot", zone_key: "hotspot", network_ids: ["guest"] },
	{ _id: "z-dmz", name: "DMZ", zone_key: "dmz", network_ids: ["cams"] },
	{ _id: "z-gw", name: "Gateway", zone_key: "gateway", network_ids: [] },
];

export const zonePolicies: UnifiFirewallPolicy[] = [
	{ _id: "p1", name: "IoT to Internet", action: "ALLOW", index: 10000, enabled: true, protocol: "all", source: { zone_id: "z-iot", matching_target: "ANY" }, destination: { zone_id: "z-ext", matching_target: "ANY" } },
	{ _id: "p2", name: "LAN to IoT", action: "ALLOW", index: 10001, enabled: true, protocol: "all", source: { zone_id: "z-int", matching_target: "ANY" }, destination: { zone_id: "z-iot", matching_target: "ANY" } },
	{ _id: "p3", name: "IoT to HA", action: "ALLOW", index: 10002, enabled: true, protocol: "tcp", source: { zone_id: "z-iot", matching_target: "ANY" }, destination: { zone_id: "z-int", matching_target: "IP", ips: ["192.168.1.10"], port_matching_type: "SPECIFIC", port: "8123" } },
	{ _id: "p4", name: "Expose NAS", action: "ALLOW", index: 10003, enabled: true, protocol: "tcp", source: { zone_id: "z-ext", matching_target: "ANY" }, destination: { zone_id: "z-int", matching_target: "IP", ips: ["192.168.1.30"], port_matching_type: "SPECIFIC", port: "5000" } },
	{ _id: "pd1", name: "Block All Traffic", action: "BLOCK", index: 30000, predefined: true, enabled: true, protocol: "all", source: { zone_id: "z-iot", matching_target: "ANY" }, destination: { zone_id: "z-int", matching_target: "ANY" } },
];

export const portForwards: UnifiPortForward[] = [
	{ _id: "pf1", name: "RDP", enabled: true, src: "any", dst_port: "3389", fwd: "192.168.1.50", fwd_port: "3389", proto: "tcp" },
	{ _id: "pf2", name: "Game", enabled: true, src: "203.0.113.5", dst_port: "25565", fwd: "192.168.1.60", proto: "tcp", log: true },
];

export const wlans: UnifiWlan[] = [
	{ _id: "w1", name: "Home", enabled: true, security: "wpapsk", wpa_mode: "wpa2", wpa3_support: false, pmf_mode: "disabled", networkconf_id: "lan", x_passphrase: "supersecret" } as UnifiWlan,
	{ _id: "w2", name: "Guest", enabled: true, security: "open", is_guest: true, networkconf_id: "guest", l2_isolation: false },
];

export const settings: UnifiSetting[] = [
	{ key: "usg", upnp_enabled: true },
	{ key: "ips", ips_mode: "disabled" },
	{ key: "mgmt", x_ssh_enabled: true, x_ssh_password: "hunter2" },
];

export const devices: UnifiDevice[] = [
	{ mac: "aa", name: "UDM Pro", model: "UDMPRO", type: "udm", version: "4.0.0", upgradable: true, upgrade_to_firmware: "4.1.0", state: 1 },
	{ mac: "bb", name: "Garage AP", model: "U6LR", type: "uap", version: "6.0", state: 0 },
];

export const clients: UnifiClient[] = [
	{ mac: "c1", hostname: "desktop", ip: "192.168.1.100", network: "Default", network_id: "lan", is_wired: true, "wired-tx_bytes": 50e9, "wired-rx_bytes": 5e9, "wired-tx_bytes-r": 1000, "wired-rx_bytes-r": 100, uptime: 86400 },
	{ mac: "c2", hostname: "esp-12345", oui: "Espressif Inc.", ip: "192.168.1.150", network: "Default", network_id: "lan", is_wired: false, tx_bytes: 1e6, rx_bytes: 1e6, "tx_bytes-r": 10, "rx_bytes-r": 10, uptime: 600 },
	{ mac: "c3", hostname: "tv", ip: "192.168.20.5", network: "IoT", network_id: "iot", is_wired: false, tx_bytes: 80e9, rx_bytes: 1e9, "tx_bytes-r": 5_000_000, "rx_bytes-r": 1000, uptime: 7200 },
];
