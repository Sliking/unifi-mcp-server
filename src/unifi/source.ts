import type {
	UnifiClient,
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

export interface DeviceUplink {
	name: string;
	mac?: string;
	model?: string;
	rxRateBps: number;
	txRateBps: number;
}

/** What a given connection mode can see. Tools use this to explain gaps instead of guessing. */
export interface SourceCapabilities {
	/** Per-client byte counters and rates. */
	clientTraffic: boolean;
	/** Port forwarding rules. */
	portForwards: boolean;
	/** Gateway settings such as UPnP, IPS and device SSH. */
	gatewaySettings: boolean;
	/** Legacy (pre zone-based) firewall rules and groups. */
	legacyFirewall: boolean;
	/** Subsystem health (WAN/LAN/WLAN/VPN). */
	health: boolean;
}

/** Read-only view of a UniFi Network application, independent of how it is reached. */
export interface UnifiSource {
	readonly mode: "local" | "cloud";
	readonly capabilities: SourceCapabilities;
	sites(): Promise<UnifiSite[]>;
	networks(site: string): Promise<UnifiNetworkConf[]>;
	zones(site: string): Promise<UnifiZone[]>;
	firewallPolicies(site: string): Promise<UnifiFirewallPolicy[]>;
	firewallRules(site: string): Promise<UnifiFirewallRule[]>;
	firewallGroups(site: string): Promise<UnifiFirewallGroup[]>;
	portForwards(site: string): Promise<UnifiPortForward[]>;
	wlans(site: string): Promise<UnifiWlan[]>;
	clients(site: string): Promise<UnifiClient[]>;
	devices(site: string): Promise<UnifiDevice[]>;
	health(site: string): Promise<UnifiHealth[]>;
	settings(site: string): Promise<UnifiSetting[]>;
	trafficRules(site: string): Promise<Record<string, unknown>[]>;
	deviceUplinks(site: string): Promise<DeviceUplink[]>;
}
