/**
 * Loose shapes of the UniFi Network Application API objects we consume.
 * UniFi does not publish a schema for these endpoints and fields vary between
 * releases, so every field is optional and normalisation code must be defensive.
 */

export interface UnifiSite {
	_id?: string;
	name?: string;
	desc?: string;
	role?: string;
}

export interface UnifiNetworkConf {
	_id: string;
	name?: string;
	purpose?: string; // corporate | guest | wan | vlan-only | remote-user-vpn | site-vpn | vpn-client
	enabled?: boolean;
	vlan_enabled?: boolean;
	vlan?: number | string;
	ip_subnet?: string;
	networkgroup?: string;
	dhcpd_enabled?: boolean;
	network_isolation_enabled?: boolean;
	internet_access_enabled?: boolean;
	mdns_enabled?: boolean;
	igmp_snooping?: boolean;
	firewall_zone_id?: string;
	ipv6_interface_type?: string;
	domain_name?: string;
}

export interface UnifiFirewallRule {
	_id: string;
	name?: string;
	enabled?: boolean;
	action?: string; // accept | drop | reject
	ruleset?: string; // WAN_IN | WAN_OUT | WAN_LOCAL | LAN_IN | LAN_OUT | LAN_LOCAL | GUEST_IN | GUEST_OUT | GUEST_LOCAL
	rule_index?: number | string;
	protocol?: string;
	protocol_match_excepted?: boolean;
	logging?: boolean;
	state_new?: boolean;
	state_established?: boolean;
	state_related?: boolean;
	state_invalid?: boolean;
	src_firewallgroup_ids?: string[];
	src_mac_address?: string;
	src_address?: string;
	src_networkconf_id?: string;
	src_networkconf_type?: string; // NETv4 | ADDRv4
	src_port?: string;
	dst_firewallgroup_ids?: string[];
	dst_address?: string;
	dst_networkconf_id?: string;
	dst_networkconf_type?: string;
	dst_port?: string;
}

export interface UnifiFirewallGroup {
	_id: string;
	name?: string;
	group_type?: string; // address-group | port-group | ipv6-address-group
	group_members?: string[];
}

export interface UnifiPortForward {
	_id: string;
	name?: string;
	enabled?: boolean;
	src?: string; // "any" or a source restriction
	dst_port?: string;
	fwd?: string;
	fwd_port?: string;
	proto?: string;
	log?: boolean;
	pfwd_interface?: string;
}

export interface UnifiZone {
	_id: string;
	name?: string;
	zone_key?: string; // internal | external | gateway | vpn | hotspot | dmz (absent for custom zones)
	network_ids?: string[];
	default_zone?: boolean;
}

export interface UnifiPolicyEndpoint {
	zone_id?: string;
	matching_target?: string; // ANY | NETWORK | IP | MAC | CLIENT | DEVICE | REGION | APP | ...
	matching_target_type?: string;
	network_ids?: string[];
	ips?: string[];
	client_macs?: string[];
	port_matching_type?: string; // ANY | SPECIFIC | OBJECT
	port?: string;
	match_opposite_ips?: boolean;
	match_opposite_ports?: boolean;
	match_opposite_networks?: boolean;
}

export interface UnifiFirewallPolicy {
	_id: string;
	name?: string;
	enabled?: boolean;
	action?: string; // ALLOW | BLOCK | REJECT
	index?: number;
	predefined?: boolean;
	protocol?: string;
	ip_version?: string; // BOTH | IPV4 | IPV6
	connection_state_type?: string; // ALL | RESPOND_ONLY | CUSTOM
	connection_states?: string[];
	logging?: boolean;
	source?: UnifiPolicyEndpoint;
	destination?: UnifiPolicyEndpoint;
	schedule?: { mode?: string };
	description?: string;
}

export interface UnifiWlan {
	_id: string;
	name?: string;
	enabled?: boolean;
	security?: string; // open | wpapsk | wpaeap | wep
	wpa_mode?: string; // wpa1 | wpa2 | auto
	wpa3_support?: boolean;
	wpa3_transition?: boolean;
	pmf_mode?: string; // disabled | optional | required
	is_guest?: boolean;
	hide_ssid?: boolean;
	networkconf_id?: string;
	l2_isolation?: boolean;
	wlan_bands?: string[];
}

export interface UnifiClient {
	mac?: string;
	hostname?: string;
	name?: string;
	ip?: string;
	network?: string;
	network_id?: string;
	oui?: string;
	is_wired?: boolean;
	is_guest?: boolean;
	essid?: string;
	uptime?: number;
	tx_bytes?: number;
	rx_bytes?: number;
	"tx_bytes-r"?: number;
	"rx_bytes-r"?: number;
	"wired-tx_bytes"?: number;
	"wired-rx_bytes"?: number;
	"wired-tx_bytes-r"?: number;
	"wired-rx_bytes-r"?: number;
	last_seen?: number;
	signal?: number;
	vlan?: number;
}

export interface UnifiDevice {
	_id?: string;
	mac?: string;
	name?: string;
	model?: string;
	type?: string; // uap | usw | ugw | udm | uxg
	version?: string;
	upgradable?: boolean;
	upgrade_to_firmware?: string;
	state?: number; // 1 = connected
	ip?: string;
	uptime?: number;
	adopted?: boolean;
	num_sta?: number;
	"tx_bytes"?: number;
	"rx_bytes"?: number;
}

export interface UnifiSetting {
	key?: string;
	[field: string]: unknown;
}

export interface UnifiHealth {
	subsystem?: string;
	status?: string;
	[field: string]: unknown;
}
