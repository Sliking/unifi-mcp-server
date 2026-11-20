import type { UnifiClient } from "../unifi/types";

export interface Talker {
	name: string;
	mac?: string;
	ip?: string;
	network?: string;
	connection: "wired" | "wireless";
	ssid?: string;
	vendor?: string;
	uploadBytes: number;
	downloadBytes: number;
	totalBytes: number;
	total: string;
	currentRate: string;
	currentRateBps: number;
	connectedFor: string;
}

export function formatBytes(bytes: number): string {
	const units = ["B", "KB", "MB", "GB", "TB", "PB"];
	let v = bytes;
	let i = 0;
	while (v >= 1024 && i < units.length - 1) {
		v /= 1024;
		i++;
	}
	return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatRate(bytesPerSecond: number): string {
	const bits = bytesPerSecond * 8;
	if (bits >= 1e9) return `${(bits / 1e9).toFixed(2)} Gbps`;
	if (bits >= 1e6) return `${(bits / 1e6).toFixed(1)} Mbps`;
	if (bits >= 1e3) return `${(bits / 1e3).toFixed(0)} Kbps`;
	return `${bits.toFixed(0)} bps`;
}

export function formatDuration(seconds: number | undefined): string {
	if (!seconds || seconds < 0) return "unknown";
	const d = Math.floor(seconds / 86400);
	const h = Math.floor((seconds % 86400) / 3600);
	const m = Math.floor((seconds % 3600) / 60);
	return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

/**
 * UniFi reports counters from the access point / switch port perspective:
 * `tx_bytes` is traffic sent to the client (download), `rx_bytes` is traffic received from it (upload).
 */
export function toTalker(c: UnifiClient): Talker {
	const wired = c.is_wired === true;
	const down = (wired ? c["wired-tx_bytes"] : c.tx_bytes) ?? c.tx_bytes ?? 0;
	const up = (wired ? c["wired-rx_bytes"] : c.rx_bytes) ?? c.rx_bytes ?? 0;
	const rate = ((wired ? c["wired-tx_bytes-r"] : c["tx_bytes-r"]) ?? 0) + ((wired ? c["wired-rx_bytes-r"] : c["rx_bytes-r"]) ?? 0);
	const total = down + up;
	return {
		name: c.name || c.hostname || c.mac || "unknown",
		mac: c.mac,
		ip: c.ip,
		network: c.network,
		connection: wired ? "wired" : "wireless",
		ssid: wired ? undefined : c.essid,
		vendor: c.oui || undefined,
		uploadBytes: up,
		downloadBytes: down,
		totalBytes: total,
		total: formatBytes(total),
		currentRate: formatRate(rate),
		currentRateBps: rate,
		connectedFor: formatDuration(c.uptime),
	};
}

export function topTalkers(
	clients: UnifiClient[],
	opts: { limit: number; sortBy: "total" | "current_rate"; network?: string },
): { sortBy: string; clientCount: number; totalTraffic: string; talkers: (Talker & { share: string })[]; notes: string[] } {
	let list = clients.map(toTalker);
	if (opts.network) {
		const needle = opts.network.toLowerCase();
		list = list.filter((t) => (t.network ?? "").toLowerCase() === needle);
	}
	const key = opts.sortBy === "current_rate" ? "currentRateBps" : "totalBytes";
	list.sort((a, b) => b[key] - a[key]);
	const sum = list.reduce((acc, t) => acc + t[key], 0);
	return {
		sortBy: opts.sortBy,
		clientCount: list.length,
		totalTraffic: opts.sortBy === "current_rate" ? formatRate(sum) : formatBytes(sum),
		talkers: list.slice(0, opts.limit).map((t) => ({ ...t, share: sum ? `${((t[key] / sum) * 100).toFixed(1)}%` : "0%" })),
		notes: [
			"Totals are cumulative since each client's current session started (see connectedFor), so long-connected clients are favoured. Use sort_by=current_rate for what is busy right now.",
		],
	};
}
