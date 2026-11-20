export interface Cidr {
	network: number;
	prefix: number;
}

export function parseIpv4(ip: string): number | null {
	const parts = ip.trim().split(".");
	if (parts.length !== 4) return null;
	let value = 0;
	for (const part of parts) {
		if (!/^\d{1,3}$/.test(part)) return null;
		const n = Number(part);
		if (n > 255) return null;
		value = value * 256 + n;
	}
	return value >>> 0;
}

export function formatIpv4(value: number): string {
	return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
}

function maskFor(prefix: number): number {
	return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

/** Parses "10.0.0.1/24", "10.0.0.0/24" or a bare address (treated as /32). Host bits are cleared. */
export function parseCidr(input: string | undefined | null): Cidr | null {
	if (!input) return null;
	const [addr, prefixRaw] = input.trim().split("/");
	const ip = parseIpv4(addr ?? "");
	if (ip === null) return null;
	const prefix = prefixRaw === undefined ? 32 : Number(prefixRaw);
	if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
	return { network: (ip & maskFor(prefix)) >>> 0, prefix };
}

/** Parses "10.0.0.10-10.0.0.20" ranges into [start, end]. */
export function parseRange(input: string): [number, number] | null {
	const [a, b] = input.split("-").map((s) => s.trim());
	if (!a || !b) return null;
	const start = parseIpv4(a);
	const end = parseIpv4(b);
	if (start === null || end === null || end < start) return null;
	return [start, end];
}

export function cidrRange(cidr: Cidr): [number, number] {
	const size = 2 ** (32 - cidr.prefix);
	return [cidr.network, cidr.network + size - 1];
}

export function formatCidr(cidr: Cidr): string {
	return `${formatIpv4(cidr.network)}/${cidr.prefix}`;
}

export type Coverage = "full" | "partial" | "none";

/**
 * Returns how much of `target` is covered by the address expression `expr`
 * (a CIDR, a bare IP or an "a-b" range).
 */
export function coverage(expr: string, target: Cidr): Coverage {
	const [tStart, tEnd] = cidrRange(target);
	let range: [number, number] | null = null;
	if (expr.includes("-")) {
		range = parseRange(expr);
	} else {
		const c = parseCidr(expr);
		if (c) range = cidrRange(c);
	}
	if (!range) return "none";
	const [start, end] = range;
	if (start <= tStart && end >= tEnd) return "full";
	if (end < tStart || start > tEnd) return "none";
	return "partial";
}

export function combineCoverage(values: Coverage[]): Coverage {
	if (values.includes("full")) return "full";
	if (values.includes("partial")) return "partial";
	return "none";
}

export function isRfc1918(cidr: Cidr): boolean {
	return (
		coverage("10.0.0.0/8", cidr) === "full" ||
		coverage("172.16.0.0/12", cidr) === "full" ||
		coverage("192.168.0.0/16", cidr) === "full"
	);
}
