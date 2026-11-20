/**
 * UniFi returns credentials (Wi-Fi passphrases, RADIUS secrets, VPN keys, SSH
 * passwords) in plain text on many configuration endpoints. Nothing returned to
 * an MCP client may contain them, because tool output ends up in third-party
 * LLM context windows and chat logs.
 */

const SENSITIVE_KEY =
	/(passphrase|password|passwd|secret|private_?key|preshared|pre_shared|psk|wpa_?key|wep_?key|token|auth_?key|api_?key|community|shared_key|x_iapp_key)/i;

export const REDACTED = "[REDACTED]";

export function isSensitiveKey(key: string): boolean {
	// UniFi convention: fields prefixed with `x_` hold secrets.
	if (key.startsWith("x_")) return true;
	return SENSITIVE_KEY.test(key);
}

export function redact<T>(value: T, depth = 0): T {
	if (depth > 32) return REDACTED as unknown as T;
	if (Array.isArray(value)) {
		return value.map((v) => redact(v, depth + 1)) as unknown as T;
	}
	if (value && typeof value === "object") {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
			out[k] = isSensitiveKey(k) ? REDACTED : redact(v, depth + 1);
		}
		return out as T;
	}
	return value;
}
