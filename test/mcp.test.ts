import { createMcpHandler } from "agents/mcp/server";
import { describe, expect, it } from "vitest";
import { createServer } from "../src/mcp/server";
import { UnifiApi } from "../src/unifi/client";
import * as f from "./fixtures";

const routes: Record<string, unknown> = {
	"/proxy/network/api/s/default/rest/networkconf": f.networks,
	"/proxy/network/api/s/default/rest/firewallrule": f.legacyRules,
	"/proxy/network/api/s/default/rest/firewallgroup": f.groups,
	"/proxy/network/api/s/default/rest/portforward": f.portForwards,
	"/proxy/network/api/s/default/rest/wlanconf": f.wlans,
	"/proxy/network/api/s/default/get/setting": f.settings,
	"/proxy/network/api/s/default/stat/device": f.devices,
	"/proxy/network/api/s/default/stat/sta": f.clients,
	"/proxy/network/api/s/default/stat/health": [],
};

const vpc = {
	fetch: async (input: RequestInfo | URL) => {
		const path = new URL(typeof input === "string" || input instanceof URL ? input : input.url).pathname;
		if (path in routes) return Response.json({ meta: { rc: "ok" }, data: routes[path] });
		return new Response("not found", { status: 404 });
	},
} as unknown as Fetcher;

const env = { UNIFI_SITE: "default" } as Env;
const api = new UnifiApi({ baseUrl: "https://unifi.internal", apiKey: "k", vpc });
const handler = createMcpHandler(() => createServer({ env, api, props: { login: "tester", id: 1, name: null } }), { route: "/mcp" });

let id = 0;
async function rpc(method: string, params: Record<string, unknown> = {}) {
	const res = await handler(
		new Request("http://localhost/mcp", {
			method: "POST",
			headers: { host: "localhost", "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18" },
			body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
		}),
		env,
		{ waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext,
	);
	const text = await res.text();
	const payload = text.startsWith("{") ? text : text.split("\n").find((l) => l.startsWith("data:"))!.slice(5);
	return JSON.parse(payload);
}

describe("MCP protocol", () => {
	it("initialises and lists read-only tools", async () => {
		const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
		expect(init.result.serverInfo.name).toBe("unifi-mcp-server");
		const list = await rpc("tools/list");
		const names = list.result.tools.map((t: { name: string }) => t.name);
		expect(names).toEqual(expect.arrayContaining(["unifi_audit_security", "unifi_vlan_connectivity", "unifi_check_iot_isolation", "unifi_top_talkers"]));
		for (const t of list.result.tools) expect(t.annotations.readOnlyHint).toBe(true);
	});

	it("runs the audit end-to-end and never leaks secrets", async () => {
		const res = await rpc("tools/call", { name: "unifi_audit_security", arguments: {} });
		const text: string = res.result.content[0].text;
		expect(res.result.isError).toBeFalsy();
		expect(JSON.parse(text).summary.total).toBeGreaterThan(0);
		const raw = await rpc("tools/call", { name: "unifi_list_firewall", arguments: {} });
		const wifi = await rpc("tools/call", { name: "unifi_list_wifi", arguments: {} });
		for (const body of [text, raw.result.content[0].text, wifi.result.content[0].text]) {
			expect(body).not.toContain("supersecret");
			expect(body).not.toContain("hunter2");
		}
	});

	it("rejects invalid arguments", async () => {
		const res = await rpc("tools/call", { name: "unifi_top_talkers", arguments: { site: "../etc" } });
		expect(res.error ?? res.result.isError).toBeTruthy();
	});

	it("exposes prompts", async () => {
		const res = await rpc("prompts/list");
		expect(res.result.prompts.map((p: { name: string }) => p.name)).toContain("iot_isolation");
	});
});
